//! One-shot bring-up policy, deliberately separate from a native drain fence.
//!
//! This experiment observes a single bootstrap/association/authorization. It
//! cannot establish that hardware retained across reset was drained by init,
//! and must not graduate a reconnect or production profile on its own.

use hisi_rf_core::OperationId;

use super::{CallbackRoute, RouteError};

/// Bring-up result only. This is not a native drain receipt.
#[doc(hidden)]
pub fn native_initial_open_result() -> Option<Result<(), super::LinkError>> {
    critical_section::with(|cs| {
        super::NATIVE_RX_ROUTE
            .state
            .borrow_ref(cs)
            .initial_open_result
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InitialSession {
    Uninitialized,
    Bootstrapped,
    Armed(OperationId),
    Associating(OperationId),
    Associated(OperationId),
    Opened,
    Rejected,
}

impl InitialSession {
    fn bootstrap(&mut self) {
        *self = match self {
            Self::Uninitialized => Self::Bootstrapped,
            _ => Self::Rejected,
        };
    }

    fn connect(&mut self, id: OperationId) {
        *self = match self {
            Self::Bootstrapped => Self::Armed(id),
            _ => Self::Rejected,
        };
    }

    fn associate(&mut self) {
        *self = match *self {
            Self::Armed(id) => Self::Associating(id),
            _ => Self::Rejected,
        };
    }

    fn result(&mut self, success: bool) {
        *self = match *self {
            Self::Associating(id) if success => Self::Associated(id),
            _ => Self::Rejected,
        };
    }

    pub(super) fn check(&self, id: OperationId) -> Result<(), RouteError> {
        if *self == Self::Associated(id) {
            Ok(())
        } else {
            Err(RouteError::InitialSessionRejected)
        }
    }
}

#[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
impl<const RX: usize, const MTU: usize> CallbackRoute<'_, RX, MTU> {
    pub(crate) fn record_initial_open_result(&self, result: Result<(), super::LinkError>) {
        critical_section::with(|cs| {
            self.state.borrow_ref_mut(cs).initial_open_result = Some(result)
        });
    }

    pub(crate) fn initial_bootstrap_complete(&self) {
        critical_section::with(|cs| self.state.borrow_ref_mut(cs).initial.bootstrap());
    }

    pub(crate) fn initial_connect_started(&self, id: OperationId) {
        critical_section::with(|cs| self.state.borrow_ref_mut(cs).initial.connect(id));
    }

    pub(crate) fn initial_association_started(&self) {
        critical_section::with(|cs| self.state.borrow_ref_mut(cs).initial.associate());
    }

    pub(crate) fn initial_association_result(&self, success: bool) {
        let wake = critical_section::with(|cs| {
            let mut state = self.state.borrow_ref_mut(cs);
            state.initial.result(success);
            // Association notification still closes admission. Only its
            // correlated AUTHORIZED completion may attempt the one-shot open.
            state.close_admission();
            state.close_waker.take()
        });
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netif_l2::{LinkError, NativeLink};
    use core::task::{Context, Waker};
    use embassy_net_driver::{Driver, LinkState, TxToken};
    use hisi_rf_core::{WifiL2Capabilities, l2::L2Storage};

    fn operation() -> OperationId {
        hisi_rf_core::OperationTracker::new().queue(0).unwrap()
    }

    fn associated(route: &CallbackRoute<'_, 2, 64>, id: OperationId) {
        route.initial_bootstrap_complete();
        route.initial_connect_started(id);
        route.initial_association_started();
        route.initial_association_result(true);
    }

    #[test]
    fn single_session_can_transfer_but_never_reopen() {
        let mut storage = L2Storage::<2, 2, 64>::new();
        let mut parts = storage.split(WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap());
        let route = CallbackRoute::new();
        let id = operation();
        // Production composition binds after bootstrap, before connect.
        route.initial_bootstrap_complete();
        let mut link = NativeLink::bind(parts.port, &route).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(parts.device.link_state(&mut cx) == LinkState::Down);
        route.initial_connect_started(id);
        route.initial_association_started();
        route.initial_association_result(true);
        link.begin_initial_session_experiment(id).unwrap();
        assert!(parts.device.link_state(&mut cx) == LinkState::Up);
        parts
            .device
            .transmit(&mut cx)
            .unwrap()
            .consume(1, |b| b[0] = 42);
        assert!(
            link.poll_transmit(&mut cx, |b| {
                assert_eq!(b, [42]);
                Ok::<_, ()>(())
            })
            .is_ready()
        );
        route.enter().unwrap().receive(&[8]).unwrap();
        assert_eq!(link.rx_diagnostics().pending, 1);
        link.close().unwrap();
        assert!(parts.device.link_state(&mut cx) == LinkState::Down);
        assert_eq!(link.rx_diagnostics().dropped, 1);
        assert_eq!(
            link.begin_initial_session_experiment(id),
            Err(LinkError::Route(RouteError::InitialSessionRejected))
        );
    }

    #[test]
    fn retry_duplicate_result_and_teardown_permanently_reject_open() {
        for fault in 0..5 {
            let mut storage = L2Storage::<2, 2, 64>::new();
            let parts = storage.split(WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap());
            let route = CallbackRoute::new();
            let mut link = NativeLink::bind(parts.port, &route).unwrap();
            let id = operation();
            associated(&route, id);
            match fault {
                0 => route.initial_association_started(),
                1 => route.initial_association_result(true),
                2 => route.close_admission(),
                3 => route.initial_bootstrap_complete(),
                _ => route.initial_connect_started(id),
            }
            assert_eq!(
                link.begin_initial_session_experiment(id),
                Err(LinkError::Route(RouteError::InitialSessionRejected))
            );
            assert!(route.enter().is_none());
        }
    }

    #[test]
    fn authorization_requires_matching_operation_and_successful_association() {
        let mut state = InitialSession::Uninitialized;
        let id = operation();
        assert!(state.check(id).is_err());
        state.bootstrap();
        state.connect(id);
        state.associate();
        assert!(state.check(id).is_err());
        let mut successful = state;
        successful.result(true);
        let other = hisi_rf_core::OperationTracker::new().queue(1).unwrap();
        assert!(successful.check(other).is_err());
        assert!(successful.check(id).is_ok());
        state.result(false);
        assert_eq!(state, InitialSession::Rejected);
        state.result(true);
        assert!(state.check(id).is_err());
    }

    #[test]
    fn close_during_open_keeps_network_and_callback_closed() {
        let mut storage = L2Storage::<2, 2, 64>::new();
        let mut parts = storage.split(WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap());
        let route = CallbackRoute::new();
        let mut registration = route.claim(parts.port.ingress()).unwrap();
        let id = operation();
        associated(&route, id);
        let intent = registration.prepare_initial_open(id).unwrap();
        route.close_admission();
        let generation = parts.port.begin_session().unwrap();
        assert_eq!(
            registration.commit_open(intent, generation),
            Err(RouteError::OpenInterrupted)
        );
        assert!(route.enter().is_none());
        parts.port.link_down().unwrap();
        assert!(registration.prepare_initial_open(id).is_err());
    }
}
