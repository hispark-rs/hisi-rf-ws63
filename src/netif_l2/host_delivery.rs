//! Observation of the earlier DMAC-to-host call, not packet admission.
//!
//! The native callback owns/frees its opaque input and may queue a host copy.
//! Always forward it exactly once, even while L2 is closed: it also transports
//! management and EAPOL work needed to establish the connection. These counters
//! do not cover work queued before callback entry or after callback return.

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
use super::CallbackRoute;

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(crate) fn install_host_delivery_observer() -> Result<(), u32> {
    use core::ffi::c_void;
    use ws63_radio_sys::frw::{
        RX_NETBUF_CALLBACK_ID, frw_get_rom_cb, frw_rom_cb_register, frw_rx_netbuf,
    };

    // Bootstrap has initialized FRW, and no station operation has been issued.
    // The audited ROM get/set functions are bounded RAM-table load/store only:
    // no hardware polling, allocation, delivery, or user callback occurs here.
    critical_section::with(|_| {
        // SAFETY: slot 261 and the receiver ABI belong to the pinned sys
        // contract. Compare the actual linked receiver, not an image address.
        let current = unsafe { frw_get_rom_cb(RX_NETBUF_CALLBACK_ID) };
        let expected = frw_rx_netbuf as *const () as *mut c_void;
        let observer = host_delivery_callback as *const () as *mut c_void;
        match installation_action(current as usize, expected as usize, observer as usize) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(()) => return Err(0x1000_0010),
        }
        // SAFETY: exclusive single-hart table update; the permanent observer
        // forwards every call to the known original without retaining data.
        unsafe { frw_rom_cb_register(RX_NETBUF_CALLBACK_ID, observer) };
        if unsafe { frw_get_rom_cb(RX_NETBUF_CALLBACK_ID) } != observer {
            return Err(0x1000_0011);
        }
        Ok(())
    })
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
fn installation_action(current: usize, expected: usize, observer: usize) -> Result<bool, ()> {
    if expected == 0 || observer == 0 || expected == observer {
        Err(())
    } else if current == observer {
        Ok(false)
    } else if current == expected {
        Ok(true)
    } else {
        Err(())
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
unsafe extern "C" fn host_delivery_callback(netbuf: *mut core::ffi::c_void, length: u32) -> u32 {
    #[cfg(feature = "standard-l2-rx-origin-experiment")]
    super::rx_origin::native::observe_delivery(netbuf);
    super::NATIVE_RX_ROUTE.observe_host_delivery(|| {
        // SAFETY: callback 261 transfers the vendor-owned netbuf and full u32
        // length. Forward exactly once, including closed L2/error cases. The
        // receiver owns freeing it; neither this observer nor its ticket reads
        // or retains the pointer. Forwarding runs outside critical sections.
        unsafe { ws63_radio_sys::frw::frw_rx_netbuf(netbuf, length) }
    })
}

/// Call-lifetime accounting. When `exhausted` is false:
/// `entered == returned + abandoned + in_flight`.
///
/// `returned` is not packet delivery: the pinned receiver can return zero on
/// allocation failure, and its downstream host dispatch can be asynchronous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostDeliveryDiagnostics {
    pub entered: u64,
    pub returned: u64,
    pub abandoned: u64,
    pub in_flight: u64,
    pub peak_in_flight: u64,
    pub entered_while_closed: u64,
    pub crossed_close: u64,
    pub nonzero_returns: u64,
    /// Counter saturation invalidates conservation; never silently wrap.
    pub exhausted: bool,
}

impl HostDeliveryDiagnostics {
    pub(super) const fn new() -> Self {
        Self {
            entered: 0,
            returned: 0,
            abandoned: 0,
            in_flight: 0,
            peak_in_flight: 0,
            entered_while_closed: 0,
            crossed_close: 0,
            nonzero_returns: 0,
            exhausted: false,
        }
    }
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
fn increment(counter: &mut u64, exhausted: &mut bool) {
    if let Some(next) = counter.checked_add(1) {
        *counter = next;
    } else {
        *exhausted = true;
    }
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
impl<const RX: usize, const MTU: usize> CallbackRoute<'_, RX, MTU> {
    pub(super) fn observe_host_delivery(&self, forward: impl FnOnce() -> u32) -> u32 {
        let revision = critical_section::with(|cs| {
            let mut state = self.state.borrow_ref_mut(cs);
            let closed = state.generation.is_none();
            let d = &mut state.host_deliveries;
            increment(&mut d.entered, &mut d.exhausted);
            increment(&mut d.in_flight, &mut d.exhausted);
            d.peak_in_flight = d.peak_in_flight.max(d.in_flight);
            if closed {
                increment(&mut d.entered_while_closed, &mut d.exhausted);
            }
            state.close_revision
        });
        let ticket = DeliveryTicket {
            route: self,
            revision,
            returned: None,
        };
        // No route borrow/critical section spans native allocation, copying,
        // queue operations, callbacks, or any possible native wait.
        let status = forward();
        ticket.finish(status);
        status
    }
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
struct DeliveryTicket<'route, 'storage, const RX: usize, const MTU: usize> {
    route: &'route CallbackRoute<'storage, RX, MTU>,
    revision: Option<u64>,
    returned: Option<u32>,
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
impl<const RX: usize, const MTU: usize> DeliveryTicket<'_, '_, RX, MTU> {
    fn finish(mut self, status: u32) {
        self.returned = Some(status);
    }
}

#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
impl<const RX: usize, const MTU: usize> Drop for DeliveryTicket<'_, '_, RX, MTU> {
    fn drop(&mut self) {
        critical_section::with(|cs| {
            let mut state = self.route.state.borrow_ref_mut(cs);
            let crossed_close = state.close_revision != self.revision;
            let d = &mut state.host_deliveries;
            d.in_flight = d.in_flight.saturating_sub(1);
            match self.returned {
                Some(status) => {
                    increment(&mut d.returned, &mut d.exhausted);
                    if status != 0 {
                        increment(&mut d.nonzero_returns, &mut d.exhausted);
                    }
                }
                None => increment(&mut d.abandoned, &mut d.exhausted),
            }
            if crossed_close {
                increment(&mut d.crossed_close, &mut d.exhausted);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netif_l2::{LinkError, NativeLink, RouteError};
    use hisi_rf_core::{WifiL2Capabilities, l2::L2Storage};

    #[test]
    fn hook_registration_rejects_missing_or_foreign_owners() {
        assert_eq!(installation_action(1, 1, 2), Ok(true));
        assert_eq!(installation_action(2, 1, 2), Ok(false));
        for current in [0, 3, usize::MAX] {
            assert_eq!(installation_action(current, 1, 2), Err(()));
        }
        assert_eq!(installation_action(0, 0, 2), Err(()));
        assert_eq!(installation_action(1, 1, 0), Err(()));
        assert_eq!(installation_action(1, 1, 1), Err(()));
    }

    fn conserved(route: &CallbackRoute<'_, 1, 64>) -> HostDeliveryDiagnostics {
        let d = route.host_delivery_diagnostics();
        assert!(!d.exhausted);
        assert_eq!(d.entered, d.returned + d.abandoned + d.in_flight);
        d
    }

    #[test]
    fn closed_route_still_forwards_each_native_owner_once() {
        let route = CallbackRoute::<1, 64>::new();
        let mut calls = 0;
        for expected in [0, 1, u32::MAX] {
            assert_eq!(
                route.observe_host_delivery(|| {
                    calls += 1;
                    assert_eq!(conserved(&route).in_flight, 1);
                    expected
                }),
                expected
            );
        }
        assert_eq!(calls, 3);
        let d = conserved(&route);
        assert_eq!(d.entered, 3);
        assert_eq!(d.returned, 3);
        assert_eq!(d.entered_while_closed, 3);
        assert_eq!(d.nonzero_returns, 2);
        assert_eq!(d.in_flight, 0);
        // No callback observation is misreported as Ethernet admission/drop.
        assert_eq!(route.diagnostics().entered, 0);
    }

    #[test]
    fn reentrant_delivery_and_close_do_not_hold_a_route_borrow() {
        let route = CallbackRoute::<1, 64>::new();
        assert_eq!(
            route.observe_host_delivery(|| {
                assert_eq!(
                    route.observe_host_delivery(|| {
                        assert_eq!(conserved(&route).in_flight, 2);
                        route.close_admission();
                        17
                    }),
                    17
                );
                assert_eq!(conserved(&route).in_flight, 1);
                23
            }),
            23
        );
        let d = conserved(&route);
        assert_eq!(d.crossed_close, 2);
        assert_eq!(d.peak_in_flight, 2);
        assert_eq!(d.returned, 2);
    }

    #[test]
    fn unwind_retires_the_observation_without_fabricating_a_return() {
        let route = CallbackRoute::<1, 64>::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            route.observe_host_delivery(|| panic!("injected native boundary failure"));
        }));
        assert!(result.is_err());
        let d = conserved(&route);
        assert_eq!(d.abandoned, 1);
        assert_eq!(d.returned, 0);
        assert_eq!(d.in_flight, 0);
    }

    #[test]
    fn exhausted_diagnostics_still_forward_but_cannot_claim_conservation() {
        let route = CallbackRoute::<1, 64>::new();
        critical_section::with(|cs| {
            route.state.borrow_ref_mut(cs).host_deliveries.entered = u64::MAX;
        });
        let mut calls = 0;
        assert_eq!(
            route.observe_host_delivery(|| {
                calls += 1;
                42
            }),
            42
        );
        let d = route.host_delivery_diagnostics();
        assert!(d.exhausted);
        assert_eq!(d.entered, u64::MAX);
        assert_eq!(d.in_flight, 0);
        assert_eq!(calls, 1);
    }

    #[test]
    fn observed_native_call_must_retire_before_open() {
        let mut storage = L2Storage::<1, 1, 64>::new();
        let parts = storage.split(WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap());
        let route = CallbackRoute::new();
        let mut link = NativeLink::bind(parts.port, &route).unwrap();
        route.observe_host_delivery(|| {
            assert_eq!(
                link.begin_after_native_quiescence(),
                Err(LinkError::Route(RouteError::CallbacksInFlight))
            );
            0
        });
        // Only the test owns all producers here. This is not a WS63 receipt.
        link.begin_after_native_quiescence().unwrap();
        assert_eq!(conserved(&route).in_flight, 0);
    }

    #[test]
    fn completed_call_between_prepare_and_commit_invalidates_open() {
        let mut storage = L2Storage::<1, 1, 64>::new();
        let mut parts = storage.split(WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap());
        let route = CallbackRoute::new();
        let mut owner = route.claim(parts.port.ingress()).unwrap();
        let intent = owner.prepare_open().unwrap();
        route.observe_host_delivery(|| 0);
        let generation = parts.port.begin_session().unwrap();
        assert_eq!(
            owner.commit_open(intent, generation),
            Err(RouteError::OpenInterrupted)
        );
        assert!(route.enter().is_none());
        assert_eq!(conserved(&route).in_flight, 0);
    }

    #[test]
    fn exhausted_observer_never_authorizes_open() {
        let mut storage = L2Storage::<1, 1, 64>::new();
        let parts = storage.split(WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap());
        let route = CallbackRoute::new();
        let mut link = NativeLink::bind(parts.port, &route).unwrap();
        critical_section::with(|cs| {
            route.state.borrow_ref_mut(cs).host_deliveries.entered = u64::MAX;
        });
        route.observe_host_delivery(|| 0);
        assert_eq!(
            link.begin_after_native_quiescence(),
            Err(LinkError::Route(RouteError::LifecycleExhausted))
        );
    }
}
