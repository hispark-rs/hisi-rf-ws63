//! Callback routing for caller-owned NET0 storage.
//!
//! A route contains only an ingress capability and metadata, never packet bytes.
//! Claim it once during composition, open it only after the native producer has
//! quiesced its previous connection, and close it before changing link epochs.
//! Callback tickets capture the epoch on entry and cannot be retagged later.
//!
//! `in_flight == 0` proves only that Rust callback tickets have drained. It does
//! NOT prove that a vendor RX queue, DMA, or an outstanding TX has quiesced. The
//! WS63 native lifecycle must establish that separate fence before reopening.
//! With `standard-l2`, `driverif_input` uses the native route below exclusively.
//! Until composition binds caller-owned storage and opens a verified session,
//! RX fails closed; it never falls back to the legacy global packet bridge.
//! The separate `standard-l2-initial-session-experiment` is a one-shot physical
//! bring-up lane. It is not a native reset/drain or reconnect guarantee.

use core::cell::RefCell;
use core::task::Waker;

use critical_section::Mutex;
use hisi_rf_core::l2::{Generation, L2Ingress, QueueError};

mod link;
pub use link::{LinkError, NativeLink, SubmitError};
mod storage;
pub use storage::{NativeStorage, StorageError, StorageReport};
mod device;
pub use device::{WifiDevice, WifiRxToken, WifiTxToken};
mod host_delivery;
pub use host_delivery::HostDeliveryDiagnostics;
#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
pub(crate) mod host_tx;
#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
pub(crate) mod rx_mode;
#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub use host_tx::HostTxDiagnostics;
#[cfg(any(
    test,
    all(
        target_arch = "riscv32",
        feature = "wifi",
        feature = "standard-l2-rx-stop-experiment"
    )
))]
pub(crate) mod rx_stop;
#[cfg(all(
    target_arch = "riscv32",
    feature = "wifi",
    feature = "standard-l2-rx-stop-experiment"
))]
pub use rx_stop::RxStopDiagnostics;
#[cfg(any(test, all(target_arch = "riscv32", feature = "wifi")))]
pub(crate) mod user_cleanup;
#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub use user_cleanup::UserCleanupDiagnostics;
#[cfg(feature = "standard-l2-initial-session-experiment")]
mod initial_session;
#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(crate) use host_delivery::install_host_delivery_observer;
#[cfg(feature = "standard-l2-initial-session-experiment")]
#[doc(hidden)]
pub use initial_session::native_initial_open_result;

/// Diagnostic snapshot of the earlier native callback, not a drain receipt.
#[doc(hidden)]
pub fn native_host_delivery_diagnostics() -> HostDeliveryDiagnostics {
    NATIVE_RX_ROUTE.host_delivery_diagnostics()
}

/// Checked HMAC user-free results; not a host/DMAC producer-drain receipt.
#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
#[doc(hidden)]
pub fn native_user_cleanup_diagnostics() -> UserCleanupDiagnostics {
    user_cleanup::diagnostics()
}

/// Host queue-4 work only; not DMAC completion or a native RX fence.
#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
#[doc(hidden)]
pub fn native_host_tx_diagnostics() -> HostTxDiagnostics {
    host_tx::diagnostics()
}

/// One-shot device-handler receipt, not a reusable producer-fence capability.
#[cfg(all(
    target_arch = "riscv32",
    feature = "wifi",
    feature = "standard-l2-rx-stop-experiment"
))]
#[doc(hidden)]
pub fn native_rx_stop_diagnostics() -> RxStopDiagnostics {
    rx_stop::diagnostics()
}

/// First-session experiment counters, not a native-drain receipt.
#[cfg(feature = "standard-l2-initial-session-experiment")]
#[doc(hidden)]
pub fn native_route_diagnostics() -> RouteDiagnostics {
    NATIVE_RX_ROUTE.diagnostics()
}

pub(crate) type NativeDevice =
    hisi_rf_core::l2::L2Device<'static, NATIVE_RX_SLOTS, NATIVE_TX_SLOTS, NATIVE_MTU>;
#[cfg(feature = "incremental-embassy-wait")]
pub(crate) type NativeWorkerLink =
    NativeLink<'static, 'static, NATIVE_RX_SLOTS, NATIVE_TX_SLOTS, NATIVE_MTU>;

/// Initial WS63 queue shape; the eventual named profile must account for these
/// bytes in caller-owned storage and its resource report before graduation.
pub const NATIVE_RX_SLOTS: usize = 4;
pub const NATIVE_TX_SLOTS: usize = 4;
pub const NATIVE_MTU: usize = 1514;

// The context-free C ABI needs one global route, not global packet storage.
// Its ingress only borrows the composition root's caller-owned static storage.
pub(crate) static NATIVE_RX_ROUTE: CallbackRoute<'static, NATIVE_RX_SLOTS, NATIVE_MTU> =
    CallbackRoute::new();

/// Bind the context-free vendor callback to one caller-owned L2 instance.
/// The returned link remains down until the native lifecycle establishes its
/// fence. There is no implicit open, reconnect, or legacy-queue fallback.
pub fn bind_native<const TX: usize>(
    port: hisi_rf_core::l2::L2Port<'static, NATIVE_RX_SLOTS, TX, NATIVE_MTU>,
) -> Result<NativeLink<'static, 'static, NATIVE_RX_SLOTS, TX, NATIVE_MTU>, LinkError> {
    NativeLink::bind(port, &NATIVE_RX_ROUTE)
}

/// Registration/lifecycle failures that must not fall back to the global bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    AlreadyRegistered,
    CallbacksInFlight,
    AlreadyOpen,
    OpenInterrupted,
    LifecycleExhausted,
    #[cfg(feature = "standard-l2-initial-session-experiment")]
    InitialSessionRejected,
}

/// Callback-entry conservation, including entries rejected while the route is down.
/// `entered == queued + dropped + in_flight` until diagnostic counter exhaustion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouteDiagnostics {
    pub entered: u64,
    pub queued: u64,
    pub dropped: u64,
    pub closed_drops: u64,
    /// Native pbufs allocated while closed or before the current connection.
    pub allocation_drops: u64,
    pub abandoned: u64,
    pub in_flight: usize,
    /// Rust TX submissions admitted before close and not yet returned.
    /// This does not count frames retained by native queues after return.
    pub transmits_in_flight: usize,
}

/// Immutable provenance of one native allocation. A close revision is never
/// reused, including after route re-registration; exhaustion fails closed.
/// This does not stamp work still queued in hardware before pbuf allocation.
#[derive(Clone, Copy)]
pub(crate) struct AllocationEpoch {
    revision: Option<u64>,
}

impl AllocationEpoch {
    pub(crate) const CLOSED: Self = Self { revision: None };
}

struct State<'storage, const RX: usize, const MTU: usize> {
    ingress: Option<L2Ingress<'storage, RX, MTU>>,
    generation: Option<Generation>,
    close_revision: Option<u64>,
    close_waker: Option<Waker>,
    diagnostics: RouteDiagnostics,
    host_deliveries: HostDeliveryDiagnostics,
    #[cfg(feature = "standard-l2-initial-session-experiment")]
    initial: initial_session::InitialSession,
    #[cfg(feature = "standard-l2-initial-session-experiment")]
    initial_open_result: Option<Result<(), LinkError>>,
}

impl<const RX: usize, const MTU: usize> State<'_, RX, MTU> {
    fn close_admission(&mut self) {
        self.generation = None;
        self.close_revision = self.close_revision.and_then(|n| n.checked_add(1));
    }
}

#[must_use]
struct OpenIntent {
    close_revision: u64,
    host_delivery_revision: u64,
    #[cfg(feature = "standard-l2-initial-session-experiment")]
    initial_operation: Option<hisi_rf_core::OperationId>,
}

/// One checked route from the vendor's context-free callback ABI to an instance.
pub struct CallbackRoute<'storage, const RX: usize, const MTU: usize> {
    state: Mutex<RefCell<State<'storage, RX, MTU>>>,
}

impl<const RX: usize, const MTU: usize> Default for CallbackRoute<'_, RX, MTU> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'storage, const RX: usize, const MTU: usize> CallbackRoute<'storage, RX, MTU> {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(State {
                ingress: None,
                generation: None,
                close_revision: Some(0),
                close_waker: None,
                diagnostics: RouteDiagnostics {
                    entered: 0,
                    queued: 0,
                    dropped: 0,
                    closed_drops: 0,
                    allocation_drops: 0,
                    abandoned: 0,
                    in_flight: 0,
                    transmits_in_flight: 0,
                },
                host_deliveries: HostDeliveryDiagnostics::new(),
                #[cfg(feature = "standard-l2-initial-session-experiment")]
                initial: initial_session::InitialSession::Uninitialized,
                #[cfg(feature = "standard-l2-initial-session-experiment")]
                initial_open_result: None,
            })),
        }
    }

    /// Claim exclusively. Newly claimed routes reject RX until explicitly opened.
    pub fn claim(
        &self,
        ingress: L2Ingress<'storage, RX, MTU>,
    ) -> Result<Registration<'_, 'storage, RX, MTU>, RouteError> {
        critical_section::with(|cs| {
            let mut state = self.state.borrow_ref_mut(cs);
            if state.ingress.is_some() {
                return Err(RouteError::AlreadyRegistered);
            }
            if state.diagnostics.in_flight != 0 || state.diagnostics.transmits_in_flight != 0 {
                return Err(RouteError::CallbacksInFlight);
            }
            if state.close_revision.is_none() {
                return Err(RouteError::LifecycleExhausted);
            }
            state.ingress = Some(ingress);
            state.generation = None;
            Ok(Registration { route: self })
        })
    }

    /// Capture an ingress/epoch pair at the beginning of one vendor callback.
    /// No frame is copied and no user code/waker is called under this lock.
    #[must_use]
    pub fn enter(&self) -> Option<CallbackTicket<'_, 'storage, RX, MTU>> {
        self.enter_with_allocation(None)
    }

    /// Capture before allocating: an allocator may be preempted by close/open.
    pub(crate) fn allocation_epoch(&self) -> AllocationEpoch {
        critical_section::with(|cs| {
            let state = self.state.borrow_ref(cs);
            AllocationEpoch {
                revision: if state.ingress.is_some() && state.generation.is_some() {
                    state.close_revision
                } else {
                    None
                },
            }
        })
    }

    pub(crate) fn enter_allocated(
        &self,
        epoch: AllocationEpoch,
    ) -> Option<CallbackTicket<'_, 'storage, RX, MTU>> {
        self.enter_with_allocation(Some(epoch))
    }

    fn enter_with_allocation(
        &self,
        allocation: Option<AllocationEpoch>,
    ) -> Option<CallbackTicket<'_, 'storage, RX, MTU>> {
        critical_section::with(|cs| {
            let mut state = self.state.borrow_ref_mut(cs);
            state.diagnostics.entered += 1;
            if let Some(epoch) = allocation
                && (epoch.revision.is_none() || epoch.revision != state.close_revision)
            {
                state.diagnostics.dropped += 1;
                state.diagnostics.allocation_drops += 1;
                return None;
            }
            match (state.ingress, state.generation) {
                (Some(ingress), Some(generation)) => {
                    state.diagnostics.in_flight += 1;
                    Some(CallbackTicket {
                        route: self,
                        ingress,
                        generation,
                        finished: false,
                    })
                }
                _ => {
                    state.diagnostics.dropped += 1;
                    state.diagnostics.closed_drops += 1;
                    None
                }
            }
        })
    }

    pub fn diagnostics(&self) -> RouteDiagnostics {
        critical_section::with(|cs| self.state.borrow_ref(cs).diagnostics)
    }

    /// Earlier DMAC-to-host callback observations, separate from Ethernet
    /// queue admission. Zero in-flight callbacks are not a native drain fence.
    pub fn host_delivery_diagnostics(&self) -> HostDeliveryDiagnostics {
        critical_section::with(|cs| self.state.borrow_ref(cs).host_deliveries)
    }

    /// A native teardown may start outside the L2 worker. Stop new callback
    /// admission before submitting it; the worker must still close the port
    /// and drain tickets/native producers. Queued TX cannot gain a new native
    /// submission ticket, but an already admitted TX may finish. This does not
    /// invalidate network tokens or revoke a payload copy already started.
    pub(crate) fn close_admission(&self) {
        let wake = critical_section::with(|cs| {
            let mut state = self.state.borrow_ref_mut(cs);
            #[cfg(feature = "standard-l2-initial-session-experiment")]
            {
                state.initial = initial_session::InitialSession::Rejected;
            }
            state.close_admission();
            state.close_waker.take()
        });
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

/// Sole registration owner. Dropping it closes the route but does not reclaim
/// storage referenced by existing callback tickets.
#[must_use]
pub struct Registration<'route, 'storage, const RX: usize, const MTU: usize> {
    route: &'route CallbackRoute<'storage, RX, MTU>,
}

impl<'storage, const RX: usize, const MTU: usize> Registration<'_, 'storage, RX, MTU> {
    fn close_revision(&self) -> Option<u64> {
        critical_section::with(|cs| self.route.state.borrow_ref(cs).close_revision)
    }

    fn subscribe_close(&self, waker: &Waker) -> Option<u64> {
        let new = waker.clone();
        let (old, revision) = critical_section::with(|cs| {
            let mut state = self.route.state.borrow_ref_mut(cs);
            (state.close_waker.replace(new), state.close_revision)
        });
        drop(old);
        revision
    }

    /// Stop admission before resetting the L2 port. Already entered callbacks
    /// keep their old generation; reset makes their later publication fail.
    pub fn close(&mut self) {
        self.route.close_admission();
    }

    fn enter_transmit(
        &self,
        generation: Generation,
    ) -> Option<TransmitTicket<'_, 'storage, RX, MTU>> {
        critical_section::with(|cs| {
            let mut state = self.route.state.borrow_ref_mut(cs);
            if state.generation != Some(generation) {
                return None;
            }
            state.diagnostics.transmits_in_flight =
                state.diagnostics.transmits_in_flight.checked_add(1)?;
            Some(TransmitTicket { route: self.route })
        })
    }

    /// Publish a newly established link after native RX/TX quiescence.
    ///
    /// The caller must separately drain/fence the native producer before this
    /// call: checking Rust `in_flight` alone cannot identify old vendor frames.
    /// This function never implicitly closes/replaces an active connection.
    pub fn open_after_native_quiescence(
        &mut self,
        generation: Generation,
    ) -> Result<(), RouteError> {
        let intent = self.prepare_open()?;
        self.commit_open(intent, generation)
    }

    fn prepare_open(&self) -> Result<OpenIntent, RouteError> {
        critical_section::with(|cs| {
            let state = self.route.state.borrow_ref(cs);
            if state.generation.is_some() {
                return Err(RouteError::AlreadyOpen);
            }
            if state.host_deliveries.exhausted {
                return Err(RouteError::LifecycleExhausted);
            }
            if state.diagnostics.in_flight != 0
                || state.diagnostics.transmits_in_flight != 0
                || state.host_deliveries.in_flight != 0
            {
                return Err(RouteError::CallbacksInFlight);
            }
            Ok(OpenIntent {
                close_revision: state.close_revision.ok_or(RouteError::LifecycleExhausted)?,
                host_delivery_revision: state.host_deliveries.entered,
                #[cfg(feature = "standard-l2-initial-session-experiment")]
                initial_operation: None,
            })
        })
    }

    #[cfg(feature = "standard-l2-initial-session-experiment")]
    fn prepare_initial_open(
        &self,
        id: hisi_rf_core::OperationId,
    ) -> Result<OpenIntent, RouteError> {
        let mut intent = self.prepare_open()?;
        critical_section::with(|cs| self.route.state.borrow_ref(cs).initial.check(id))?;
        intent.initial_operation = Some(id);
        Ok(intent)
    }

    fn commit_open(
        &mut self,
        intent: OpenIntent,
        generation: Generation,
    ) -> Result<(), RouteError> {
        critical_section::with(|cs| {
            let mut state = self.route.state.borrow_ref_mut(cs);
            let revision = state.close_revision.ok_or(RouteError::LifecycleExhausted)?;
            if state.host_deliveries.exhausted {
                return Err(RouteError::LifecycleExhausted);
            }
            if revision != intent.close_revision
                || state.host_deliveries.entered != intent.host_delivery_revision
            {
                return Err(RouteError::OpenInterrupted);
            }
            if state.generation.is_some() {
                return Err(RouteError::AlreadyOpen);
            }
            if state.diagnostics.in_flight != 0
                || state.diagnostics.transmits_in_flight != 0
                || state.host_deliveries.in_flight != 0
            {
                return Err(RouteError::CallbacksInFlight);
            }
            #[cfg(feature = "standard-l2-initial-session-experiment")]
            if let Some(id) = intent.initial_operation {
                state.initial.check(id)?;
                state.initial = initial_session::InitialSession::Opened;
            }
            state.generation = Some(generation);
            Ok(())
        })
    }
}

impl<const RX: usize, const MTU: usize> Drop for Registration<'_, '_, RX, MTU> {
    fn drop(&mut self) {
        let wake = critical_section::with(|cs| {
            let mut state = self.route.state.borrow_ref_mut(cs);
            #[cfg(feature = "standard-l2-initial-session-experiment")]
            {
                state.initial = initial_session::InitialSession::Rejected;
            }
            state.close_admission();
            state.ingress = None;
            state.close_waker.take()
        });
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

/// A native submit permission linearized against close. Keep it alive while
/// native code borrows the queue payload, including unwinding/error paths.
#[must_use]
struct TransmitTicket<'route, 'storage, const RX: usize, const MTU: usize> {
    route: &'route CallbackRoute<'storage, RX, MTU>,
}

impl<const RX: usize, const MTU: usize> Drop for TransmitTicket<'_, '_, RX, MTU> {
    fn drop(&mut self) {
        critical_section::with(|cs| {
            self.route
                .state
                .borrow_ref_mut(cs)
                .diagnostics
                .transmits_in_flight -= 1;
        });
    }
}

/// A non-cloneable RX-entry snapshot, retaining the originating connection.
#[must_use]
pub struct CallbackTicket<'route, 'storage, const RX: usize, const MTU: usize> {
    route: &'route CallbackRoute<'storage, RX, MTU>,
    ingress: L2Ingress<'storage, RX, MTU>,
    generation: Generation,
    finished: bool,
}

impl<const RX: usize, const MTU: usize> CallbackTicket<'_, '_, RX, MTU> {
    /// Copy into the caller-owned queue outside the route's critical section.
    pub fn receive(mut self, frame: &[u8]) -> Result<(), QueueError> {
        let open = critical_section::with(|cs| {
            self.route.state.borrow_ref(cs).generation == Some(self.generation)
        });
        let result = if open {
            self.ingress.receive(self.generation, frame)
        } else {
            Err(QueueError::StaleGeneration)
        };
        self.finish(result.is_ok(), false);
        result
    }

    fn finish(&mut self, queued: bool, abandoned: bool) {
        critical_section::with(|cs| {
            let mut state = self.route.state.borrow_ref_mut(cs);
            state.diagnostics.in_flight -= 1;
            if queued {
                state.diagnostics.queued += 1;
            } else {
                state.diagnostics.dropped += 1;
                state.diagnostics.abandoned += u64::from(abandoned);
            }
        });
        self.finished = true;
    }
}

impl<const RX: usize, const MTU: usize> Drop for CallbackTicket<'_, '_, RX, MTU> {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(false, true);
        }
    }
}

#[cfg(test)]
mod tests;
