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

use core::cell::RefCell;

use critical_section::Mutex;
use hisi_rf_core::l2::{Generation, L2Ingress, QueueError};

mod link;
pub use link::{LinkError, NativeLink, SubmitError};

/// Initial WS63 queue shape; the eventual named profile must account for these
/// bytes in caller-owned storage and its resource report before graduation.
pub const NATIVE_RX_SLOTS: usize = 4;
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
}

/// Callback-entry conservation, including entries rejected while the route is down.
/// `entered == queued + dropped + in_flight` until diagnostic counter exhaustion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouteDiagnostics {
    pub entered: u64,
    pub queued: u64,
    pub dropped: u64,
    pub closed_drops: u64,
    pub abandoned: u64,
    pub in_flight: usize,
}

struct State<'storage, const RX: usize, const MTU: usize> {
    ingress: Option<L2Ingress<'storage, RX, MTU>>,
    generation: Option<Generation>,
    diagnostics: RouteDiagnostics,
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
                diagnostics: RouteDiagnostics {
                    entered: 0,
                    queued: 0,
                    dropped: 0,
                    closed_drops: 0,
                    abandoned: 0,
                    in_flight: 0,
                },
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
            if state.diagnostics.in_flight != 0 {
                return Err(RouteError::CallbacksInFlight);
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
        critical_section::with(|cs| {
            let mut state = self.state.borrow_ref_mut(cs);
            state.diagnostics.entered += 1;
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
}

/// Sole registration owner. Dropping it closes the route but does not reclaim
/// storage referenced by existing callback tickets.
#[must_use]
pub struct Registration<'route, 'storage, const RX: usize, const MTU: usize> {
    route: &'route CallbackRoute<'storage, RX, MTU>,
}

impl<const RX: usize, const MTU: usize> Registration<'_, '_, RX, MTU> {
    /// Stop admission before resetting the L2 port. Already entered callbacks
    /// keep their old generation; reset makes their later publication fail.
    pub fn close(&mut self) {
        critical_section::with(|cs| self.route.state.borrow_ref_mut(cs).generation = None);
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
        critical_section::with(|cs| {
            let mut state = self.route.state.borrow_ref_mut(cs);
            if state.generation.is_some() {
                return Err(RouteError::AlreadyOpen);
            }
            if state.diagnostics.in_flight != 0 {
                return Err(RouteError::CallbacksInFlight);
            }
            state.generation = Some(generation);
            Ok(())
        })
    }
}

impl<const RX: usize, const MTU: usize> Drop for Registration<'_, '_, RX, MTU> {
    fn drop(&mut self) {
        critical_section::with(|cs| {
            let mut state = self.route.state.borrow_ref_mut(cs);
            state.generation = None;
            state.ingress = None;
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
