//! WS63 wake bridge for the non-default incremental radio runner.

use core::convert::Infallible;
use core::task::{Context, Poll};

#[cfg(target_arch = "riscv32")]
use core::future::Future;
#[cfg(target_arch = "riscv32")]
use core::pin::Pin;
use embassy_sync::waitqueue::AtomicWaker;
#[cfg(target_arch = "riscv32")]
use embassy_time::Timer;
use hisi_rf_core::{IncrementalWaitPlatform, WaitSet};
use portable_atomic::{AtomicU32, Ordering};

/// Secret-free counters for the WS63 incremental wait bridge.
///
/// Counters saturate at `u32::MAX` and never participate in readiness or wake
/// decisions. Readiness counts preserve distinct signal calls until the
/// runner consumes them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ws63IncrementalWaitDiagnostics {
    /// Native supplicant or vendor callback signal calls.
    pub backend_signals: u32,
    /// L2 receive signal calls.
    pub l2_rx_signals: u32,
    /// Calls made to the executor waker after recording a signal.
    pub waker_notifications: u32,
    /// Polls of the platform wait contract.
    pub poll_calls: u32,
    /// Polls that returned `Pending`.
    pub pending_polls: u32,
    /// Polls that returned at least one ready source.
    pub ready_polls: u32,
    /// Ready polls containing the monotonic timer source.
    pub timer_ready_polls: u32,
}

struct WaitSignals {
    backend_pending: AtomicU32,
    l2_rx_pending: AtomicU32,
    waker: AtomicWaker,
    backend_signals: AtomicU32,
    l2_rx_signals: AtomicU32,
    waker_notifications: AtomicU32,
    poll_calls: AtomicU32,
    pending_polls: AtomicU32,
    ready_polls: AtomicU32,
    timer_ready_polls: AtomicU32,
}

impl WaitSignals {
    const fn new() -> Self {
        Self {
            backend_pending: AtomicU32::new(0),
            l2_rx_pending: AtomicU32::new(0),
            waker: AtomicWaker::new(),
            backend_signals: AtomicU32::new(0),
            l2_rx_signals: AtomicU32::new(0),
            waker_notifications: AtomicU32::new(0),
            poll_calls: AtomicU32::new(0),
            pending_polls: AtomicU32::new(0),
            ready_polls: AtomicU32::new(0),
            timer_ready_polls: AtomicU32::new(0),
        }
    }

    fn signal(&self, source: WaitSet) {
        if source.contains(WaitSet::BACKEND) {
            saturating_increment(&self.backend_signals);
            saturating_increment(&self.backend_pending);
        }
        if source.contains(WaitSet::L2_RX) {
            saturating_increment(&self.l2_rx_signals);
            saturating_increment(&self.l2_rx_pending);
        }
        saturating_increment(&self.waker_notifications);
        self.waker.wake();
    }

    fn take_ready(&self, sources: WaitSet) -> WaitSet {
        let mut ready = WaitSet::empty();
        if sources.contains(WaitSet::BACKEND) && take_one(&self.backend_pending) {
            ready = ready.union(WaitSet::BACKEND);
        }
        if sources.contains(WaitSet::L2_RX) && take_one(&self.l2_rx_pending) {
            ready = ready.union(WaitSet::L2_RX);
        }
        ready
    }

    fn diagnostics(&self) -> Ws63IncrementalWaitDiagnostics {
        Ws63IncrementalWaitDiagnostics {
            backend_signals: self.backend_signals.load(Ordering::Relaxed),
            l2_rx_signals: self.l2_rx_signals.load(Ordering::Relaxed),
            waker_notifications: self.waker_notifications.load(Ordering::Relaxed),
            poll_calls: self.poll_calls.load(Ordering::Relaxed),
            pending_polls: self.pending_polls.load(Ordering::Relaxed),
            ready_polls: self.ready_polls.load(Ordering::Relaxed),
            timer_ready_polls: self.timer_ready_polls.load(Ordering::Relaxed),
        }
    }
}

static SIGNALS: WaitSignals = WaitSignals::new();

pub(crate) fn signal_backend() {
    SIGNALS.signal(WaitSet::BACKEND);
}

pub(crate) fn signal_l2_rx() {
    SIGNALS.signal(WaitSet::L2_RX);
}

/// Snapshot the singleton WS63 callback/L2/timer wait bridge.
///
/// This exposes counters only. It does not consume readiness, register a
/// waker, or disclose frame and credential contents.
pub fn incremental_wait_diagnostics() -> Ws63IncrementalWaitDiagnostics {
    SIGNALS.diagnostics()
}

/// WS63 callback/L2/deadline bridge owned by one incremental runner.
///
/// The radio singleton guarantees that only one instance exists. Callback and
/// IRQ paths only set bounded readiness bits and wake the executor; all vendor
/// and network work remains in normal runner context.
pub(crate) struct Ws63IncrementalWaitPlatform {
    signals: &'static WaitSignals,
    #[cfg(target_arch = "riscv32")]
    timer_deadline_us: Option<u64>,
    #[cfg(target_arch = "riscv32")]
    timer: Option<Timer>,
}

impl Ws63IncrementalWaitPlatform {
    pub(crate) fn new() -> Self {
        Self::with_signals(&SIGNALS)
    }

    fn with_signals(signals: &'static WaitSignals) -> Self {
        Self {
            signals,
            #[cfg(target_arch = "riscv32")]
            timer_deadline_us: None,
            #[cfg(target_arch = "riscv32")]
            timer: None,
        }
    }

    fn take_ready(&self, sources: WaitSet) -> WaitSet {
        self.signals.take_ready(sources)
    }

    #[cfg(target_arch = "riscv32")]
    fn poll_timer(&mut self, cx: &mut Context<'_>, deadline_us: Option<u64>) -> Poll<()> {
        let Some(deadline_us) = deadline_us else {
            self.clear_timer();
            return Poll::Pending;
        };

        let now_us = crate::uapi::monotonic_us();
        if deadline_us <= now_us {
            self.clear_timer();
            return Poll::Ready(());
        }

        if self.timer_deadline_us != Some(deadline_us) {
            self.timer_deadline_us = Some(deadline_us);
            self.timer = Some(Timer::after_micros(deadline_us - now_us));
        }

        let timer = self
            .timer
            .as_mut()
            .expect("a future deadline always installs a timer");
        Pin::new(timer).poll(cx)
    }

    #[cfg(not(target_arch = "riscv32"))]
    fn poll_timer(&mut self, _cx: &mut Context<'_>, deadline_us: Option<u64>) -> Poll<()> {
        match deadline_us {
            Some(deadline_us) if deadline_us <= crate::uapi::monotonic_us() => Poll::Ready(()),
            Some(_) | None => Poll::Pending,
        }
    }

    fn clear_timer(&mut self) {
        #[cfg(target_arch = "riscv32")]
        {
            self.timer_deadline_us = None;
            self.timer = None;
        }
    }

    pub(crate) fn diagnostics(&self) -> Ws63IncrementalWaitDiagnostics {
        self.signals.diagnostics()
    }
}

impl IncrementalWaitPlatform for Ws63IncrementalWaitPlatform {
    type Error = Infallible;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
        sources: WaitSet,
        deadline_us: Option<u64>,
    ) -> Poll<Result<WaitSet, Self::Error>> {
        saturating_increment(&self.signals.poll_calls);
        self.signals.waker.register(cx.waker());

        let mut ready = self.take_ready(sources);
        if sources.contains(WaitSet::L2_RX) && crate::netif_smoltcp::rx_ready() {
            ready = ready.union(WaitSet::L2_RX);
        }
        if sources.contains(WaitSet::TIMER) && self.poll_timer(cx, deadline_us).is_ready() {
            ready = ready.union(WaitSet::TIMER);
        } else if !sources.contains(WaitSet::TIMER) {
            self.clear_timer();
        }

        if ready.is_empty() {
            // Close the register-before-check race. An IRQ that arrives after
            // this check observes the registered waker and wakes the executor.
            ready = self.take_ready(sources);
        }

        if ready.is_empty() {
            saturating_increment(&self.signals.pending_polls);
            Poll::Pending
        } else {
            saturating_increment(&self.signals.ready_polls);
            if ready.contains(WaitSet::TIMER) {
                saturating_increment(&self.signals.timer_ready_polls);
            }
            Poll::Ready(Ok(ready))
        }
    }
}

fn saturating_increment(counter: &AtomicU32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

fn take_one(counter: &AtomicU32) -> bool {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_sub(1)
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering as CoreOrdering};
    use std::boxed::Box;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, CoreOrdering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, CoreOrdering::Relaxed);
        }
    }

    #[test]
    fn backend_signal_is_bounded_to_subscribed_source() {
        let signals = Box::leak(Box::new(WaitSignals::new()));
        let mut platform = Ws63IncrementalWaitPlatform::with_signals(signals);
        signals.signal(WaitSet::BACKEND);
        let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            platform.poll_ready(&mut cx, WaitSet::TIMER, None),
            Poll::Pending
        ));
        assert!(matches!(
            platform.poll_ready(&mut cx, WaitSet::BACKEND, None),
            Poll::Ready(Ok(ready)) if ready == WaitSet::BACKEND
        ));
        assert_eq!(
            platform.diagnostics(),
            Ws63IncrementalWaitDiagnostics {
                backend_signals: 1,
                l2_rx_signals: 0,
                waker_notifications: 1,
                poll_calls: 2,
                pending_polls: 1,
                ready_polls: 1,
                timer_ready_polls: 0,
            }
        );
    }

    #[test]
    fn registered_waiter_is_woken_by_callback_edge() {
        let signals = Box::leak(Box::new(WaitSignals::new()));
        let mut platform = Ws63IncrementalWaitPlatform::with_signals(signals);
        let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            platform.poll_ready(&mut cx, WaitSet::BACKEND, None),
            Poll::Pending
        ));
        signals.signal(WaitSet::BACKEND);
        assert_eq!(counter.0.load(CoreOrdering::Relaxed), 1);
        assert!(matches!(
            platform.poll_ready(&mut cx, WaitSet::BACKEND, None),
            Poll::Ready(Ok(ready)) if ready == WaitSet::BACKEND
        ));
    }

    #[test]
    fn coalesced_backend_edges_remain_independently_ready() {
        let signals = Box::leak(Box::new(WaitSignals::new()));
        let mut platform = Ws63IncrementalWaitPlatform::with_signals(signals);
        let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);

        signals.signal(WaitSet::BACKEND);
        signals.signal(WaitSet::BACKEND);

        for _ in 0..2 {
            assert!(matches!(
                platform.poll_ready(&mut cx, WaitSet::BACKEND, None),
                Poll::Ready(Ok(ready)) if ready == WaitSet::BACKEND
            ));
        }
        assert!(matches!(
            platform.poll_ready(&mut cx, WaitSet::BACKEND, None),
            Poll::Pending
        ));
        assert_eq!(counter.0.load(CoreOrdering::Relaxed), 0);
    }

    #[test]
    fn elapsed_deadline_is_reported_as_timer_readiness() {
        let signals = Box::leak(Box::new(WaitSignals::new()));
        let mut platform = Ws63IncrementalWaitPlatform::with_signals(signals);
        let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(counter);
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            platform.poll_ready(&mut cx, WaitSet::TIMER, Some(0)),
            Poll::Ready(Ok(ready)) if ready == WaitSet::TIMER
        ));
        assert_eq!(platform.diagnostics().timer_ready_polls, 1);
    }
}
