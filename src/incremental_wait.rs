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
use portable_atomic::{AtomicU8, Ordering};

struct WaitSignals {
    pending: AtomicU8,
    waker: AtomicWaker,
}

impl WaitSignals {
    const fn new() -> Self {
        Self {
            pending: AtomicU8::new(0),
            waker: AtomicWaker::new(),
        }
    }

    fn signal(&self, source: WaitSet) {
        self.pending.fetch_or(source.bits(), Ordering::Release);
        self.waker.wake();
    }

    fn take_ready(&self, sources: WaitSet) -> WaitSet {
        let observed = self.pending.fetch_and(!sources.bits(), Ordering::AcqRel) & sources.bits();
        let mut ready = WaitSet::empty();
        if observed & WaitSet::BACKEND.bits() != 0 {
            ready = ready.union(WaitSet::BACKEND);
        }
        if observed & WaitSet::L2_RX.bits() != 0 {
            ready = ready.union(WaitSet::L2_RX);
        }
        ready
    }
}

static SIGNALS: WaitSignals = WaitSignals::new();

pub(crate) fn signal_backend() {
    SIGNALS.signal(WaitSet::BACKEND);
}

pub(crate) fn signal_l2_rx() {
    SIGNALS.signal(WaitSet::L2_RX);
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
}

impl IncrementalWaitPlatform for Ws63IncrementalWaitPlatform {
    type Error = Infallible;

    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
        sources: WaitSet,
        deadline_us: Option<u64>,
    ) -> Poll<Result<WaitSet, Self::Error>> {
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
            Poll::Pending
        } else {
            Poll::Ready(Ok(ready))
        }
    }
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
    }
}
