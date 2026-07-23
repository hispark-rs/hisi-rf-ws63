//! Migration diagnostics for the current blocking Wi-Fi backend.

use portable_atomic::{AtomicU32, Ordering};

/// Per-operation blocking-call statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockingOperationMetrics {
    /// Calls that entered the operation.
    pub calls: u32,
    /// Calls measured with an initialized monotonic timebase.
    pub timed_calls: u32,
    /// Longest measured call duration in milliseconds.
    pub max_elapsed_ms: u32,
}

/// Snapshot of the current WS63 blocking backend workload.
///
/// The snapshot contains no network configuration or key material. Counters
/// saturate at `u32::MAX` and are observational only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockingBackendMetrics {
    /// Vendor runtime initialization calls.
    pub initialize: BlockingOperationMetrics,
    /// Blocking scan calls.
    pub scan: BlockingOperationMetrics,
    /// Blocking station-connect calls.
    pub connect: BlockingOperationMetrics,
    /// Blocking disconnect calls.
    pub disconnect: BlockingOperationMetrics,
    /// Background backend poll calls.
    pub poll: BlockingOperationMetrics,
    /// One-millisecond sleeps performed inside blocking operations.
    pub internal_sleep_calls: u32,
    /// Native supplicant poll calls made by all blocking operations.
    pub supplicant_poll_calls: u32,
}

pub(crate) enum Operation {
    Initialize,
    Scan,
    Connect,
    Disconnect,
    Poll,
}

struct Metric {
    calls: AtomicU32,
    timed_calls: AtomicU32,
    max_elapsed_ms: AtomicU32,
}

impl Metric {
    const fn new() -> Self {
        Self {
            calls: AtomicU32::new(0),
            timed_calls: AtomicU32::new(0),
            max_elapsed_ms: AtomicU32::new(0),
        }
    }

    fn snapshot(&self) -> BlockingOperationMetrics {
        BlockingOperationMetrics {
            calls: self.calls.load(Ordering::Relaxed),
            timed_calls: self.timed_calls.load(Ordering::Relaxed),
            max_elapsed_ms: self.max_elapsed_ms.load(Ordering::Relaxed),
        }
    }

    fn begin(&self) {
        saturating_increment(&self.calls);
    }

    fn finish(&self, elapsed_ms: u64) {
        saturating_increment(&self.timed_calls);
        self.max_elapsed_ms.fetch_max(
            u32::try_from(elapsed_ms).unwrap_or(u32::MAX),
            Ordering::Relaxed,
        );
    }

    #[cfg(test)]
    fn reset(&self) {
        self.calls.store(0, Ordering::Relaxed);
        self.timed_calls.store(0, Ordering::Relaxed);
        self.max_elapsed_ms.store(0, Ordering::Relaxed);
    }
}

static INITIALIZE: Metric = Metric::new();
static SCAN: Metric = Metric::new();
static CONNECT: Metric = Metric::new();
static DISCONNECT: Metric = Metric::new();
static POLL: Metric = Metric::new();
static INTERNAL_SLEEP_CALLS: AtomicU32 = AtomicU32::new(0);
static SUPPLICANT_POLL_CALLS: AtomicU32 = AtomicU32::new(0);

/// Record one blocking operation until the returned guard is dropped.
pub(crate) struct OperationTimer {
    metric: &'static Metric,
    started_at_ms: Option<u64>,
}

impl OperationTimer {
    pub(crate) fn start(operation: Operation) -> Self {
        let metric = match operation {
            Operation::Initialize => &INITIALIZE,
            Operation::Scan => &SCAN,
            Operation::Connect => &CONNECT,
            Operation::Disconnect => &DISCONNECT,
            Operation::Poll => &POLL,
        };
        metric.begin();
        Self {
            metric,
            started_at_ms: crate::uapi::try_monotonic_ms(),
        }
    }
}

impl Drop for OperationTimer {
    fn drop(&mut self) {
        let (Some(started_at_ms), Some(finished_at_ms)) =
            (self.started_at_ms, crate::uapi::try_monotonic_ms())
        else {
            return;
        };
        self.metric
            .finish(finished_at_ms.wrapping_sub(started_at_ms));
    }
}

pub(crate) fn record_internal_sleep() {
    saturating_increment(&INTERNAL_SLEEP_CALLS);
}

pub(crate) fn record_supplicant_poll() {
    saturating_increment(&SUPPLICANT_POLL_CALLS);
}

pub(crate) fn snapshot() -> BlockingBackendMetrics {
    BlockingBackendMetrics {
        initialize: INITIALIZE.snapshot(),
        scan: SCAN.snapshot(),
        connect: CONNECT.snapshot(),
        disconnect: DISCONNECT.snapshot(),
        poll: POLL.snapshot(),
        internal_sleep_calls: INTERNAL_SLEEP_CALLS.load(Ordering::Relaxed),
        supplicant_poll_calls: SUPPLICANT_POLL_CALLS.load(Ordering::Relaxed),
    }
}

fn saturating_increment(counter: &AtomicU32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        for metric in [&INITIALIZE, &SCAN, &CONNECT, &DISCONNECT, &POLL] {
            metric.reset();
        }
        INTERNAL_SLEEP_CALLS.store(0, Ordering::Relaxed);
        SUPPLICANT_POLL_CALLS.store(0, Ordering::Relaxed);
    }

    #[test]
    fn snapshot_separates_calls_timing_and_loop_work() {
        reset();
        CONNECT.begin();
        CONNECT.finish(7);
        CONNECT.begin();
        CONNECT.finish(3);
        INITIALIZE.begin();
        record_internal_sleep();
        record_internal_sleep();
        record_supplicant_poll();

        assert_eq!(
            snapshot(),
            BlockingBackendMetrics {
                initialize: BlockingOperationMetrics {
                    calls: 1,
                    timed_calls: 0,
                    max_elapsed_ms: 0,
                },
                connect: BlockingOperationMetrics {
                    calls: 2,
                    timed_calls: 2,
                    max_elapsed_ms: 7,
                },
                internal_sleep_calls: 2,
                supplicant_poll_calls: 1,
                ..BlockingBackendMetrics::default()
            }
        );
    }
}
