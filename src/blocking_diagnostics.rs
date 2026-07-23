//! Migration diagnostics for the current blocking Wi-Fi backend.

use portable_atomic::{AtomicU32, Ordering};

/// Ordered stages in the one-shot WS63 Wi-Fi bootstrap.
///
/// A stage boundary does not imply that the enclosed vendor call is
/// preemptible. These identifiers exist so HIL can measure each blocking
/// boundary before any of them is admitted into the incremental runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum BootstrapStage {
    /// Consume the uniquely owned HAL resources from the backend.
    ResourceClaim = 0,
    /// Install the explicitly selected WS63 crypto backend.
    CryptoInstall = 1,
    /// Run the enabled hardware-crypto startup self-tests.
    CryptoSelfTest = 2,
    /// Prepare the dedicated vendor RAM and linker-owned state.
    VendorMemoryPrepare = 3,
    /// Initialize the mask-ROM monotonic timebase.
    RomTimebaseInitialize = 4,
    /// Start the vendor Wi-Fi runtime.
    VendorWifiInitialize = 5,
    /// Create the station network device.
    StationDeviceCreate = 6,
    /// Register bounded vendor event delivery.
    EventRegistration = 7,
    /// Open the station data path after event delivery is installed.
    StationDeviceOpen = 8,
    /// Install the upstream supplicant OS/driver port.
    SupplicantPortPrepare = 9,
    /// Create the pinned upstream native supplicant context.
    NativeSupplicantCreate = 10,
}

impl BootstrapStage {
    /// Stages in execution order, suitable for allocation-free reporting.
    pub const ALL: [Self; 11] = [
        Self::ResourceClaim,
        Self::CryptoInstall,
        Self::CryptoSelfTest,
        Self::VendorMemoryPrepare,
        Self::RomTimebaseInitialize,
        Self::VendorWifiInitialize,
        Self::StationDeviceCreate,
        Self::EventRegistration,
        Self::StationDeviceOpen,
        Self::SupplicantPortPrepare,
        Self::NativeSupplicantCreate,
    ];

    const COUNT: usize = Self::ALL.len();

    /// Stable machine-readable stage name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceClaim => "resource_claim",
            Self::CryptoInstall => "crypto_install",
            Self::CryptoSelfTest => "crypto_self_test",
            Self::VendorMemoryPrepare => "vendor_memory_prepare",
            Self::RomTimebaseInitialize => "rom_timebase_initialize",
            Self::VendorWifiInitialize => "vendor_wifi_initialize",
            Self::StationDeviceCreate => "station_device_create",
            Self::EventRegistration => "event_registration",
            Self::StationDeviceOpen => "station_device_open",
            Self::SupplicantPortPrepare => "supplicant_port_prepare",
            Self::NativeSupplicantCreate => "native_supplicant_create",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Per-stage bootstrap statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BootstrapStageMetrics {
    /// Calls that entered this stage.
    pub calls: u32,
    /// Calls that completed this stage successfully.
    pub completed_calls: u32,
    /// Calls that returned or unwound before successful completion.
    pub failed_calls: u32,
    /// Calls measured with an initialized monotonic timebase.
    pub timed_calls: u32,
    /// Longest measured stage duration in milliseconds.
    pub max_elapsed_ms: u32,
}

/// Stage-by-stage view of the one-shot WS63 Wi-Fi bootstrap.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockingBootstrapMetrics {
    stages: [BootstrapStageMetrics; BootstrapStage::COUNT],
}

impl BlockingBootstrapMetrics {
    /// Return the metrics for one stable bootstrap stage identifier.
    pub fn stage(&self, stage: BootstrapStage) -> BootstrapStageMetrics {
        self.stages[stage.index()]
    }
}

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
    /// Stage-level evidence for the one-shot initialization prerequisite.
    pub bootstrap: BlockingBootstrapMetrics,
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
static BOOTSTRAP_STAGES: [BootstrapStageMetric; BootstrapStage::COUNT] =
    [const { BootstrapStageMetric::new() }; BootstrapStage::COUNT];
static INTERNAL_SLEEP_CALLS: AtomicU32 = AtomicU32::new(0);
static SUPPLICANT_POLL_CALLS: AtomicU32 = AtomicU32::new(0);

struct BootstrapStageMetric {
    calls: AtomicU32,
    completed_calls: AtomicU32,
    failed_calls: AtomicU32,
    timed_calls: AtomicU32,
    max_elapsed_ms: AtomicU32,
}

impl BootstrapStageMetric {
    const fn new() -> Self {
        Self {
            calls: AtomicU32::new(0),
            completed_calls: AtomicU32::new(0),
            failed_calls: AtomicU32::new(0),
            timed_calls: AtomicU32::new(0),
            max_elapsed_ms: AtomicU32::new(0),
        }
    }

    fn snapshot(&self) -> BootstrapStageMetrics {
        BootstrapStageMetrics {
            calls: self.calls.load(Ordering::Relaxed),
            completed_calls: self.completed_calls.load(Ordering::Relaxed),
            failed_calls: self.failed_calls.load(Ordering::Relaxed),
            timed_calls: self.timed_calls.load(Ordering::Relaxed),
            max_elapsed_ms: self.max_elapsed_ms.load(Ordering::Relaxed),
        }
    }

    fn begin(&self) {
        saturating_increment(&self.calls);
    }

    fn finish(&self, completed: bool, elapsed_ms: Option<u64>) {
        if completed {
            saturating_increment(&self.completed_calls);
        } else {
            saturating_increment(&self.failed_calls);
        }
        if let Some(elapsed_ms) = elapsed_ms {
            saturating_increment(&self.timed_calls);
            self.max_elapsed_ms.fetch_max(
                u32::try_from(elapsed_ms).unwrap_or(u32::MAX),
                Ordering::Relaxed,
            );
        }
    }

    #[cfg(test)]
    fn reset(&self) {
        self.calls.store(0, Ordering::Relaxed);
        self.completed_calls.store(0, Ordering::Relaxed);
        self.failed_calls.store(0, Ordering::Relaxed);
        self.timed_calls.store(0, Ordering::Relaxed);
        self.max_elapsed_ms.store(0, Ordering::Relaxed);
    }
}

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

/// Record one bootstrap stage until it succeeds or leaves scope.
pub(crate) struct BootstrapStageTimer {
    metric: &'static BootstrapStageMetric,
    started_at_ms: Option<u64>,
    completed: bool,
}

impl BootstrapStageTimer {
    pub(crate) fn start(stage: BootstrapStage) -> Self {
        let metric = &BOOTSTRAP_STAGES[stage.index()];
        metric.begin();
        Self {
            metric,
            started_at_ms: crate::uapi::try_monotonic_ms(),
            completed: false,
        }
    }

    pub(crate) fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for BootstrapStageTimer {
    fn drop(&mut self) {
        let elapsed_ms = match (self.started_at_ms, crate::uapi::try_monotonic_ms()) {
            (Some(started_at_ms), Some(finished_at_ms)) => {
                Some(finished_at_ms.wrapping_sub(started_at_ms))
            }
            _ => None,
        };
        self.metric.finish(self.completed, elapsed_ms);
    }
}

pub(crate) fn record_internal_sleep() {
    saturating_increment(&INTERNAL_SLEEP_CALLS);
}

pub(crate) fn record_supplicant_poll() {
    saturating_increment(&SUPPLICANT_POLL_CALLS);
}

pub(crate) fn snapshot() -> BlockingBackendMetrics {
    let mut bootstrap = BlockingBootstrapMetrics::default();
    for (snapshot, metric) in bootstrap.stages.iter_mut().zip(&BOOTSTRAP_STAGES) {
        *snapshot = metric.snapshot();
    }
    BlockingBackendMetrics {
        bootstrap,
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
    extern crate std;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_metrics() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn reset() {
        for metric in [&INITIALIZE, &SCAN, &CONNECT, &DISCONNECT, &POLL] {
            metric.reset();
        }
        for metric in &BOOTSTRAP_STAGES {
            metric.reset();
        }
        INTERNAL_SLEEP_CALLS.store(0, Ordering::Relaxed);
        SUPPLICANT_POLL_CALLS.store(0, Ordering::Relaxed);
    }

    #[test]
    fn snapshot_separates_calls_timing_and_loop_work() {
        let _guard = lock_metrics();
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

    #[test]
    fn bootstrap_stages_separate_success_from_failure() {
        let _guard = lock_metrics();
        reset();
        BootstrapStageTimer::start(BootstrapStage::ResourceClaim).complete();
        {
            let _stage = BootstrapStageTimer::start(BootstrapStage::CryptoInstall);
        }

        let metrics = snapshot().bootstrap;
        let completed = metrics.stage(BootstrapStage::ResourceClaim);
        assert_eq!(completed.calls, 1);
        assert_eq!(completed.completed_calls, 1);
        assert_eq!(completed.failed_calls, 0);
        assert_eq!(completed.timed_calls, 1);

        let failed = metrics.stage(BootstrapStage::CryptoInstall);
        assert_eq!(failed.calls, 1);
        assert_eq!(failed.completed_calls, 0);
        assert_eq!(failed.failed_calls, 1);
        assert_eq!(failed.timed_calls, 1);
        assert_eq!(
            metrics.stage(BootstrapStage::NativeSupplicantCreate),
            BootstrapStageMetrics::default()
        );
        assert_eq!(BootstrapStage::ALL.len(), BootstrapStage::COUNT);
        assert_eq!(
            BootstrapStage::StationDeviceOpen.as_str(),
            "station_device_open"
        );
    }
}
