//! Non-default A5B scan/connect/disconnect slice for the upstream supplicant.
//!
//! Initialization still enters blocking vendor calls. This module therefore
//! accepts only a backend that has completed that explicit prerequisite; the
//! incremental `Initialize` command acknowledges the established state and
//! never re-enters vendor initialization. It is not wired into the default
//! [`hisi_rf_core::RadioRunner`].

use core::num::NonZeroU32;

use hisi_rf_core::{
    BackendError, BackendErrorClass, ConnectionInfo, DiagnosticStage, DiagnosticTraceKind,
    IncrementalCompletion, IncrementalRequest, IncrementalWifiBackend, OperationId,
    PollDisposition, ScanConfig, ScanOutcome, ScanResult, Security, Ssid, StationConfig, WaitSet,
    WakeReason, WorkBudget, WorkReport,
};
use ws63_radio_sys::supplicant::{Event, PollResult};

use super::{
    NativeConnectEvent, Ws63ScanResult, Ws63WifiBackend, channel_to_frequency,
    classify_native_connect_event, map_error, map_native_error, not_initialized, staged_error,
};
use crate::upstream_supplicant::NativeSupplicant;

const ERROR_STALE_OPERATION: u32 = 0x5732_b002;
const ERROR_WORK_BUDGET: u32 = 0x5732_b003;
const ERROR_OPERATION_TIMEOUT: u32 = 0x5732_b004;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationKind {
    Initialize,
    Scan,
    Connect(ConnectionInfo),
    Disconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationOutcome {
    Continue,
    Complete(IncrementalCompletion),
    Cancelled,
    Failed(i32),
}

#[derive(Clone, Copy, Debug)]
struct ActiveOperation {
    id: OperationId,
    kind: OperationKind,
    deadline_us: u64,
    backend_deadline_us: Option<u64>,
    cancellation_requested: bool,
    last_event_kind: u8,
    last_disconnect_status: Option<i32>,
    scan_total: Option<usize>,
    scan_seen: usize,
    scan_written: usize,
    scan_truncated: bool,
    scan_timed_out: bool,
}

impl ActiveOperation {
    fn initialize(id: OperationId, now_us: u64) -> Self {
        Self::new(id, OperationKind::Initialize, 0, now_us)
    }

    fn connect(id: OperationId, info: ConnectionInfo, timeout_ms: u32, now_us: u64) -> Self {
        Self::new(id, OperationKind::Connect(info), timeout_ms, now_us)
    }

    fn scan(id: OperationId, config: ScanConfig, now_us: u64) -> Self {
        Self::new(id, OperationKind::Scan, config.timeout_ms(), now_us)
    }

    fn disconnect(id: OperationId, timeout_ms: u32, now_us: u64) -> Self {
        Self::new(id, OperationKind::Disconnect, timeout_ms, now_us)
    }

    fn new(id: OperationId, kind: OperationKind, timeout_ms: u32, now_us: u64) -> Self {
        Self {
            id,
            kind,
            deadline_us: now_us.saturating_add(u64::from(timeout_ms).saturating_mul(1_000)),
            backend_deadline_us: None,
            cancellation_requested: false,
            last_event_kind: 0,
            last_disconnect_status: None,
            scan_total: None,
            scan_seen: 0,
            scan_written: 0,
            scan_truncated: false,
            scan_timed_out: false,
        }
    }

    fn ensure_id(&self, id: OperationId) -> Result<(), BackendError> {
        if self.id == id {
            Ok(())
        } else {
            Err(operation_error(ERROR_STALE_OPERATION))
        }
    }

    fn next_deadline_us(&self) -> u64 {
        self.backend_deadline_us
            .map_or(self.deadline_us, |deadline| deadline.min(self.deadline_us))
    }

    fn observe(&mut self, kind: u8, status: i32) -> OperationOutcome {
        self.last_event_kind = kind;
        match self.kind {
            OperationKind::Initialize => OperationOutcome::Continue,
            OperationKind::Scan => OperationOutcome::Continue,
            OperationKind::Connect(info) => match classify_native_connect_event(kind) {
                NativeConnectEvent::Progress => OperationOutcome::Continue,
                NativeConnectEvent::Authorized if self.cancellation_requested => {
                    OperationOutcome::Continue
                }
                NativeConnectEvent::Authorized => {
                    OperationOutcome::Complete(IncrementalCompletion::Connected(info))
                }
                NativeConnectEvent::Disconnected if self.cancellation_requested => {
                    OperationOutcome::Cancelled
                }
                NativeConnectEvent::Disconnected => {
                    if status != 0 {
                        self.last_disconnect_status = Some(status);
                    }
                    OperationOutcome::Continue
                }
                NativeConnectEvent::Failed => OperationOutcome::Failed(status),
            },
            OperationKind::Disconnect => match classify_native_connect_event(kind) {
                NativeConnectEvent::Disconnected if self.cancellation_requested => {
                    OperationOutcome::Cancelled
                }
                NativeConnectEvent::Disconnected => {
                    OperationOutcome::Complete(IncrementalCompletion::Disconnected)
                }
                NativeConnectEvent::Failed => OperationOutcome::Failed(status),
                NativeConnectEvent::Progress | NativeConnectEvent::Authorized => {
                    OperationOutcome::Continue
                }
            },
        }
    }
}

pub(crate) trait SupplicantPort {
    fn start_scan(&mut self) -> Result<(), BackendError>;
    fn poll_scan(&mut self) -> Result<Option<usize>, BackendError>;
    fn scan_result(&self, index: usize) -> Option<ScanResult>;
    fn scan_cache_pending(&self) -> bool;
    fn cancel_scan(&mut self);
    fn configure(&mut self, config: &StationConfig) -> Result<(), BackendError>;
    fn connect(&mut self) -> Result<(), BackendError>;
    fn disconnect(&mut self) -> Result<(), BackendError>;
    fn poll(&mut self, budget: NonZeroU32) -> Result<PollResult, BackendError>;
    fn next_event(&mut self) -> Result<Option<Event>, BackendError>;
}

impl<T: SupplicantPort + ?Sized> SupplicantPort for &mut T {
    fn start_scan(&mut self) -> Result<(), BackendError> {
        (**self).start_scan()
    }

    fn poll_scan(&mut self) -> Result<Option<usize>, BackendError> {
        (**self).poll_scan()
    }

    fn scan_result(&self, index: usize) -> Option<ScanResult> {
        (**self).scan_result(index)
    }

    fn scan_cache_pending(&self) -> bool {
        (**self).scan_cache_pending()
    }

    fn cancel_scan(&mut self) {
        (**self).cancel_scan();
    }

    fn configure(&mut self, config: &StationConfig) -> Result<(), BackendError> {
        (**self).configure(config)
    }

    fn connect(&mut self) -> Result<(), BackendError> {
        (**self).connect()
    }

    fn disconnect(&mut self) -> Result<(), BackendError> {
        (**self).disconnect()
    }

    fn poll(&mut self, budget: NonZeroU32) -> Result<PollResult, BackendError> {
        (**self).poll(budget)
    }

    fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
        (**self).next_event()
    }
}

impl SupplicantPort for Ws63WifiBackend<'static> {
    fn start_scan(&mut self) -> Result<(), BackendError> {
        let supplicant = self.supplicant.as_mut().ok_or_else(not_initialized)?;
        supplicant
            .begin_scan_cache_capture()
            .map_err(map_native_error)?;
        let wifi = self.wifi.as_mut().ok_or_else(not_initialized)?;
        if let Err(error) = wifi.begin_scan() {
            supplicant.cancel_scan_cache_capture();
            return Err(map_error(error));
        }
        Ok(())
    }

    fn poll_scan(&mut self) -> Result<Option<usize>, BackendError> {
        self.wifi
            .as_mut()
            .ok_or_else(not_initialized)?
            .poll_scan()
            .map_err(map_error)
    }

    fn scan_result(&self, index: usize) -> Option<ScanResult> {
        self.wifi
            .as_ref()?
            .scan_result(index)
            .and_then(convert_scan_result)
    }

    fn scan_cache_pending(&self) -> bool {
        self.supplicant
            .as_ref()
            .is_some_and(NativeSupplicant::scan_cache_capture_pending)
    }

    fn cancel_scan(&mut self) {
        if let Some(wifi) = self.wifi.as_mut() {
            wifi.cancel_scan();
        }
        if let Some(supplicant) = self.supplicant.as_mut() {
            supplicant.cancel_scan_cache_capture();
        }
    }

    fn configure(&mut self, config: &StationConfig) -> Result<(), BackendError> {
        self.supplicant
            .as_mut()
            .ok_or_else(not_initialized)?
            .configure(config)
            .map_err(map_native_error)
    }

    fn connect(&mut self) -> Result<(), BackendError> {
        self.supplicant
            .as_mut()
            .ok_or_else(not_initialized)?
            .connect()
            .map_err(map_native_error)
    }

    fn disconnect(&mut self) -> Result<(), BackendError> {
        self.supplicant
            .as_mut()
            .ok_or_else(not_initialized)?
            .disconnect()
            .map_err(map_native_error)
    }

    fn poll(&mut self, budget: NonZeroU32) -> Result<PollResult, BackendError> {
        self.supplicant
            .as_mut()
            .ok_or_else(not_initialized)?
            .poll(budget)
            .map_err(map_native_error)
    }

    fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
        self.supplicant
            .as_mut()
            .ok_or_else(not_initialized)?
            .next_event()
            .map_err(map_native_error)
    }
}

trait MonotonicClock {
    fn now_us(&self) -> u64;
}

pub(crate) struct Ws63Clock;

impl MonotonicClock for Ws63Clock {
    fn now_us(&self) -> u64 {
        crate::uapi::monotonic_us()
    }
}

/// Borrowed prototype over an already initialized native supplicant.
pub(crate) struct IncrementalSupplicantBackend<P, C> {
    port: P,
    clock: C,
    active: Option<ActiveOperation>,
}

impl<P: SupplicantPort, C> IncrementalSupplicantBackend<P, C> {
    fn new(port: P, clock: C) -> Self {
        Self {
            port,
            clock,
            active: None,
        }
    }

    fn active_mut(&mut self, id: OperationId) -> Result<&mut ActiveOperation, BackendError> {
        let active = self
            .active
            .as_mut()
            .ok_or_else(|| operation_error(ERROR_STALE_OPERATION))?;
        active.ensure_id(id)?;
        Ok(active)
    }

    fn clear_with_error(&mut self, error: BackendError) -> Result<WorkReport, BackendError> {
        if matches!(
            self.active.as_ref().map(|active| active.kind),
            Some(OperationKind::Scan)
        ) {
            self.port.cancel_scan();
        }
        self.active = None;
        Err(error)
    }
}

impl Ws63WifiBackend<'static> {
    /// Borrow the bounded supplicant slice after blocking initialization.
    pub(crate) fn incremental_supplicant(
        &mut self,
    ) -> Result<IncrementalSupplicantBackend<&mut Self, Ws63Clock>, BackendError> {
        self.ensure_incremental_ready()?;
        Ok(IncrementalSupplicantBackend::new(self, Ws63Clock))
    }

    fn ensure_incremental_ready(&self) -> Result<(), BackendError> {
        if self.wifi.is_none() || self.supplicant.is_none() {
            return Err(not_initialized());
        }
        Ok(())
    }

    pub(crate) fn into_incremental(
        self,
    ) -> Result<OwnedIncrementalSupplicantBackend, BackendError> {
        self.ensure_incremental_ready()?;
        Ok(OwnedIncrementalSupplicantBackend {
            inner: IncrementalSupplicantBackend::new(self, Ws63Clock),
        })
    }
}

/// Owned bounded backend created only after the explicit blocking bootstrap.
pub(crate) struct OwnedIncrementalSupplicantBackend {
    inner: IncrementalSupplicantBackend<Ws63WifiBackend<'static>, Ws63Clock>,
}

impl IncrementalWifiBackend for OwnedIncrementalSupplicantBackend {
    fn start(&mut self, id: OperationId, request: IncrementalRequest) -> Result<(), BackendError> {
        self.inner.start(id, request)
    }

    fn poll(
        &mut self,
        id: OperationId,
        reason: WakeReason,
        budget: WorkBudget,
        scan_output: &mut [ScanResult],
    ) -> Result<WorkReport, BackendError> {
        self.inner.poll(id, reason, budget, scan_output)
    }

    fn cancel(&mut self, id: OperationId) -> Result<(), BackendError> {
        self.inner.cancel(id)
    }

    fn next_deadline_us(&self, id: OperationId) -> Option<u64> {
        self.inner.next_deadline_us(id)
    }
}

impl<P: SupplicantPort, C: MonotonicClock> IncrementalWifiBackend
    for IncrementalSupplicantBackend<P, C>
{
    fn start(&mut self, id: OperationId, request: IncrementalRequest) -> Result<(), BackendError> {
        if self.active.is_some() {
            return Err(staged_error(
                BackendErrorClass::Busy,
                1,
                DiagnosticStage::ControlPlane,
            ));
        }
        let now_us = self.clock.now_us();
        let active = match request {
            IncrementalRequest::Scan(config) => {
                self.port.start_scan()?;
                ActiveOperation::scan(id, config, now_us)
            }
            IncrementalRequest::Connect(config) => {
                self.port.configure(&config)?;
                self.port.connect()?;
                let info = ConnectionInfo {
                    bssid: config.bssid,
                    frequency_mhz: channel_to_frequency(config.channel),
                };
                ActiveOperation::connect(id, info, config.timeout_ms(), now_us)
            }
            IncrementalRequest::Disconnect(config) => {
                self.port.disconnect()?;
                ActiveOperation::disconnect(id, config.disconnect_timeout_ms, now_us)
            }
            IncrementalRequest::Initialize(_) => ActiveOperation::initialize(id, now_us),
        };
        self.active = Some(active);
        Ok(())
    }

    fn poll(
        &mut self,
        id: OperationId,
        _reason: WakeReason,
        budget: WorkBudget,
        scan_output: &mut [ScanResult],
    ) -> Result<WorkReport, BackendError> {
        let started_us = self.clock.now_us();
        let initialized = {
            let active = self.active_mut(id)?;
            matches!(active.kind, OperationKind::Initialize)
                .then_some(active.cancellation_requested)
        };
        if let Some(cancelled) = initialized {
            self.active = None;
            return WorkReport::try_new(
                id,
                budget,
                0,
                0,
                true,
                if cancelled {
                    PollDisposition::Cancelled
                } else {
                    PollDisposition::Complete(IncrementalCompletion::Initialized)
                },
            )
            .ok_or_else(|| operation_error(ERROR_WORK_BUDGET));
        }
        let timeout = {
            let active = self.active_mut(id)?;
            if started_us >= active.deadline_us {
                if matches!(active.kind, OperationKind::Scan) {
                    active.cancellation_requested = true;
                    active.scan_timed_out = true;
                    None
                } else {
                    Some(timeout_error(active))
                }
            } else {
                None
            }
        };
        if let Some(error) = timeout {
            return self.clear_with_error(error);
        }

        let event_budget = u32::from(budget.max_events().get());
        let result = match self
            .port
            .poll(NonZeroU32::new(event_budget).expect("work budget is non-zero"))
        {
            Ok(result) => result,
            Err(error) => return self.clear_with_error(error),
        };
        if result.work_completed > event_budget {
            return self.clear_with_error(operation_error(ERROR_WORK_BUDGET));
        }

        let mut consumed = result.work_completed as u16;
        let mut made_progress = consumed != 0;
        let mut outcome = OperationOutcome::Continue;
        while result.output_pending != 0 && consumed < budget.max_events().get() {
            let event = match self.port.next_event() {
                Ok(event) => event,
                Err(error) => return self.clear_with_error(error),
            };
            let Some(event) = event else {
                break;
            };
            consumed += 1;
            made_progress = true;
            outcome = self.active_mut(id)?.observe(event.kind, event.status);
            if !matches!(outcome, OperationOutcome::Continue) {
                break;
            }
        }

        let is_scan = matches!(self.active_mut(id)?.kind, OperationKind::Scan);
        if is_scan && matches!(outcome, OperationOutcome::Continue) {
            let total = match self.port.poll_scan() {
                Ok(total) => total,
                Err(error) => return self.clear_with_error(error),
            };
            if let Some(total) = total {
                self.active_mut(id)?.scan_total = Some(total);
            }

            if !self.port.scan_cache_pending() {
                let (cancelled, timed_out) = {
                    let active = self.active_mut(id)?;
                    (active.cancellation_requested, active.scan_timed_out)
                };
                if timed_out {
                    let error = timeout_error(self.active_mut(id)?);
                    self.active = None;
                    return Err(error);
                }
                if cancelled {
                    made_progress = true;
                    outcome = OperationOutcome::Cancelled;
                }

                if matches!(outcome, OperationOutcome::Continue) {
                    loop {
                        let (index, total) = {
                            let active = self.active_mut(id)?;
                            let Some(total) = active.scan_total else {
                                break;
                            };
                            (active.scan_seen, total)
                        };
                        if index >= total || consumed == budget.max_events().get() {
                            break;
                        }
                        let result = self.port.scan_result(index);
                        let active = self.active_mut(id)?;
                        active.scan_seen += 1;
                        consumed += 1;
                        made_progress = true;
                        match result {
                            Some(result) if active.scan_written < scan_output.len() => {
                                scan_output[active.scan_written] = result;
                                active.scan_written += 1;
                            }
                            Some(_) | None => active.scan_truncated = true,
                        }
                    }
                }

                let active = self.active_mut(id)?;
                if let Some(total) = active.scan_total
                    && active.scan_seen == total
                {
                    made_progress = true;
                    outcome =
                        OperationOutcome::Complete(IncrementalCompletion::Scan(ScanOutcome {
                            count: active.scan_written,
                            truncated: active.scan_truncated || active.scan_written < total,
                        }));
                }
            }
        }

        let finished_us = self.clock.now_us();
        let elapsed = finished_us.wrapping_sub(started_us);
        if elapsed > u64::from(budget.max_time_us().get()) || elapsed > u64::from(u32::MAX) {
            return self.clear_with_error(operation_error(ERROR_WORK_BUDGET));
        }

        let timeout = {
            let active = self.active_mut(id)?;
            active.backend_deadline_us = (result.next_deadline_ms != u64::MAX)
                .then(|| result.next_deadline_ms.saturating_mul(1_000));
            if finished_us >= active.deadline_us && matches!(outcome, OperationOutcome::Continue) {
                if matches!(active.kind, OperationKind::Scan) {
                    active.cancellation_requested = true;
                    active.scan_timed_out = true;
                    None
                } else {
                    Some(timeout_error(active))
                }
            } else {
                None
            }
        };
        if let Some(error) = timeout {
            return self.clear_with_error(error);
        }

        let wait = WaitSet::BACKEND.union(WaitSet::TIMER);
        let terminal = !matches!(outcome, OperationOutcome::Continue);
        let disposition = match outcome {
            OperationOutcome::Complete(completion) => PollDisposition::Complete(completion),
            OperationOutcome::Cancelled => PollDisposition::Cancelled,
            OperationOutcome::Failed(status) => {
                let error = staged_error(
                    BackendErrorClass::Connect,
                    status as u32,
                    DiagnosticStage::Connect,
                )
                .with_trace(DiagnosticTraceKind::VendorStatus, status as u32);
                return self.clear_with_error(error);
            }
            OperationOutcome::Continue if consumed == budget.max_events().get() => {
                PollDisposition::BudgetExhausted(wait)
            }
            OperationOutcome::Continue => PollDisposition::Pending(wait),
        };
        let report = WorkReport::try_new(
            id,
            budget,
            consumed,
            elapsed as u32,
            made_progress,
            disposition,
        );
        let Some(report) = report else {
            return self.clear_with_error(operation_error(ERROR_WORK_BUDGET));
        };
        if terminal {
            self.active = None;
        }
        Ok(report)
    }

    fn cancel(&mut self, id: OperationId) -> Result<(), BackendError> {
        let needs_disconnect = {
            let active = self.active_mut(id)?;
            if active.cancellation_requested {
                return Ok(());
            }
            matches!(active.kind, OperationKind::Connect(_))
        };
        if needs_disconnect && let Err(error) = self.port.disconnect() {
            self.active = None;
            return Err(error);
        }
        let active = self.active_mut(id)?;
        if active.cancellation_requested {
            return Ok(());
        }
        active.cancellation_requested = true;
        Ok(())
    }

    fn next_deadline_us(&self, id: OperationId) -> Option<u64> {
        self.active
            .as_ref()
            .filter(|active| active.id == id)
            .map(ActiveOperation::next_deadline_us)
    }
}

fn operation_error(code: u32) -> BackendError {
    staged_error(BackendErrorClass::Other, code, DiagnosticStage::Operation)
}

fn convert_scan_result(scan: Ws63ScanResult) -> Option<ScanResult> {
    let ssid = Ssid::try_from_bytes(scan.ssid())?;
    let security = match scan.security() {
        crate::wifi::ScanSecurity::Open => Security::Open,
        #[cfg(feature = "upstream-supplicant-wpa3")]
        crate::wifi::ScanSecurity::Protected if scan.supports_wpa2_wpa3_transition() => {
            Security::Wpa2Wpa3PersonalTransition
        }
        #[cfg(feature = "upstream-supplicant-wpa3")]
        crate::wifi::ScanSecurity::Protected if scan.supports_wpa3_personal() => {
            Security::Wpa3Personal
        }
        crate::wifi::ScanSecurity::Protected if scan.supports_wpa2_personal() => {
            Security::Wpa2Personal
        }
        crate::wifi::ScanSecurity::Protected => Security::OtherProtected,
    };
    Some(ScanResult {
        ssid,
        bssid: scan.bssid,
        frequency_mhz: scan.frequency_mhz,
        rssi_dbm: scan.rssi_dbm,
        security,
        channel: scan.channel(),
    })
}

fn timeout_error(active: &ActiveOperation) -> BackendError {
    let status = active.last_disconnect_status.unwrap_or_default() as u32;
    staged_error(
        BackendErrorClass::Timeout,
        ERROR_OPERATION_TIMEOUT | u32::from(active.last_event_kind),
        match active.kind {
            OperationKind::Initialize => DiagnosticStage::Initialize,
            OperationKind::Scan => DiagnosticStage::Scan,
            OperationKind::Connect(_) => DiagnosticStage::Connect,
            OperationKind::Disconnect => DiagnosticStage::Disconnect,
        },
    )
    .with_trace(DiagnosticTraceKind::VendorStatus, status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hisi_rf_core::{OperationTracker, WifiConfig};
    use ws63_radio_sys::supplicant::{ABI_VERSION, EVENT_DATA_LEN};

    struct FakePort {
        result: PollResult,
        events: [Option<Event>; 2],
        next_event: usize,
        disconnect_calls: u8,
        scan_results: [Option<ScanResult>; 3],
        scan_total: Option<usize>,
        scan_cache_pending: bool,
        scan_start_calls: u8,
        scan_cancel_calls: u8,
    }

    impl FakePort {
        fn new(result: PollResult, events: [Option<Event>; 2]) -> Self {
            Self {
                result,
                events,
                next_event: 0,
                disconnect_calls: 0,
                scan_results: [None; 3],
                scan_total: None,
                scan_cache_pending: false,
                scan_start_calls: 0,
                scan_cancel_calls: 0,
            }
        }
    }

    impl SupplicantPort for FakePort {
        fn start_scan(&mut self) -> Result<(), BackendError> {
            self.scan_start_calls += 1;
            Ok(())
        }

        fn poll_scan(&mut self) -> Result<Option<usize>, BackendError> {
            Ok(self.scan_total)
        }

        fn scan_result(&self, index: usize) -> Option<ScanResult> {
            self.scan_results.get(index).copied().flatten()
        }

        fn scan_cache_pending(&self) -> bool {
            self.scan_cache_pending
        }

        fn cancel_scan(&mut self) {
            self.scan_cancel_calls += 1;
            self.scan_cache_pending = false;
        }

        fn configure(&mut self, _: &StationConfig) -> Result<(), BackendError> {
            Ok(())
        }

        fn connect(&mut self) -> Result<(), BackendError> {
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), BackendError> {
            self.disconnect_calls += 1;
            Ok(())
        }

        fn poll(&mut self, _: NonZeroU32) -> Result<PollResult, BackendError> {
            Ok(self.result)
        }

        fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
            let event = self.events.get(self.next_event).copied().flatten();
            self.next_event += 1;
            Ok(event)
        }
    }

    struct FakeClock(u64);

    impl MonotonicClock for FakeClock {
        fn now_us(&self) -> u64 {
            self.0
        }
    }

    fn operation_id() -> OperationId {
        OperationTracker::new().queue(0).unwrap()
    }

    fn connection() -> ConnectionInfo {
        ConnectionInfo {
            bssid: [1, 2, 3, 4, 5, 6],
            frequency_mhz: 2_412,
        }
    }

    fn scan_result(ssid: &[u8], bssid_suffix: u8) -> ScanResult {
        ScanResult {
            ssid: Ssid::try_from_bytes(ssid).unwrap(),
            bssid: [0, 1, 2, 3, 4, bssid_suffix],
            frequency_mhz: 2_412,
            rssi_dbm: -40,
            security: Security::Open,
            channel: 1,
        }
    }

    fn poll_result(work_completed: u32, output_pending: bool) -> PollResult {
        PollResult {
            status: 0,
            work_completed,
            output_pending: u32::from(output_pending),
            reserved: 0,
            next_deadline_ms: u64::MAX,
        }
    }

    fn event(kind: u8, status: i32) -> Event {
        Event {
            abi_version: ABI_VERSION,
            kind,
            data_len: 0,
            status,
            timestamp_ms: 0,
            data: [0; EVENT_DATA_LEN],
        }
    }

    #[test]
    fn connect_requires_authorized_and_treats_disconnect_as_progress() {
        let mut active = ActiveOperation::connect(operation_id(), connection(), 1_000, 50);
        assert_eq!(
            active.observe(super::super::NATIVE_EVENT_DISCONNECTED, 30),
            OperationOutcome::Continue
        );
        assert_eq!(active.last_disconnect_status, Some(30));
        assert_eq!(
            active.observe(super::super::NATIVE_EVENT_AUTHORIZED, 0),
            OperationOutcome::Complete(IncrementalCompletion::Connected(connection()))
        );
    }

    #[test]
    fn cancellation_suppresses_late_authorized_until_disconnect() {
        let mut active = ActiveOperation::connect(operation_id(), connection(), 1_000, 0);
        active.cancellation_requested = true;
        assert_eq!(
            active.observe(super::super::NATIVE_EVENT_AUTHORIZED, 0),
            OperationOutcome::Continue
        );
        assert_eq!(
            active.observe(super::super::NATIVE_EVENT_DISCONNECTED, 0),
            OperationOutcome::Cancelled
        );
    }

    #[test]
    fn disconnect_completion_and_deadline_are_explicit() {
        let id = operation_id();
        let mut active = ActiveOperation::disconnect(id, 10, 2_000);
        active.backend_deadline_us = Some(2_500);
        assert_eq!(active.next_deadline_us(), 2_500);
        assert!(active.ensure_id(id).is_ok());
        assert_eq!(
            active.observe(super::super::NATIVE_EVENT_DISCONNECTED, 0),
            OperationOutcome::Complete(IncrementalCompletion::Disconnected)
        );
    }

    #[test]
    fn stale_generation_is_rejected() {
        let mut tracker = OperationTracker::new();
        let first = tracker.queue(0).unwrap();
        tracker.mark_started(first).unwrap();
        tracker.commit_terminal(first).unwrap();
        tracker.reap(first).unwrap();
        let second = tracker.queue(0).unwrap();
        let active = ActiveOperation::disconnect(second, 10, 0);
        assert!(active.ensure_id(first).is_err());
        assert!(active.ensure_id(second).is_ok());
    }

    #[test]
    fn real_adapter_contract_completes_disconnect_with_exact_work_charge() {
        let id = operation_id();
        let mut port = FakePort::new(
            poll_result(2, true),
            [
                Some(event(super::super::NATIVE_EVENT_DISCONNECTED, 0)),
                None,
            ],
        );
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(1_000));
        backend
            .start(id, IncrementalRequest::Disconnect(WifiConfig::default()))
            .unwrap();
        let report = backend
            .poll(
                id,
                WakeReason::Backend,
                WorkBudget::try_new(4, 100).unwrap(),
                &mut [],
            )
            .unwrap();
        assert_eq!(report.consumed_events(), 3);
        assert_eq!(
            report.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Disconnected)
        );
        drop(backend);
        assert_eq!(port.disconnect_calls, 1);
        assert_eq!(port.next_event, 1);
    }

    #[test]
    fn full_eloop_charge_defers_output_event_to_the_next_fair_turn() {
        let id = operation_id();
        let mut port = FakePort::new(
            poll_result(2, true),
            [
                Some(event(super::super::NATIVE_EVENT_DISCONNECTED, 0)),
                None,
            ],
        );
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(id, IncrementalRequest::Disconnect(WifiConfig::default()))
            .unwrap();
        let report = backend
            .poll(
                id,
                WakeReason::Backend,
                WorkBudget::try_new(2, 100).unwrap(),
                &mut [],
            )
            .unwrap();
        assert_eq!(report.consumed_events(), 2);
        assert!(matches!(
            report.disposition(),
            PollDisposition::BudgetExhausted(wait) if wait.contains(WaitSet::BACKEND)
        ));
        drop(backend);
        assert_eq!(port.next_event, 0);
    }

    #[test]
    fn backend_overreport_is_rejected_and_clears_the_operation() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(3, false), [None, None]);
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(id, IncrementalRequest::Disconnect(WifiConfig::default()))
            .unwrap();
        let error = backend
            .poll(
                id,
                WakeReason::Backend,
                WorkBudget::try_new(2, 100).unwrap(),
                &mut [],
            )
            .unwrap_err();
        assert_eq!(error.code(), ERROR_WORK_BUDGET);
        assert!(backend.next_deadline_us(id).is_none());
    }

    #[test]
    fn cancelling_disconnect_does_not_submit_a_duplicate_driver_request() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(id, IncrementalRequest::Disconnect(WifiConfig::default()))
            .unwrap();
        backend.cancel(id).unwrap();
        drop(backend);
        assert_eq!(port.disconnect_calls, 1);
    }

    #[test]
    fn scan_results_are_copied_incrementally_and_report_truncation() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.scan_total = Some(3);
        port.scan_results = [
            Some(scan_result(b"first", 1)),
            Some(scan_result(b"second", 2)),
            None,
        ];
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(
                id,
                IncrementalRequest::Scan(ScanConfig::try_from_timeout_ms(1_000).unwrap()),
            )
            .unwrap();
        let mut output = [ScanResult::empty(); 1];
        let first = backend
            .poll(
                id,
                WakeReason::Backend,
                WorkBudget::try_new(2, 100).unwrap(),
                &mut output,
            )
            .unwrap();
        assert_eq!(first.consumed_events(), 2);
        assert!(matches!(
            first.disposition(),
            PollDisposition::BudgetExhausted(_)
        ));

        let second = backend
            .poll(
                id,
                WakeReason::Backend,
                WorkBudget::try_new(2, 100).unwrap(),
                &mut output,
            )
            .unwrap();
        assert_eq!(second.consumed_events(), 1);
        assert_eq!(
            second.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Scan(ScanOutcome {
                count: 1,
                truncated: true,
            }))
        );
        assert_eq!(output[0].ssid.as_bytes(), b"first");
        drop(backend);
        assert_eq!(port.scan_start_calls, 1);
    }

    #[test]
    fn scan_cancel_waits_for_the_old_transaction_to_quiesce() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.scan_total = Some(1);
        port.scan_results = [Some(scan_result(b"late", 1)), None, None];
        port.scan_cache_pending = true;
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(
                id,
                IncrementalRequest::Scan(ScanConfig::try_from_timeout_ms(1_000).unwrap()),
            )
            .unwrap();
        backend.cancel(id).unwrap();

        let mut output = [ScanResult::empty(); 1];
        let pending = backend
            .poll(
                id,
                WakeReason::Backend,
                WorkBudget::try_new(2, 100).unwrap(),
                &mut output,
            )
            .unwrap();
        assert!(matches!(pending.disposition(), PollDisposition::Pending(_)));
        assert_eq!(output[0], ScanResult::empty());

        backend.port.scan_cache_pending = false;
        let cancelled = backend
            .poll(
                id,
                WakeReason::Backend,
                WorkBudget::try_new(2, 100).unwrap(),
                &mut output,
            )
            .unwrap();
        assert_eq!(cancelled.disposition(), PollDisposition::Cancelled);
        assert_eq!(output[0], ScanResult::empty());
        drop(backend);
        assert_eq!(port.scan_cancel_calls, 0);
    }

    #[test]
    fn initialize_acknowledges_the_explicit_bootstrap() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(id, IncrementalRequest::Initialize(WifiConfig::default()))
            .unwrap();
        let report = backend
            .poll(
                id,
                WakeReason::Command,
                WorkBudget::try_new(1, 1).unwrap(),
                &mut [],
            )
            .unwrap();
        assert_eq!(report.consumed_events(), 0);
        assert_eq!(report.elapsed_us(), 0);
        assert!(report.made_progress());
        assert_eq!(
            report.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Initialized)
        );
    }

    #[test]
    fn initialize_can_be_cancelled_before_acknowledgement() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(id, IncrementalRequest::Initialize(WifiConfig::default()))
            .unwrap();
        backend.cancel(id).unwrap();
        let report = backend
            .poll(
                id,
                WakeReason::Command,
                WorkBudget::try_new(1, 1).unwrap(),
                &mut [],
            )
            .unwrap();
        assert_eq!(report.disposition(), PollDisposition::Cancelled);
    }
}
