//! Non-default A5B connect/disconnect slice for the upstream supplicant.
//!
//! Initialization and scan still enter blocking vendor calls, so this module
//! deliberately borrows an already initialized backend and rejects those two
//! request kinds. It is not wired into the default [`hisi_rf_core::RadioRunner`].

use core::num::NonZeroU32;

use hisi_rf_core::{
    BackendError, BackendErrorClass, ConnectionInfo, DiagnosticStage, DiagnosticTraceKind,
    IncrementalCompletion, IncrementalRequest, IncrementalWifiBackend, OperationId,
    PollDisposition, ScanResult, StationConfig, WaitSet, WakeReason, WorkBudget, WorkReport,
};
use ws63_radio_sys::supplicant::{Event, PollResult};

use super::{
    NativeConnectEvent, Ws63WifiBackend, channel_to_frequency, classify_native_connect_event,
    map_native_error, not_initialized, staged_error,
};
use crate::upstream_supplicant::NativeSupplicant;

const ERROR_UNSUPPORTED_REQUEST: u32 = 0x5732_b001;
const ERROR_STALE_OPERATION: u32 = 0x5732_b002;
const ERROR_WORK_BUDGET: u32 = 0x5732_b003;
const ERROR_OPERATION_TIMEOUT: u32 = 0x5732_b004;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationKind {
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
}

impl ActiveOperation {
    fn connect(id: OperationId, info: ConnectionInfo, timeout_ms: u32, now_us: u64) -> Self {
        Self::new(id, OperationKind::Connect(info), timeout_ms, now_us)
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

trait SupplicantPort {
    fn configure(&mut self, config: &StationConfig) -> Result<(), BackendError>;
    fn connect(&mut self) -> Result<(), BackendError>;
    fn disconnect(&mut self) -> Result<(), BackendError>;
    fn poll(&mut self, budget: NonZeroU32) -> Result<PollResult, BackendError>;
    fn next_event(&mut self) -> Result<Option<Event>, BackendError>;
}

impl SupplicantPort for NativeSupplicant {
    fn configure(&mut self, config: &StationConfig) -> Result<(), BackendError> {
        NativeSupplicant::configure(self, config).map_err(map_native_error)
    }

    fn connect(&mut self) -> Result<(), BackendError> {
        NativeSupplicant::connect(self).map_err(map_native_error)
    }

    fn disconnect(&mut self) -> Result<(), BackendError> {
        NativeSupplicant::disconnect(self).map_err(map_native_error)
    }

    fn poll(&mut self, budget: NonZeroU32) -> Result<PollResult, BackendError> {
        NativeSupplicant::poll(self, budget).map_err(map_native_error)
    }

    fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
        NativeSupplicant::next_event(self).map_err(map_native_error)
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
pub(crate) struct IncrementalSupplicantBackend<'a, P, C> {
    supplicant: &'a mut P,
    clock: C,
    active: Option<ActiveOperation>,
}

impl<'a, P, C> IncrementalSupplicantBackend<'a, P, C> {
    fn new(supplicant: &'a mut P, clock: C) -> Self {
        Self {
            supplicant,
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
        self.active = None;
        Err(error)
    }
}

impl Ws63WifiBackend<'static> {
    /// Borrow the bounded supplicant slice after blocking initialization.
    pub(crate) fn incremental_supplicant(
        &mut self,
    ) -> Result<IncrementalSupplicantBackend<'_, NativeSupplicant, Ws63Clock>, BackendError> {
        let supplicant = self.supplicant.as_mut().ok_or_else(not_initialized)?;
        Ok(IncrementalSupplicantBackend::new(supplicant, Ws63Clock))
    }
}

impl<P: SupplicantPort, C: MonotonicClock> IncrementalWifiBackend
    for IncrementalSupplicantBackend<'_, P, C>
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
            IncrementalRequest::Connect(config) => {
                self.supplicant.configure(&config)?;
                self.supplicant.connect()?;
                let info = ConnectionInfo {
                    bssid: config.bssid,
                    frequency_mhz: channel_to_frequency(config.channel),
                };
                ActiveOperation::connect(id, info, config.timeout_ms(), now_us)
            }
            IncrementalRequest::Disconnect(config) => {
                self.supplicant.disconnect()?;
                ActiveOperation::disconnect(id, config.disconnect_timeout_ms, now_us)
            }
            IncrementalRequest::Initialize(_) | IncrementalRequest::Scan(_) => {
                return Err(staged_error(
                    BackendErrorClass::Other,
                    ERROR_UNSUPPORTED_REQUEST,
                    DiagnosticStage::Operation,
                ));
            }
        };
        self.active = Some(active);
        Ok(())
    }

    fn poll(
        &mut self,
        id: OperationId,
        _reason: WakeReason,
        budget: WorkBudget,
        _scan_output: &mut [ScanResult],
    ) -> Result<WorkReport, BackendError> {
        let started_us = self.clock.now_us();
        let timeout = {
            let active = self.active_mut(id)?;
            if started_us >= active.deadline_us {
                Some(timeout_error(active))
            } else {
                None
            }
        };
        if let Some(error) = timeout {
            return self.clear_with_error(error);
        }

        let event_budget = u32::from(budget.max_events().get());
        let result = match self
            .supplicant
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
            let event = match self.supplicant.next_event() {
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

        let finished_us = self.clock.now_us();
        let elapsed = finished_us.wrapping_sub(started_us);
        if elapsed > u64::from(budget.max_time_us().get()) || elapsed > u64::from(u32::MAX) {
            return self.clear_with_error(operation_error(ERROR_WORK_BUDGET));
        }

        let timeout = {
            let active = self.active_mut(id)?;
            active.backend_deadline_us = (result.next_deadline_ms != u64::MAX)
                .then(|| result.next_deadline_ms.saturating_mul(1_000));
            (finished_us >= active.deadline_us && matches!(outcome, OperationOutcome::Continue))
                .then(|| timeout_error(active))
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
        if needs_disconnect && let Err(error) = self.supplicant.disconnect() {
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

fn timeout_error(active: &ActiveOperation) -> BackendError {
    let status = active.last_disconnect_status.unwrap_or_default() as u32;
    staged_error(
        BackendErrorClass::Timeout,
        ERROR_OPERATION_TIMEOUT | u32::from(active.last_event_kind),
        match active.kind {
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
    }

    impl FakePort {
        fn new(result: PollResult, events: [Option<Event>; 2]) -> Self {
            Self {
                result,
                events,
                next_event: 0,
                disconnect_calls: 0,
            }
        }
    }

    impl SupplicantPort for FakePort {
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
    fn initialize_and_scan_remain_fail_closed() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        let error = backend
            .start(id, IncrementalRequest::Initialize(WifiConfig::default()))
            .unwrap_err();
        assert_eq!(error.class(), BackendErrorClass::Other);
        assert_eq!(error.code(), ERROR_UNSUPPORTED_REQUEST);
    }
}
