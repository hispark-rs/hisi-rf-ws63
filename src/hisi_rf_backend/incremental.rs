//! Non-default A5B scan/connect/disconnect slice for the upstream supplicant.
//!
//! Initialization still enters blocking vendor calls. This module therefore
//! accepts only a backend that has completed that explicit prerequisite; the
//! incremental `Initialize` command acknowledges the established state and
//! never re-enters vendor initialization. It is not wired into the default
//! [`hisi_rf_core::RadioRunner`].

use core::num::NonZeroU32;

#[cfg(feature = "firmware-example")]
use core::{
    cell::Cell,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use hisi_rf_core::{
    BackendError, BackendErrorClass, ConnectionInfo, DiagnosticStage, DiagnosticTraceKind,
    IncrementalCompletion, IncrementalRequest, IncrementalWifiBackend, OperationId,
    PollDisposition, ScanConfig, ScanOutcome, ScanResult, Security, Ssid, StationConfig, WaitSet,
    WakeReason, WorkBudget, WorkReport,
};
#[cfg(feature = "firmware-example")]
use hisi_rf_core::{
    Diagnostic, Error, IncrementalDriverEvent, Passphrase, RadioConfig, RadioResources, RadioState,
    WifiEvent, init,
};
use portable_atomic::{AtomicU32, Ordering};
use ws63_radio_sys::supplicant::{Event, PollResult};

use super::{
    NativeConnectEvent, Ws63ScanResult, Ws63WifiBackend, channel_to_frequency,
    classify_native_connect_event, map_error, map_native_error, not_initialized, staged_error,
};
use crate::upstream_supplicant::NativeSupplicant;

const ERROR_STALE_OPERATION: u32 = 0x5732_b002;
const ERROR_WORK_BUDGET: u32 = 0x5732_b003;
const ERROR_OPERATION_TIMEOUT: u32 = 0x5732_b004;
const FIRST_EAPOL_RECONNECT_DELAY_US: u64 = 1_000_000;
// The WS63 vendor hostap fork defers same-SSID reconnect by 5 ms after a
// disconnect event (`events.c`, CONFIG_SSID_RECONNECT). Match that observed
// cleanup window instead of resubmitting from the disconnect callback turn.
const RECONNECT_SETTLE_US: u64 = 5_000;
const FIRST_EAPOL_TIMEOUT_MASK: u32 = 0x0000_000f;
const FIRST_EAPOL_RETRY_MASK: u32 = 0x00ff_0000;
const FIRST_EAPOL_RETRY_PENDING: u32 = 1 << 24;

static DIAG_FIRST_EAPOL_RECONNECTS: AtomicU32 = AtomicU32::new(0);
static DIAG_EXTERNAL_AUTH_RECONNECTS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationKind {
    Initialize,
    Scan,
    Connect(ConnectionInfo),
    Disconnect,
}

#[derive(Debug)]
enum StartPhase {
    Ready,
    Scan,
    ConnectConfigure(StationConfig),
    ConnectSubmit,
    Disconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationOutcome {
    Continue,
    Complete(IncrementalCompletion),
    Cancelled,
    Failed(i32),
}

#[derive(Debug)]
struct ActiveOperation {
    id: OperationId,
    kind: OperationKind,
    start_phase: StartPhase,
    deadline_us: u64,
    backend_deadline_us: Option<u64>,
    cancellation_requested: bool,
    cancellation_action_submitted: bool,
    first_eapol_reconnect_deadline_us: Option<u64>,
    first_eapol_reconnect_submitted: bool,
    external_auth_reconnect_deadline_us: Option<u64>,
    external_auth_reconnect_submitted: bool,
    reconnect_after_disconnect: bool,
    reconnect_submit_deadline_us: Option<u64>,
    last_event_kind: u8,
    last_disconnect_status: Option<i32>,
    scan_total: Option<usize>,
    scan_seen: usize,
    scan_written: usize,
    scan_truncated: bool,
}

impl ActiveOperation {
    fn initialize(id: OperationId, now_us: u64) -> Self {
        Self::new(id, OperationKind::Initialize, 0, now_us)
    }

    fn connect(id: OperationId, info: ConnectionInfo, timeout_ms: u32, now_us: u64) -> Self {
        Self::new(id, OperationKind::Connect(info), timeout_ms, now_us)
    }

    fn scan(id: OperationId, config: ScanConfig, now_us: u64) -> Self {
        Self::new(
            id,
            OperationKind::Scan,
            config.operation_timeout().as_millis(),
            now_us,
        )
    }

    fn disconnect(id: OperationId, timeout_ms: u32, now_us: u64) -> Self {
        Self::new(id, OperationKind::Disconnect, timeout_ms, now_us)
    }

    fn new(id: OperationId, kind: OperationKind, timeout_ms: u32, now_us: u64) -> Self {
        Self {
            id,
            kind,
            start_phase: StartPhase::Ready,
            deadline_us: now_us.saturating_add(u64::from(timeout_ms).saturating_mul(1_000)),
            backend_deadline_us: None,
            cancellation_requested: false,
            cancellation_action_submitted: false,
            first_eapol_reconnect_deadline_us: None,
            first_eapol_reconnect_submitted: false,
            external_auth_reconnect_deadline_us: None,
            external_auth_reconnect_submitted: false,
            reconnect_after_disconnect: false,
            reconnect_submit_deadline_us: None,
            last_event_kind: 0,
            last_disconnect_status: None,
            scan_total: None,
            scan_seen: 0,
            scan_written: 0,
            scan_truncated: false,
        }
    }

    fn from_request(id: OperationId, request: IncrementalRequest, now_us: u64) -> Self {
        match request {
            IncrementalRequest::Initialize(_) => Self::initialize(id, now_us),
            IncrementalRequest::Scan(config) => {
                let mut active = Self::scan(id, config, now_us);
                active.start_phase = StartPhase::Scan;
                active
            }
            IncrementalRequest::Connect(config) => {
                let info = ConnectionInfo {
                    bssid: config.bssid,
                    frequency_mhz: channel_to_frequency(config.channel),
                };
                let timeout_ms = config.operation_timeout().as_millis();
                let mut active = Self::connect(id, info, timeout_ms, now_us);
                active.start_phase = StartPhase::ConnectConfigure(config);
                active
            }
            IncrementalRequest::Disconnect(config) => {
                let mut active =
                    Self::disconnect(id, config.disconnect_timeout.as_millis(), now_us);
                active.start_phase = StartPhase::Disconnect;
                active
            }
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
        let deadline = self
            .backend_deadline_us
            .map_or(self.deadline_us, |deadline| deadline.min(self.deadline_us));
        let deadline = self
            .first_eapol_reconnect_deadline_us
            .map_or(deadline, |reconnect| reconnect.min(deadline));
        let deadline = self
            .external_auth_reconnect_deadline_us
            .map_or(deadline, |reconnect| reconnect.min(deadline));
        self.reconnect_submit_deadline_us
            .map_or(deadline, |reconnect| reconnect.min(deadline))
    }

    fn should_submit_first_eapol_reconnect(&mut self, recovery: u32, now_us: u64) -> bool {
        if !matches!(self.kind, OperationKind::Connect(_))
            || self.cancellation_requested
            || self.first_eapol_reconnect_submitted
            || recovery & FIRST_EAPOL_TIMEOUT_MASK == 0
            || recovery & FIRST_EAPOL_RETRY_MASK == 0
            || recovery & FIRST_EAPOL_RETRY_PENDING != 0
        {
            return false;
        }
        let deadline = self
            .first_eapol_reconnect_deadline_us
            .get_or_insert_with(|| now_us.saturating_add(FIRST_EAPOL_RECONNECT_DELAY_US));
        if now_us < *deadline {
            return false;
        }
        self.first_eapol_reconnect_submitted = true;
        self.first_eapol_reconnect_deadline_us = None;
        true
    }

    fn should_submit_external_auth_reconnect(&mut self, stalled: bool, now_us: u64) -> bool {
        if !matches!(self.kind, OperationKind::Connect(_))
            || self.cancellation_requested
            || self.external_auth_reconnect_submitted
        {
            return false;
        }
        if !stalled {
            self.external_auth_reconnect_deadline_us = None;
            return false;
        }
        let deadline = self
            .external_auth_reconnect_deadline_us
            .get_or_insert_with(|| now_us.saturating_add(FIRST_EAPOL_RECONNECT_DELAY_US));
        if now_us < *deadline {
            return false;
        }
        self.external_auth_reconnect_submitted = true;
        self.external_auth_reconnect_deadline_us = None;
        true
    }

    fn request_reconnect_after_disconnect(&mut self) {
        self.reconnect_after_disconnect = true;
    }

    fn observe_reconnect_disconnect(&mut self, kind: u8, now_us: u64) {
        if self.reconnect_after_disconnect
            && !self.cancellation_requested
            && classify_native_connect_event(kind) == NativeConnectEvent::Disconnected
        {
            self.reconnect_after_disconnect = false;
            self.reconnect_submit_deadline_us = Some(now_us.saturating_add(RECONNECT_SETTLE_US));
        }
    }

    fn take_reconnect_when_settled(&mut self, now_us: u64) -> bool {
        if self
            .reconnect_submit_deadline_us
            .is_some_and(|deadline| now_us >= deadline)
        {
            self.reconnect_submit_deadline_us = None;
            true
        } else {
            false
        }
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
    fn input_pending(&self) -> bool {
        false
    }
    fn next_event(&mut self) -> Result<Option<Event>, BackendError>;
    fn recovery_diagnostic_word(&self) -> u32;
    fn context_diagnostic_word(&self) -> u32 {
        0
    }
    fn driver_diagnostic_word(&self) -> u32 {
        0
    }
    fn match_diagnostic_word(&self) -> u32 {
        0
    }
    fn external_auth_retry_stalled(&self) -> bool;
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

    fn input_pending(&self) -> bool {
        (**self).input_pending()
    }

    fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
        (**self).next_event()
    }

    fn recovery_diagnostic_word(&self) -> u32 {
        (**self).recovery_diagnostic_word()
    }

    fn context_diagnostic_word(&self) -> u32 {
        (**self).context_diagnostic_word()
    }

    fn driver_diagnostic_word(&self) -> u32 {
        (**self).driver_diagnostic_word()
    }

    fn match_diagnostic_word(&self) -> u32 {
        (**self).match_diagnostic_word()
    }

    fn external_auth_retry_stalled(&self) -> bool {
        (**self).external_auth_retry_stalled()
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

    fn input_pending(&self) -> bool {
        self.supplicant
            .as_ref()
            .is_some_and(NativeSupplicant::input_pending)
    }

    fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
        self.supplicant
            .as_mut()
            .ok_or_else(not_initialized)?
            .next_event()
            .map_err(map_native_error)
    }

    fn recovery_diagnostic_word(&self) -> u32 {
        crate::upstream_supplicant::recovery_diagnostic_word()
    }

    fn context_diagnostic_word(&self) -> u32 {
        self.supplicant
            .as_ref()
            .map_or(0, NativeSupplicant::context_diagnostic_word)
    }

    fn driver_diagnostic_word(&self) -> u32 {
        crate::upstream_supplicant::diagnostic_word()
    }

    fn match_diagnostic_word(&self) -> u32 {
        self.supplicant
            .as_ref()
            .map_or(0, NativeSupplicant::match_diagnostic_word)
    }

    fn external_auth_retry_stalled(&self) -> bool {
        self.supplicant
            .as_ref()
            .is_some_and(NativeSupplicant::external_auth_retry_stalled)
    }
}

pub(crate) fn reconnect_diagnostic_snapshot() -> [u32; 2] {
    [
        DIAG_FIRST_EAPOL_RECONNECTS.load(Ordering::Acquire),
        DIAG_EXTERNAL_AUTH_RECONNECTS.load(Ordering::Acquire),
    ]
}

pub(crate) trait MonotonicClock {
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

impl<P: SupplicantPort, C: MonotonicClock> IncrementalSupplicantBackend<P, C> {
    fn bounded_step_report(
        &mut self,
        id: OperationId,
        budget: WorkBudget,
        started_us: u64,
        consumed_events: u16,
        disposition: PollDisposition,
    ) -> Result<WorkReport, BackendError> {
        let finished_us = self.clock.now_us();
        let elapsed = finished_us.wrapping_sub(started_us);
        if elapsed > u64::from(u32::MAX) {
            return self.clear_with_error(operation_error(ERROR_WORK_BUDGET));
        }
        let disposition = if elapsed >= u64::from(budget.max_time_us().get()) {
            match disposition {
                PollDisposition::Pending(wait) => PollDisposition::BudgetExhausted(wait),
                disposition => disposition,
            }
        } else {
            disposition
        };
        let report = WorkReport::try_new(
            id,
            budget,
            consumed_events,
            elapsed as u32,
            true,
            disposition,
        );
        match report {
            Some(report) => Ok(report),
            None => self.clear_with_error(operation_error(ERROR_WORK_BUDGET)),
        }
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

    fn l2_capabilities(&self) -> Option<hisi_rf_core::WifiL2Capabilities> {
        crate::netif::hardware_address().and_then(hisi_rf_core::WifiL2Capabilities::try_new)
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
        self.active = Some(ActiveOperation::from_request(id, request, now_us));
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

        if self.active_mut(id)?.cancellation_requested {
            let (kind, start_pending, action_submitted) = {
                let active = self.active_mut(id)?;
                (
                    active.kind,
                    !matches!(active.start_phase, StartPhase::Ready),
                    active.cancellation_action_submitted,
                )
            };
            if start_pending {
                self.active = None;
                return self.bounded_step_report(
                    id,
                    budget,
                    started_us,
                    0,
                    PollDisposition::Cancelled,
                );
            }
            if !action_submitted {
                match kind {
                    OperationKind::Scan => self.port.cancel_scan(),
                    OperationKind::Connect(_) => self.port.disconnect()?,
                    OperationKind::Initialize | OperationKind::Disconnect => {}
                }
                self.active_mut(id)?.cancellation_action_submitted = true;
                if matches!(
                    kind,
                    OperationKind::Initialize | OperationKind::Scan | OperationKind::Disconnect
                ) {
                    self.active = None;
                    return self.bounded_step_report(
                        id,
                        budget,
                        started_us,
                        1,
                        PollDisposition::Cancelled,
                    );
                }
                return self.bounded_step_report(
                    id,
                    budget,
                    started_us,
                    1,
                    PollDisposition::Pending(WaitSet::BACKEND.union(WaitSet::TIMER)),
                );
            }
        }

        let start_phase = {
            let active = self.active_mut(id)?;
            core::mem::replace(&mut active.start_phase, StartPhase::Ready)
        };
        let start_wait = match start_phase {
            StartPhase::Ready => None,
            StartPhase::Scan => {
                self.port.start_scan()?;
                Some(WaitSet::BACKEND.union(WaitSet::TIMER))
            }
            StartPhase::ConnectConfigure(config) => {
                self.port.configure(&config)?;
                self.active_mut(id)?.start_phase = StartPhase::ConnectSubmit;
                Some(WaitSet::empty())
            }
            StartPhase::ConnectSubmit => {
                self.port.connect()?;
                Some(WaitSet::BACKEND.union(WaitSet::TIMER))
            }
            StartPhase::Disconnect => {
                self.port.disconnect()?;
                Some(WaitSet::BACKEND.union(WaitSet::TIMER))
            }
        };
        if let Some(wait) = start_wait {
            return self.bounded_step_report(
                id,
                budget,
                started_us,
                1,
                PollDisposition::Pending(wait),
            );
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
            {
                let now_us = self.clock.now_us();
                let active = self.active_mut(id)?;
                let outcome_from_event = active.observe(event.kind, event.status);
                active.observe_reconnect_disconnect(event.kind, now_us);
                outcome = outcome_from_event;
            }
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
                let cancelled = self.active_mut(id)?.cancellation_requested;
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

        if matches!(outcome, OperationOutcome::Continue) {
            let now_us = self.clock.now_us();
            if self.active_mut(id)?.take_reconnect_when_settled(now_us) {
                if let Err(error) = self.port.connect() {
                    return self.clear_with_error(error);
                }
                made_progress = true;
            }

            let recovery = self.port.recovery_diagnostic_word();
            let external_auth_stalled = self.port.external_auth_retry_stalled();
            let now_us = self.clock.now_us();
            let (submit_first_eapol, submit_external_auth) = {
                let active = self.active_mut(id)?;
                (
                    active.should_submit_first_eapol_reconnect(recovery, now_us),
                    active.should_submit_external_auth_reconnect(external_auth_stalled, now_us),
                )
            };
            if submit_first_eapol || submit_external_auth {
                if let Err(error) = self.port.disconnect() {
                    return self.clear_with_error(error);
                }
                self.active_mut(id)?.request_reconnect_after_disconnect();
                if submit_first_eapol {
                    DIAG_FIRST_EAPOL_RECONNECTS.fetch_add(1, Ordering::Relaxed);
                }
                if submit_external_auth {
                    DIAG_EXTERNAL_AUTH_RECONNECTS.fetch_add(1, Ordering::Relaxed);
                }
                made_progress = true;
            }
        }

        let mut finished_us = self.clock.now_us();
        // Linearize scan completion against its timeout as late as possible.
        // The vendor callback can publish `done` after the first `poll_scan`
        // snapshot but before this deadline check. A final snapshot makes a
        // completion published before this point win; a later callback belongs
        // after the operation's timeout boundary.
        if is_scan
            && matches!(outcome, OperationOutcome::Continue)
            && finished_us >= self.active_mut(id)?.deadline_us
            && self.active_mut(id)?.scan_total.is_none()
        {
            let total = match self.port.poll_scan() {
                Ok(total) => total,
                Err(error) => return self.clear_with_error(error),
            };
            if let Some(total) = total {
                self.active_mut(id)?.scan_total = Some(total);
                made_progress = true;
                finished_us = self.clock.now_us();
                if total == 0 && !self.port.scan_cache_pending() {
                    outcome =
                        OperationOutcome::Complete(IncrementalCompletion::Scan(ScanOutcome {
                            count: 0,
                            truncated: false,
                        }));
                }
            }
        }
        let elapsed = finished_us.wrapping_sub(started_us);
        if elapsed > u64::from(u32::MAX) {
            return self.clear_with_error(operation_error(ERROR_WORK_BUDGET));
        }

        let (scan_completion_observed, scan_work_pending) = if is_scan {
            let cache_pending = self.port.scan_cache_pending();
            let active = self.active_mut(id)?;
            (
                active.scan_total.is_some(),
                cache_pending
                    || active
                        .scan_total
                        .is_some_and(|total| active.scan_seen < total),
            )
        } else {
            (false, false)
        };
        let timeout = {
            let active = self.active_mut(id)?;
            active.backend_deadline_us = (result.next_deadline_ms != u64::MAX)
                .then(|| result.next_deadline_ms.saturating_mul(1_000));
            if finished_us >= active.deadline_us
                && matches!(outcome, OperationOutcome::Continue)
                // Scan completion is the operation's timeout linearization
                // point. Once observed, the bounded native-cache drain and
                // result copy are already-owned work and must not be turned
                // into a timeout merely because one runner turn made no
                // progress.
                && !(is_scan && scan_completion_observed && scan_work_pending)
            {
                Some(timeout_error(active))
            } else {
                None
            }
        };
        if let Some(error) = timeout {
            let error = error
                .with_trace(
                    DiagnosticTraceKind::SupplicantContext,
                    self.port.context_diagnostic_word(),
                )
                .with_trace(
                    DiagnosticTraceKind::DriverContext,
                    self.port.driver_diagnostic_word(),
                )
                .with_trace(
                    DiagnosticTraceKind::BackendStatus,
                    self.port.match_diagnostic_word(),
                );
            return self.clear_with_error(error);
        }

        // A full output grant means the native output ring may still hold
        // work even though no new callback edge will arrive. Supplicant input
        // and scan work already owned by this backend are level-ready for the
        // same reason. In particular, a worker-response wake must not consume
        // the only edge for an EAPOL frame that arrived during that worker turn.
        let output_work_pending =
            result.output_pending != 0 && consumed == budget.max_events().get();
        let input_work_pending = self.port.input_pending();
        let wait =
            if made_progress && (scan_work_pending || input_work_pending || output_work_pending) {
                WaitSet::empty()
            } else {
                WaitSet::BACKEND.union(WaitSet::TIMER)
            };
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
            OperationOutcome::Continue
                if consumed == budget.max_events().get()
                    || elapsed >= u64::from(budget.max_time_us().get()) =>
            {
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
        BackendErrorClass::OperationTimeout,
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

#[cfg(feature = "firmware-example")]
struct OperationFixturePort {
    scan_pending: bool,
    disconnect_event_pending: bool,
}

#[cfg(feature = "firmware-example")]
impl OperationFixturePort {
    const fn new() -> Self {
        Self {
            scan_pending: false,
            disconnect_event_pending: false,
        }
    }
}

#[cfg(feature = "firmware-example")]
impl SupplicantPort for OperationFixturePort {
    fn start_scan(&mut self) -> Result<(), BackendError> {
        self.scan_pending = true;
        Ok(())
    }

    fn poll_scan(&mut self) -> Result<Option<usize>, BackendError> {
        Ok(None)
    }

    fn scan_result(&self, _: usize) -> Option<ScanResult> {
        None
    }

    fn scan_cache_pending(&self) -> bool {
        self.scan_pending
    }

    fn cancel_scan(&mut self) {
        self.scan_pending = false;
    }

    fn configure(&mut self, _: &StationConfig) -> Result<(), BackendError> {
        Ok(())
    }

    fn connect(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), BackendError> {
        self.disconnect_event_pending = true;
        Ok(())
    }

    fn poll(&mut self, _: NonZeroU32) -> Result<PollResult, BackendError> {
        Ok(PollResult {
            status: 0,
            work_completed: 0,
            output_pending: u32::from(self.disconnect_event_pending),
            reserved: 0,
            next_deadline_ms: u64::MAX,
        })
    }

    fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
        if !self.disconnect_event_pending {
            return Ok(None);
        }
        self.disconnect_event_pending = false;
        Ok(Some(Event {
            abi_version: ws63_radio_sys::supplicant::ABI_VERSION,
            kind: super::NATIVE_EVENT_DISCONNECTED,
            data_len: 0,
            status: 0,
            timestamp_ms: 0,
            data: [0; ws63_radio_sys::supplicant::EVENT_DATA_LEN],
        }))
    }

    fn recovery_diagnostic_word(&self) -> u32 {
        0
    }

    fn external_auth_retry_stalled(&self) -> bool {
        false
    }
}

#[cfg(feature = "firmware-example")]
struct OperationFixtureClock<'a>(&'a Cell<u64>);

#[cfg(feature = "firmware-example")]
impl MonotonicClock for OperationFixtureClock<'_> {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
}

#[cfg(feature = "firmware-example")]
fn poll_fixture<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[cfg(feature = "firmware-example")]
fn fixture_station_config(timeout_ms: u32) -> Option<StationConfig> {
    let scan = ScanResult {
        ssid: Ssid::try_from_bytes(b"source-path-fixture")?,
        bssid: [0x02, 0, 0, 0, 0, 1],
        frequency_mhz: 2_412,
        rssi_dbm: -40,
        security: Security::Wpa2Personal,
        channel: 1,
    };
    StationConfig::wpa2_personal(
        &scan,
        Passphrase::try_from_ascii(b"fixture-only")?,
        hisi_rf_core::OperationTimeout::try_from_millis(timeout_ms)?,
    )
}

/// Exercise cancellation and timeout through the public controller, facade
/// command/completion channels, incremental runner, and WS63 backend state
/// machine without touching radio hardware.
#[cfg(feature = "firmware-example")]
pub(crate) fn operation_error_injection_fixture() -> Option<(Diagnostic, Diagnostic)> {
    static CANCELLATION_STATE: RadioState<4> = RadioState::new();
    static TIMEOUT_STATE: RadioState<4> = RadioState::new();

    let budget = WorkBudget::try_new(4, 100)?;

    let cancellation_clock = Cell::new(0);
    let cancellation_backend = IncrementalSupplicantBackend::new(
        OperationFixturePort::new(),
        OperationFixtureClock(&cancellation_clock),
    );
    let cancellation_radio = init(
        RadioConfig::default(),
        RadioResources {
            backend: cancellation_backend,
            device: (),
        },
        &CANCELLATION_STATE,
    )
    .ok()?;
    let hisi_rf_core::IncrementalRadioParts {
        mut wifi,
        mut runner,
    } = cancellation_radio.split_incremental(budget);
    {
        let mut connect = core::pin::pin!(wifi.controller.connect(fixture_station_config(1_000)?));
        if !poll_fixture(connect.as_mut()).is_pending() {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::empty()).ok()?,
            IncrementalDriverEvent::Started { .. }
        ) {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::empty()).ok()?,
            IncrementalDriverEvent::Pending { .. }
        ) {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::empty()).ok()?,
            IncrementalDriverEvent::Pending { .. }
        ) {
            return None;
        }
    }

    {
        let mut disconnect = core::pin::pin!(wifi.controller.disconnect());
        if !poll_fixture(disconnect.as_mut()).is_pending() {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::empty()).ok()?,
            IncrementalDriverEvent::CancelRequested { .. }
        ) {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::empty()).ok()?,
            IncrementalDriverEvent::Pending { .. }
        ) {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::BACKEND).ok()?,
            IncrementalDriverEvent::Cancelled { .. }
        ) {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::empty()).ok()?,
            IncrementalDriverEvent::Started { .. }
        ) {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::empty()).ok()?,
            IncrementalDriverEvent::Pending { .. }
        ) {
            return None;
        }
        if !matches!(
            runner.run_once(WaitSet::BACKEND).ok()?,
            IncrementalDriverEvent::Completed {
                completion: IncrementalCompletion::Disconnected,
                ..
            }
        ) {
            return None;
        }
        if !matches!(poll_fixture(disconnect.as_mut()), Poll::Ready(Ok(()))) {
            return None;
        }
    }

    let cancellation = loop {
        let mut event = core::pin::pin!(wifi.controller.next_event());
        match poll_fixture(event.as_mut()) {
            Poll::Ready(WifiEvent::Failed(error))
                if error.class() == BackendErrorClass::Cancelled =>
            {
                break error.diagnostic();
            }
            Poll::Ready(_) => {}
            Poll::Pending => return None,
        }
    };

    let timeout_clock = Cell::new(0);
    let timeout_backend = IncrementalSupplicantBackend::new(
        OperationFixturePort::new(),
        OperationFixtureClock(&timeout_clock),
    );
    let timeout_radio = init(
        RadioConfig::default(),
        RadioResources {
            backend: timeout_backend,
            device: (),
        },
        &TIMEOUT_STATE,
    )
    .ok()?;
    let hisi_rf_core::IncrementalRadioParts {
        mut wifi,
        mut runner,
    } = timeout_radio.split_incremental(budget);
    let mut connect = core::pin::pin!(wifi.controller.connect(fixture_station_config(1)?));
    if !poll_fixture(connect.as_mut()).is_pending() {
        return None;
    }
    if !matches!(
        runner.run_once(WaitSet::empty()).ok()?,
        IncrementalDriverEvent::Started { .. }
    ) {
        return None;
    }
    if !matches!(
        runner.run_once(WaitSet::empty()).ok()?,
        IncrementalDriverEvent::Pending { .. }
    ) {
        return None;
    }
    if !matches!(
        runner.run_once(WaitSet::empty()).ok()?,
        IncrementalDriverEvent::Pending { .. }
    ) {
        return None;
    }
    timeout_clock.set(1_000);
    if !matches!(
        runner.run_once(WaitSet::TIMER).ok()?,
        IncrementalDriverEvent::Failed {
            cancellation_pending: false,
            ..
        }
    ) {
        return None;
    }
    let timeout = match poll_fixture(connect.as_mut()) {
        Poll::Ready(Err(Error::Backend(error)))
            if error.class() == BackendErrorClass::OperationTimeout =>
        {
            error.diagnostic()
        }
        _ => return None,
    };

    Some((cancellation, timeout))
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;
    use hisi_rf_core::{
        CommandSequence, IncrementalBackendDriver, IncrementalDriverEvent, OperationTracker,
        Passphrase, SaePwe, WifiConfig,
    };
    use ws63_radio_sys::supplicant::{ABI_VERSION, EVENT_DATA_LEN};

    struct FakePort<'a> {
        result: PollResult,
        events: [Option<Event>; 2],
        next_event: usize,
        disconnect_calls: u8,
        scan_results: [Option<ScanResult>; 3],
        scan_total: Option<usize>,
        scan_poll_calls: u8,
        scan_complete_on_poll: u8,
        scan_cache_pending: bool,
        scan_start_calls: u8,
        scan_cancel_calls: u8,
        connect_calls: u8,
        input_pending: bool,
        recovery_diagnostic_word: u32,
        external_auth_retry_stalled: bool,
        connect_clock: Option<&'a Cell<u64>>,
        connect_elapsed_us: u64,
        poll_clock: Option<&'a Cell<u64>>,
        poll_elapsed_us: u64,
    }

    impl FakePort<'_> {
        fn new(result: PollResult, events: [Option<Event>; 2]) -> Self {
            Self {
                result,
                events,
                next_event: 0,
                disconnect_calls: 0,
                scan_results: [None; 3],
                scan_total: None,
                scan_poll_calls: 0,
                scan_complete_on_poll: 0,
                scan_cache_pending: false,
                scan_start_calls: 0,
                scan_cancel_calls: 0,
                connect_calls: 0,
                input_pending: false,
                recovery_diagnostic_word: 0,
                external_auth_retry_stalled: false,
                connect_clock: None,
                connect_elapsed_us: 0,
                poll_clock: None,
                poll_elapsed_us: 0,
            }
        }
    }

    impl SupplicantPort for FakePort<'_> {
        fn start_scan(&mut self) -> Result<(), BackendError> {
            self.scan_start_calls += 1;
            Ok(())
        }

        fn poll_scan(&mut self) -> Result<Option<usize>, BackendError> {
            self.scan_poll_calls += 1;
            if self.scan_complete_on_poll != 0 && self.scan_poll_calls < self.scan_complete_on_poll
            {
                return Ok(None);
            }
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
            self.connect_calls += 1;
            if let Some(clock) = self.connect_clock {
                clock.set(clock.get().saturating_add(self.connect_elapsed_us));
            }
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), BackendError> {
            self.disconnect_calls += 1;
            Ok(())
        }

        fn poll(&mut self, _: NonZeroU32) -> Result<PollResult, BackendError> {
            if let Some(clock) = self.poll_clock {
                clock.set(clock.get().saturating_add(self.poll_elapsed_us));
            }
            Ok(self.result)
        }

        fn input_pending(&self) -> bool {
            self.input_pending
        }

        fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
            let event = self.events.get(self.next_event).copied().flatten();
            self.next_event += 1;
            Ok(event)
        }

        fn recovery_diagnostic_word(&self) -> u32 {
            self.recovery_diagnostic_word
        }

        fn external_auth_retry_stalled(&self) -> bool {
            self.external_auth_retry_stalled
        }
    }

    struct ResourceFixture {
        key_installed: Cell<bool>,
        disconnect_calls: Cell<u8>,
        next_event: Cell<u8>,
    }

    impl ResourceFixture {
        const fn new() -> Self {
            Self {
                key_installed: Cell::new(false),
                disconnect_calls: Cell::new(0),
                next_event: Cell::new(0),
            }
        }
    }

    struct ResourcePort<'a>(&'a ResourceFixture);

    impl SupplicantPort for ResourcePort<'_> {
        fn start_scan(&mut self) -> Result<(), BackendError> {
            Ok(())
        }

        fn poll_scan(&mut self) -> Result<Option<usize>, BackendError> {
            Ok(Some(0))
        }

        fn scan_result(&self, _: usize) -> Option<ScanResult> {
            None
        }

        fn scan_cache_pending(&self) -> bool {
            false
        }

        fn cancel_scan(&mut self) {}

        fn configure(&mut self, _: &StationConfig) -> Result<(), BackendError> {
            Ok(())
        }

        fn connect(&mut self) -> Result<(), BackendError> {
            self.0.key_installed.set(true);
            Ok(())
        }

        fn disconnect(&mut self) -> Result<(), BackendError> {
            self.0
                .disconnect_calls
                .set(self.0.disconnect_calls.get() + 1);
            self.0.key_installed.set(false);
            Ok(())
        }

        fn poll(&mut self, _: NonZeroU32) -> Result<PollResult, BackendError> {
            Ok(poll_result(0, true))
        }

        fn next_event(&mut self) -> Result<Option<Event>, BackendError> {
            let index = self.0.next_event.get();
            self.0.next_event.set(index + 1);
            Ok(match index {
                0 => Some(event(super::super::NATIVE_EVENT_AUTHORIZED, 0)),
                1 => Some(event(super::super::NATIVE_EVENT_DISCONNECTED, 0)),
                _ => None,
            })
        }

        fn recovery_diagnostic_word(&self) -> u32 {
            0
        }

        fn external_auth_retry_stalled(&self) -> bool {
            false
        }
    }

    struct FakeClock(u64);

    impl MonotonicClock for FakeClock {
        fn now_us(&self) -> u64 {
            self.0
        }
    }

    struct SharedClock<'a>(&'a Cell<u64>);

    impl MonotonicClock for SharedClock<'_> {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
    }

    fn operation_id() -> OperationId {
        OperationTracker::new().queue(0).unwrap()
    }

    fn advance_start<P: SupplicantPort, C: MonotonicClock>(
        backend: &mut IncrementalSupplicantBackend<P, C>,
        id: OperationId,
        budget: WorkBudget,
    ) {
        while backend
            .active
            .as_ref()
            .is_some_and(|active| !matches!(active.start_phase, StartPhase::Ready))
        {
            backend
                .poll(id, WakeReason::Command, budget, &mut [])
                .unwrap();
        }
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

    fn transition_station_config(timeout_ms: u32) -> StationConfig {
        let result = ScanResult {
            ssid: Ssid::try_from_bytes(b"transition-ap").unwrap(),
            bssid: [1, 2, 3, 4, 5, 6],
            frequency_mhz: 2_412,
            rssi_dbm: -40,
            security: Security::Wpa2Wpa3PersonalTransition,
            channel: 1,
        };
        StationConfig::wpa3_personal(
            &result,
            Passphrase::try_from_ascii(b"testtest").unwrap(),
            SaePwe::Both,
            hisi_rf_core::OperationTimeout::try_from_millis(timeout_ms).unwrap(),
        )
        .unwrap()
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
    fn connect_time_overrun_preserves_operation_until_authorized() {
        let id = operation_id();
        let now_us = Cell::new(0);
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.connect_clock = Some(&now_us);
        port.connect_elapsed_us = 179_000;
        let mut backend = IncrementalSupplicantBackend::new(&mut port, SharedClock(&now_us));
        backend
            .start(
                id,
                IncrementalRequest::Connect(transition_station_config(10_000)),
            )
            .unwrap();
        let budget = WorkBudget::try_new(2, 100_000).unwrap();

        let configured = backend
            .poll(id, WakeReason::Command, budget, &mut [])
            .unwrap();
        assert!(matches!(
            configured.disposition(),
            PollDisposition::Pending(wait) if wait.is_empty()
        ));

        let submitted = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(submitted.elapsed_us(), 179_000);
        assert!(submitted.time_budget_exhausted());
        assert!(matches!(
            submitted.disposition(),
            PollDisposition::BudgetExhausted(wait)
                if wait == WaitSet::BACKEND.union(WaitSet::TIMER)
        ));
        assert!(backend.active.is_some());
        assert_eq!(backend.port.connect_calls, 1);

        backend.port.result = poll_result(0, true);
        backend.port.events[0] = Some(event(super::super::NATIVE_EVENT_AUTHORIZED, 0));
        let authorized = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(
            authorized.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Connected(ConnectionInfo {
                bssid: [1, 2, 3, 4, 5, 6],
                frequency_mhz: 2_412,
            }))
        );
        assert!(backend.active.is_none());
    }

    #[test]
    fn supplicant_poll_time_overrun_preserves_operation_until_authorized() {
        let id = operation_id();
        let now_us = Cell::new(0);
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.poll_clock = Some(&now_us);
        let mut backend = IncrementalSupplicantBackend::new(&mut port, SharedClock(&now_us));
        backend
            .start(
                id,
                IncrementalRequest::Connect(transition_station_config(10_000)),
            )
            .unwrap();
        let budget = WorkBudget::try_new(2, 100_000).unwrap();
        advance_start(&mut backend, id, budget);

        backend.port.poll_elapsed_us = 179_000;
        let overrun = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(overrun.elapsed_us(), 179_000);
        assert!(overrun.time_budget_exhausted());
        assert!(matches!(
            overrun.disposition(),
            PollDisposition::BudgetExhausted(wait)
                if wait == WaitSet::BACKEND.union(WaitSet::TIMER)
        ));
        assert!(backend.active.is_some());

        backend.port.poll_elapsed_us = 0;
        backend.port.result = poll_result(0, true);
        backend.port.events[0] = Some(event(super::super::NATIVE_EVENT_AUTHORIZED, 0));
        let authorized = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert!(matches!(
            authorized.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Connected(_))
        ));
        assert!(backend.active.is_none());
    }

    #[test]
    fn first_eapol_reconnect_waits_for_the_recovery_deadline_and_runs_once() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        // timeout=1, disconnect event=1, completed cached-association retry=1.
        port.recovery_diagnostic_word = 0x0001_0011;
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(
                id,
                IncrementalRequest::Connect(transition_station_config(10_000)),
            )
            .unwrap();

        let budget = WorkBudget::try_new(1, 100).unwrap();
        advance_start(&mut backend, id, budget);
        let first = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert!(matches!(first.disposition(), PollDisposition::Pending(_)));
        assert_eq!(backend.next_deadline_us(id), Some(1_000_000));
        assert_eq!(backend.port.connect_calls, 1);

        backend.clock.0 = 999_999;
        backend
            .poll(id, WakeReason::Timer, budget, &mut [])
            .unwrap();
        assert_eq!(backend.port.connect_calls, 1);

        backend.clock.0 = 1_000_000;
        let reconnect = backend
            .poll(id, WakeReason::Timer, budget, &mut [])
            .unwrap();
        assert!(reconnect.made_progress());
        assert_eq!(backend.port.disconnect_calls, 1);
        assert_eq!(backend.port.connect_calls, 1);

        backend.port.result = poll_result(0, true);
        backend.port.events[0] = Some(event(super::super::NATIVE_EVENT_DISCONNECTED, 0));
        backend.clock.0 = 1_000_001;
        backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(backend.next_deadline_us(id), Some(1_005_001));
        assert_eq!(backend.port.connect_calls, 1);

        backend.port.result = poll_result(0, false);
        backend.clock.0 = 1_005_001;
        backend
            .poll(id, WakeReason::Timer, budget, &mut [])
            .unwrap();
        assert_eq!(backend.port.connect_calls, 2);

        backend.clock.0 = 2_000_000;
        backend
            .poll(id, WakeReason::Timer, budget, &mut [])
            .unwrap();
        assert_eq!(backend.port.disconnect_calls, 1);
        assert_eq!(backend.port.connect_calls, 2);
    }

    #[test]
    fn first_eapol_reconnect_does_not_run_without_completed_recovery_evidence() {
        for recovery in [0, 0x0000_0011, 0x0101_0011] {
            let id = operation_id();
            let mut port = FakePort::new(poll_result(0, false), [None, None]);
            port.recovery_diagnostic_word = recovery;
            let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(2_000_000));
            backend
                .start(
                    id,
                    IncrementalRequest::Connect(transition_station_config(10_000)),
                )
                .unwrap();
            let budget = WorkBudget::try_new(1, 100).unwrap();
            advance_start(&mut backend, id, budget);
            backend
                .poll(id, WakeReason::Timer, budget, &mut [])
                .unwrap();
            assert_eq!(backend.port.connect_calls, 1);
            assert_eq!(backend.port.disconnect_calls, 0);
        }
    }

    #[test]
    fn external_auth_reconnect_requires_a_persistent_post_retry_stall() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.external_auth_retry_stalled = true;
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(
                id,
                IncrementalRequest::Connect(transition_station_config(10_000)),
            )
            .unwrap();
        let budget = WorkBudget::try_new(1, 100).unwrap();
        advance_start(&mut backend, id, budget);

        backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(backend.next_deadline_us(id), Some(1_000_000));
        assert_eq!(backend.port.connect_calls, 1);

        backend.port.external_auth_retry_stalled = false;
        backend.clock.0 = 500_000;
        backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(backend.next_deadline_us(id), Some(10_000_000));

        backend.port.external_auth_retry_stalled = true;
        backend.clock.0 = 1_000_000;
        backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(backend.port.connect_calls, 1);

        backend.clock.0 = 2_000_000;
        backend
            .poll(id, WakeReason::Timer, budget, &mut [])
            .unwrap();
        assert_eq!(backend.port.disconnect_calls, 1);
        assert_eq!(backend.port.connect_calls, 1);

        backend.port.result = poll_result(0, true);
        backend.port.events[0] = Some(event(super::super::NATIVE_EVENT_DISCONNECTED, 0));
        backend.clock.0 = 2_000_001;
        backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(backend.next_deadline_us(id), Some(2_005_001));
        assert_eq!(backend.port.connect_calls, 1);

        backend.port.result = poll_result(0, false);
        backend.clock.0 = 2_005_001;
        backend
            .poll(id, WakeReason::Timer, budget, &mut [])
            .unwrap();
        assert_eq!(backend.port.connect_calls, 2);

        backend.clock.0 = 3_000_000;
        backend
            .poll(id, WakeReason::Timer, budget, &mut [])
            .unwrap();
        assert_eq!(backend.port.disconnect_calls, 1);
        assert_eq!(backend.port.connect_calls, 2);
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
    fn cancellation_conserves_operation_queue_timer_and_key_resources() {
        let resources = ResourceFixture::new();
        let backend = IncrementalSupplicantBackend::new(ResourcePort(&resources), FakeClock(1_000));
        let mut driver =
            IncrementalBackendDriver::new(backend, WorkBudget::try_new(1, 100).unwrap());
        let first_sequence = CommandSequence::try_from_raw(1).unwrap();
        let replacement_sequence = CommandSequence::try_from_raw(2).unwrap();
        let mut output = [ScanResult::empty(); 1];

        driver
            .submit(
                first_sequence,
                IncrementalRequest::Connect(transition_station_config(1_000)),
            )
            .unwrap();
        let IncrementalDriverEvent::Started {
            operation: first, ..
        } = driver.drive_once(WaitSet::empty(), &mut output).unwrap()
        else {
            panic!("connect did not start");
        };
        assert!(matches!(
            driver.drive_once(WaitSet::empty(), &mut output).unwrap(),
            IncrementalDriverEvent::Pending {
                operation,
                ..
            } if operation == first
        ));
        assert!(matches!(
            driver.drive_once(WaitSet::empty(), &mut output).unwrap(),
            IncrementalDriverEvent::Pending {
                operation,
                wait_for,
                ..
            } if operation == first
                && wait_for.contains(WaitSet::BACKEND)
                && wait_for.contains(WaitSet::TIMER)
        ));
        assert!(resources.key_installed.get());
        assert!(driver.next_deadline_us().is_some());

        driver
            .submit(
                replacement_sequence,
                IncrementalRequest::Initialize(WifiConfig::default()),
            )
            .unwrap();
        assert!(!driver.can_submit());
        assert_eq!(
            driver.drive_once(WaitSet::empty(), &mut output).unwrap(),
            IncrementalDriverEvent::CancelRequested {
                sequence: first_sequence,
                operation: first,
            }
        );
        assert!(resources.key_installed.get());
        assert_eq!(resources.disconnect_calls.get(), 0);

        assert!(matches!(
            driver.drive_once(WaitSet::empty(), &mut output).unwrap(),
            IncrementalDriverEvent::Pending {
                operation,
                wait_for,
                ..
            } if operation == first
                && wait_for.contains(WaitSet::BACKEND)
                && wait_for.contains(WaitSet::TIMER)
        ));
        assert!(!resources.key_installed.get());
        assert_eq!(resources.disconnect_calls.get(), 1);

        assert!(matches!(
            driver.drive_once(WaitSet::BACKEND, &mut output).unwrap(),
            IncrementalDriverEvent::BudgetExhausted {
                sequence,
                operation,
                ..
            } if sequence == first_sequence && operation == first
        ));
        assert_eq!(resources.disconnect_calls.get(), 1);

        assert_eq!(
            driver.drive_once(WaitSet::BACKEND, &mut output).unwrap(),
            IncrementalDriverEvent::Cancelled {
                sequence: first_sequence,
                suppressed_completion: false,
            }
        );
        assert!(driver.next_deadline_us().is_none());

        let IncrementalDriverEvent::Started {
            sequence,
            operation: replacement,
        } = driver.drive_once(WaitSet::empty(), &mut output).unwrap()
        else {
            panic!("replacement did not start");
        };
        assert_eq!(sequence, replacement_sequence);
        assert_ne!(replacement.generation(), first.generation());
        assert!(driver.can_submit());
        assert!(!resources.key_installed.get());
        assert_eq!(resources.disconnect_calls.get(), 1);
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
        let budget = WorkBudget::try_new(4, 100).unwrap();
        advance_start(&mut backend, id, budget);
        let report = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
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
        let budget = WorkBudget::try_new(2, 100).unwrap();
        advance_start(&mut backend, id, budget);
        let report = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();
        assert_eq!(report.consumed_events(), 2);
        assert!(matches!(
            report.disposition(),
            PollDisposition::BudgetExhausted(wait) if wait.is_empty()
        ));
        drop(backend);
        assert_eq!(port.next_event, 0);
    }

    #[test]
    fn level_ready_input_survives_the_worker_response_wake() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(1, false), [None, None]);
        port.input_pending = true;
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(id, IncrementalRequest::Disconnect(WifiConfig::default()))
            .unwrap();
        let budget = WorkBudget::try_new(4, 100).unwrap();
        advance_start(&mut backend, id, budget);

        let report = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap();

        assert_eq!(report.consumed_events(), 1);
        assert!(matches!(
            report.disposition(),
            PollDisposition::Pending(wait) if wait.is_empty()
        ));
    }

    #[test]
    fn backend_overreport_is_rejected_and_clears_the_operation() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(3, false), [None, None]);
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(id, IncrementalRequest::Disconnect(WifiConfig::default()))
            .unwrap();
        let budget = WorkBudget::try_new(2, 100).unwrap();
        advance_start(&mut backend, id, budget);
        let error = backend
            .poll(id, WakeReason::Backend, budget, &mut [])
            .unwrap_err();
        assert_eq!(error.code(), ERROR_WORK_BUDGET);
        assert!(backend.next_deadline_us(id).is_none());
    }

    #[test]
    fn cancelling_before_disconnect_start_submits_no_driver_request() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(id, IncrementalRequest::Disconnect(WifiConfig::default()))
            .unwrap();
        backend.cancel(id).unwrap();
        let report = backend
            .poll(
                id,
                WakeReason::Command,
                WorkBudget::try_new(1, 100).unwrap(),
                &mut [],
            )
            .unwrap();
        assert_eq!(report.disposition(), PollDisposition::Cancelled);
        drop(backend);
        assert_eq!(port.disconnect_calls, 0);
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
                IncrementalRequest::Scan(ScanConfig::new(
                    hisi_rf_core::OperationTimeout::try_from_millis(1_000).unwrap(),
                )),
            )
            .unwrap();
        let mut output = [ScanResult::empty(); 1];
        let budget = WorkBudget::try_new(2, 100).unwrap();
        advance_start(&mut backend, id, budget);
        let first = backend
            .poll(id, WakeReason::Backend, budget, &mut output)
            .unwrap();
        assert_eq!(first.consumed_events(), 2);
        assert!(matches!(
            first.disposition(),
            PollDisposition::BudgetExhausted(wait) if wait.is_empty()
        ));

        let second = backend
            .poll(id, WakeReason::Backend, budget, &mut output)
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
                IncrementalRequest::Scan(ScanConfig::new(
                    hisi_rf_core::OperationTimeout::try_from_millis(1_000).unwrap(),
                )),
            )
            .unwrap();
        let budget = WorkBudget::try_new(2, 100).unwrap();
        advance_start(&mut backend, id, budget);
        backend.cancel(id).unwrap();

        let mut output = [ScanResult::empty(); 1];
        let cancelled = backend
            .poll(id, WakeReason::Backend, budget, &mut output)
            .unwrap();
        assert_eq!(cancelled.disposition(), PollDisposition::Cancelled);
        assert_eq!(output[0], ScanResult::empty());
        drop(backend);
        assert_eq!(port.scan_cancel_calls, 1);
    }

    #[test]
    fn scan_timeout_cancels_the_native_scan_and_clears_the_expired_deadline() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.scan_cache_pending = true;
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(2_000));
        backend
            .start(
                id,
                IncrementalRequest::Scan(ScanConfig::new(
                    hisi_rf_core::OperationTimeout::try_from_millis(1).unwrap(),
                )),
            )
            .unwrap();
        let budget = WorkBudget::try_new(2, 100).unwrap();
        advance_start(&mut backend, id, budget);
        backend.clock.0 = 3_000;

        let error = backend
            .poll(id, WakeReason::Timer, budget, &mut [])
            .unwrap_err();
        assert_eq!(error.code(), ERROR_OPERATION_TIMEOUT);
        assert!(backend.next_deadline_us(id).is_none());
        drop(backend);
        assert_eq!(port.scan_cancel_calls, 1);
        assert!(!port.scan_cache_pending);
    }

    #[test]
    fn scan_completion_ready_at_the_deadline_wins_over_timeout() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.scan_total = Some(1);
        port.scan_results = [Some(scan_result(b"ready", 1)), None, None];
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(
                id,
                IncrementalRequest::Scan(ScanConfig::new(
                    hisi_rf_core::OperationTimeout::try_from_millis(1).unwrap(),
                )),
            )
            .unwrap();
        let budget = WorkBudget::try_new(2, 100).unwrap();
        advance_start(&mut backend, id, budget);
        backend.clock.0 = 1_000;
        let mut output = [ScanResult::empty(); 1];

        let report = backend
            .poll(id, WakeReason::Backend, budget, &mut output)
            .unwrap();

        assert_eq!(
            report.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Scan(ScanOutcome {
                count: 1,
                truncated: false,
            }))
        );
        assert_eq!(output[0].ssid.as_bytes(), b"ready");
    }

    #[test]
    fn scan_completion_published_during_deadline_check_is_retained() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.scan_total = Some(1);
        port.scan_complete_on_poll = 2;
        port.scan_results = [Some(scan_result(b"late-ready", 1)), None, None];
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(
                id,
                IncrementalRequest::Scan(ScanConfig::new(
                    hisi_rf_core::OperationTimeout::try_from_millis(1).unwrap(),
                )),
            )
            .unwrap();
        let budget = WorkBudget::try_new(2, 100).unwrap();
        advance_start(&mut backend, id, budget);
        backend.clock.0 = 1_000;
        let mut output = [ScanResult::empty(); 1];

        let retained = backend
            .poll(id, WakeReason::Timer, budget, &mut output)
            .unwrap();
        assert!(matches!(
            retained.disposition(),
            PollDisposition::Pending(wait) if wait.is_empty()
        ));
        assert_eq!(backend.port.scan_poll_calls, 2);

        let completed = backend
            .poll(id, WakeReason::Backend, budget, &mut output)
            .unwrap();
        assert_eq!(
            completed.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Scan(ScanOutcome {
                count: 1,
                truncated: false,
            }))
        );
        assert_eq!(output[0].ssid.as_bytes(), b"late-ready");
    }

    #[test]
    fn scan_owned_results_are_drained_after_the_hardware_deadline() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.scan_total = Some(3);
        port.scan_results = [
            Some(scan_result(b"first", 1)),
            Some(scan_result(b"second", 2)),
            Some(scan_result(b"third", 3)),
        ];
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(
                id,
                IncrementalRequest::Scan(ScanConfig::new(
                    hisi_rf_core::OperationTimeout::try_from_millis(1).unwrap(),
                )),
            )
            .unwrap();
        let budget = WorkBudget::try_new(1, 100).unwrap();
        advance_start(&mut backend, id, budget);
        backend.clock.0 = 1_000;
        let mut output = [ScanResult::empty(); 3];

        for now_us in [1_000, 1_001] {
            backend.clock.0 = now_us;
            let report = backend
                .poll(id, WakeReason::Backend, budget, &mut output)
                .unwrap();
            assert!(matches!(
                report.disposition(),
                PollDisposition::BudgetExhausted(_)
            ));
        }
        backend.clock.0 = 1_002;
        let report = backend
            .poll(id, WakeReason::Backend, budget, &mut output)
            .unwrap();

        assert_eq!(
            report.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Scan(ScanOutcome {
                count: 3,
                truncated: false,
            }))
        );
        assert_eq!(output[2].ssid.as_bytes(), b"third");
    }

    #[test]
    fn observed_scan_completion_survives_a_no_progress_cache_drain_turn() {
        let id = operation_id();
        let mut port = FakePort::new(poll_result(0, false), [None, None]);
        port.scan_total = Some(1);
        port.scan_results = [Some(scan_result(b"retained", 1)), None, None];
        port.scan_cache_pending = true;
        let mut backend = IncrementalSupplicantBackend::new(&mut port, FakeClock(0));
        backend
            .start(
                id,
                IncrementalRequest::Scan(ScanConfig::new(
                    hisi_rf_core::OperationTimeout::try_from_millis(1).unwrap(),
                )),
            )
            .unwrap();
        let budget = WorkBudget::try_new(1, 100).unwrap();
        advance_start(&mut backend, id, budget);
        backend.clock.0 = 1_000;
        let mut output = [ScanResult::empty(); 1];

        let draining = backend
            .poll(id, WakeReason::Timer, budget, &mut output)
            .unwrap();
        assert!(matches!(
            draining.disposition(),
            PollDisposition::Pending(wait) if wait == WaitSet::BACKEND.union(WaitSet::TIMER)
        ));
        assert_eq!(output[0], ScanResult::empty());

        backend.port.scan_cache_pending = false;
        backend.clock.0 = 1_001;
        let completed = backend
            .poll(id, WakeReason::Backend, budget, &mut output)
            .unwrap();
        assert_eq!(
            completed.disposition(),
            PollDisposition::Complete(IncrementalCompletion::Scan(ScanOutcome {
                count: 1,
                truncated: false,
            }))
        );
        assert_eq!(output[0].ssid.as_bytes(), b"retained");
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

    #[cfg(feature = "firmware-example")]
    #[test]
    fn operation_fixture_crosses_the_public_controller_path() {
        let (cancelled, timed_out) =
            operation_error_injection_fixture().expect("fixture must complete");

        assert_eq!(
            cancelled.code(),
            hisi_rf_core::DiagnosticCode::OperationCancelled
        );
        assert_eq!(cancelled.stage(), DiagnosticStage::Operation);
        assert_eq!(cancelled.backend_code(), Some(0));

        assert_eq!(
            timed_out.code(),
            hisi_rf_core::DiagnosticCode::OperationTimeout
        );
        assert_eq!(timed_out.stage(), DiagnosticStage::Connect);
        assert_eq!(timed_out.backend_code(), Some(ERROR_OPERATION_TIMEOUT));
    }
}
