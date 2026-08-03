//! Budgeted RTOS worker for the non-default incremental WS63 backend.

use core::cell::RefCell;
use core::ffi::c_void;
use core::num::{NonZeroU32, NonZeroUsize};

use critical_section::Mutex;
use hisi_rf_core::{
    BackendError, BackendErrorClass, IncrementalRequest, IncrementalWifiBackend, OperationId,
    PollDisposition, ScanResult, WaitSet, WakeReason, WifiL2Capabilities, WorkBudget, WorkReport,
};
use hisi_rf_rtos_driver::{
    Semaphore, TaskBudget, TaskConfig, TaskExecutionPolicy, TaskPriority, TaskReservation,
};

use crate::hisi_rf_backend::OwnedIncrementalSupplicantBackend;

pub(crate) const WORKER_STACK_BYTES: usize = 8 * 1024;
const WORKER_PRIORITY: u8 = 9;
const WORKER_CAPACITY_MS: u32 = 100;
const WORKER_PERIOD_MS: u32 = 200;
const SCAN_CAPACITY: usize = 32;
const ERROR_WORKER_BUSY: u32 = 0x5732_b101;
const ERROR_WORKER_RUNTIME: u32 = 0x5732_b102;
const ERROR_WORKER_PROTOCOL: u32 = 0x5732_b103;

enum WorkerCommand {
    Start {
        id: OperationId,
        request: IncrementalRequest,
    },
    Poll {
        id: OperationId,
        reason: WakeReason,
        budget: WorkBudget,
    },
}

enum WorkerResponse {
    Started {
        id: OperationId,
        result: Result<(), BackendError>,
    },
    Polled {
        id: OperationId,
        result: Result<WorkReport, BackendError>,
    },
}

struct WorkerMailbox {
    command: Option<WorkerCommand>,
    response: Option<WorkerResponse>,
    cancellation: Option<OperationId>,
    worker_busy: bool,
    active: Option<OperationId>,
    last_terminal: Option<OperationId>,
    deadline_us: Option<u64>,
    stale_responses_dropped: u32,
    stale_responses_injected: u32,
    stale_injection_armed: bool,
}

impl WorkerMailbox {
    const fn new() -> Self {
        Self {
            command: None,
            response: None,
            cancellation: None,
            worker_busy: false,
            active: None,
            last_terminal: None,
            deadline_us: None,
            stale_responses_dropped: 0,
            stale_responses_injected: 0,
            stale_injection_armed: false,
        }
    }
}

struct WorkerScanStorage(core::cell::UnsafeCell<[ScanResult; SCAN_CAPACITY]>);

impl WorkerScanStorage {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(
            [ScanResult::empty(); SCAN_CAPACITY],
        ))
    }

    /// Reset the operation-owned output before starting a new scan.
    ///
    /// # Safety
    ///
    /// Only the worker task may call this method, while no completed scan is
    /// being copied by the runner.
    unsafe fn reset(&self) {
        // SAFETY: upheld by the worker ownership contract above.
        unsafe { *self.0.get() = [ScanResult::empty(); SCAN_CAPACITY] };
    }

    /// Return the persistent output storage owned by the worker task.
    ///
    /// Only the worker may dereference this pointer, and its mutable borrow
    /// must end before publishing the corresponding response.
    fn worker_output_ptr(&self) -> *mut [ScanResult; SCAN_CAPACITY] {
        self.0.get()
    }

    /// Copy a terminal scan result after the mailbox has blocked new work.
    ///
    /// # Safety
    ///
    /// The caller must hold the mailbox's scan-copy ownership, which prevents
    /// the worker from accepting another command until this copy completes.
    unsafe fn copy_to(&self, output: &mut [ScanResult], count: usize) {
        // SAFETY: the mailbox protocol excludes a concurrent worker writer.
        let scan = unsafe { &*self.0.get() };
        output[..count].copy_from_slice(&scan[..count]);
    }
}

/// Caller-owned worker state initialized exactly once by the composition root.
pub(crate) struct IncrementalWorkerState {
    backend: core::cell::UnsafeCell<OwnedIncrementalSupplicantBackend>,
    mailbox: Mutex<RefCell<WorkerMailbox>>,
    scan: WorkerScanStorage,
    wake: Semaphore,
    l2_capabilities: Option<WifiL2Capabilities>,
}

// SAFETY: only the spawned worker dereferences `backend`. All runner-facing
// communication is moved through `mailbox`, which is serialized by the target
// critical-section implementation. Initialization completes before spawn.
unsafe impl Sync for IncrementalWorkerState {}

impl IncrementalWorkerState {
    pub(crate) fn new(backend: OwnedIncrementalSupplicantBackend) -> Self {
        let l2_capabilities = backend.l2_capabilities();
        Self {
            backend: core::cell::UnsafeCell::new(backend),
            mailbox: Mutex::new(RefCell::new(WorkerMailbox::new())),
            scan: WorkerScanStorage::new(),
            wake: Semaphore::new(0),
            l2_capabilities,
        }
    }

    pub(crate) fn start(
        &'static self,
        reservation: &'static TaskReservation,
    ) -> Result<WorkerBackedIncrementalBackend, hisi_rf_rtos_driver::Error> {
        self.wake.try_init()?;
        let capacity = NonZeroU32::new(WORKER_CAPACITY_MS).expect("worker capacity is non-zero");
        let period = NonZeroU32::new(WORKER_PERIOD_MS).expect("worker period is non-zero");
        let budget = TaskBudget::try_new(capacity, period).expect("worker quota is valid");
        let priority = TaskPriority::new(WORKER_PRIORITY)
            .expect("worker priority is inside the runtime contract");
        hisi_rf_rtos_driver::spawn_reserved_scheduled(
            reservation,
            worker_entry,
            (self as *const Self).cast_mut().cast(),
            TaskConfig {
                stack_size: NonZeroUsize::new(WORKER_STACK_BYTES)
                    .expect("worker stack is non-zero"),
                priority,
            },
            TaskExecutionPolicy::Budgeted(budget),
        )?;
        Ok(WorkerBackedIncrementalBackend { state: self })
    }

    fn submit(&self, command: WorkerCommand) -> Result<(), BackendError> {
        let accepted = critical_section::with(|cs| {
            let mut mailbox = self.mailbox.borrow_ref_mut(cs);
            if mailbox.command.is_some() || mailbox.worker_busy || mailbox.response.is_some() {
                false
            } else {
                mailbox.command = Some(command);
                true
            }
        });
        if !accepted {
            return Err(worker_error(ERROR_WORKER_BUSY));
        }
        self.wake
            .up()
            .map_err(|_| worker_error(ERROR_WORKER_RUNTIME))
    }

    fn request_cancel(&self, id: OperationId) -> Result<(), BackendError> {
        critical_section::with(|cs| {
            self.mailbox.borrow_ref_mut(cs).cancellation = Some(id);
        });
        self.wake
            .up()
            .map_err(|_| worker_error(ERROR_WORKER_RUNTIME))
    }

    fn take_response(
        &self,
        expected_id: OperationId,
        scan_output: &mut [ScanResult],
    ) -> Option<WorkerResponse> {
        let (response, scan_count) = critical_section::with(|cs| {
            let mut mailbox = self.mailbox.borrow_ref_mut(cs);
            let response = mailbox.response.take();
            if response
                .as_ref()
                .is_some_and(|response| response.id() != expected_id)
            {
                mailbox.stale_responses_dropped = mailbox.stale_responses_dropped.saturating_add(1);
                return (response, None);
            }
            let scan_count = if let Some(WorkerResponse::Polled {
                result: Ok(report), ..
            }) = response.as_ref()
                && let PollDisposition::Complete(hisi_rf_core::IncrementalCompletion::Scan(outcome)) =
                    report.disposition()
            {
                mailbox.worker_busy = true;
                Some(outcome.count.min(scan_output.len()).min(SCAN_CAPACITY))
            } else {
                None
            };
            (response, scan_count)
        });
        if let Some(count) = scan_count {
            // SAFETY: `worker_busy` prevents a new command from being
            // accepted until the copy has completed. Bulk copying deliberately
            // happens outside the interrupt-disabled critical section.
            unsafe { self.scan.copy_to(scan_output, count) };
            critical_section::with(|cs| {
                self.mailbox.borrow_ref_mut(cs).worker_busy = false;
            });
        }
        response
    }

    #[cfg(feature = "incremental-late-completion-profile")]
    pub(crate) fn diagnostics(&self) -> (u32, u32) {
        critical_section::with(|cs| {
            let mailbox = self.mailbox.borrow_ref(cs);
            (
                mailbox.stale_responses_dropped,
                mailbox.stale_responses_injected,
            )
        })
    }

    #[cfg(feature = "incremental-late-completion-profile")]
    pub(crate) fn arm_stale_completion_injection(&self) -> Result<(), BackendError> {
        let armed = critical_section::with(|cs| {
            let mut mailbox = self.mailbox.borrow_ref_mut(cs);
            if mailbox.last_terminal.is_none() || mailbox.stale_injection_armed {
                false
            } else {
                mailbox.stale_injection_armed = true;
                true
            }
        });
        if armed {
            Ok(())
        } else {
            Err(worker_error(ERROR_WORKER_PROTOCOL))
        }
    }

    fn deadline(&self, id: OperationId) -> Option<u64> {
        critical_section::with(|cs| {
            let mailbox = self.mailbox.borrow_ref(cs);
            (mailbox.active == Some(id))
                .then_some(mailbox.deadline_us)
                .flatten()
        })
    }

    fn run(&'static self) -> ! {
        loop {
            if self.wake.down().is_err() {
                let _ = hisi_rf_rtos_driver::yield_now();
                continue;
            }
            let (cancel, command, previous_active, injected_stale) = critical_section::with(|cs| {
                let mut mailbox = self.mailbox.borrow_ref_mut(cs);
                let cancel = mailbox.cancellation.take();
                let command = mailbox.command.take();
                let previous_active = mailbox.active;
                let injected_stale = match (&command, mailbox.last_terminal) {
                    (Some(WorkerCommand::Poll { id, budget, .. }), Some(stale_id))
                        if mailbox.stale_injection_armed && stale_id != *id =>
                    {
                        mailbox.stale_injection_armed = false;
                        mailbox.stale_responses_injected =
                            mailbox.stale_responses_injected.saturating_add(1);
                        Some((stale_id, *budget))
                    }
                    _ => None,
                };
                mailbox.worker_busy = cancel.is_some() || command.is_some();
                (cancel, command, previous_active, injected_stale)
            });

            // SAFETY: this worker is the sole code path that dereferences the
            // backend after initialization; the proxy only touches the mailbox.
            let backend = unsafe { &mut *self.backend.get() };
            if let Some(id) = cancel {
                let _ = backend.cancel(id);
            }

            let response = match command {
                Some(WorkerCommand::Start { id, request }) => {
                    if matches!(request, IncrementalRequest::Scan(_)) {
                        // SAFETY: only this worker accesses scan storage until
                        // it publishes a terminal response.
                        unsafe { self.scan.reset() };
                    }
                    Some(WorkerResponse::Started {
                        id,
                        result: backend.start(id, request),
                    })
                }
                Some(WorkerCommand::Poll { .. }) if injected_stale.is_some() => {
                    let (stale_id, budget) = injected_stale.expect("matched stale injection");
                    let report = WorkReport::try_new(
                        stale_id,
                        budget,
                        0,
                        1,
                        true,
                        PollDisposition::Complete(hisi_rf_core::IncrementalCompletion::Initialized),
                    )
                    .expect("diagnostic completion fits its submitted budget");
                    Some(WorkerResponse::Polled {
                        id: stale_id,
                        result: Ok(report),
                    })
                }
                Some(WorkerCommand::Poll { id, reason, budget }) => {
                    // SAFETY: this worker is the sole writer. The runner may
                    // read only after a terminal response blocks new work.
                    // SAFETY: the worker task is the sole writer and the
                    // returned borrow ends before the response is published.
                    let scan_output = unsafe { &mut *self.scan.worker_output_ptr() };
                    let result = backend.poll(id, reason, budget, scan_output);
                    Some(WorkerResponse::Polled { id, result })
                }
                None => None,
            };
            let active = next_active(previous_active, response.as_ref());
            let deadline = active.and_then(|id| backend.next_deadline_us(id));
            critical_section::with(|cs| {
                let mut mailbox = self.mailbox.borrow_ref_mut(cs);
                if previous_active.is_some() && active.is_none() {
                    mailbox.last_terminal = previous_active;
                }
                mailbox.worker_busy = false;
                mailbox.active = active;
                mailbox.deadline_us = deadline;
                if response.is_some() {
                    debug_assert!(mailbox.response.is_none());
                    mailbox.response = response;
                }
            });
            crate::incremental_wait::signal_backend();
        }
    }
}

extern "C" fn worker_entry(argument: *mut c_void) -> *mut c_void {
    // SAFETY: `IncrementalWorkerState::start` passes its unique static state.
    let state = unsafe { &*argument.cast::<IncrementalWorkerState>() };
    state.run()
}

/// Runner-facing proxy; it never enters vendor or hardware code directly.
pub(crate) struct WorkerBackedIncrementalBackend {
    state: &'static IncrementalWorkerState,
}

impl WorkerBackedIncrementalBackend {
    fn waiting_report(id: OperationId, budget: WorkBudget) -> Result<WorkReport, BackendError> {
        WorkReport::try_new(
            id,
            budget,
            0,
            0,
            false,
            PollDisposition::Pending(WaitSet::BACKEND),
        )
        .ok_or_else(|| worker_error(ERROR_WORKER_PROTOCOL))
    }

    fn submit_poll(
        &self,
        id: OperationId,
        reason: WakeReason,
        budget: WorkBudget,
    ) -> Result<WorkReport, BackendError> {
        match self
            .state
            .submit(WorkerCommand::Poll { id, reason, budget })
        {
            Ok(()) => Self::waiting_report(id, budget),
            Err(error) if error.code() == ERROR_WORKER_BUSY => Self::waiting_report(id, budget),
            Err(error) => Err(error),
        }
    }
}

impl IncrementalWifiBackend for WorkerBackedIncrementalBackend {
    fn start(&mut self, id: OperationId, request: IncrementalRequest) -> Result<(), BackendError> {
        self.state.submit(WorkerCommand::Start { id, request })
    }

    fn poll(
        &mut self,
        id: OperationId,
        reason: WakeReason,
        budget: WorkBudget,
        scan_output: &mut [ScanResult],
    ) -> Result<WorkReport, BackendError> {
        while let Some(response) = self.state.take_response(id, scan_output) {
            match response {
                WorkerResponse::Started {
                    id: response_id,
                    result,
                } if response_id == id => {
                    result?;
                    return self.submit_poll(id, reason, budget);
                }
                WorkerResponse::Polled {
                    id: response_id,
                    result,
                } if response_id == id => return result,
                _ => continue,
            }
        }
        self.submit_poll(id, reason, budget)
    }

    fn cancel(&mut self, id: OperationId) -> Result<(), BackendError> {
        self.state.request_cancel(id)
    }

    fn next_deadline_us(&self, id: OperationId) -> Option<u64> {
        self.state.deadline(id)
    }

    fn l2_capabilities(&self) -> Option<WifiL2Capabilities> {
        self.state.l2_capabilities
    }
}

fn worker_error(code: u32) -> BackendError {
    BackendError::new(BackendErrorClass::Other, code)
}

fn next_active(
    previous: Option<OperationId>,
    response: Option<&WorkerResponse>,
) -> Option<OperationId> {
    response.map_or(previous, |response| {
        if previous.is_some_and(|active| active != response.id()) {
            return previous;
        }
        match response {
            WorkerResponse::Started { id, result: Ok(()) } => Some(*id),
            WorkerResponse::Polled {
                id,
                result: Ok(report),
            } if matches!(
                report.disposition(),
                PollDisposition::Pending(_) | PollDisposition::BudgetExhausted(_)
            ) =>
            {
                Some(*id)
            }
            _ => None,
        }
    })
}

impl WorkerResponse {
    fn id(&self) -> OperationId {
        match self {
            Self::Started { id, .. } | Self::Polled { id, .. } => *id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hisi_rf_core::{IncrementalCompletion, OperationTracker, Security, Ssid};

    fn operation() -> OperationId {
        OperationTracker::new().queue(0).unwrap()
    }

    #[test]
    fn waiting_report_is_level_triggered_without_claiming_progress() {
        let id = operation();
        let budget = WorkBudget::try_new(4, 100_000).unwrap();
        let report = WorkerBackedIncrementalBackend::waiting_report(id, budget).unwrap();
        assert_eq!(report.operation(), id);
        assert!(!report.made_progress());
        assert_eq!(
            report.disposition(),
            PollDisposition::Pending(WaitSet::BACKEND)
        );
    }

    #[test]
    fn cancellation_only_wake_keeps_the_active_identity() {
        let id = operation();
        assert_eq!(next_active(Some(id), None), Some(id));
    }

    #[test]
    fn terminal_worker_response_releases_the_active_identity() {
        let id = operation();
        let budget = WorkBudget::try_new(1, 100).unwrap();
        let report = WorkReport::try_new(
            id,
            budget,
            0,
            1,
            true,
            PollDisposition::Complete(IncrementalCompletion::Initialized),
        )
        .unwrap();
        let response = WorkerResponse::Polled {
            id,
            result: Ok(report),
        };
        assert_eq!(next_active(Some(id), Some(&response)), None);
    }

    #[test]
    fn stale_terminal_response_cannot_release_replacement_identity() {
        let mut tracker = OperationTracker::new();
        let stale = tracker.queue(0).unwrap();
        tracker.mark_started(stale).unwrap();
        tracker.commit_terminal(stale).unwrap();
        tracker.reap(stale).unwrap();
        let replacement = tracker.queue(0).unwrap();
        let budget = WorkBudget::try_new(1, 100).unwrap();
        let report = WorkReport::try_new(
            stale,
            budget,
            0,
            1,
            true,
            PollDisposition::Complete(IncrementalCompletion::Initialized),
        )
        .unwrap();
        let response = WorkerResponse::Polled {
            id: stale,
            result: Ok(report),
        };
        assert_eq!(
            next_active(Some(replacement), Some(&response)),
            Some(replacement)
        );
    }

    #[test]
    fn scan_storage_is_not_embedded_in_each_response_variant() {
        assert!(core::mem::size_of::<WorkerResponse>() < 256);
        assert_eq!(SCAN_CAPACITY, 32);
    }

    #[test]
    fn scan_storage_accumulates_results_across_worker_poll_turns() {
        let storage = WorkerScanStorage::new();
        let first = ScanResult {
            ssid: Ssid::try_from_bytes(b"first").unwrap(),
            bssid: [1; 6],
            frequency_mhz: 2_437,
            rssi_dbm: -30,
            security: Security::Wpa2Personal,
            channel: 6,
        };
        let second = ScanResult {
            ssid: Ssid::try_from_bytes(b"second").unwrap(),
            bssid: [2; 6],
            frequency_mhz: 2_437,
            rssi_dbm: -31,
            security: Security::Wpa2Personal,
            channel: 6,
        };

        // SAFETY: this test models the single worker writer serially.
        unsafe { (*storage.worker_output_ptr())[0] = first };
        // SAFETY: the previous mutable borrow ended before this poll turn.
        unsafe { (*storage.worker_output_ptr())[1] = second };

        let mut copied = [ScanResult::empty(); 2];
        // SAFETY: no writer is active while the terminal output is copied.
        unsafe { storage.copy_to(&mut copied, 2) };
        assert_eq!(copied, [first, second]);
    }
}
