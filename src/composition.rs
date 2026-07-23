use core::ffi::c_void;
use core::fmt;
use core::num::NonZeroUsize;
use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_hal::peripherals::{Efuse, Km, Pke, Spacc, Trng};
use hisi_rf_core::{
    BackendError, BackendErrorClass, Diagnostic, DiagnosticStage, DiagnosticTraceKind, Error,
    RadioConfig, WifiParts,
};

#[cfg(feature = "incremental-backend-experiment")]
use hisi_rf_core::{
    IncrementalDriverEvent, IncrementalRadioRunnerError, IncrementalWaitError,
    IncrementalWaitIntent, IncrementalWaitPlatform, RadioResources, WaitSet, WifiBackend,
    WorkBudget,
};

#[cfg(feature = "incremental-backend-experiment")]
use crate::hisi_rf_backend::OwnedIncrementalSupplicantBackend;
use crate::hisi_rf_backend::Ws63WifiBackend;
use crate::netif_smoltcp::Ws63Device;
use crate::profile::{ActiveProfile, Profile, Storage};

/// WS63 radio resources assembled from uniquely owned HAL peripheral tokens.
pub struct Resources {
    efuse: Efuse<'static>,
    km: Km<'static>,
    spacc: Spacc<'static>,
    pke: Pke<'static>,
    trng: Trng<'static>,
}

impl Resources {
    /// Assemble the WS63 Wi-Fi backend and L2 device without touching hardware.
    pub fn new(
        efuse: Efuse<'static>,
        km: Km<'static>,
        spacc: Spacc<'static>,
        pke: Pke<'static>,
        trng: Trng<'static>,
    ) -> Self {
        Self {
            efuse,
            km,
            spacc,
            pke,
            trng,
        }
    }
}

/// Failure before the WS63 radio backend starts executing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitError {
    /// The installed runtime cannot satisfy the profile contract.
    Runtime(hisi_rf_rtos_driver::Error),
    /// The runtime could not atomically reserve the profile's task slots.
    TaskAdmission(hisi_rf_rtos_driver::TaskAdmissionError),
    /// The caller-owned storage was already consumed by an earlier init.
    StorageAlreadyClaimed,
    /// The chip-neutral controller rejected initialization.
    Core(Error),
}

impl InitError {
    /// Convert an initialization failure into the shared, secret-free schema.
    pub fn diagnostic(self) -> Diagnostic {
        match self {
            Self::Runtime(error) => runtime_diagnostic(error),
            Self::TaskAdmission(error) => task_admission_diagnostic(error),
            Self::StorageAlreadyClaimed => Error::AlreadyInitialized.diagnostic(),
            Self::Core(error) => error.diagnostic(),
        }
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.diagnostic().fmt(formatter)
    }
}

const RADIO_RUNNER_STACK_BYTES: usize = 8 * 1024;
const RADIO_RUNNER_PRIORITY: u8 = 10;

type CoreRadioController<const EVENTS: usize> =
    hisi_rf_core::RadioController<Ws63WifiBackend<'static>, Ws63Device, EVENTS>;

#[cfg(feature = "incremental-backend-experiment")]
type CoreIncrementalRadioController<const EVENTS: usize> =
    hisi_rf_core::RadioController<OwnedIncrementalSupplicantBackend, Ws63Device, EVENTS>;

/// WS63 controller bound to the caller-owned storage that will hold its runner.
pub struct RadioController<P: Profile + 'static, const EVENTS: usize> {
    inner: CoreRadioController<EVENTS>,
    storage: &'static Storage<P, EVENTS>,
}

/// WS63 controller whose vendor bootstrap has completed before construction.
///
/// This type is available only through the non-default A5B experiment. Its
/// scan/connect/disconnect work is bounded, but construction remains a
/// synchronous prerequisite until the vendor initialization boundary itself
/// can be split or assigned a measured worst-case latency.
#[cfg(feature = "incremental-backend-experiment")]
pub struct IncrementalRadioController<P: Profile + 'static, const EVENTS: usize> {
    inner: CoreIncrementalRadioController<EVENTS>,
    _profile: core::marker::PhantomData<P>,
}

/// Wi-Fi handles and the explicit A5B bounded runner.
#[cfg(feature = "incremental-backend-experiment")]
pub struct IncrementalRadioParts<const EVENTS: usize> {
    /// Existing async Wi-Fi controller and WS63 L2 device.
    pub wifi: WifiParts<Ws63Device, EVENTS>,
    /// Runner that advances at most one budgeted backend action per call.
    pub runner: IncrementalRadioRunner<EVENTS>,
}

/// Opaque WS63 runner over the owned initialized backend.
#[cfg(feature = "incremental-backend-experiment")]
pub struct IncrementalRadioRunner<const EVENTS: usize> {
    inner: hisi_rf_core::IncrementalRadioRunner<OwnedIncrementalSupplicantBackend, EVENTS>,
}

#[cfg(feature = "incremental-backend-experiment")]
impl<P: Profile + 'static, const EVENTS: usize> IncrementalRadioController<P, EVENTS> {
    /// Split into the stable Wi-Fi handles and an opt-in bounded runner.
    pub fn split(self, budget: WorkBudget) -> IncrementalRadioParts<EVENTS> {
        let hisi_rf_core::IncrementalRadioParts { wifi, runner } =
            self.inner.split_incremental(budget);
        IncrementalRadioParts {
            wifi,
            runner: IncrementalRadioRunner { inner: runner },
        }
    }
}

#[cfg(feature = "incremental-backend-experiment")]
impl<const EVENTS: usize> IncrementalRadioRunner<EVENTS> {
    /// Advance at most one bounded driver action.
    pub fn run_once(
        &mut self,
        ready: WaitSet,
    ) -> Result<IncrementalDriverEvent, IncrementalRadioRunnerError> {
        self.inner.run_once(ready)
    }

    /// Snapshot immediate work, wake subscriptions, and the next deadline.
    pub fn wait_intent(&self) -> IncrementalWaitIntent {
        self.inner.wait_intent()
    }

    /// Wait for one subscribed source without consuming a control command.
    pub async fn wait_ready<P: IncrementalWaitPlatform>(
        &self,
        platform: &mut P,
    ) -> Result<WaitSet, IncrementalWaitError<P::Error>> {
        self.inner.wait_ready(platform).await
    }

    /// Monotonic deadline requested by the active operation.
    pub fn next_deadline_us(&self) -> Option<u64> {
        self.inner.next_deadline_us()
    }
}

impl<P: Profile + 'static, const EVENTS: usize> RadioController<P, EVENTS> {
    /// Split the radio without starting its runner.
    ///
    /// Prefer [`Self::start_runner`] in applications. This escape hatch exists
    /// for runtimes that provide their own task/executor integration.
    pub fn split(self) -> hisi_rf_core::RadioParts<Ws63WifiBackend<'static>, Ws63Device, EVENTS> {
        self.inner.split()
    }

    /// Start the mandatory bounded-work runner and return Wi-Fi control/L2 handles.
    pub fn start_runner(self) -> Result<WifiParts<Ws63Device, EVENTS>, InitError> {
        let hisi_rf_core::RadioParts { wifi, runner } = self.inner.split();
        let runner = self.storage.store_runner(runner);
        crate::runtime::spawn_vendor_task(
            radio_runner_task::<EVENTS>,
            (runner as *mut hisi_rf_core::RadioRunner<Ws63WifiBackend<'static>, EVENTS>).cast(),
            RADIO_RUNNER_STACK_BYTES,
            RADIO_RUNNER_PRIORITY,
        )
        .map_err(InitError::Runtime)?;
        Ok(wifi)
    }
}

/// Claim one WS63 radio instance using caller-owned state and resources.
pub fn init<P: Profile + ActiveProfile + 'static, const EVENTS: usize>(
    config: RadioConfig,
    resources: Resources,
    storage: &'static Storage<P, EVENTS>,
) -> Result<RadioController<P, EVENTS>, InitError> {
    let (state, crypto_storage, reservation) = claim_profile_storage::<P, EVENTS>(storage)?;
    let inner = crate::hisi_rf_backend::resources(
        resources.efuse,
        resources.km,
        resources.spacc,
        resources.pke,
        resources.trng,
        crypto_storage,
    );
    match hisi_rf_core::init(config, inner, state) {
        Ok(controller) => Ok(RadioController {
            inner: controller,
            storage,
        }),
        Err(error) => {
            release_profile_reservation(reservation)?;
            Err(InitError::Core(error))
        }
    }
}

/// Complete the existing blocking vendor bootstrap, then transfer ownership to
/// the non-default bounded A5B runner.
///
/// This function is intentionally named after its blocking prerequisite. It
/// does not claim that vendor initialization is incremental; only operations
/// after the returned controller is split use [`WorkBudget`]. A bootstrap
/// failure consumes the one-shot storage and resources because vendor tasks
/// may already own the installed task reservation; retry with fresh firmware
/// state rather than reusing this storage.
#[cfg(feature = "incremental-backend-experiment")]
pub fn init_incremental_after_blocking_bootstrap<
    P: Profile + ActiveProfile + 'static,
    const EVENTS: usize,
>(
    config: RadioConfig,
    resources: Resources,
    storage: &'static Storage<P, EVENTS>,
) -> Result<IncrementalRadioController<P, EVENTS>, InitError> {
    let (state, crypto_storage, _reservation) = claim_profile_storage::<P, EVENTS>(storage)?;
    let RadioResources {
        mut backend,
        device,
    } = crate::hisi_rf_backend::resources(
        resources.efuse,
        resources.km,
        resources.spacc,
        resources.pke,
        resources.trng,
        crypto_storage,
    );
    if let Err(error) = backend.initialize(&config.wifi) {
        // The vendor bootstrap may already have spawned tasks through this
        // reservation. It is installed in the process-wide compatibility
        // adapter and cannot be safely detached or reused after a partial
        // failure, so this one-shot storage remains claimed.
        return Err(InitError::Core(Error::Backend(error)));
    }
    let backend = match backend.into_incremental() {
        Ok(backend) => backend,
        Err(error) => return Err(InitError::Core(Error::Backend(error))),
    };
    match hisi_rf_core::init(config, RadioResources { backend, device }, state) {
        Ok(controller) => Ok(IncrementalRadioController {
            inner: controller,
            _profile: core::marker::PhantomData,
        }),
        Err(error) => Err(InitError::Core(error)),
    }
}

fn claim_profile_storage<P: Profile + ActiveProfile + 'static, const EVENTS: usize>(
    storage: &'static Storage<P, EVENTS>,
) -> Result<
    (
        &'static hisi_rf_core::RadioState<EVENTS>,
        &'static mut Ws63CryptoStorage,
        &'static hisi_rf_rtos_driver::TaskReservation,
    ),
    InitError,
> {
    #[cfg(target_arch = "riscv32")]
    crate::link_contract::ensure();
    hisi_rf_rtos_driver::require_runtime(
        hisi_rf_rtos_driver::RuntimeRequirements::V1_3_PORTED_COOPERATIVE,
    )
    .map_err(InitError::Runtime)?;
    hisi_rf_rtos_driver::current_task().map_err(InitError::Runtime)?;
    let required = NonZeroUsize::new(P::DYNAMIC_TASKS_REQUIRED).ok_or(InitError::TaskAdmission(
        hisi_rf_rtos_driver::TaskAdmissionError::Runtime(hisi_rf_rtos_driver::Error::Runtime),
    ))?;
    let reservation =
        hisi_rf_rtos_driver::reserve_task_capacity(required).map_err(InitError::TaskAdmission)?;
    let (state, crypto_storage, reservation) = match storage.claim(reservation) {
        Ok(claimed) => claimed,
        Err(reservation) => {
            hisi_rf_rtos_driver::release_task_reservation(&reservation)
                .map_err(InitError::Runtime)?;
            return Err(InitError::StorageAlreadyClaimed);
        }
    };
    if let Err(error) = crate::runtime::install_task_reservation(reservation) {
        hisi_rf_rtos_driver::release_task_reservation(reservation).map_err(InitError::Runtime)?;
        return Err(InitError::Runtime(error));
    }
    Ok((state, crypto_storage, reservation))
}

fn release_profile_reservation(
    reservation: &'static hisi_rf_rtos_driver::TaskReservation,
) -> Result<(), InitError> {
    hisi_rf_rtos_driver::release_task_reservation(reservation).map_err(InitError::Runtime)
}

/// Return the station MAC address installed by the initialized WS63 netif.
///
/// The address becomes available after [`hisi_rf_core::WifiController::initialize`]
/// completes. Applications use it to configure a standard L2/IP stack without
/// reaching into the vendor netif or chip backend internals.
pub fn station_mac_address() -> Option<[u8; 6]> {
    crate::netif::hardware_address()
}

extern "C" fn radio_runner_task<const EVENTS: usize>(argument: *mut c_void) -> *mut c_void {
    // SAFETY: `start_runner` passes the unique runner stored for the entire
    // firmware lifetime. The task is the only code that mutates it.
    let runner = unsafe {
        &mut *argument.cast::<hisi_rf_core::RadioRunner<Ws63WifiBackend<'static>, EVENTS>>()
    };
    loop {
        let _ = runner.run_once();
        crate::runtime::yield_now();
    }
}

fn runtime_diagnostic(error: hisi_rf_rtos_driver::Error) -> Diagnostic {
    let class = match error {
        hisi_rf_rtos_driver::Error::ResourceExhausted | hisi_rf_rtos_driver::Error::NoTaskSlots => {
            BackendErrorClass::ResourceUnavailable
        }
        hisi_rf_rtos_driver::Error::TimedOut => BackendErrorClass::Timeout,
        _ => BackendErrorClass::Other,
    };
    let code = crate::hisi_rf_backend::runtime_code(error);
    Error::Backend(
        BackendError::new(class, 0x5732_e000 | code)
            .with_stage(DiagnosticStage::Runtime)
            .with_profile_revision(crate::profile::PROFILE_REVISION)
            .with_trace(DiagnosticTraceKind::RuntimeCode, code),
    )
    .diagnostic()
}

fn task_admission_diagnostic(error: hisi_rf_rtos_driver::TaskAdmissionError) -> Diagnostic {
    let code = crate::hisi_rf_backend::task_admission_code(error);
    let mut backend = match error {
        hisi_rf_rtos_driver::TaskAdmissionError::Runtime(runtime) => {
            let class = match runtime {
                hisi_rf_rtos_driver::Error::ResourceExhausted
                | hisi_rf_rtos_driver::Error::NoTaskSlots => BackendErrorClass::ResourceUnavailable,
                hisi_rf_rtos_driver::Error::TimedOut => BackendErrorClass::Timeout,
                _ => BackendErrorClass::Other,
            };
            BackendError::new(class, 0x5732_a000 | code).with_trace(
                DiagnosticTraceKind::RuntimeCode,
                crate::hisi_rf_backend::runtime_code(runtime),
            )
        }
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskSlots {
            required,
            available,
        } => BackendError::new(BackendErrorClass::ResourceUnavailable, 0x5732_a000 | code)
            .with_trace(
                DiagnosticTraceKind::ResourceRequired,
                required.min(u32::MAX as usize) as u32,
            )
            .with_trace(
                DiagnosticTraceKind::ResourceAvailable,
                available.min(u32::MAX as usize) as u32,
            ),
    };
    backend = backend
        .with_stage(DiagnosticStage::Runtime)
        .with_profile_revision(crate::profile::PROFILE_REVISION);
    Error::Backend(backend).diagnostic()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use hisi_rf_core::{DiagnosticCode, RecoveryAction};

    use super::*;

    #[test]
    fn task_admission_error_is_actionable_and_lossless() {
        let diagnostic = InitError::TaskAdmission(
            hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskSlots {
                required: 7,
                available: 3,
            },
        )
        .diagnostic();

        assert_eq!(diagnostic.code(), DiagnosticCode::ResourceUnavailable);
        assert_eq!(diagnostic.stage(), DiagnosticStage::Runtime);
        assert_eq!(diagnostic.action(), RecoveryAction::ProvideResources);
        assert_eq!(diagnostic.profile_revision(), Some("ws63-wifi-2026-07-22"));
        assert_eq!(
            diagnostic.trace().get(0).map(|entry| entry.value()),
            Some(7)
        );
        assert_eq!(
            diagnostic.trace().get(1).map(|entry| entry.value()),
            Some(3)
        );
    }

    #[test]
    fn runtime_and_storage_failures_share_the_public_schema() {
        let timeout = InitError::Runtime(hisi_rf_rtos_driver::Error::TimedOut).diagnostic();
        assert_eq!(timeout.code(), DiagnosticCode::BackendTimeout);
        assert_eq!(timeout.stage(), DiagnosticStage::Runtime);

        let claimed = InitError::StorageAlreadyClaimed.diagnostic();
        assert_eq!(claimed.code(), DiagnosticCode::AlreadyInitialized);
    }

    #[test]
    fn initialization_json_never_contains_configuration_secrets() {
        let mut json = String::new();
        InitError::TaskAdmission(
            hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskSlots {
                required: 7,
                available: 3,
            },
        )
        .diagnostic()
        .write_json(&mut json)
        .unwrap();

        assert!(json.contains("resource.unavailable"));
        assert!(!json.contains("ssid"));
        assert!(!json.contains("passphrase"));
        assert!(!json.contains("secret"));
    }
}
