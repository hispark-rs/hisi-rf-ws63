use core::fmt;
use core::num::NonZeroUsize;
use hisi_hal::peripherals::{Efuse, Km, Pke, Spacc, Trng};
use hisi_rf_core::{
    BackendError, BackendErrorClass, Diagnostic, DiagnosticStage, DiagnosticTraceKind, Error,
    RadioConfig,
};

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

/// Concrete WS63 controller before it is split into Wi-Fi and runner handles.
pub type RadioController<const EVENTS: usize> =
    hisi_rf_core::RadioController<Ws63WifiBackend<'static>, Ws63Device, EVENTS>;

/// Claim one WS63 radio instance using caller-owned state and resources.
pub fn init<P: Profile + ActiveProfile, const EVENTS: usize>(
    config: RadioConfig,
    resources: Resources,
    storage: &'static Storage<P, EVENTS>,
) -> Result<RadioController<EVENTS>, InitError> {
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
    let inner = crate::hisi_rf_backend::resources(
        resources.efuse,
        resources.km,
        resources.spacc,
        resources.pke,
        resources.trng,
        crypto_storage,
    );
    match hisi_rf_core::init(config, inner, state) {
        Ok(controller) => Ok(controller),
        Err(error) => {
            hisi_rf_rtos_driver::release_task_reservation(reservation)
                .map_err(InitError::Runtime)?;
            Err(InitError::Core(error))
        }
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
