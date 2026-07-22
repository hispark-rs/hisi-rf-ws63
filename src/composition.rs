use core::num::NonZeroUsize;
use hisi_hal::peripherals::{Efuse, Km, Pke, Spacc, Trng};
use hisi_rf_core::{Error, RadioConfig};

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
