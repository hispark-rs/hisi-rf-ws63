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
    let (state, crypto_storage) = storage.claim().ok_or(InitError::StorageAlreadyClaimed)?;
    let inner = crate::hisi_rf_backend::resources(
        resources.efuse,
        resources.km,
        resources.spacc,
        resources.pke,
        resources.trng,
        crypto_storage,
    );
    hisi_rf_core::init(config, inner, state).map_err(InitError::Core)
}
