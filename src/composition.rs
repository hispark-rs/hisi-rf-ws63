use hisi_hal::peripherals::{Efuse, Km, Pke, Spacc, Trng};
use hisi_rf_core::{Error, RadioConfig, RadioState};

use crate::hisi_rf_backend::Ws63WifiBackend;
use crate::netif_smoltcp::Ws63Device;

/// WS63 radio resources assembled from uniquely owned HAL peripheral tokens.
pub struct Resources {
    inner: hisi_rf_core::RadioResources<Ws63WifiBackend<'static>, Ws63Device>,
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
            inner: crate::hisi_rf_backend::resources(efuse, km, spacc, pke, trng),
        }
    }
}

/// Concrete WS63 controller before it is split into Wi-Fi and runner handles.
pub type RadioController<const EVENTS: usize> =
    hisi_rf_core::RadioController<Ws63WifiBackend<'static>, Ws63Device, EVENTS>;

/// Claim one WS63 radio instance using caller-owned state and resources.
pub fn init<const EVENTS: usize>(
    config: RadioConfig,
    resources: Resources,
    state: &'static RadioState<EVENTS>,
) -> Result<RadioController<EVENTS>, Error> {
    #[cfg(target_arch = "riscv32")]
    crate::link_contract::ensure();
    hisi_rf_core::init(config, resources.inner, state)
}
