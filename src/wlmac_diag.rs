//! Bounded WLMAC snapshots shared by RF diagnostic profiles.

#[allow(dead_code)]
pub(crate) struct Snapshot {
    pub(crate) rx: hisi_hal::wlmac::WlmacRxCounters,
    pub(crate) security: hisi_hal::wlmac::WlmacRxSecurityCounters,
    pub(crate) filter: hisi_hal::wlmac::WlmacFilterState,
}

pub(crate) fn snapshot() -> Snapshot {
    #[cfg(target_arch = "riscv32")]
    {
        // SAFETY: both diagnostic features are consumed only after the radio
        // composition root has initialized WLMAC and while it retains the RF
        // resources. The HAL capability is read-only and does not claim the
        // vendor-owned peripheral singleton.
        let diagnostics = unsafe { hisi_hal::wlmac::WlmacDiagnostics::assume_radio_ready() };
        Snapshot {
            rx: diagnostics.snapshot_rx(),
            security: diagnostics.snapshot_rx_security(),
            filter: diagnostics.snapshot_filter_state(),
        }
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        Snapshot {
            rx: hisi_hal::wlmac::WlmacRxCounters::default(),
            security: hisi_hal::wlmac::WlmacRxSecurityCounters::default(),
            filter: hisi_hal::wlmac::WlmacFilterState::default(),
        }
    }
}
