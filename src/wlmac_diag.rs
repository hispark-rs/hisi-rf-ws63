//! Bounded WLMAC snapshot shared by RF diagnostic profiles.

pub(crate) fn snapshot() -> hisi_hal::wlmac::WlmacRxCounters {
    #[cfg(target_arch = "riscv32")]
    {
        // SAFETY: both diagnostic features are consumed only after the radio
        // composition root has initialized WLMAC and while it retains the RF
        // resources. The HAL capability is read-only and does not claim the
        // vendor-owned peripheral singleton.
        let diagnostics = unsafe { hisi_hal::wlmac::WlmacDiagnostics::assume_radio_ready() };
        diagnostics.snapshot_rx()
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        hisi_hal::wlmac::WlmacRxCounters::default()
    }
}
