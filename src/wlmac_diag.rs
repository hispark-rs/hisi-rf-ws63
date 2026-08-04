//! Bounded WLMAC snapshots shared by RF diagnostic profiles.

#[allow(dead_code)]
pub(crate) struct Snapshot {
    pub(crate) rx: hisi_hal::wlmac::WlmacRxCounters,
    pub(crate) security: hisi_hal::wlmac::WlmacRxSecurityCounters,
    pub(crate) filter: hisi_hal::wlmac::WlmacFilterState,
    pub(crate) tx: TxCounters,
}

/// Transmit counters returned by the WS63 mask-ROM statistics helper.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TxCounters {
    pub(crate) high_priority_mpdu: u32,
    pub(crate) normal_priority_mpdu: u32,
    pub(crate) mpdu_in_ampdu: u32,
    pub(crate) ampdu: u32,
    pub(crate) complete_interrupts: u32,
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    fn hh503_get_mac_tx_statistics_data(counters: *mut TxCounters);
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
            tx: {
                let mut counters = TxCounters::default();
                // SAFETY: the mask-ROM helper only snapshots initialized WLMAC
                // counters into the caller-owned five-word output structure.
                unsafe { hh503_get_mac_tx_statistics_data(&mut counters) };
                counters
            },
        }
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        Snapshot {
            rx: hisi_hal::wlmac::WlmacRxCounters::default(),
            security: hisi_hal::wlmac::WlmacRxSecurityCounters::default(),
            filter: hisi_hal::wlmac::WlmacFilterState::default(),
            tx: TxCounters::default(),
        }
    }
}
