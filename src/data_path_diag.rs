//! Bounded packet-path counters for low-disturbance silicon diagnosis.

#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;
use portable_atomic::{AtomicU32, Ordering};

static TX_COMPLETIONS: AtomicU32 = AtomicU32::new(0);
static RX_PREPARES: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_ZERO: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_NONZERO: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_LAST_RESULT: AtomicU32 = AtomicU32::new(0);
static HMAC_DATA_EVENT_ADAPT_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_PROCESS_DATA_MSG_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_RX_DATA_CALLS: AtomicU32 = AtomicU32::new(0);
static RX_STATUS_SUCCESS: AtomicU32 = AtomicU32::new(0);
static RX_STATUS_DUPLICATE: AtomicU32 = AtomicU32::new(0);
static RX_STATUS_KEY_FAILURE: AtomicU32 = AtomicU32::new(0);
static RX_STATUS_CCMP_MIC_FAILURE: AtomicU32 = AtomicU32::new(0);
static RX_STATUS_CCMP_REPLAY_FAILURE: AtomicU32 = AtomicU32::new(0);
static RX_STATUS_OTHER: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    #[link_name = "__real_dmac_tx_complete_event_handler"]
    fn vendor_dmac_tx_complete_event_handler(vap: *mut c_void, message: *mut c_void) -> i32;
    #[link_name = "__real_dmac_rx_prepare_data_patch"]
    fn vendor_dmac_rx_prepare_data_patch(
        netbuf: *mut c_void,
        rx_ctl: *mut c_void,
        vap_id: u32,
        rx_status: *mut c_void,
        process_flag: *mut c_void,
    ) -> u32;
    #[link_name = "__real_hmac_rx_data_event_adapt"]
    fn vendor_hmac_rx_data_event_adapt(vap: *mut c_void, message: *mut c_void) -> i32;
    #[link_name = "__real_hmac_rx_process_data_msg"]
    fn vendor_hmac_rx_process_data_msg(vap: *mut c_void, message: *mut c_void) -> i32;
    #[link_name = "__real_hmac_rx_data"]
    fn vendor_hmac_rx_data(vap: *mut c_void, netbuf: *mut c_void) -> u32;
}

pub(crate) fn tx_completions() -> u32 {
    TX_COMPLETIONS.load(Ordering::Relaxed)
}

pub(crate) fn rx_prepares() -> u32 {
    RX_PREPARES.load(Ordering::Relaxed)
}

pub(crate) fn rx_prepare_results() -> [u32; 3] {
    [
        RX_PREPARE_ZERO.load(Ordering::Relaxed),
        RX_PREPARE_NONZERO.load(Ordering::Relaxed),
        RX_PREPARE_LAST_RESULT.load(Ordering::Relaxed),
    ]
}

pub(crate) fn rx_pipeline_stages() -> [u32; 3] {
    [
        HMAC_DATA_EVENT_ADAPT_CALLS.load(Ordering::Relaxed),
        HMAC_PROCESS_DATA_MSG_CALLS.load(Ordering::Relaxed),
        HMAC_RX_DATA_CALLS.load(Ordering::Relaxed),
    ]
}

pub(crate) fn rx_status_counts() -> [u32; 6] {
    [
        RX_STATUS_SUCCESS.load(Ordering::Relaxed),
        RX_STATUS_DUPLICATE.load(Ordering::Relaxed),
        RX_STATUS_KEY_FAILURE.load(Ordering::Relaxed),
        RX_STATUS_CCMP_MIC_FAILURE.load(Ordering::Relaxed),
        RX_STATUS_CCMP_REPLAY_FAILURE.load(Ordering::Relaxed),
        RX_STATUS_OTHER.load(Ordering::Relaxed),
    ]
}

#[cfg(target_arch = "riscv32")]
fn record_rx_status(rx_status: *const c_void) {
    if rx_status.is_null() {
        RX_STATUS_OTHER.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // SAFETY: `hal_rx_status_stru` is a packed four-byte input structure in
    // the vendor ABI. Byte zero stores cipher type in the low nibble and the
    // descriptor status in the high nibble. The pointer remains live for the
    // duration of `dmac_rx_prepare_data_patch`.
    let status = unsafe { rx_status.cast::<u8>().read() } >> 4;
    match status {
        1 => &RX_STATUS_SUCCESS,
        2 => &RX_STATUS_DUPLICATE,
        4 | 12 => &RX_STATUS_KEY_FAILURE,
        5 => &RX_STATUS_CCMP_MIC_FAILURE,
        8 => &RX_STATUS_CCMP_REPLAY_FAILURE,
        _ => &RX_STATUS_OTHER,
    }
    .fetch_add(1, Ordering::Relaxed);
}

/// Count a DMAC completion callback and preserve the vendor implementation.
///
/// The count is deliberately aggregate: one callback may complete more than
/// one descriptor. The wrapper performs no allocation, locking, frame parsing,
/// or user callback.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_dmac_tx_complete_event_handler")]
pub unsafe extern "C" fn dmac_tx_complete_event_handler(
    vap: *mut c_void,
    message: *mut c_void,
) -> i32 {
    TX_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the linker redirects the exact vendor ABI through `--wrap` and
    // `__real_*` resolves to the original mask-ROM implementation.
    unsafe { vendor_dmac_tx_complete_event_handler(vap, message) }
}

/// Count a call entering the DMAC RX preparation path and forward it.
///
/// The count includes management and internal driver traffic. It is not a
/// count of Ethernet frames delivered to the Rust L2 device.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_dmac_rx_prepare_data_patch")]
pub unsafe extern "C" fn dmac_rx_prepare_data_patch(
    netbuf: *mut c_void,
    rx_ctl: *mut c_void,
    vap_id: u32,
    rx_status: *mut c_void,
    process_flag: *mut c_void,
) -> u32 {
    RX_PREPARES.fetch_add(1, Ordering::Relaxed);
    record_rx_status(rx_status);
    // SAFETY: the linker redirects the exact vendor ABI through `--wrap` and
    // this call preserves all arguments and the return value.
    let result = unsafe {
        vendor_dmac_rx_prepare_data_patch(netbuf, rx_ctl, vap_id, rx_status, process_flag)
    };
    RX_PREPARE_LAST_RESULT.store(result, Ordering::Relaxed);
    if result == 0 {
        RX_PREPARE_ZERO.fetch_add(1, Ordering::Relaxed);
    } else {
        RX_PREPARE_NONZERO.fetch_add(1, Ordering::Relaxed);
    }
    result
}

/// Count host-side RX event adaptation without inspecting the message.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_hmac_rx_data_event_adapt")]
pub unsafe extern "C" fn hmac_rx_data_event_adapt(vap: *mut c_void, message: *mut c_void) -> i32 {
    HMAC_DATA_EVENT_ADAPT_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the wrapper preserves the vendor declaration from
    // `hmac_rx_data_event.h` and forwards both opaque pointers unchanged.
    unsafe { vendor_hmac_rx_data_event_adapt(vap, message) }
}

/// Count host-side data-message processing without inspecting the message.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_hmac_rx_process_data_msg")]
pub unsafe extern "C" fn hmac_rx_process_data_msg(vap: *mut c_void, message: *mut c_void) -> i32 {
    HMAC_PROCESS_DATA_MSG_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the wrapper preserves the vendor declaration from
    // `hmac_rx_data_event.h` and forwards both opaque pointers unchanged.
    unsafe { vendor_hmac_rx_process_data_msg(vap, message) }
}

/// Count host-side data-frame processing without inspecting the netbuf.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_hmac_rx_data")]
pub unsafe extern "C" fn hmac_rx_data(vap: *mut c_void, netbuf: *mut c_void) -> u32 {
    HMAC_RX_DATA_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the wrapper preserves the vendor declaration from
    // `hmac_rx_data.h` and forwards both opaque pointers unchanged.
    unsafe { vendor_hmac_rx_data(vap, netbuf) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_are_monotonic() {
        let tx_before = tx_completions();
        let rx_before = rx_prepares();
        TX_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
        RX_PREPARES.fetch_add(1, Ordering::Relaxed);
        assert!(tx_completions() >= tx_before.saturating_add(1));
        assert!(rx_prepares() >= rx_before.saturating_add(1));
    }
}
