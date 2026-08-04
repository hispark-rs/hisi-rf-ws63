//! Bounded packet-path counters for low-disturbance silicon diagnosis.

#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;
use portable_atomic::{AtomicU32, Ordering};

static TX_COMPLETIONS: AtomicU32 = AtomicU32::new(0);
static TX_COMPLETION_STATUS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
static RX_PREPARES: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_ZERO: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_NONZERO: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_LAST_RESULT: AtomicU32 = AtomicU32::new(0);
static HMAC_DATA_EVENT_ADAPT_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_PROCESS_DATA_MSG_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_RX_DATA_CALLS: AtomicU32 = AtomicU32::new(0);

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

pub(crate) fn tx_completion_status() -> [u32; 16] {
    core::array::from_fn(|status| TX_COMPLETION_STATUS[status].load(Ordering::Relaxed))
}

fn record_tx_completion_status(status: u8) {
    TX_COMPLETION_STATUS[usize::from(status & 0x0f)].fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn rx_prepares() -> u32 {
    RX_PREPARES.load(Ordering::Relaxed)
}

#[allow(dead_code)]
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
    if !message.is_null() {
        // `frw_msg.data` points at a completion record whose first word is the
        // hardware descriptor. Descriptor word 0 starts 16 bytes later; its
        // high nibble is `hal_tx_dscr_status_enum`.
        let data = unsafe { message.cast::<*const u32>().read_unaligned() };
        if !data.is_null() {
            let descriptor = unsafe { data.read_unaligned() } as *const u32;
            if !descriptor.is_null() {
                let control = unsafe { descriptor.add(4).read_unaligned() };
                record_tx_completion_status((control >> 28) as u8);
            }
        }
    }
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
        record_tx_completion_status(1);
        RX_PREPARES.fetch_add(1, Ordering::Relaxed);
        assert!(tx_completions() >= tx_before.saturating_add(1));
        assert_ne!(tx_completion_status()[1], 0);
        assert!(rx_prepares() >= rx_before.saturating_add(1));
    }
}
