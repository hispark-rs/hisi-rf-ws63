//! Bounded packet-path counters for low-disturbance silicon diagnosis.

#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;
use portable_atomic::{AtomicU32, Ordering};

static TX_COMPLETIONS: AtomicU32 = AtomicU32::new(0);
static TX_COMPLETION_STATUS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
const TX_COMPLETION_TRACE_SLOTS: usize = 32;
static TX_COMPLETION_TRACE_TOTAL: AtomicU32 = AtomicU32::new(0);
static TX_COMPLETION_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
    [const { AtomicU32::new(0) }; TX_COMPLETION_TRACE_SLOTS];
static TX_COMPLETION_PN_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
    [const { AtomicU32::new(0) }; TX_COMPLETION_TRACE_SLOTS];
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

#[allow(dead_code)]
pub(crate) fn tx_completion_trace() -> (
    u32,
    [u32; TX_COMPLETION_TRACE_SLOTS],
    [u32; TX_COMPLETION_TRACE_SLOTS],
) {
    (
        TX_COMPLETION_TRACE_TOTAL.load(Ordering::Acquire),
        core::array::from_fn(|slot| TX_COMPLETION_TRACE[slot].load(Ordering::Acquire)),
        core::array::from_fn(|slot| TX_COMPLETION_PN_TRACE[slot].load(Ordering::Acquire)),
    )
}

fn record_tx_completion_status(status: u8) {
    TX_COMPLETION_STATUS[usize::from(status & 0x0f)].fetch_add(1, Ordering::Relaxed);
}

fn record_tx_completion_trace(
    status: u8,
    sequence_valid: bool,
    tid: u8,
    queue: u8,
    sequence: u16,
    packet_number_lsb: u32,
) {
    let total = TX_COMPLETION_TRACE_TOTAL.fetch_add(1, Ordering::AcqRel);
    let slot = total as usize % TX_COMPLETION_TRACE_SLOTS;
    let packed = (u32::from(status & 0x0f) << 28)
        | (u32::from(sequence_valid) << 27)
        | (u32::from(tid & 0x0f) << 23)
        | (u32::from(queue & 0x07) << 20)
        | u32::from(sequence & 0x0fff);
    TX_COMPLETION_TRACE[slot].store(packed, Ordering::Release);
    TX_COMPLETION_PN_TRACE[slot].store(packet_number_lsb, Ordering::Release);
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
                let status = (control >> 28) as u8;
                record_tx_completion_status(status);
                // `hal_tx_dscr_stru::data` begins 16 bytes into the software
                // descriptor. Hardware word 4 carries the 12-bit sequence
                // number and its validity bit. Reading the descriptor avoids
                // following a packet-buffer pointer during early beacon TX.
                let sequence_word = unsafe { descriptor.add(8).read_unaligned() };
                let flags = unsafe { descriptor.cast::<u8>().add(15).read() };
                let queue = unsafe { descriptor.cast::<u8>().add(14).read() };
                record_tx_completion_trace(
                    status,
                    sequence_word & (1 << 17) != 0,
                    flags >> 4,
                    queue,
                    (sequence_word >> 20) as u16,
                    unsafe { descriptor.add(9).read_unaligned() },
                );
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
        record_tx_completion_trace(1, true, 2, 3, 0x123, 0x4567_89ab);
        RX_PREPARES.fetch_add(1, Ordering::Relaxed);
        assert!(tx_completions() >= tx_before.saturating_add(1));
        assert_ne!(tx_completion_status()[1], 0);
        let (trace_total, trace, packet_numbers) = tx_completion_trace();
        assert_ne!(trace_total, 0);
        assert!(trace.contains(&0x1930_0123));
        assert!(packet_numbers.contains(&0x4567_89ab));
        assert!(rx_prepares() >= rx_before.saturating_add(1));
    }
}
