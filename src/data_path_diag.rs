//! Bounded packet-path counters for low-disturbance silicon diagnosis.

#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;
use portable_atomic::{AtomicU32, Ordering};

static TX_COMPLETIONS: AtomicU32 = AtomicU32::new(0);
static TX_COMPLETION_STATUS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
const TX_COMPLETION_TRACE_SLOTS: usize = 18;
static TX_COMPLETION_TRACE_TOTAL: AtomicU32 = AtomicU32::new(0);
static TX_COMPLETION_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
    [const { AtomicU32::new(0) }; TX_COMPLETION_TRACE_SLOTS];
static TX_COMPLETION_PN_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
    [const { AtomicU32::new(0) }; TX_COMPLETION_TRACE_SLOTS];
static TX_COMPLETION_TIME_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
    [const { AtomicU32::new(0) }; TX_COMPLETION_TRACE_SLOTS];
static TX_COMPLETION_ECHO_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
    [const { AtomicU32::new(0) }; TX_COMPLETION_TRACE_SLOTS];
static TX_SUBMISSION_TRACE_TOTAL: AtomicU32 = AtomicU32::new(0);
static TX_SUBMISSION_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
    [const { AtomicU32::new(0) }; TX_COMPLETION_TRACE_SLOTS];
static TX_SUBMISSION_TIME_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
    [const { AtomicU32::new(0) }; TX_COMPLETION_TRACE_SLOTS];
static TX_SUBMISSION_SKB_TRACE: [AtomicU32; TX_COMPLETION_TRACE_SLOTS] =
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
    fn oal_netbuf_mac_header(netbuf: *const c_void) -> *const u8;
    fn oal_netbuf_skb(netbuf: *const c_void) -> *const u8;
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

#[allow(dead_code)]
pub(crate) fn tx_timeline() -> crate::TxTimelineDiagnostics {
    crate::TxTimelineDiagnostics {
        submission_total: TX_SUBMISSION_TRACE_TOTAL.load(Ordering::Acquire),
        completion_total: TX_COMPLETION_TRACE_TOTAL.load(Ordering::Acquire),
        callback_total: TX_COMPLETIONS.load(Ordering::Acquire),
        submissions: core::array::from_fn(|slot| TX_SUBMISSION_TRACE[slot].load(Ordering::Acquire)),
        submission_time_ms: core::array::from_fn(|slot| {
            TX_SUBMISSION_TIME_TRACE[slot].load(Ordering::Acquire)
        }),
        completions: core::array::from_fn(|slot| TX_COMPLETION_TRACE[slot].load(Ordering::Acquire)),
        packet_number_lsb: core::array::from_fn(|slot| {
            TX_COMPLETION_PN_TRACE[slot].load(Ordering::Acquire)
        }),
        completion_time_ms: core::array::from_fn(|slot| {
            TX_COMPLETION_TIME_TRACE[slot].load(Ordering::Acquire)
        }),
        completion_echo: core::array::from_fn(|slot| {
            TX_COMPLETION_ECHO_TRACE[slot].load(Ordering::Acquire)
        }),
    }
}

fn record_tx_completion_status(status: u8) {
    TX_COMPLETION_STATUS[usize::from(status & 0x0f)].fetch_add(1, Ordering::Relaxed);
}

#[allow(clippy::too_many_arguments)]
fn record_tx_completion_trace(
    status: u8,
    sequence_valid: bool,
    tid: u8,
    queue: u8,
    sequence: u16,
    packet_number_lsb: u32,
    timestamp_ms: u32,
    echo: u32,
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
    TX_COMPLETION_TIME_TRACE[slot].store(timestamp_ms, Ordering::Release);
    TX_COMPLETION_ECHO_TRACE[slot].store(echo, Ordering::Release);
}

fn record_tx_submission(skb: usize, echo: u32, timestamp_ms: u32) {
    let total = TX_SUBMISSION_TRACE_TOTAL.fetch_add(1, Ordering::AcqRel);
    let slot = total as usize % TX_COMPLETION_TRACE_SLOTS;
    TX_SUBMISSION_TRACE[slot].store(echo, Ordering::Release);
    TX_SUBMISSION_TIME_TRACE[slot].store(timestamp_ms, Ordering::Release);
    TX_SUBMISSION_SKB_TRACE[slot].store(skb as u32, Ordering::Release);
}

pub(crate) fn record_tx_frame_submission(skb: usize, frame: &[u8]) {
    record_tx_submission(
        skb,
        classify_udp_echo(frame).unwrap_or(0),
        crate::uapi::monotonic_ms() as u32,
    );
}

fn submission_for_skb(skb: usize) -> u32 {
    let total = TX_SUBMISSION_TRACE_TOTAL.load(Ordering::Acquire);
    let retained = total.min(TX_COMPLETION_TRACE_SLOTS as u32);
    for age in 0..retained {
        let sequence = total.wrapping_sub(age + 1);
        let slot = sequence as usize % TX_COMPLETION_TRACE_SLOTS;
        if TX_SUBMISSION_SKB_TRACE[slot].load(Ordering::Acquire) == skb as u32 {
            return TX_SUBMISSION_TRACE[slot].load(Ordering::Acquire);
        }
    }
    0
}

// Bit 31 marks a one-byte UDP echo payload. Bits 29:28 encode request (1) or
// reply (2); the low byte is the application sequence.
fn classify_udp_echo(frame: &[u8]) -> Option<u32> {
    const ETHERNET_HEADER: usize = 14;
    const UDP_HEADER: usize = 8;
    if frame.len() < ETHERNET_HEADER + 20 + UDP_HEADER + 1
        || frame[12..14] != [0x08, 0x00]
        || frame[14] >> 4 != 4
        || frame[23] != 17
    {
        return None;
    }
    let ip_header = usize::from(frame[14] & 0x0f) * 4;
    let udp = ETHERNET_HEADER + ip_header;
    if ip_header < 20 || udp + UDP_HEADER + 1 > frame.len() {
        return None;
    }
    let udp_length = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
    if udp_length != UDP_HEADER + 1 || udp + udp_length > frame.len() {
        return None;
    }
    let source = u16::from_be_bytes([frame[udp], frame[udp + 1]]);
    let destination = u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]);
    let direction = if destination == 9 {
        1
    } else if source == 9 {
        2
    } else {
        return None;
    };
    Some(0x8000_0000 | (direction << 28) | u32::from(frame[udp + UDP_HEADER]))
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
                let descriptor_skb = unsafe { descriptor.add(2).read_unaligned() } as usize;
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
                let frame = if descriptor_skb == 0 {
                    core::ptr::null()
                } else {
                    unsafe { oal_netbuf_mac_header(descriptor_skb as *const c_void) }
                };
                // Beacon and management completions would evict the ten-packet
                // local probe before it can be printed. The aggregate callback
                // and status counters still include them; the bounded timeline
                // intentionally retains data MPDUs only.
                if !frame.is_null() && unsafe { frame.read() } & 0x0c == 0x08 {
                    record_tx_completion_trace(
                        status,
                        sequence_word & (1 << 17) != 0,
                        flags >> 4,
                        queue,
                        (sequence_word >> 20) as u16,
                        unsafe { descriptor.add(9).read_unaligned() },
                        crate::uapi::monotonic_ms() as u32,
                        {
                            // `oal_netbuf_skb` maps the packet-RAM descriptor
                            // back to the host skb observed before encapsulation.
                            let skb = unsafe { oal_netbuf_skb(descriptor_skb as *const c_void) };
                            submission_for_skb(skb as usize)
                        },
                    );
                }
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
        record_tx_submission(0x1234, 0xa000_0007, 0x42);
        record_tx_completion_trace(
            1,
            true,
            2,
            3,
            0x123,
            0x4567_89ab,
            0x43,
            submission_for_skb(0x1234),
        );
        RX_PREPARES.fetch_add(1, Ordering::Relaxed);
        assert!(tx_completions() >= tx_before.saturating_add(1));
        assert_ne!(tx_completion_status()[1], 0);
        let (trace_total, trace, packet_numbers) = tx_completion_trace();
        assert_ne!(trace_total, 0);
        assert!(trace.contains(&0x1930_0123));
        assert!(packet_numbers.contains(&0x4567_89ab));
        let timeline = tx_timeline();
        assert_ne!(timeline.submission_total, 0);
        assert_ne!(timeline.completion_total, 0);
        assert!(timeline.submission_time_ms.contains(&0x42));
        assert!(timeline.completion_time_ms.contains(&0x43));
        assert!(timeline.completion_echo.contains(&0xa000_0007));
        assert!(rx_prepares() >= rx_before.saturating_add(1));
    }

    #[test]
    fn classifies_one_byte_udp_echo_direction() {
        let mut frame = [0_u8; 43];
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        frame[23] = 17;
        frame[34..36].copy_from_slice(&1234_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&9_u16.to_be_bytes());
        frame[38..40].copy_from_slice(&9_u16.to_be_bytes());
        frame[42] = 7;
        assert_eq!(classify_udp_echo(&frame), Some(0x9000_0007));

        frame[34..36].copy_from_slice(&9_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&1234_u16.to_be_bytes());
        assert_eq!(classify_udp_echo(&frame), Some(0xa000_0007));
        frame[38..40].copy_from_slice(&10_u16.to_be_bytes());
        assert_eq!(classify_udp_echo(&frame), None);
    }
}
