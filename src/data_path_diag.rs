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
static TX_SUBMISSION_TRACE_CONSUMED: AtomicU32 = AtomicU32::new(0);
static RX_PREPARES: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_ZERO: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_NONZERO: AtomicU32 = AtomicU32::new(0);
static RX_PREPARE_LAST_RESULT: AtomicU32 = AtomicU32::new(0);
static HMAC_DATA_EVENT_ADAPT_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_PROCESS_DATA_MSG_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_RX_DATA_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_TX_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_TX_LAST_STATUS: AtomicU32 = AtomicU32::new(0);
static HMAC_TX_STATUS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
static HMAC_TX_PROCESS_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_TX_PROCESS_LAST_STATUS: AtomicU32 = AtomicU32::new(0);
static HMAC_TX_PROCESS_STATUS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
static HMAC_TX_DATA_SEND_CALLS: AtomicU32 = AtomicU32::new(0);
static HMAC_TX_DATA_SEND_RETURNS: AtomicU32 = AtomicU32::new(0);
static FRW_HMAC_SEND_DATA_CALLS: AtomicU32 = AtomicU32::new(0);
static FRW_HMAC_SEND_DATA_LAST_STATUS: AtomicU32 = AtomicU32::new(0);
static FRW_HMAC_SEND_DATA_STATUS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
static DMAC_TX_DATA_EVENT_CALLS: AtomicU32 = AtomicU32::new(0);
static DMAC_TX_DATA_EVENT_LAST_STATUS: AtomicU32 = AtomicU32::new(0);
static DMAC_TX_DATA_EVENT_STATUS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
const DMAC_TX_QUEUE_COUNT: usize = 6;
static DMAC_TX_SOFTWARE_QUEUES: [AtomicU32; DMAC_TX_QUEUE_COUNT] =
    [const { AtomicU32::new(0) }; DMAC_TX_QUEUE_COUNT];
static DMAC_TX_HARDWARE_QUEUES: [AtomicU32; DMAC_TX_QUEUE_COUNT] =
    [const { AtomicU32::new(0) }; DMAC_TX_QUEUE_COUNT];
static DMAC_TX_MAC_QUEUE_STATUS: AtomicU32 = AtomicU32::new(0);
static DMAC_TX_MAC_EXT_QUEUE_STATUS: AtomicU32 = AtomicU32::new(0);
static DMAC_TX_QUEUE_SNAPSHOT_STAGE: AtomicU32 = AtomicU32::new(0);
static DMAC_TX_SCHEDULE_HOOK: AtomicU32 = AtomicU32::new(0);

// This private callback ID is sampled only after a TX completion. Reading it
// in the enqueue wrapper changes the verified RF text layout before init.
const FRD_ROM_TX_SCH: u32 = 239;

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
    #[link_name = "__real_hmac_tx_lan_to_wlan_no_tcp_opt_etc"]
    fn vendor_hmac_tx_lan_to_wlan_no_tcp_opt_etc(vap: *mut c_void, netbuf: *mut c_void) -> u32;
    #[link_name = "__real_hmac_tx_process_data"]
    fn vendor_hmac_tx_process_data(
        hal_device: *mut c_void,
        vap: *mut c_void,
        netbuf: *mut c_void,
    ) -> u32;
    #[link_name = "__real_hmac_tx_data_send"]
    fn vendor_hmac_tx_data_send(tx_data: *mut c_void, buffers: *mut c_void);
    #[link_name = "__real_frw_hmac_send_data"]
    fn vendor_frw_hmac_send_data(netbuf: *mut c_void, vap_id: u8, data_type: u8) -> u32;
    #[link_name = "__real_dmac_tx_process_data_event"]
    fn vendor_dmac_tx_process_data_event(vap: *mut c_void, message: *mut c_void) -> i32;
    fn mac_res_get_hmac_vap(index: u8) -> *mut c_void;
    fn mac_vap_get_hmac_user_by_addr_etc(vap: *mut c_void, address: *const u8) -> *mut c_void;
    fn hmac_user_get_ps_mode(user: *const c_void) -> u8;
    fn hmac_psm_is_psm_empty(user: *mut c_void) -> u8;
    fn hmac_psm_tid_mpdu_num(user: *const c_void) -> u32;
    fn hal_chip_get_hal_device() -> *mut c_void;
    fn frw_get_rom_cb(function_id: u32) -> *mut c_void;
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

fn is_normal_data_queue(queue: u8) -> bool {
    queue & 0x07 == 0
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

fn record_tx_submission(echo: u32, timestamp_ms: u32) {
    let total = TX_SUBMISSION_TRACE_TOTAL.fetch_add(1, Ordering::AcqRel);
    let slot = total as usize % TX_COMPLETION_TRACE_SLOTS;
    TX_SUBMISSION_TRACE[slot].store(echo, Ordering::Release);
    TX_SUBMISSION_TIME_TRACE[slot].store(timestamp_ms, Ordering::Release);
}

pub(crate) fn record_tx_frame_submission(frame: &[u8]) {
    record_tx_submission(
        classify_udp_echo(frame).unwrap_or(0),
        crate::uapi::monotonic_ms() as u32,
    );
}

fn consume_tx_submission() -> u32 {
    let total = TX_SUBMISSION_TRACE_TOTAL.load(Ordering::Acquire);
    let oldest = total.saturating_sub(TX_COMPLETION_TRACE_SLOTS as u32);
    let consumed = TX_SUBMISSION_TRACE_CONSUMED
        .fetch_max(oldest, Ordering::AcqRel)
        .max(oldest);
    if consumed >= total {
        return 0;
    }
    let sequence = TX_SUBMISSION_TRACE_CONSUMED.fetch_add(1, Ordering::AcqRel);
    TX_SUBMISSION_TRACE[sequence as usize % TX_COMPLETION_TRACE_SLOTS].load(Ordering::Acquire)
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

pub(crate) fn hmac_tx_diagnostics() -> (u32, u32, [u32; 16]) {
    (
        HMAC_TX_CALLS.load(Ordering::Relaxed),
        HMAC_TX_LAST_STATUS.load(Ordering::Relaxed),
        core::array::from_fn(|status| HMAC_TX_STATUS[status].load(Ordering::Relaxed)),
    )
}

pub(crate) fn hmac_tx_process_diagnostics() -> (u32, u32, [u32; 16]) {
    (
        HMAC_TX_PROCESS_CALLS.load(Ordering::Relaxed),
        HMAC_TX_PROCESS_LAST_STATUS.load(Ordering::Relaxed),
        core::array::from_fn(|status| HMAC_TX_PROCESS_STATUS[status].load(Ordering::Relaxed)),
    )
}

pub(crate) fn hmac_tx_data_send_diagnostics() -> [u32; 2] {
    [
        HMAC_TX_DATA_SEND_CALLS.load(Ordering::Relaxed),
        HMAC_TX_DATA_SEND_RETURNS.load(Ordering::Relaxed),
    ]
}

pub(crate) fn frw_hmac_send_data_diagnostics() -> (u32, u32, [u32; 16]) {
    (
        FRW_HMAC_SEND_DATA_CALLS.load(Ordering::Relaxed),
        FRW_HMAC_SEND_DATA_LAST_STATUS.load(Ordering::Relaxed),
        core::array::from_fn(|status| FRW_HMAC_SEND_DATA_STATUS[status].load(Ordering::Relaxed)),
    )
}

pub(crate) fn dmac_tx_data_event_diagnostics() -> (u32, u32, [u32; 16]) {
    (
        DMAC_TX_DATA_EVENT_CALLS.load(Ordering::Relaxed),
        DMAC_TX_DATA_EVENT_LAST_STATUS.load(Ordering::Relaxed),
        core::array::from_fn(|status| DMAC_TX_DATA_EVENT_STATUS[status].load(Ordering::Relaxed)),
    )
}

pub(crate) fn dmac_tx_queue_diagnostics() -> ([u32; DMAC_TX_QUEUE_COUNT], [u32; DMAC_TX_QUEUE_COUNT])
{
    (
        core::array::from_fn(|queue| DMAC_TX_SOFTWARE_QUEUES[queue].load(Ordering::Acquire)),
        core::array::from_fn(|queue| DMAC_TX_HARDWARE_QUEUES[queue].load(Ordering::Acquire)),
    )
}

pub(crate) fn dmac_tx_mac_queue_status() -> [u32; 2] {
    [
        DMAC_TX_MAC_QUEUE_STATUS.load(Ordering::Acquire),
        DMAC_TX_MAC_EXT_QUEUE_STATUS.load(Ordering::Acquire),
    ]
}

pub(crate) fn dmac_tx_queue_snapshot_metadata() -> [u32; 2] {
    [
        DMAC_TX_QUEUE_SNAPSHOT_STAGE.load(Ordering::Acquire),
        DMAC_TX_SCHEDULE_HOOK.load(Ordering::Acquire),
    ]
}

fn pack_dmac_tx_queue(valid: bool, list_empty: bool, status: u8, ppdu: u8, mpdu: u8) -> u32 {
    (u32::from(valid) << 31)
        | (u32::from(list_empty) << 30)
        | (u32::from(status) << 16)
        | (u32::from(ppdu) << 8)
        | u32::from(mpdu)
}

#[cfg(target_arch = "riscv32")]
unsafe fn snapshot_dmac_tx_queue_state(
    vap: *mut c_void,
    software_values: &[AtomicU32; DMAC_TX_QUEUE_COUNT],
    hardware_values: &[AtomicU32; DMAC_TX_QUEUE_COUNT],
    mac_status: &AtomicU32,
    mac_ext_status: &AtomicU32,
) {
    const SOFTWARE_QUEUE_OFFSET: usize = 456;
    const HARDWARE_QUEUE_OFFSET: usize = 40;
    const QUEUE_SIZE: usize = 12;
    const MAC_TX_QUEUE_STATUS: *const u32 = 0x4421_0850 as *const u32;
    const MAC_TX_EXT_QUEUE_STATUS: *const u32 = 0x4421_084c as *const u32;

    unsafe fn snapshot(base: *const u8, queue: usize) -> u32 {
        if base.is_null() {
            return 0;
        }
        let header = unsafe { base.add(queue * QUEUE_SIZE) };
        let next = unsafe { header.cast::<u32>().read_volatile() };
        let previous = unsafe { header.add(4).cast::<u32>().read_volatile() };
        let header_address = header as usize as u32;
        let status = unsafe { header.add(8).read_volatile() };
        let ppdu = unsafe { header.add(9).read_volatile() };
        let mpdu = unsafe { header.add(10).read_volatile() };
        pack_dmac_tx_queue(
            true,
            next == header_address && previous == header_address,
            status,
            ppdu,
            mpdu,
        )
    }

    if !vap.is_null() {
        let software = unsafe { vap.cast::<u8>().add(SOFTWARE_QUEUE_OFFSET) };
        for (queue, value) in software_values.iter().enumerate() {
            value.store(unsafe { snapshot(software, queue) }, Ordering::Release);
        }
    }

    // `hal_get_tx_q_status()` reads these MAC status registers before ROM
    // scheduling dequeues a DMAC software queue. Keep the raw words so a
    // stalled software queue can be distinguished from a scheduler decision
    // that was blocked by hardware state.
    mac_status.store(
        unsafe { MAC_TX_QUEUE_STATUS.read_volatile() },
        Ordering::Release,
    );
    mac_ext_status.store(
        unsafe { MAC_TX_EXT_QUEUE_STATUS.read_volatile() },
        Ordering::Release,
    );

    // The original WS63 DWARF layout places `hal_to_dmac_device_stru::tx_dscr_queue`
    // at byte 40. The six entries use the same 12-byte queue-header layout.
    let device = unsafe { hal_chip_get_hal_device() };
    if !device.is_null() {
        let hardware = unsafe { device.cast::<u8>().add(HARDWARE_QUEUE_OFFSET) };
        for (queue, value) in hardware_values.iter().enumerate() {
            value.store(unsafe { snapshot(hardware, queue) }, Ordering::Release);
        }
    }
}

#[cfg(target_arch = "riscv32")]
unsafe fn snapshot_dmac_tx_queues(vap: *mut c_void) {
    unsafe {
        snapshot_dmac_tx_queue_state(
            vap,
            &DMAC_TX_SOFTWARE_QUEUES,
            &DMAC_TX_HARDWARE_QUEUES,
            &DMAC_TX_MAC_QUEUE_STATUS,
            &DMAC_TX_MAC_EXT_QUEUE_STATUS,
        )
    };
    DMAC_TX_QUEUE_SNAPSHOT_STAGE.store(1, Ordering::Release);
}

#[cfg(target_arch = "riscv32")]
unsafe fn snapshot_dmac_tx_completion_queues(vap: *mut c_void) {
    unsafe {
        snapshot_dmac_tx_queue_state(
            vap,
            &DMAC_TX_SOFTWARE_QUEUES,
            &DMAC_TX_HARDWARE_QUEUES,
            &DMAC_TX_MAC_QUEUE_STATUS,
            &DMAC_TX_MAC_EXT_QUEUE_STATUS,
        )
    };
    DMAC_TX_SCHEDULE_HOOK.store(
        unsafe { frw_get_rom_cb(FRD_ROM_TX_SCH) } as usize as u32,
        Ordering::Release,
    );
    DMAC_TX_QUEUE_SNAPSHOT_STAGE.store(2, Ordering::Release);
}

/// Observe the HMAC Ethernet-to-WLAN boundary and preserve its return status.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_hmac_tx_lan_to_wlan_no_tcp_opt_etc")]
pub unsafe extern "C" fn hmac_tx_lan_to_wlan_no_tcp_opt_etc(
    vap: *mut c_void,
    netbuf: *mut c_void,
) -> u32 {
    HMAC_TX_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the linker redirects the exact vendor ABI through `--wrap`.
    let status = unsafe { vendor_hmac_tx_lan_to_wlan_no_tcp_opt_etc(vap, netbuf) };
    HMAC_TX_LAST_STATUS.store(status, Ordering::Relaxed);
    HMAC_TX_STATUS[usize::from((status & 0x0f) as u8)].fetch_add(1, Ordering::Relaxed);
    status
}

/// Observe the HMAC data-processing boundary and preserve its return status.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_hmac_tx_process_data")]
pub unsafe extern "C" fn hmac_tx_process_data(
    hal_device: *mut c_void,
    vap: *mut c_void,
    netbuf: *mut c_void,
) -> u32 {
    HMAC_TX_PROCESS_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the signature matches `hmac_tx_mpdu_adapt.h`, and the linker
    // redirects the exact vendor implementation through `--wrap`.
    let status = unsafe { vendor_hmac_tx_process_data(hal_device, vap, netbuf) };
    HMAC_TX_PROCESS_LAST_STATUS.store(status, Ordering::Relaxed);
    HMAC_TX_PROCESS_STATUS[usize::from((status & 0x0f) as u8)].fetch_add(1, Ordering::Relaxed);
    status
}

/// Observe entry and return at the final HMAC data-send boundary.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_hmac_tx_data_send")]
pub unsafe extern "C" fn hmac_tx_data_send(tx_data: *mut c_void, buffers: *mut c_void) {
    HMAC_TX_DATA_SEND_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the signature matches `hmac_tx_mpdu_adapt.h`, and both opaque
    // pointers are forwarded unchanged to the vendor implementation.
    unsafe { vendor_hmac_tx_data_send(tx_data, buffers) };
    HMAC_TX_DATA_SEND_RETURNS.fetch_add(1, Ordering::Relaxed);
}

/// Observe the HMAC-to-DMAC FRW submission boundary and preserve its status.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_frw_hmac_send_data")]
pub unsafe extern "C" fn frw_hmac_send_data(netbuf: *mut c_void, vap_id: u8, data_type: u8) -> u32 {
    FRW_HMAC_SEND_DATA_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the signature matches `frw_hmac_adapt.h`, and all arguments are
    // forwarded unchanged to the vendor implementation.
    let status = unsafe { vendor_frw_hmac_send_data(netbuf, vap_id, data_type) };
    FRW_HMAC_SEND_DATA_LAST_STATUS.store(status, Ordering::Relaxed);
    FRW_HMAC_SEND_DATA_STATUS[usize::from((status & 0x0f) as u8)].fetch_add(1, Ordering::Relaxed);
    status
}

/// Observe the registered host-to-device data event without changing dispatch.
///
/// The vendor `g_msg_entry` table registers `dmac_tx_process_data_event` for
/// message `0x42` through `frw_dmac_msg_hook_register`. Its callback type is
/// `osal_s32 (*)(dmac_vap_stru *, frw_msg *)` in `frw_dmac_rom.h`.
#[cfg(target_arch = "riscv32")]
#[unsafe(export_name = "__wrap_dmac_tx_process_data_event")]
pub unsafe extern "C" fn dmac_tx_process_data_event(vap: *mut c_void, message: *mut c_void) -> i32 {
    DMAC_TX_DATA_EVENT_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the signature is the registered `dmac_frw_msg_callback` ABI;
    // both opaque pointers are forwarded unchanged to the vendor callback.
    let status = unsafe { vendor_dmac_tx_process_data_event(vap, message) };
    // SAFETY: the queue offsets and 12-byte queue-header layout are taken from
    // the original WS63 ELF DWARF and agree with the mask-ROM address arithmetic.
    unsafe { snapshot_dmac_tx_queues(vap) };
    DMAC_TX_DATA_EVENT_LAST_STATUS.store(status as u32, Ordering::Relaxed);
    DMAC_TX_DATA_EVENT_STATUS[usize::from((status as u32 & 0x0f) as u8)]
        .fetch_add(1, Ordering::Relaxed);
    status
}

/// Read the associated station's vendor power-save state without modifying it.
///
/// Returns `[found, vap_index, ps_mode, ps_queue_empty, tid_mpdu_count]`.
#[cfg(target_arch = "riscv32")]
pub(crate) fn associated_station_ps(address: Option<[u8; 6]>) -> [u32; 5] {
    let Some(address) = address else {
        return [0, u32::MAX, u32::MAX, u32::MAX, 0];
    };
    // WS63 has one device with three service VAPs plus one configuration VAP.
    for vap_index in 0..4 {
        // SAFETY: these are read-only vendor resource lookups. The caller runs
        // in thread context, and null handles are rejected before dereference.
        let vap = unsafe { mac_res_get_hmac_vap(vap_index) };
        if vap.is_null() {
            continue;
        }
        // SAFETY: `address` remains live for the duration of the call.
        let user = unsafe { mac_vap_get_hmac_user_by_addr_etc(vap, address.as_ptr()) };
        if user.is_null() {
            continue;
        }
        // SAFETY: the resource lookup returned the live user owned by this VAP.
        return unsafe {
            [
                1,
                u32::from(vap_index),
                u32::from(hmac_user_get_ps_mode(user)),
                u32::from(hmac_psm_is_psm_empty(user)),
                hmac_psm_tid_mpdu_num(user),
            ]
        };
    }
    [0, u32::MAX, u32::MAX, u32::MAX, 0]
}

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn associated_station_ps(_address: Option<[u8; 6]>) -> [u32; 5] {
    [0, u32::MAX, u32::MAX, u32::MAX, 0]
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
    let mut normal_data_completion = false;
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
                // Beacon and management completions would evict the ten-packet
                // local probe before it can be printed. The aggregate callback
                // and status counters still include them; the bounded timeline
                // intentionally retains the normal data queue. Rust submits
                // this queue in FIFO order, so the matching identity can be
                // consumed without following a vendor-private packet pointer.
                if is_normal_data_queue(queue) {
                    normal_data_completion = true;
                    record_tx_completion_trace(
                        status,
                        sequence_word & (1 << 17) != 0,
                        flags >> 4,
                        queue,
                        (sequence_word >> 20) as u16,
                        unsafe { descriptor.add(9).read_unaligned() },
                        crate::uapi::monotonic_ms() as u32,
                        consume_tx_submission(),
                    );
                }
            }
        }
    }
    // SAFETY: the linker redirects the exact vendor ABI through `--wrap` and
    // `__real_*` resolves to the original mask-ROM implementation.
    let status = unsafe { vendor_dmac_tx_complete_event_handler(vap, message) };
    if normal_data_completion {
        // Management/beacon completion callbacks do not promise the data-VAP
        // layout used below. A normal data descriptor establishes that ABI;
        // after the vendor handler returns it has also attempted to schedule
        // the next queued data descriptor.
        unsafe { snapshot_dmac_tx_completion_queues(vap) };
    }
    status
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
        record_tx_submission(0xa000_0007, 0x42);
        record_tx_completion_trace(
            1,
            true,
            2,
            3,
            0x123,
            0x4567_89ab,
            0x43,
            consume_tx_submission(),
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

    #[test]
    fn normal_data_queue_ignores_descriptor_flag_bits() {
        assert!(is_normal_data_queue(0));
        assert!(is_normal_data_queue(0x80));
        assert!(!is_normal_data_queue(4));
        assert!(!is_normal_data_queue(0x84));
    }

    #[test]
    fn packs_dmac_queue_state_without_losing_counts() {
        assert_eq!(pack_dmac_tx_queue(true, true, 2, 3, 4), 0xc002_0304);
        assert_eq!(
            pack_dmac_tx_queue(true, false, 0xff, 0xfe, 0xfd),
            0x80ff_fefd
        );
    }

    #[test]
    fn uses_the_powersave_off_tx_scheduler_callback_id() {
        assert_eq!(FRD_ROM_TX_SCH, 239);
    }
}
