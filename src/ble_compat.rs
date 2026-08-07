//! Bounded runtime and platform ABI required by the pinned WS63 BLE archives.
//!
//! This module is not a LiteOS backend. It translates only the symbols in the
//! archive-bound BLE B1 profile to native runtime, allocator, timer and queue
//! services. Optional vendor diagnostics are explicit sinks. Unsupported
//! unified-cipher and PKE operations fail instead of silently pretending that
//! key setup or cryptographic work succeeded.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(non_snake_case)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::num::{NonZeroU32, NonZeroUsize};
use hisi_rf_rtos_driver::{MutexHandle, SemaphoreHandle, WaitOutcome, WaitTimeout};

const OK: u32 = 0;
const ERROR: u32 = 1;
const OS_OK: c_int = 0;
const OS_ERROR: c_int = -1;
const OS_ERROR_TIMEOUT: c_int = -2;
const OS_ERROR_PARAMETER: c_int = -4;
const WAIT_FOREVER: u32 = u32::MAX;

fn wait_timeout(ticks: u32) -> WaitTimeout {
    if ticks == WAIT_FOREVER {
        WaitTimeout::Forever
    } else {
        WaitTimeout::from_millis(ticks)
    }
}

fn semaphore(raw: u32) -> Option<SemaphoreHandle> {
    let raw = NonZeroUsize::new(raw as usize)?;
    // SAFETY: this module only publishes runtime-created semaphore handles.
    Some(unsafe { SemaphoreHandle::from_raw(raw) })
}

fn mutex(raw: u32) -> Option<MutexHandle> {
    let raw = NonZeroUsize::new(raw as usize)?;
    // SAFETY: this module only publishes runtime-created mutex handles.
    Some(unsafe { MutexHandle::from_raw(raw) })
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_MS2Tick(milliseconds: u32) -> u32 {
    milliseconds
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_Tick2MS(ticks: u32) -> u32 {
    ticks
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_TickCountGet() -> u64 {
    crate::osal_ext::osal_get_jiffies()
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_TaskDelay(ticks: u32) -> u32 {
    if ticks == 0 {
        let _ = hisi_rf_rtos_driver::yield_now();
    } else if let Some(ticks) = NonZeroU32::new(ticks) {
        let _ = hisi_rf_rtos_driver::sleep_ms(ticks);
    }
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn osDelay(ticks: u32) -> c_int {
    LOS_TaskDelay(ticks);
    OS_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_SemCreate(count: u16, output: *mut u32) -> u32 {
    if output.is_null() {
        return ERROR;
    }
    match hisi_rf_rtos_driver::semaphore_create(count.into()) {
        Ok(handle) => {
            unsafe { *output = handle.into_raw().get() as u32 };
            OK
        }
        Err(_) => ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_SemPend(raw: u32, timeout: u32) -> u32 {
    match semaphore(raw)
        .and_then(|handle| hisi_rf_rtos_driver::semaphore_down(handle, wait_timeout(timeout)).ok())
    {
        Some(WaitOutcome::Acquired) => OK,
        _ => ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_SemPost(raw: u32) -> u32 {
    match semaphore(raw).and_then(|handle| hisi_rf_rtos_driver::semaphore_up(handle).ok()) {
        Some(()) => OK,
        None => ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_SemDelete(raw: u32) -> u32 {
    match semaphore(raw)
        .and_then(|handle| unsafe { hisi_rf_rtos_driver::semaphore_destroy(handle) }.ok())
    {
        Some(()) => OK,
        None => ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_MuxCreate(output: *mut u32) -> u32 {
    if output.is_null() {
        return ERROR;
    }
    match hisi_rf_rtos_driver::mutex_create() {
        Ok(handle) => {
            unsafe { *output = handle.into_raw().get() as u32 };
            OK
        }
        Err(_) => ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_MuxPend(raw: u32, timeout: u32) -> u32 {
    match mutex(raw)
        .and_then(|handle| hisi_rf_rtos_driver::mutex_lock(handle, wait_timeout(timeout)).ok())
    {
        Some(WaitOutcome::Acquired) => OK,
        _ => ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_MuxPost(raw: u32) -> u32 {
    match mutex(raw).and_then(|handle| hisi_rf_rtos_driver::mutex_unlock(handle).ok()) {
        Some(()) => OK,
        None => ERROR,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_MuxDelete(raw: u32) -> u32 {
    match mutex(raw).and_then(|handle| unsafe { hisi_rf_rtos_driver::mutex_destroy(handle) }.ok()) {
        Some(()) => OK,
        None => ERROR,
    }
}

#[repr(C)]
struct CmsisMutex {
    raw: u32,
}

#[unsafe(no_mangle)]
pub extern "C" fn osMutexNew(_attributes: *const c_void) -> *mut c_void {
    let object = crate::alloc::osal_kmalloc(core::mem::size_of::<CmsisMutex>()) as *mut CmsisMutex;
    if object.is_null() {
        return core::ptr::null_mut();
    }
    if LOS_MuxCreate(unsafe { &mut (*object).raw }) != OK {
        crate::alloc::osal_kfree(object.cast());
        return core::ptr::null_mut();
    }
    object.cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn osMutexAcquire(id: *mut c_void, timeout: u32) -> c_int {
    if id.is_null() {
        return OS_ERROR_PARAMETER;
    }
    if LOS_MuxPend(unsafe { (*(id as *mut CmsisMutex)).raw }, timeout) == OK {
        OS_OK
    } else if timeout == 0 {
        OS_ERROR_TIMEOUT
    } else {
        OS_ERROR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn osMutexRelease(id: *mut c_void) -> c_int {
    if id.is_null() {
        return OS_ERROR_PARAMETER;
    }
    if LOS_MuxPost(unsafe { (*(id as *mut CmsisMutex)).raw }) == OK {
        OS_OK
    } else {
        OS_ERROR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn osMutexDelete(id: *mut c_void) -> c_int {
    if id.is_null() {
        return OS_ERROR_PARAMETER;
    }
    let raw = unsafe { (*(id as *mut CmsisMutex)).raw };
    if LOS_MuxDelete(raw) != OK {
        return OS_ERROR;
    }
    crate::alloc::osal_kfree(id);
    OS_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn osMessageQueueNew(
    count: u32,
    size: u32,
    _attributes: *const c_void,
) -> *mut c_void {
    let mut id: c_ulong = 0;
    if count > u16::MAX.into() || size > u16::MAX.into() {
        return core::ptr::null_mut();
    }
    if crate::osal_queue::osal_msg_queue_create(
        core::ptr::null::<c_char>(),
        count as u16,
        &mut id,
        0,
        size as u16,
    ) == crate::OSAL_OK
    {
        id as *mut c_void
    } else {
        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn osMessageQueuePut(
    id: *mut c_void,
    message: *const c_void,
    _priority: u8,
    timeout: u32,
) -> c_int {
    if id.is_null() || message.is_null() {
        return OS_ERROR_PARAMETER;
    }
    let size = queue_item_size(id as c_ulong);
    if size == 0 {
        return OS_ERROR_PARAMETER;
    }
    if crate::osal_queue::osal_msg_queue_write_copy(
        id as c_ulong,
        message.cast_mut(),
        size,
        timeout,
    ) == crate::OSAL_OK
    {
        OS_OK
    } else {
        OS_ERROR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn osMessageQueueGet(
    id: *mut c_void,
    message: *mut c_void,
    _priority: *mut u8,
    timeout: u32,
) -> c_int {
    if id.is_null() || message.is_null() {
        return OS_ERROR_PARAMETER;
    }
    let mut size = queue_item_size(id as c_ulong);
    if size == 0 {
        return OS_ERROR_PARAMETER;
    }
    if crate::osal_queue::osal_msg_queue_read_copy(id as c_ulong, message, &mut size, timeout)
        == crate::OSAL_OK
    {
        OS_OK
    } else {
        OS_ERROR
    }
}

fn queue_item_size(id: c_ulong) -> u32 {
    crate::osal_queue::osal_msg_queue_item_size(id)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LosSwtmrCb {
    sort_link: [u32; 3],
    state: u8,
    mode: u8,
    overrun: u8,
    in_process: u8,
    timer_id: u16,
    _padding: u16,
    interval: u32,
    expiry: u32,
    arg: u32,
    handler: u32,
}

impl LosSwtmrCb {
    const EMPTY: Self = Self {
        sort_link: [0; 3],
        state: 0,
        mode: 0,
        overrun: 0,
        in_process: 0,
        timer_id: 0,
        _padding: 0,
        interval: 0,
        expiry: 0,
        arg: 0,
        handler: 0,
    };
}

const SWTMR_COUNT: usize = 16;
struct SwtmrStorage(UnsafeCell<[LosSwtmrCb; SWTMR_COUNT]>);
unsafe impl Sync for SwtmrStorage {}
static SWTMR_CBS: SwtmrStorage = SwtmrStorage(UnsafeCell::new([LosSwtmrCb::EMPTY; SWTMR_COUNT]));

#[unsafe(no_mangle)]
pub static mut g_osSwtmrCBArray: *mut LosSwtmrCb = SWTMR_CBS.0.get().cast();

#[repr(C)]
struct SwtmrRuntime {
    osal: crate::timer::OsalTimer,
}

struct SwtmrRuntimeStorage(UnsafeCell<[SwtmrRuntime; SWTMR_COUNT]>);
unsafe impl Sync for SwtmrRuntimeStorage {}
static SWTMR_RUNTIME: SwtmrRuntimeStorage = SwtmrRuntimeStorage(UnsafeCell::new(
    [const {
        SwtmrRuntime {
            osal: crate::timer::OsalTimer {
                timer: core::ptr::null_mut(),
                handler: Some(swtmr_fire),
                data: 0,
                interval: 1,
            },
        }
    }; SWTMR_COUNT],
));

extern "C" fn swtmr_fire(index: c_ulong) {
    let index = index as usize;
    if index >= SWTMR_COUNT {
        return;
    }
    let (handler, arg, periodic) = critical_section::with(|_| {
        let cb = unsafe { &mut (*SWTMR_CBS.0.get())[index] };
        cb.in_process = cb.in_process.saturating_add(1);
        cb.state = if cb.mode == 1 { 3 } else { 2 };
        (cb.handler, cb.arg, cb.mode == 1)
    });
    #[cfg(target_arch = "riscv32")]
    if handler != 0 {
        // SAFETY: `LOS_SwtmrCreate` stores a non-null RV32 C callback address.
        let handler: extern "C" fn(usize) = unsafe { core::mem::transmute(handler as usize) };
        handler(arg as usize);
    }
    #[cfg(not(target_arch = "riscv32"))]
    let _ = (handler, arg);
    critical_section::with(|_| {
        let cb = unsafe { &mut (*SWTMR_CBS.0.get())[index] };
        cb.in_process = cb.in_process.saturating_sub(1);
    });
    if periodic {
        let runtime = unsafe { &mut (*SWTMR_RUNTIME.0.get())[index] };
        let interval = unsafe { (*SWTMR_CBS.0.get())[index].interval.max(1) };
        let _ = crate::timer::osal_timer_mod(&mut runtime.osal, interval);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_SwtmrCreate(
    interval: u32,
    mode: u8,
    handler: Option<extern "C" fn(usize)>,
    output: *mut u16,
    arg: usize,
) -> u32 {
    if interval == 0 || handler.is_none() || output.is_null() || mode > 2 {
        return ERROR;
    }
    let index = critical_section::with(|_| {
        let slots = unsafe { &mut *SWTMR_CBS.0.get() };
        let index = slots.iter().position(|slot| slot.state == 0)?;
        slots[index] = LosSwtmrCb {
            state: 2,
            mode,
            timer_id: index as u16,
            interval,
            expiry: interval,
            arg: arg as u32,
            handler: handler.map_or(0, |callback| callback as usize as u32),
            ..LosSwtmrCb::EMPTY
        };
        Some(index)
    });
    let Some(index) = index else { return ERROR };
    let runtime = unsafe { &mut (*SWTMR_RUNTIME.0.get())[index] };
    runtime.osal.timer = core::ptr::null_mut();
    runtime.osal.data = index as c_ulong;
    runtime.osal.interval = interval;
    if crate::timer::osal_timer_init(&mut runtime.osal) != crate::OSAL_OK {
        critical_section::with(|_| unsafe {
            (*SWTMR_CBS.0.get())[index] = LosSwtmrCb::EMPTY;
        });
        return ERROR;
    }
    unsafe { *output = index as u16 };
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_SwtmrStart(id: u16) -> u32 {
    let index = id as usize;
    if index >= SWTMR_COUNT {
        return ERROR;
    }
    let interval = critical_section::with(|_| {
        let cb = unsafe { &mut (*SWTMR_CBS.0.get())[index] };
        if cb.state == 0 {
            None
        } else {
            cb.state = 3;
            Some(cb.expiry.max(1))
        }
    });
    let Some(interval) = interval else {
        return ERROR;
    };
    let runtime = unsafe { &mut (*SWTMR_RUNTIME.0.get())[index] };
    if crate::timer::osal_timer_mod(&mut runtime.osal, interval) == crate::OSAL_OK {
        OK
    } else {
        ERROR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_SwtmrStop(id: u16) -> u32 {
    let index = id as usize;
    if index >= SWTMR_COUNT {
        return ERROR;
    }
    let allocated = critical_section::with(|_| unsafe { (*SWTMR_CBS.0.get())[index].state != 0 });
    if !allocated {
        return ERROR;
    }
    let runtime = unsafe { &mut (*SWTMR_RUNTIME.0.get())[index] };
    if crate::timer::osal_timer_stop(&mut runtime.osal) != crate::OSAL_OK {
        return ERROR;
    }
    critical_section::with(|_| unsafe { (*SWTMR_CBS.0.get())[index].state = 2 });
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_SwtmrDelete(id: u16) -> u32 {
    let index = id as usize;
    if index >= SWTMR_COUNT {
        return ERROR;
    }
    let runtime = unsafe { &mut (*SWTMR_RUNTIME.0.get())[index] };
    let _ = crate::timer::osal_timer_destroy(&mut runtime.osal);
    critical_section::with(|_| unsafe { (*SWTMR_CBS.0.get())[index] = LosSwtmrCb::EMPTY });
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn osTimerNew(
    handler: Option<extern "C" fn(usize)>,
    timer_type: u32,
    argument: *mut c_void,
    _attributes: *const c_void,
) -> *mut c_void {
    let mode = match timer_type {
        0 => 2,
        1 => 1,
        _ => return core::ptr::null_mut(),
    };
    let mut id = 0u16;
    if LOS_SwtmrCreate(1, mode, handler, &mut id, argument as usize) == OK {
        unsafe { (*SWTMR_CBS.0.get()).as_mut_ptr().add(id as usize).cast() }
    } else {
        core::ptr::null_mut()
    }
}

fn timer_id(id: *mut c_void) -> Option<u16> {
    if id.is_null() {
        return None;
    }
    let base = SWTMR_CBS.0.get() as usize;
    let offset = (id as usize).checked_sub(base)?;
    if offset % core::mem::size_of::<LosSwtmrCb>() != 0 {
        return None;
    }
    let index = offset / core::mem::size_of::<LosSwtmrCb>();
    (index < SWTMR_COUNT).then_some(index as u16)
}

#[unsafe(no_mangle)]
pub extern "C" fn osTimerStart(id: *mut c_void, ticks: u32) -> c_int {
    let Some(index) = timer_id(id) else {
        return OS_ERROR_PARAMETER;
    };
    if ticks == 0 {
        return OS_ERROR_PARAMETER;
    }
    critical_section::with(|_| unsafe {
        let cb = &mut (*SWTMR_CBS.0.get())[index as usize];
        cb.expiry = ticks;
        cb.interval = ticks;
    });
    if LOS_SwtmrStart(index) == OK {
        OS_OK
    } else {
        OS_ERROR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn osTimerDelete(id: *mut c_void) -> c_int {
    match timer_id(id) {
        Some(index) if LOS_SwtmrDelete(index) == OK => OS_OK,
        Some(_) => OS_ERROR,
        None => OS_ERROR_PARAMETER,
    }
}

#[repr(C)]
pub struct LosMemPoolStatus {
    total_used: u32,
    total_free: u32,
    max_free_node: u32,
    used_nodes: u32,
    free_nodes: u32,
    usage_waterline: u32,
}

#[unsafe(no_mangle)]
pub extern "C" fn LOS_MemInfoGet(_pool: *mut c_void, output: *mut LosMemPoolStatus) -> u32 {
    if output.is_null() {
        return ERROR;
    }
    let metrics = crate::alloc::heap_metrics();
    unsafe {
        *output = LosMemPoolStatus {
            total_used: metrics.used_bytes as u32,
            total_free: metrics.free_bytes as u32,
            max_free_node: crate::alloc::largest_allocatable(core::mem::align_of::<usize>()) as u32,
            used_nodes: metrics.live_allocations as u32,
            free_nodes: u32::from(metrics.free_bytes != 0),
            usage_waterline: metrics.peak_used_bytes as u32,
        };
    }
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn dyn_get_em_mem_cfg() -> u8 {
    32
}

#[unsafe(no_mangle)]
pub static m_auc_int_pri: [u8; 73] = [
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 7, 6, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 5, 7, 7, 7, 7, 6, 6, 7, 7, 7, 7, 7, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 4, 7, 7, 7, 7, 7,
];

// Optional vendor diagnostics. The Rust firmware does not install the DFX
// transport in the B1 profile, so these are explicit sinks, not success mocks.
#[unsafe(no_mangle)]
pub extern "C" fn log_oam_register_handler_callback(_kind: u8, _callback: *mut c_void) -> bool {
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn diag_sample_data_register(_kind: u32, _callback: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn diag_cmd_report_sample_data(_buffer: *mut u8, _length: u32) -> u32 {
    // The B1 profile deliberately has no DFX transport. Match the vendor
    // `errcode_t` failure value instead of pretending that the sample was sent.
    u32::MAX
}

#[unsafe(no_mangle)]
pub extern "C" fn massdata_record_system_error(_event: u8, _a: u8, _b: u8, _c: u32) {}

#[unsafe(no_mangle)]
pub extern "C" fn massdata_record_system_event(_event: u8, _a: u8, _b: u8, _c: u32) {}

#[unsafe(no_mangle)]
pub extern "C" fn log_event_print_alterable_para_press(_header: u32, _press: u32, _count: u32) {}

#[unsafe(no_mangle)]
pub extern "C" fn global_thread_status_update(_running: bool) {}

#[unsafe(no_mangle)]
pub extern "C" fn global_isr_time_statistics_get() -> u64 {
    0
}

// The mask-ROM BTC data ABI contains function tables that reference the
// vendor unified-cipher service layer. B1 does not perform pairing or encrypted
// link setup, but the table entries must still resolve to valid functions.
// Keep these signatures aligned with the public SDK headers and fail closed
// until B2 replaces them with hisi-crypto-ws63 keyslot/hash/MAC capabilities.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_km_init() -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_km_deinit() -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_keyslot_create(_handle: *mut u32, _kind: u32) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_keyslot_destroy(_handle: u32) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_create(_handle: *mut u32) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_destroy(_handle: u32) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_attach(_handle: u32, _destination: u32, _keyslot: u32) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_detach(_handle: u32, _destination: u32, _keyslot: u32) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_set_attr(_handle: u32, _attribute: *const c_void) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_set_clear_key(_handle: u32, _key: *const c_void) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_init() -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_deinit() -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_start(_handle: *mut u32, _attribute: *const c_void) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_update(
    _handle: u32,
    _source: *const c_void,
    _length: u32,
) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_finish(
    _handle: u32,
    _output: *mut u8,
    _length: *mut u32,
) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_symc_init() -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_symc_deinit() -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_symc_destroy(_handle: u32) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_mac_start(_handle: *mut u32, _attribute: *const c_void) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_mac_update(
    _handle: u32,
    _source: *const c_void,
    _length: u32,
) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_mac_finish(
    _handle: u32,
    _output: *mut u8,
    _length: *mut u32,
) -> u32 {
    ERROR
}

// Pairing crypto is outside B1. Returning failure keeps the boundary explicit;
// B2 must replace these with hisi-crypto-ws63 PKE capabilities before pairing.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_pke_ecc_gen_key(
    _curve: u32,
    _input: *const c_void,
    _private_key: *mut c_void,
    _public_key: *mut c_void,
) -> u32 {
    ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_pke_ecc_gen_ecdh_key(
    _curve: u32,
    _public_key: *const c_void,
    _private_key: *const c_void,
    _shared_key: *mut c_void,
) -> u32 {
    ERROR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swtmr_control_block_matches_ws63_archive_abi() {
        assert_eq!(core::mem::size_of::<LosSwtmrCb>(), 36);
        assert_eq!(core::mem::offset_of!(LosSwtmrCb, interval), 20);
        assert_eq!(core::mem::offset_of!(LosSwtmrCb, expiry), 24);
        assert_eq!(core::mem::offset_of!(LosSwtmrCb, arg), 28);
        assert_eq!(core::mem::offset_of!(LosSwtmrCb, handler), 32);
    }

    #[test]
    fn timer_id_rejects_unaligned_and_out_of_range_pointers() {
        let base = SWTMR_CBS.0.get().cast::<LosSwtmrCb>();
        assert_eq!(timer_id(base.cast()), Some(0));
        assert_eq!(
            timer_id(unsafe { base.add(SWTMR_COUNT - 1) }.cast()),
            Some(15)
        );
        assert_eq!(timer_id(unsafe { base.cast::<u8>().add(1) }.cast()), None);
        assert_eq!(timer_id(unsafe { base.add(SWTMR_COUNT) }.cast()), None);
    }

    #[test]
    fn b1_crypto_table_entries_fail_closed() {
        let mut handle = 0;
        assert_eq!(uapi_drv_km_init(), ERROR);
        assert_eq!(uapi_drv_keyslot_create(&mut handle, 0), ERROR);
        assert_eq!(uapi_drv_klad_create(&mut handle), ERROR);
        assert_eq!(uapi_drv_cipher_hash_init(), ERROR);
        assert_eq!(
            uapi_drv_cipher_hash_start(&mut handle, core::ptr::null()),
            ERROR
        );
        assert_eq!(uapi_drv_cipher_symc_init(), ERROR);
        assert_eq!(
            uapi_drv_cipher_mac_start(&mut handle, core::ptr::null()),
            ERROR
        );
    }

    #[test]
    fn stopping_an_unallocated_software_timer_fails() {
        critical_section::with(|_| unsafe {
            (*SWTMR_CBS.0.get())[0] = LosSwtmrCb::EMPTY;
        });
        assert_eq!(LOS_SwtmrStop(0), ERROR);
    }

    #[test]
    fn disabled_dfx_sample_transport_fails_closed() {
        assert_eq!(
            diag_cmd_report_sample_data(core::ptr::null_mut(), 0),
            u32::MAX
        );
    }
}
