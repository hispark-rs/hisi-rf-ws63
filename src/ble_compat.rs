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

const BLE_CRYPTO_SLOT_COUNT: usize = 2;
const BLE_CRYPTO_KEY_BYTES: usize = 64;
const HANDLE_INDEX_MASK: u32 = 0xff;

#[derive(Clone, Copy)]
struct KeyslotState {
    generation: u32,
    kind: u32,
    key_len: u8,
    in_use: bool,
    key: [u8; BLE_CRYPTO_KEY_BYTES],
}

impl KeyslotState {
    const EMPTY: Self = Self {
        generation: 0,
        kind: 0,
        key_len: 0,
        in_use: false,
        key: [0; BLE_CRYPTO_KEY_BYTES],
    };
}

#[derive(Clone, Copy)]
struct KladState {
    generation: u32,
    destination: u32,
    keyslot: u32,
    engine: u32,
    in_use: bool,
}

impl KladState {
    const EMPTY: Self = Self {
        generation: 0,
        destination: u32::MAX,
        keyslot: 0,
        engine: u32::MAX,
        in_use: false,
    };
}

#[derive(Clone, Copy)]
struct CryptoOpState {
    generation: u32,
    state: u8,
    key_len: u8,
    result_len: u8,
    key: [u8; BLE_CRYPTO_KEY_BYTES],
    result: [u8; 32],
}

impl CryptoOpState {
    const EMPTY: Self = Self {
        generation: 0,
        state: 0,
        key_len: 0,
        result_len: 0,
        key: [0; BLE_CRYPTO_KEY_BYTES],
        result: [0; 32],
    };

    fn clear(&mut self) {
        let generation = self.generation;
        self.key.fill(0);
        self.result.fill(0);
        *self = Self {
            generation,
            ..Self::EMPTY
        };
    }
}

struct BleCryptoState {
    keyslots: [KeyslotState; BLE_CRYPTO_SLOT_COUNT],
    klads: [KladState; BLE_CRYPTO_SLOT_COUNT],
    hashes: [CryptoOpState; BLE_CRYPTO_SLOT_COUNT],
    macs: [CryptoOpState; BLE_CRYPTO_SLOT_COUNT],
}

impl BleCryptoState {
    const fn new() -> Self {
        Self {
            keyslots: [KeyslotState::EMPTY; BLE_CRYPTO_SLOT_COUNT],
            klads: [KladState::EMPTY; BLE_CRYPTO_SLOT_COUNT],
            hashes: [CryptoOpState::EMPTY; BLE_CRYPTO_SLOT_COUNT],
            macs: [CryptoOpState::EMPTY; BLE_CRYPTO_SLOT_COUNT],
        }
    }
}

struct BleCryptoStorage(UnsafeCell<BleCryptoState>);

// SAFETY: every access to the contained state is serialized by a critical
// section, while hardware execution occurs only after an operation is marked
// busy and outside the critical section.
unsafe impl Sync for BleCryptoStorage {}

static BLE_CRYPTO: BleCryptoStorage = BleCryptoStorage(UnsafeCell::new(BleCryptoState::new()));

#[cfg(any(test, all(target_arch = "riscv32", feature = "ble-init-diag")))]
fn reset_ble_crypto_state() {
    with_ble_crypto(|state| {
        for slot in &mut state.keyslots {
            let generation = slot.generation;
            slot.key.fill(0);
            *slot = KeyslotState {
                generation,
                ..KeyslotState::EMPTY
            };
        }
        for slot in &mut state.klads {
            let generation = slot.generation;
            *slot = KladState {
                generation,
                ..KladState::EMPTY
            };
        }
        for slot in &mut state.hashes {
            slot.clear();
        }
        for slot in &mut state.macs {
            slot.clear();
        }
    });
}

fn next_generation(current: u32) -> u32 {
    let next = current.wrapping_add(1) & 0x00ff_ffff;
    next.max(1)
}

fn encode_handle(index: usize, generation: u32) -> u32 {
    (generation << 8) | (index as u32 + 1)
}

fn decode_handle(handle: u32) -> Option<(usize, u32)> {
    let raw_index = handle & HANDLE_INDEX_MASK;
    let generation = handle >> 8;
    if raw_index == 0 || raw_index as usize > BLE_CRYPTO_SLOT_COUNT || generation == 0 {
        None
    } else {
        Some((raw_index as usize - 1, generation))
    }
}

fn with_ble_crypto<T>(operation: impl FnOnce(&mut BleCryptoState) -> T) -> T {
    critical_section::with(|_| {
        // SAFETY: BLE_CRYPTO is accessed only under this critical section.
        operation(unsafe { &mut *BLE_CRYPTO.0.get() })
    })
}

fn allocate_crypto_op(
    slots: &mut [CryptoOpState; BLE_CRYPTO_SLOT_COUNT],
    key: &[u8],
) -> Option<u32> {
    let (index, slot) = slots
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| slot.state == 0)?;
    slot.generation = next_generation(slot.generation);
    slot.state = 1;
    slot.key_len = u8::try_from(key.len()).ok()?;
    slot.key[..key.len()].copy_from_slice(key);
    Some(encode_handle(index, slot.generation))
}

#[cfg(target_arch = "riscv32")]
fn begin_crypto_update(
    slots: &mut [CryptoOpState; BLE_CRYPTO_SLOT_COUNT],
    handle: u32,
) -> Option<([u8; BLE_CRYPTO_KEY_BYTES], usize, usize, u32)> {
    let (index, generation) = decode_handle(handle)?;
    let slot = &mut slots[index];
    if slot.generation != generation || slot.state != 1 {
        return None;
    }
    slot.state = 2;
    Some((slot.key, slot.key_len.into(), index, generation))
}

#[cfg(target_arch = "riscv32")]
fn complete_crypto_update(
    slots: &mut [CryptoOpState; BLE_CRYPTO_SLOT_COUNT],
    index: usize,
    generation: u32,
    result: &[u8],
) -> bool {
    let slot = &mut slots[index];
    if slot.generation != generation || slot.state != 2 || result.len() > slot.result.len() {
        return false;
    }
    slot.result[..result.len()].copy_from_slice(result);
    slot.result_len = result.len() as u8;
    slot.state = 3;
    true
}

#[cfg(target_arch = "riscv32")]
fn fail_crypto_update(
    slots: &mut [CryptoOpState; BLE_CRYPTO_SLOT_COUNT],
    index: usize,
    generation: u32,
) {
    let slot = &mut slots[index];
    if slot.generation == generation && slot.state == 2 {
        slot.clear();
    }
}

fn take_crypto_result(
    slots: &mut [CryptoOpState; BLE_CRYPTO_SLOT_COUNT],
    handle: u32,
) -> Option<([u8; 32], usize)> {
    let (index, generation) = decode_handle(handle)?;
    let slot = &mut slots[index];
    if slot.generation != generation || slot.state != 3 {
        return None;
    }
    let result = slot.result;
    let length = slot.result_len.into();
    slot.clear();
    Some((result, length))
}

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

// The mask-ROM BTC data ABI references a narrow subset of the vendor
// unified-cipher API. These structs and handles model only the archive-proven
// HMAC-SM3 and AES-128-CMAC call sequences. Other algorithms fail closed.
const KEYSLOT_MCIPHER: u32 = 0;
const KEYSLOT_HMAC: u32 = 1;
const KLAD_DEST_MCIPHER: u32 = 0;
const KLAD_DEST_HMAC: u32 = 1;
const KLAD_ENGINE_AES: u32 = 0x20;
const KLAD_ENGINE_SM3_HMAC: u32 = 0xa2;
const KLAD_HMAC_SM3: u32 = 0x30;

#[repr(C)]
struct KladAttribute {
    root_key: u32,
    engine: u32,
    decrypt_support: bool,
    encrypt_support: bool,
    key_security: [bool; 6],
    rkp_software_config: u32,
}

#[repr(C)]
struct KladClearKey {
    key: *const u8,
    key_length: u32,
    key_parity: bool,
    hmac_type: u32,
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_km_init() -> u32 {
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_km_deinit() -> u32 {
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_keyslot_create(handle: *mut u32, kind: u32) -> u32 {
    if handle.is_null() || !matches!(kind, KEYSLOT_MCIPHER | KEYSLOT_HMAC) {
        return ERROR;
    }
    let allocated = with_ble_crypto(|state| {
        let (index, slot) = state
            .keyslots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.in_use)?;
        slot.generation = next_generation(slot.generation);
        slot.kind = kind;
        slot.key_len = 0;
        slot.in_use = true;
        slot.key.fill(0);
        Some(encode_handle(index, slot.generation))
    });
    let Some(allocated) = allocated else {
        return ERROR;
    };
    // SAFETY: non-null output is owned by the synchronous C caller.
    unsafe { *handle = allocated };
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_keyslot_destroy(handle: u32) -> u32 {
    with_ble_crypto(|state| {
        let Some((index, generation)) = decode_handle(handle) else {
            return ERROR;
        };
        if state
            .klads
            .iter()
            .any(|klad| klad.in_use && klad.keyslot == handle)
        {
            return ERROR;
        }
        let slot = &mut state.keyslots[index];
        if !slot.in_use || slot.generation != generation {
            return ERROR;
        }
        slot.key.fill(0);
        slot.key_len = 0;
        slot.in_use = false;
        OK
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_create(handle: *mut u32) -> u32 {
    if handle.is_null() {
        return ERROR;
    }
    let allocated = with_ble_crypto(|state| {
        let (index, slot) = state
            .klads
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.in_use)?;
        slot.generation = next_generation(slot.generation);
        slot.destination = u32::MAX;
        slot.keyslot = 0;
        slot.engine = u32::MAX;
        slot.in_use = true;
        Some(encode_handle(index, slot.generation))
    });
    let Some(allocated) = allocated else {
        return ERROR;
    };
    // SAFETY: non-null output is owned by the synchronous C caller.
    unsafe { *handle = allocated };
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_destroy(handle: u32) -> u32 {
    with_ble_crypto(|state| {
        let Some((index, generation)) = decode_handle(handle) else {
            return ERROR;
        };
        let slot = &mut state.klads[index];
        if !slot.in_use || slot.generation != generation || slot.keyslot != 0 {
            return ERROR;
        }
        slot.in_use = false;
        slot.destination = u32::MAX;
        slot.engine = u32::MAX;
        OK
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_attach(handle: u32, destination: u32, keyslot: u32) -> u32 {
    with_ble_crypto(|state| {
        let Some((klad_index, klad_generation)) = decode_handle(handle) else {
            return ERROR;
        };
        let Some((key_index, key_generation)) = decode_handle(keyslot) else {
            return ERROR;
        };
        let key = state.keyslots[key_index];
        let klad = &mut state.klads[klad_index];
        if !klad.in_use
            || klad.generation != klad_generation
            || klad.keyslot != 0
            || !key.in_use
            || key.generation != key_generation
            || !matches!(
                (destination, key.kind),
                (KLAD_DEST_MCIPHER, KEYSLOT_MCIPHER) | (KLAD_DEST_HMAC, KEYSLOT_HMAC)
            )
        {
            return ERROR;
        }
        klad.destination = destination;
        klad.keyslot = keyslot;
        OK
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_detach(handle: u32, destination: u32, keyslot: u32) -> u32 {
    with_ble_crypto(|state| {
        let Some((index, generation)) = decode_handle(handle) else {
            return ERROR;
        };
        let klad = &mut state.klads[index];
        if !klad.in_use
            || klad.generation != generation
            || klad.destination != destination
            || klad.keyslot != keyslot
        {
            return ERROR;
        }
        klad.destination = u32::MAX;
        klad.keyslot = 0;
        OK
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_set_attr(handle: u32, attribute: *const c_void) -> u32 {
    if attribute.is_null() {
        return ERROR;
    }
    // SAFETY: the archive passes the public SDK's aligned attribute for this call.
    let attribute = unsafe { &*attribute.cast::<KladAttribute>() };
    if !matches!(attribute.engine, KLAD_ENGINE_AES | KLAD_ENGINE_SM3_HMAC) {
        return ERROR;
    }
    with_ble_crypto(|state| {
        let Some((index, generation)) = decode_handle(handle) else {
            return ERROR;
        };
        let klad = &mut state.klads[index];
        if !klad.in_use || klad.generation != generation {
            return ERROR;
        }
        klad.engine = attribute.engine;
        OK
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_klad_set_clear_key(handle: u32, key: *const c_void) -> u32 {
    if key.is_null() {
        return ERROR;
    }
    // SAFETY: the archive passes the public SDK's aligned clear-key descriptor.
    let key = unsafe { &*key.cast::<KladClearKey>() };
    let Ok(key_length) = usize::try_from(key.key_length) else {
        return ERROR;
    };
    if key.key.is_null() || key_length == 0 || key_length > BLE_CRYPTO_KEY_BYTES {
        return ERROR;
    }
    let mut material = [0u8; BLE_CRYPTO_KEY_BYTES];
    // SAFETY: the validated descriptor promises key_length readable bytes.
    material[..key_length]
        .copy_from_slice(unsafe { core::slice::from_raw_parts(key.key, key_length) });
    let status = with_ble_crypto(|state| {
        let Some((klad_index, klad_generation)) = decode_handle(handle) else {
            return ERROR;
        };
        let klad = state.klads[klad_index];
        let Some((key_index, key_generation)) = decode_handle(klad.keyslot) else {
            return ERROR;
        };
        let keyslot = &mut state.keyslots[key_index];
        let valid_profile = match (klad.destination, klad.engine, keyslot.kind) {
            (KLAD_DEST_HMAC, KLAD_ENGINE_SM3_HMAC, KEYSLOT_HMAC) => key.hmac_type == KLAD_HMAC_SM3,
            (KLAD_DEST_MCIPHER, KLAD_ENGINE_AES, KEYSLOT_MCIPHER) => key_length == 16,
            _ => false,
        };
        if !klad.in_use
            || klad.generation != klad_generation
            || !keyslot.in_use
            || keyslot.generation != key_generation
            || !valid_profile
        {
            return ERROR;
        }
        keyslot.key.fill(0);
        keyslot.key[..key_length].copy_from_slice(&material[..key_length]);
        keyslot.key_len = key_length as u8;
        OK
    });
    material.fill(0);
    status
}

const HASH_HMAC_SM3: u32 = 0x1216_9100;
const SYMC_ALG_AES: u32 = 1;
const SYMC_MODE_CMAC: u32 = 8;
const SYMC_KEY_128BIT: u32 = 1;

#[repr(C)]
struct CipherHashAttribute {
    key: *const u8,
    key_len: u32,
    keyslot_handle: u32,
    hash_type: u32,
    is_keyslot: bool,
    is_long_term: bool,
}

#[repr(C)]
struct CipherMacAttribute {
    is_long_term: bool,
    symc_algorithm: u32,
    work_mode: u32,
    key_length: u32,
    keyslot_handle: u32,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct CipherBufferAttribute {
    memory_handle: u64,
    address_offset: u64,
    kernel_memory_handle: *mut c_void,
    physical_address: usize,
    virtual_address: *const u8,
    security: u32,
}

fn keyslot_material(handle: u32, expected_kind: u32) -> Option<([u8; 64], usize)> {
    with_ble_crypto(|state| {
        let (index, generation) = decode_handle(handle)?;
        let slot = state.keyslots[index];
        if !slot.in_use
            || slot.generation != generation
            || slot.kind != expected_kind
            || slot.key_len == 0
        {
            return None;
        }
        Some((slot.key, slot.key_len.into()))
    })
}

#[cfg(target_arch = "riscv32")]
unsafe fn cipher_input<'a>(source: *const c_void, length: u32) -> Option<&'a [u8]> {
    if source.is_null() {
        return None;
    }
    // SAFETY: the archive passes the public SDK buffer descriptor for this call.
    let source = unsafe { &*source.cast::<CipherBufferAttribute>() };
    let length = usize::try_from(length).ok()?;
    if source.virtual_address.is_null() && length != 0 {
        return None;
    }
    // SAFETY: the descriptor promises `length` readable bytes synchronously.
    Some(unsafe { core::slice::from_raw_parts(source.virtual_address, length) })
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_init() -> u32 {
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_deinit() -> u32 {
    with_ble_crypto(|state| {
        for slot in &mut state.hashes {
            slot.clear();
        }
    });
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_start(handle: *mut u32, attribute: *const c_void) -> u32 {
    if handle.is_null() || attribute.is_null() {
        return ERROR;
    }
    // SAFETY: the archive passes the reviewed public SDK attribute.
    let attribute = unsafe { &*attribute.cast::<CipherHashAttribute>() };
    if attribute.hash_type != HASH_HMAC_SM3 || !attribute.is_keyslot {
        return ERROR;
    }
    let Some((mut key, key_len)) = keyslot_material(attribute.keyslot_handle, KEYSLOT_HMAC) else {
        return ERROR;
    };
    let allocated = with_ble_crypto(|state| allocate_crypto_op(&mut state.hashes, &key[..key_len]));
    key.fill(0);
    let Some(allocated) = allocated else {
        return ERROR;
    };
    // SAFETY: non-null output is owned by the synchronous C caller.
    unsafe { *handle = allocated };
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_update(
    handle: u32,
    source: *const c_void,
    length: u32,
) -> u32 {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        let Some(input) = cipher_input(source, length) else {
            return ERROR;
        };
        let Some((mut key, key_len, index, generation)) =
            with_ble_crypto(|state| begin_crypto_update(&mut state.hashes, handle))
        else {
            return ERROR;
        };
        let mut output = [0u8; 32];
        let result = crate::crypto::hmac_sm3_hardware(&key[..key_len], input, &mut output);
        key.fill(0);
        let completed = with_ble_crypto(|state| {
            if result.is_ok() {
                complete_crypto_update(&mut state.hashes, index, generation, &output)
            } else {
                fail_crypto_update(&mut state.hashes, index, generation);
                false
            }
        });
        output.fill(0);
        if completed { OK } else { ERROR }
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (handle, source, length);
        ERROR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_hash_finish(
    handle: u32,
    output: *mut u8,
    length: *mut u32,
) -> u32 {
    finish_crypto_op(handle, output, length, true)
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_symc_init() -> u32 {
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_symc_deinit() -> u32 {
    with_ble_crypto(|state| {
        for slot in &mut state.macs {
            slot.clear();
        }
    });
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_symc_destroy(handle: u32) -> u32 {
    with_ble_crypto(|state| {
        let Some((index, generation)) = decode_handle(handle) else {
            return ERROR;
        };
        let slot = &mut state.macs[index];
        if slot.generation != generation || slot.state == 0 {
            return ERROR;
        }
        slot.clear();
        OK
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_mac_start(handle: *mut u32, attribute: *const c_void) -> u32 {
    if handle.is_null() || attribute.is_null() {
        return ERROR;
    }
    // SAFETY: the archive passes the reviewed public SDK attribute.
    let attribute = unsafe { &*attribute.cast::<CipherMacAttribute>() };
    if attribute.symc_algorithm != SYMC_ALG_AES
        || attribute.work_mode != SYMC_MODE_CMAC
        || attribute.key_length != SYMC_KEY_128BIT
    {
        return ERROR;
    }
    let Some((mut key, key_len)) = keyslot_material(attribute.keyslot_handle, KEYSLOT_MCIPHER)
    else {
        return ERROR;
    };
    if key_len != 16 {
        key.fill(0);
        return ERROR;
    }
    let allocated = with_ble_crypto(|state| allocate_crypto_op(&mut state.macs, &key[..key_len]));
    key.fill(0);
    let Some(allocated) = allocated else {
        return ERROR;
    };
    // SAFETY: non-null output is owned by the synchronous C caller.
    unsafe { *handle = allocated };
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_mac_update(
    handle: u32,
    source: *const c_void,
    length: u32,
) -> u32 {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        let Some(input) = cipher_input(source, length) else {
            return ERROR;
        };
        let Some((mut key, key_len, index, generation)) =
            with_ble_crypto(|state| begin_crypto_update(&mut state.macs, handle))
        else {
            return ERROR;
        };
        let mut output = [0u8; 16];
        let result = crate::crypto::aes_cmac_hardware(&key[..key_len], input, &mut output);
        key.fill(0);
        let completed = with_ble_crypto(|state| {
            if result.is_ok() {
                complete_crypto_update(&mut state.macs, index, generation, &output)
            } else {
                fail_crypto_update(&mut state.macs, index, generation);
                false
            }
        });
        output.fill(0);
        if completed { OK } else { ERROR }
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (handle, source, length);
        ERROR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_mac_finish(
    handle: u32,
    output: *mut u8,
    length: *mut u32,
) -> u32 {
    finish_crypto_op(handle, output, length, false)
}

fn finish_crypto_op(handle: u32, output: *mut u8, length: *mut u32, hash: bool) -> u32 {
    if output.is_null() || length.is_null() {
        return ERROR;
    }
    // SAFETY: non-null in/out length belongs to the synchronous C caller.
    let capacity = unsafe { *length } as usize;
    let expected = if hash { 32 } else { 16 };
    if capacity < expected {
        return ERROR;
    }
    let result = with_ble_crypto(|state| {
        if hash {
            take_crypto_result(&mut state.hashes, handle)
        } else {
            take_crypto_result(&mut state.macs, handle)
        }
    });
    let Some((mut result, result_len)) = result else {
        return ERROR;
    };
    if result_len != expected {
        result.fill(0);
        return ERROR;
    }
    // SAFETY: the caller advertises at least result_len writable bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(result.as_ptr(), output, result_len);
        *length = result_len as u32;
    }
    result.fill(0);
    OK
}

#[cfg(any(target_arch = "riscv32", test))]
const PKE_FIPS_P256R: u32 = 6;
#[cfg(target_arch = "riscv32")]
const P256_BYTES: usize = 32;

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct CipherPkeData {
    length: u32,
    data: *mut u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct CipherPkePoint {
    x: *mut u8,
    y: *mut u8,
    length: u32,
}

#[cfg(target_arch = "riscv32")]
unsafe fn read_pke_data<'a>(pointer: *const c_void) -> Option<&'a CipherPkeData> {
    if pointer.is_null() {
        None
    } else {
        // SAFETY: the pinned BLE archive passes the public SDK's aligned
        // `uapi_drv_cipher_pke_data_t` object for the duration of this call.
        Some(unsafe { &*pointer.cast::<CipherPkeData>() })
    }
}

#[cfg(target_arch = "riscv32")]
unsafe fn read_pke_point<'a>(pointer: *const c_void) -> Option<&'a CipherPkePoint> {
    if pointer.is_null() {
        None
    } else {
        // SAFETY: the pinned BLE archive passes the public SDK's aligned
        // `uapi_drv_cipher_pke_ecc_point_t` object for this synchronous call.
        Some(unsafe { &*pointer.cast::<CipherPkePoint>() })
    }
}

#[cfg(target_arch = "riscv32")]
unsafe fn pke_bytes(pointer: *const u8, length: u32) -> Option<[u8; P256_BYTES]> {
    if pointer.is_null() || length != P256_BYTES as u32 {
        return None;
    }
    let mut bytes = [0; P256_BYTES];
    // SAFETY: the validated SDK descriptor promises exactly 32 readable bytes
    // and the operation is synchronous.
    bytes.copy_from_slice(unsafe { core::slice::from_raw_parts(pointer, P256_BYTES) });
    Some(bytes)
}

#[cfg(target_arch = "riscv32")]
unsafe fn write_pke_bytes(pointer: *mut u8, bytes: &[u8; P256_BYTES]) -> Option<()> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the validated SDK descriptor promises exactly 32 writable bytes
    // and the operation is synchronous.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer, P256_BYTES) };
    Some(())
}

// The BLE archive uses caller-provided P-256 private scalars. Random key
// generation (`input == NULL`) remains fail closed until a production DRBG is
// injected; raw TRNG output is deliberately not treated as a CSPRNG.
#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_pke_ecc_gen_key(
    curve: u32,
    input: *const c_void,
    private_key: *mut c_void,
    public_key: *mut c_void,
) -> u32 {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        if curve != PKE_FIPS_P256R {
            return ERROR;
        }
        let Some(input) = read_pke_data(input) else {
            return ERROR;
        };
        let Some(output_private) = read_pke_data(private_key) else {
            return ERROR;
        };
        let Some(output_public) = read_pke_point(public_key) else {
            return ERROR;
        };
        if output_private.length != P256_BYTES as u32 || output_public.length != P256_BYTES as u32 {
            return ERROR;
        }
        let Some(scalar) = pke_bytes(input.data, input.length) else {
            return ERROR;
        };
        let Ok(private) = hisi_crypto::p256::P256PrivateKey::try_from_be_bytes(scalar) else {
            return ERROR;
        };
        let Ok(public) = crate::crypto::p256_public_key_hardware(private) else {
            return ERROR;
        };
        if write_pke_bytes(output_private.data, &scalar).is_none()
            || write_pke_bytes(output_public.x, &public.x).is_none()
            || write_pke_bytes(output_public.y, &public.y).is_none()
        {
            return ERROR;
        }
        OK
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (curve, input, private_key, public_key);
        ERROR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn uapi_drv_cipher_pke_ecc_gen_ecdh_key(
    curve: u32,
    public_key: *const c_void,
    private_key: *const c_void,
    shared_key: *mut c_void,
) -> u32 {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        if curve != PKE_FIPS_P256R {
            return ERROR;
        }
        let Some(public) = read_pke_point(public_key) else {
            return ERROR;
        };
        let Some(private) = read_pke_data(private_key) else {
            return ERROR;
        };
        let Some(output) = read_pke_data(shared_key) else {
            return ERROR;
        };
        if public.length != P256_BYTES as u32 || output.length != P256_BYTES as u32 {
            return ERROR;
        }
        let Some(x) = pke_bytes(public.x, public.length) else {
            return ERROR;
        };
        let Some(y) = pke_bytes(public.y, public.length) else {
            return ERROR;
        };
        let Some(scalar) = pke_bytes(private.data, private.length) else {
            return ERROR;
        };
        let Ok(private) = hisi_crypto::p256::P256PrivateKey::try_from_be_bytes(scalar) else {
            return ERROR;
        };
        let peer = hisi_crypto::sae::P256AffinePoint::new(x, y);
        let Ok(secret) = crate::crypto::p256_ecdh_hardware(private, &peer) else {
            return ERROR;
        };
        if write_pke_bytes(output.data, secret.expose_secret()).is_none() {
            return ERROR;
        }
        OK
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (curve, public_key, private_key, shared_key);
        ERROR
    }
}

#[cfg(all(target_arch = "riscv32", feature = "ble-init-diag"))]
pub(crate) fn ble_crypto_compat_self_test() -> bool {
    const HMAC_KEY: [u8; 20] = [0x0b; 20];
    const HMAC_EXPECTED: [u8; 32] = [
        0x8e, 0xc4, 0xd9, 0xf9, 0xe5, 0x15, 0x9d, 0x52, 0xd8, 0xb7, 0xf8, 0xe8, 0xe6, 0x81, 0xa6,
        0x2e, 0xcd, 0x2f, 0xb0, 0xcb, 0x58, 0xba, 0x55, 0x4e, 0xe5, 0x6c, 0x96, 0x2d, 0x0f, 0xa5,
        0xda, 0xa1,
    ];
    const CMAC_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const CMAC_MESSAGE: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];
    const CMAC_EXPECTED: [u8; 16] = [
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28,
        0x7c,
    ];
    const GENERATOR_X: [u8; 32] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];
    const GENERATOR_Y: [u8; 32] = [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];
    const DOUBLE_GENERATOR_X: [u8; 32] = [
        0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a,
        0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66,
        0x99, 0x78,
    ];
    const DOUBLE_GENERATOR_Y: [u8; 32] = [
        0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30,
        0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78,
        0x73, 0xd1,
    ];

    fn buffer(bytes: &[u8]) -> CipherBufferAttribute {
        CipherBufferAttribute {
            memory_handle: 0,
            address_offset: 0,
            kernel_memory_handle: core::ptr::null_mut(),
            physical_address: bytes.as_ptr() as usize,
            virtual_address: bytes.as_ptr(),
            security: 0,
        }
    }

    reset_ble_crypto_state();
    let hmac_ok = (|| {
        let mut keyslot = 0;
        let mut klad = 0;
        let mut hash = 0;
        let mut output = [0u8; 32];
        let mut output_len = output.len() as u32;
        let klad_attribute = KladAttribute {
            root_key: 0,
            engine: KLAD_ENGINE_SM3_HMAC,
            decrypt_support: false,
            encrypt_support: false,
            key_security: [false; 6],
            rkp_software_config: 0,
        };
        let clear_key = KladClearKey {
            key: HMAC_KEY.as_ptr(),
            key_length: HMAC_KEY.len() as u32,
            key_parity: false,
            hmac_type: KLAD_HMAC_SM3,
        };
        if uapi_drv_km_init() != OK
            || uapi_drv_keyslot_create(&mut keyslot, KEYSLOT_HMAC) != OK
            || uapi_drv_klad_create(&mut klad) != OK
            || uapi_drv_klad_attach(klad, KLAD_DEST_HMAC, keyslot) != OK
            || uapi_drv_klad_set_attr(klad, (&klad_attribute as *const KladAttribute).cast()) != OK
            || uapi_drv_klad_set_clear_key(klad, (&clear_key as *const KladClearKey).cast()) != OK
        {
            return false;
        }
        let hash_attribute = CipherHashAttribute {
            key: core::ptr::null(),
            key_len: 0,
            keyslot_handle: keyslot,
            hash_type: HASH_HMAC_SM3,
            is_keyslot: true,
            is_long_term: true,
        };
        let input = buffer(b"abc");
        uapi_drv_cipher_hash_init() == OK
            && uapi_drv_cipher_hash_start(
                &mut hash,
                (&hash_attribute as *const CipherHashAttribute).cast(),
            ) == OK
            && uapi_drv_cipher_hash_update(hash, (&input as *const CipherBufferAttribute).cast(), 3)
                == OK
            && uapi_drv_cipher_hash_finish(hash, output.as_mut_ptr(), &mut output_len) == OK
            && output_len == 32
            && output == HMAC_EXPECTED
    })();

    reset_ble_crypto_state();
    let cmac_ok = (|| {
        let mut keyslot = 0;
        let mut klad = 0;
        let mut mac = 0;
        let mut output = [0u8; 16];
        let mut output_len = output.len() as u32;
        let klad_attribute = KladAttribute {
            root_key: 0,
            engine: KLAD_ENGINE_AES,
            decrypt_support: false,
            encrypt_support: true,
            key_security: [false; 6],
            rkp_software_config: 0,
        };
        let clear_key = KladClearKey {
            key: CMAC_KEY.as_ptr(),
            key_length: CMAC_KEY.len() as u32,
            key_parity: false,
            hmac_type: 0,
        };
        if uapi_drv_km_init() != OK
            || uapi_drv_keyslot_create(&mut keyslot, KEYSLOT_MCIPHER) != OK
            || uapi_drv_klad_create(&mut klad) != OK
            || uapi_drv_klad_attach(klad, KLAD_DEST_MCIPHER, keyslot) != OK
            || uapi_drv_klad_set_attr(klad, (&klad_attribute as *const KladAttribute).cast()) != OK
            || uapi_drv_klad_set_clear_key(klad, (&clear_key as *const KladClearKey).cast()) != OK
        {
            return false;
        }
        let mac_attribute = CipherMacAttribute {
            is_long_term: true,
            symc_algorithm: SYMC_ALG_AES,
            work_mode: SYMC_MODE_CMAC,
            key_length: SYMC_KEY_128BIT,
            keyslot_handle: keyslot,
        };
        let input = buffer(&CMAC_MESSAGE);
        uapi_drv_cipher_symc_init() == OK
            && uapi_drv_cipher_mac_start(
                &mut mac,
                (&mac_attribute as *const CipherMacAttribute).cast(),
            ) == OK
            && uapi_drv_cipher_mac_update(
                mac,
                (&input as *const CipherBufferAttribute).cast(),
                CMAC_MESSAGE.len() as u32,
            ) == OK
            && uapi_drv_cipher_mac_finish(mac, output.as_mut_ptr(), &mut output_len) == OK
            && output_len == 16
            && output == CMAC_EXPECTED
    })();

    reset_ble_crypto_state();
    let p256_ok = {
        let mut scalar = [0u8; 32];
        scalar[31] = 2;
        let mut private_output = [0u8; 32];
        let mut public_x = [0u8; 32];
        let mut public_y = [0u8; 32];
        let mut shared = [0u8; 32];
        let input = CipherPkeData {
            length: 32,
            data: scalar.as_mut_ptr(),
        };
        let private = CipherPkeData {
            length: 32,
            data: private_output.as_mut_ptr(),
        };
        let public = CipherPkePoint {
            x: public_x.as_mut_ptr(),
            y: public_y.as_mut_ptr(),
            length: 32,
        };
        let generator = CipherPkePoint {
            x: GENERATOR_X.as_ptr().cast_mut(),
            y: GENERATOR_Y.as_ptr().cast_mut(),
            length: 32,
        };
        let shared_output = CipherPkeData {
            length: 32,
            data: shared.as_mut_ptr(),
        };
        uapi_drv_cipher_pke_ecc_gen_key(
            PKE_FIPS_P256R,
            (&input as *const CipherPkeData).cast(),
            (&private as *const CipherPkeData).cast_mut().cast(),
            (&public as *const CipherPkePoint).cast_mut().cast(),
        ) == OK
            && private_output == scalar
            && public_x == DOUBLE_GENERATOR_X
            && public_y == DOUBLE_GENERATOR_Y
            && uapi_drv_cipher_pke_ecc_gen_ecdh_key(
                PKE_FIPS_P256R,
                (&generator as *const CipherPkePoint).cast(),
                (&private as *const CipherPkeData).cast(),
                (&shared_output as *const CipherPkeData).cast_mut().cast(),
            ) == OK
            && shared == DOUBLE_GENERATOR_X
    };

    reset_ble_crypto_state();
    hmac_ok && cmac_ok && p256_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    static CRYPTO_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    fn b1_crypto_handles_are_bounded_and_stale_safe() {
        let _guard = CRYPTO_TEST_LOCK.lock().unwrap();
        reset_ble_crypto_state();
        let mut keyslot = 0;
        let mut klad = 0;
        let key = [0x5a; 16];
        let attribute = KladAttribute {
            root_key: 0,
            engine: KLAD_ENGINE_SM3_HMAC,
            decrypt_support: false,
            encrypt_support: false,
            key_security: [false; 6],
            rkp_software_config: 0,
        };
        let clear_key = KladClearKey {
            key: key.as_ptr(),
            key_length: key.len() as u32,
            key_parity: false,
            hmac_type: KLAD_HMAC_SM3,
        };
        let hash_attribute = CipherHashAttribute {
            key: core::ptr::null(),
            key_len: 0,
            keyslot_handle: 0,
            hash_type: HASH_HMAC_SM3,
            is_keyslot: true,
            is_long_term: true,
        };

        assert_eq!(core::mem::size_of::<KladAttribute>(), 20);
        assert_eq!(core::mem::offset_of!(KladAttribute, engine), 4);
        assert_eq!(uapi_drv_km_init(), OK);
        assert_eq!(uapi_drv_keyslot_create(&mut keyslot, KEYSLOT_HMAC), OK);
        assert_ne!(keyslot, 0);
        assert_eq!(uapi_drv_klad_create(&mut klad), OK);
        assert_eq!(uapi_drv_klad_attach(klad, KLAD_DEST_HMAC, keyslot), OK);
        assert_eq!(
            uapi_drv_klad_set_attr(klad, (&attribute as *const KladAttribute).cast()),
            OK
        );
        assert_eq!(
            uapi_drv_klad_set_clear_key(klad, (&clear_key as *const KladClearKey).cast()),
            OK
        );
        let mut hash_attribute = hash_attribute;
        hash_attribute.keyslot_handle = keyslot;
        let mut hash = 0;
        assert_eq!(uapi_drv_cipher_hash_init(), OK);
        assert_eq!(
            uapi_drv_cipher_hash_start(
                &mut hash,
                (&hash_attribute as *const CipherHashAttribute).cast(),
            ),
            OK
        );
        assert_ne!(hash, 0);
        assert_eq!(uapi_drv_cipher_hash_deinit(), OK);
        assert_eq!(uapi_drv_klad_detach(klad, KLAD_DEST_HMAC, keyslot), OK);
        assert_eq!(uapi_drv_klad_destroy(klad), OK);
        assert_eq!(uapi_drv_keyslot_destroy(keyslot), OK);
        assert_eq!(uapi_drv_keyslot_destroy(keyslot), ERROR);
        assert_eq!(uapi_drv_km_deinit(), OK);
        reset_ble_crypto_state();
    }

    #[test]
    fn unsupported_crypto_operations_fail_closed() {
        let _guard = CRYPTO_TEST_LOCK.lock().unwrap();
        reset_ble_crypto_state();
        let mut handle = 0;
        assert_eq!(uapi_drv_cipher_hash_init(), OK);
        assert_eq!(
            uapi_drv_cipher_hash_start(&mut handle, core::ptr::null()),
            ERROR
        );
        assert_eq!(uapi_drv_cipher_hash_deinit(), OK);
        assert_eq!(uapi_drv_cipher_symc_init(), OK);
        assert_eq!(
            uapi_drv_cipher_mac_start(&mut handle, core::ptr::null()),
            ERROR
        );
        assert_eq!(uapi_drv_cipher_symc_deinit(), OK);
        assert_eq!(
            uapi_drv_cipher_pke_ecc_gen_key(
                PKE_FIPS_P256R,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            ),
            ERROR
        );
        assert_eq!(
            uapi_drv_cipher_pke_ecc_gen_ecdh_key(
                PKE_FIPS_P256R,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
            ),
            ERROR
        );
        reset_ble_crypto_state();
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
