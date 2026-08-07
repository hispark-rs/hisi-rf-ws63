//! Internal WS63 SLE S1 initialization and bounded announce/seek slice.

use core::cell::{RefCell, UnsafeCell};
#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;
use core::mem::MaybeUninit;
#[cfg(any(target_arch = "riscv32", test))]
use core::num::{NonZeroU32, NonZeroUsize};

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_hal::peripherals::{Efuse, Km, Spacc, Trng};
#[cfg(target_arch = "riscv32")]
use portable_atomic::AtomicPtr;
use portable_atomic::{AtomicBool, AtomicU32, Ordering};
use static_cell::StaticCell;
use ws63_radio_sys::sle::Address;
#[cfg(target_arch = "riscv32")]
use ws63_radio_sys::sle::{
    AnnounceData, AnnounceParameters, AnnounceSeekCallbacks, ConnectionCallbacks,
    DefaultConnectionParameters, SeekParameters, SeekResult,
};

/// Caller-owned heap shared by the SLE host, controller, and RTOS objects.
pub const SLE_S1_ARENA_BYTES: usize = crate::WS63_SHARED_RADIO_ARENA_BYTES;
/// Smallest stack in the pinned heterogeneous SLE S1 task profile.
pub const SLE_S1_MINIMUM_TASK_STACK_BYTES: usize = 512;
/// Maximum payload copied from one vendor seek callback.
pub const SLE_S1_EVENT_DATA_CAPACITY: usize = 64;

const EVENT_CAPACITY: usize = 32;
#[cfg(any(target_arch = "riscv32", test))]
const TASK_COUNT: usize = 4;
#[cfg(any(target_arch = "riscv32", test))]
const STACKS: [usize; TASK_COUNT] = [3_584, 2_048, 512, 4_096];
#[cfg(any(target_arch = "riscv32", test))]
const PRIORITIES: [u8; TASK_COUNT] = [1, 12, 13, 12];
#[cfg(any(target_arch = "riscv32", test))]
#[cfg_attr(test, allow(dead_code))]
const OWNERS: [u32; TASK_COUNT] = [0x534c_4501, 0x534c_4502, 0x534c_4503, 0x534c_4504];

/// One bounded event copied out of the vendor SLE service callback context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleS1Event {
    Enabled {
        status: u32,
    },
    Disabled {
        status: u32,
    },
    AnnounceEnabled {
        announce_id: u32,
        status: u32,
    },
    AnnounceDisabled {
        announce_id: u32,
        status: u32,
    },
    AnnounceTerminated {
        announce_id: u32,
    },
    AnnounceRemoved {
        announce_id: u32,
        status: u32,
    },
    SeekEnabled {
        status: u32,
    },
    SeekDisabled {
        status: u32,
    },
    SeekResult {
        event_type: u8,
        address: Address,
        direct_address: Address,
        rssi: u8,
        data_status: u8,
        data_len: u8,
        truncated: bool,
        data: [u8; SLE_S1_EVENT_DATA_CAPACITY],
    },
    ConnectionStateChanged {
        connection_id: u16,
        address: Address,
        connection_state: u32,
        pair_state: u32,
        disconnect_reason: u32,
    },
}

impl SleS1Event {
    const EMPTY: Self = Self::Enabled { status: u32::MAX };
}

struct EventRing {
    events: [SleS1Event; EVENT_CAPACITY],
    head: usize,
    len: usize,
}

impl EventRing {
    const fn new() -> Self {
        Self {
            events: [SleS1Event::EMPTY; EVENT_CAPACITY],
            head: 0,
            len: 0,
        }
    }
}

struct EventQueue {
    ring: critical_section::Mutex<RefCell<EventRing>>,
    dropped: AtomicU32,
}

impl EventQueue {
    const fn new() -> Self {
        Self {
            ring: critical_section::Mutex::new(RefCell::new(EventRing::new())),
            dropped: AtomicU32::new(0),
        }
    }

    #[cfg_attr(not(any(target_arch = "riscv32", test)), allow(dead_code))]
    fn push(&self, event: SleS1Event) {
        let accepted = critical_section::with(|cs| {
            let mut ring = self.ring.borrow(cs).borrow_mut();
            if ring.len == EVENT_CAPACITY {
                return false;
            }
            let index = (ring.head + ring.len) % EVENT_CAPACITY;
            ring.events[index] = event;
            ring.len += 1;
            true
        });
        if !accepted {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn pop(&self) -> Option<SleS1Event> {
        critical_section::with(|cs| {
            let mut ring = self.ring.borrow(cs).borrow_mut();
            if ring.len == 0 {
                return None;
            }
            let event = ring.events[ring.head];
            ring.head = (ring.head + 1) % EVENT_CAPACITY;
            ring.len -= 1;
            Some(event)
        })
    }
}

#[cfg(target_arch = "riscv32")]
static EVENT_QUEUE: AtomicPtr<EventQueue> = AtomicPtr::new(core::ptr::null_mut());

/// Caller-owned SLE S1 allocator bytes. They may be claimed exactly once.
#[repr(C, align(64))]
pub struct SleS1ArenaStorage<const N: usize> {
    arena: UnsafeCell<[MaybeUninit<u8>; N]>,
    claimed: AtomicBool,
}

// SAFETY: the one-shot install transfers process-lifetime ownership.
unsafe impl<const N: usize> Sync for SleS1ArenaStorage<N> {}

impl<const N: usize> SleS1ArenaStorage<N> {
    pub const fn new() -> Self {
        Self {
            arena: UnsafeCell::new([MaybeUninit::uninit(); N]),
            claimed: AtomicBool::new(false),
        }
    }
}

impl<const N: usize> Default for SleS1ArenaStorage<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Small caller-owned SLE S1 control and crypto state.
pub struct SleS1ControlStorage {
    crypto: StaticCell<Ws63CryptoStorage>,
    events: StaticCell<EventQueue>,
}

impl SleS1ControlStorage {
    pub const fn new() -> Self {
        Self {
            crypto: StaticCell::new(),
            events: StaticCell::new(),
        }
    }
}

impl Default for SleS1ControlStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Composition object joining SLE S1 control state and its dedicated arena.
pub struct SleS1Storage<const N: usize> {
    control: &'static SleS1ControlStorage,
    arena: &'static SleS1ArenaStorage<N>,
}

impl<const N: usize> SleS1Storage<N> {
    #[doc(hidden)]
    pub const fn from_parts(
        control: &'static SleS1ControlStorage,
        arena: &'static SleS1ArenaStorage<N>,
    ) -> Self {
        Self { control, arena }
    }

    pub fn install(&'static self) -> Result<InstalledSleS1Storage, SleS1InitError> {
        if N < SLE_S1_ARENA_BYTES {
            return Err(SleS1InitError::InsufficientArena {
                required: SLE_S1_ARENA_BYTES,
                available: N,
            });
        }
        self.arena
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SleS1InitError::StorageAlreadyInstalled)?;
        // SAFETY: the successful one-shot claim transfers this static region.
        if unsafe { crate::alloc::install_raw_arena(self.arena.arena.get().cast(), N) }.is_err() {
            return Err(SleS1InitError::AllocatorInstall);
        }
        Ok(InstalledSleS1Storage {
            crypto: self.control.crypto.init(Ws63CryptoStorage::new()),
            events: self.control.events.init(EventQueue::new()),
        })
    }
}

/// Proof that the SLE S1 arena and control storage were installed.
pub struct InstalledSleS1Storage {
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    crypto: &'static mut Ws63CryptoStorage,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    events: &'static EventQueue,
}

impl InstalledSleS1Storage {
    /// # Safety
    /// The returned pointer must be released only through [`Self::deallocate`].
    pub unsafe fn allocate(size: usize) -> *mut u8 {
        crate::alloc::allocate_zeroed(size, 16).cast()
    }

    /// # Safety
    /// `pointer` must be null or a live allocation from this arena.
    pub unsafe fn deallocate(pointer: *mut u8) {
        crate::alloc::osal_kfree(pointer.cast());
    }
}

/// HAL capabilities consumed by SLE S1 initialization.
pub struct SleS1Resources {
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    efuse: Efuse<'static>,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    km: Km<'static>,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    spacc: Spacc<'static>,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    trng: Trng<'static>,
}

impl SleS1Resources {
    pub const fn new(
        efuse: Efuse<'static>,
        km: Km<'static>,
        spacc: Spacc<'static>,
        trng: Trng<'static>,
    ) -> Self {
        Self {
            efuse,
            km,
            spacc,
            trng,
        }
    }
}

/// Process-lifetime proof that the SLE S1 runtime is active.
#[must_use = "retain the SLE controller so the eFuse capability stays owned"]
pub struct SleS1Controller {
    _efuse: Efuse<'static>,
    events: &'static EventQueue,
}

impl SleS1Controller {
    pub fn next_event(&mut self) -> Option<SleS1Event> {
        self.events.pop()
    }

    pub fn dropped_events(&self) -> u32 {
        self.events.dropped.load(Ordering::Relaxed)
    }

    #[cfg(target_arch = "riscv32")]
    pub fn set_local_address(&mut self, mut address: Address) -> Result<(), SleS1OperationError> {
        let status = unsafe { ws63_radio_sys::sle::sle_set_local_addr(&raw mut address) };
        if status != 0 {
            return Err(SleS1OperationError::SetLocalAddress(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn configure_default_connection(&mut self) -> Result<(), SleS1OperationError> {
        let mut parameters = DefaultConnectionParameters {
            enable_filter_policy: 0,
            initiate_phys: 1,
            gt_negotiate: 1,
            scan_interval: 400,
            scan_window: 20,
            min_interval: 0x14,
            max_interval: 0x14,
            timeout: 0x1f4,
        };
        let status =
            unsafe { ws63_radio_sys::sle::sle_default_connection_param_set(&raw mut parameters) };
        if status != 0 {
            return Err(SleS1OperationError::SetConnectionParameters(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn start_announce(
        &mut self,
        announce_data: &'static mut [u8],
        seek_response_data: &'static mut [u8],
    ) -> Result<(), SleS1OperationError> {
        const HANDLE: u8 = 1;
        let parameters = AnnounceParameters {
            announce_handle: HANDLE,
            announce_mode: 0x03,
            announce_gt_role: 0,
            announce_level: 1,
            announce_interval_min: 0xc8,
            announce_interval_max: 0xc8,
            announce_channel_map: 0x07,
            announce_tx_power: 20,
            own_address: Address {
                address_type: 0,
                bytes: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            },
            peer_address: Address {
                address_type: 0,
                bytes: [0; 6],
            },
            connection_interval_min: 0x14,
            connection_interval_max: 0x14,
            connection_max_latency: 0x1f3,
            connection_supervision_timeout: 0x1f4,
            extended_parameters: core::ptr::null_mut(),
        };
        let status = unsafe { ws63_radio_sys::sle::sle_set_announce_param(HANDLE, &parameters) };
        if status != 0 {
            return Err(SleS1OperationError::SetAnnounceParameters(status));
        }
        let data = AnnounceData {
            announce_data_len: announce_data.len().try_into().map_err(|_| {
                SleS1OperationError::AnnounceDataTooLong {
                    length: announce_data.len(),
                }
            })?,
            seek_response_data_len: seek_response_data.len().try_into().map_err(|_| {
                SleS1OperationError::SeekResponseDataTooLong {
                    length: seek_response_data.len(),
                }
            })?,
            announce_data: announce_data.as_mut_ptr(),
            seek_response_data: seek_response_data.as_mut_ptr(),
        };
        let status = unsafe { ws63_radio_sys::sle::sle_set_announce_data(HANDLE, &data) };
        if status != 0 {
            return Err(SleS1OperationError::SetAnnounceData(status));
        }
        let status = unsafe { ws63_radio_sys::sle::sle_start_announce(HANDLE) };
        if status != 0 {
            return Err(SleS1OperationError::StartAnnounce(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn start_seek(&mut self) -> Result<(), SleS1OperationError> {
        let mut parameters = SeekParameters {
            own_address_type: 0,
            filter_duplicates: 0,
            filter_policy: 0,
            phys: 1,
            seek_type: [0, 0, 0],
            interval: [100, 0, 0],
            window: [100, 0, 0],
        };
        let status = unsafe { ws63_radio_sys::sle::sle_set_seek_param(&raw mut parameters) };
        if status != 0 {
            return Err(SleS1OperationError::SetSeekParameters(status));
        }
        let status = unsafe { ws63_radio_sys::sle::sle_start_seek() };
        if status != 0 {
            return Err(SleS1OperationError::StartSeek(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn stop_seek(&mut self) -> Result<(), SleS1OperationError> {
        let status = unsafe { ws63_radio_sys::sle::sle_stop_seek() };
        if status != 0 {
            return Err(SleS1OperationError::StopSeek(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn connect(&mut self, address: &Address) -> Result<(), SleS1OperationError> {
        let status = unsafe { ws63_radio_sys::sle::sle_connect_remote_device(address) };
        if status != 0 {
            return Err(SleS1OperationError::Connect(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn disconnect(&mut self, address: &Address) -> Result<(), SleS1OperationError> {
        let status = unsafe { ws63_radio_sys::sle::sle_disconnect_remote_device(address) };
        if status != 0 {
            return Err(SleS1OperationError::Disconnect(status));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleS1OperationError {
    AnnounceDataTooLong { length: usize },
    SeekResponseDataTooLong { length: usize },
    SetAnnounceParameters(u32),
    SetAnnounceData(u32),
    StartAnnounce(u32),
    SetSeekParameters(u32),
    StartSeek(u32),
    StopSeek(u32),
    SetLocalAddress(u32),
    SetConnectionParameters(u32),
    Connect(u32),
    Disconnect(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleS1InitError {
    StorageAlreadyInstalled,
    InsufficientArena { required: usize, available: usize },
    AllocatorInstall,
    TaskPlan,
    TaskAdmission,
    SchedulerLock,
    TaskSpawn { index: usize },
    SchedulerUnlock,
    TaskHandoff,
    Crypto,
    EventSinkAlreadyInstalled,
    RegisterCallbacks(u32),
    RegisterConnectionCallbacks(u32),
    Enable(u32),
    UnsupportedTarget,
}

#[cfg(target_arch = "riscv32")]
fn push_event(event: SleS1Event) {
    let queue = EVENT_QUEUE.load(Ordering::Acquire);
    if !queue.is_null() {
        // SAFETY: initialization publishes process-lifetime StaticCell storage.
        unsafe { &*queue }.push(event);
    }
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn enabled(status: u32) {
    push_event(SleS1Event::Enabled { status });
}
#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn disabled(status: u32) {
    push_event(SleS1Event::Disabled { status });
}
#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn announce_enabled(announce_id: u32, status: u32) {
    push_event(SleS1Event::AnnounceEnabled {
        announce_id,
        status,
    });
}
#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn announce_disabled(announce_id: u32, status: u32) {
    push_event(SleS1Event::AnnounceDisabled {
        announce_id,
        status,
    });
}
#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn announce_terminated(announce_id: u32) {
    push_event(SleS1Event::AnnounceTerminated { announce_id });
}
#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn announce_removed(announce_id: u32, status: u32) {
    push_event(SleS1Event::AnnounceRemoved {
        announce_id,
        status,
    });
}
#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn seek_enabled(status: u32) {
    push_event(SleS1Event::SeekEnabled { status });
}
#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn seek_disabled(status: u32) {
    push_event(SleS1Event::SeekDisabled { status });
}
#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn seek_result(result: *mut SeekResult) {
    let Some(result) = (unsafe { result.as_ref() }) else {
        return;
    };
    let source_len = usize::from(result.data_length);
    let copy_len = source_len.min(SLE_S1_EVENT_DATA_CAPACITY);
    let mut data = [0; SLE_S1_EVENT_DATA_CAPACITY];
    if copy_len != 0 && !result.data.is_null() {
        // SAFETY: vendor callback storage is live for this callback only.
        unsafe { core::ptr::copy_nonoverlapping(result.data, data.as_mut_ptr(), copy_len) };
    }
    push_event(SleS1Event::SeekResult {
        event_type: result.event_type,
        address: result.address,
        direct_address: result.direct_address,
        rssi: result.rssi,
        data_status: result.data_status,
        data_len: copy_len as u8,
        truncated: copy_len != source_len,
        data,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn connection_state_changed(
    connection_id: u16,
    address: *const Address,
    connection_state: u32,
    pair_state: u32,
    disconnect_reason: u32,
) {
    let address = unsafe { address.as_ref() }.copied().unwrap_or(Address {
        address_type: 0,
        bytes: [0; 6],
    });
    push_event(SleS1Event::ConnectionStateChanged {
        connection_id,
        address,
        connection_state,
        pair_state,
        disconnect_reason,
    });
}

#[cfg(target_arch = "riscv32")]
static mut CALLBACKS: AnnounceSeekCallbacks = AnnounceSeekCallbacks {
    enable: Some(enabled),
    disable: Some(disabled),
    announce_enable: Some(announce_enabled),
    announce_disable: Some(announce_disabled),
    announce_terminal: Some(announce_terminated),
    announce_remove: Some(announce_removed),
    seek_enable: Some(seek_enabled),
    seek_disable: Some(seek_disabled),
    seek_result: Some(seek_result),
    dfr: None,
};

#[cfg(target_arch = "riscv32")]
static mut CONNECTION_CALLBACKS: ConnectionCallbacks = ConnectionCallbacks {
    connection_state_changed: Some(connection_state_changed),
    connection_parameter_update_request: None,
    connection_parameter_update: None,
    authentication_complete: None,
    pair_complete: None,
    read_rssi: None,
    low_latency: None,
    set_phy: None,
    pair_remove: None,
};

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    fn bt_thread_handle(argument: *mut c_void);
    fn bt_acore_task_main();
    fn sdk_msg_thread();
    fn btsrv_task_body(argument: *const c_void);
}

#[cfg(target_arch = "riscv32")]
extern "C" fn task_bt(argument: *mut c_void) -> *mut c_void {
    unsafe { bt_thread_handle(argument) };
    core::ptr::null_mut()
}
#[cfg(target_arch = "riscv32")]
extern "C" fn task_bt_sdk(_: *mut c_void) -> *mut c_void {
    unsafe { bt_acore_task_main() };
    core::ptr::null_mut()
}
#[cfg(target_arch = "riscv32")]
extern "C" fn task_bth_sdk(_: *mut c_void) -> *mut c_void {
    unsafe { sdk_msg_thread() };
    core::ptr::null_mut()
}
#[cfg(target_arch = "riscv32")]
extern "C" fn task_service(argument: *mut c_void) -> *mut c_void {
    unsafe { btsrv_task_body(argument.cast_const()) };
    core::ptr::null_mut()
}

#[cfg(any(target_arch = "riscv32", test))]
#[cfg_attr(test, allow(dead_code))]
fn task_group(
    index: usize,
) -> Result<hisi_rf_rtos_driver::TaskResourceGroupRequirements, SleS1InitError> {
    let owner = NonZeroU32::new(OWNERS[index]).ok_or(SleS1InitError::TaskPlan)?;
    let slots = NonZeroUsize::new(1).ok_or(SleS1InitError::TaskPlan)?;
    let stack = NonZeroUsize::new(STACKS[index]).ok_or(SleS1InitError::TaskPlan)?;
    let resources = hisi_rf_rtos_driver::TaskResourceRequirements::new(slots, stack)
        .ok_or(SleS1InitError::TaskPlan)?;
    Ok(hisi_rf_rtos_driver::TaskResourceGroupRequirements::new(
        hisi_rf_rtos_driver::TaskResourceOwner::new(owner),
        resources,
    ))
}

#[cfg(target_arch = "riscv32")]
fn spawn_task(
    reservations: &mut hisi_rf_rtos_driver::TaskReservationBatch,
    index: usize,
    entry: hisi_rf_rtos_driver::TaskEntry,
) -> Result<(), SleS1InitError> {
    let reservation = reservations
        .take(index)
        .ok_or(SleS1InitError::TaskSpawn { index })?;
    let config = hisi_rf_rtos_driver::TaskConfig {
        stack_size: NonZeroUsize::new(STACKS[index]).ok_or(SleS1InitError::TaskPlan)?,
        priority: hisi_rf_rtos_driver::TaskPriority::new(PRIORITIES[index])
            .ok_or(SleS1InitError::TaskPlan)?,
    };
    hisi_rf_rtos_driver::spawn_reserved(&reservation, entry, core::ptr::null_mut(), config)
        .map(|_| ())
        .map_err(|_| SleS1InitError::TaskSpawn { index })
}

#[cfg(target_arch = "riscv32")]
pub fn init_sle_s1(
    resources: SleS1Resources,
    storage: InstalledSleS1Storage,
) -> Result<SleS1Controller, SleS1InitError> {
    crate::ensure_sle_init_link_contract();
    unsafe { crate::prepare_vendor_memory() };
    let _ = crate::uapi::initialize_rom_timebases();
    crate::uapi::enable_efuse_reads();
    crate::crypto::install_hardware_crypto(
        resources.km,
        resources.spacc,
        None,
        resources.trng,
        storage.crypto,
    )
    .map_err(|_| SleS1InitError::Crypto)?;
    EVENT_QUEUE
        .compare_exchange(
            core::ptr::null_mut(),
            (storage.events as *const EventQueue).cast_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| SleS1InitError::EventSinkAlreadyInstalled)?;
    let status =
        unsafe { ws63_radio_sys::sle::sle_announce_seek_register_callbacks(&raw mut CALLBACKS) };
    if status != 0 {
        return Err(SleS1InitError::RegisterCallbacks(status));
    }
    let status = unsafe {
        ws63_radio_sys::sle::sle_connection_register_callbacks(&raw mut CONNECTION_CALLBACKS)
    };
    if status != 0 {
        return Err(SleS1InitError::RegisterConnectionCallbacks(status));
    }

    let groups = [
        task_group(0)?,
        task_group(1)?,
        task_group(2)?,
        task_group(3)?,
    ];
    let plan =
        hisi_rf_rtos_driver::TaskResourcePlan::new(&groups).ok_or(SleS1InitError::TaskPlan)?;
    let mut reservations = hisi_rf_rtos_driver::reserve_task_resource_plan(plan)
        .map_err(|_| SleS1InitError::TaskAdmission)?;
    hisi_rf_rtos_driver::lock_scheduler().map_err(|_| SleS1InitError::SchedulerLock)?;
    let spawn_result = (|| {
        spawn_task(&mut reservations, 0, task_bt)?;
        spawn_task(&mut reservations, 1, task_bt_sdk)?;
        spawn_task(&mut reservations, 2, task_bth_sdk)?;
        spawn_task(&mut reservations, 3, task_service)
    })();
    let unlock_result = hisi_rf_rtos_driver::unlock_scheduler();
    spawn_result?;
    unlock_result.map_err(|_| SleS1InitError::SchedulerUnlock)?;
    hisi_rf_rtos_driver::yield_now().map_err(|_| SleS1InitError::TaskHandoff)?;

    let status = unsafe { ws63_radio_sys::sle::enable_sle() };
    if status != 0 {
        return Err(SleS1InitError::Enable(status));
    }
    Ok(SleS1Controller {
        _efuse: resources.efuse,
        events: storage.events,
    })
}

#[cfg(not(target_arch = "riscv32"))]
pub fn init_sle_s1(
    _resources: SleS1Resources,
    _storage: InstalledSleS1Storage,
) -> Result<SleS1Controller, SleS1InitError> {
    Err(SleS1InitError::UnsupportedTarget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_inventory_matches_shared_bgle_controller_profile() {
        assert_eq!(TASK_COUNT, 4);
        assert_eq!(STACKS.iter().sum::<usize>(), 10_240);
        assert_eq!(STACKS[2], SLE_S1_MINIMUM_TASK_STACK_BYTES);
        assert_eq!(PRIORITIES, [1, 12, 13, 12]);
    }

    #[test]
    fn event_queue_is_bounded_and_fifo() {
        let queue = EventQueue::new();
        for status in 0..EVENT_CAPACITY as u32 {
            queue.push(SleS1Event::Enabled { status });
        }
        queue.push(SleS1Event::Enabled { status: 99 });
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 1);
        for status in 0..EVENT_CAPACITY as u32 {
            assert_eq!(queue.pop(), Some(SleS1Event::Enabled { status }));
        }
        assert_eq!(queue.pop(), None);
    }
}
