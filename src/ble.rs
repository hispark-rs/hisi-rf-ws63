//! Internal WS63 BLE controller/host initialization and B2 discovery slice.
//!
//! B1 is deliberately narrower than a public BLE API: it installs the fixed
//! vendor task set, platform services, and controller/host runtime, then proves
//! that `enable_ble` completes. B2 adds advertising, scanning, and a bounded
//! copied-event queue. GATT, pairing, and user callbacks remain out of scope.

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

/// Caller-owned heap shared by the BLE host, controller, and RTOS objects.
pub const BLE_B1_ARENA_BYTES: usize = crate::WS63_SHARED_RADIO_ARENA_BYTES;
/// Smallest stack in the pinned heterogeneous BLE B1 task profile.
pub const BLE_B1_MINIMUM_TASK_STACK_BYTES: usize = 512;

#[cfg(any(target_arch = "riscv32", test))]
const TASK_COUNT: usize = 4;
#[cfg(any(target_arch = "riscv32", test))]
const STACK_BT: usize = 3_584;
#[cfg(any(target_arch = "riscv32", test))]
const STACK_BT_SDK: usize = 2_048;
#[cfg(any(target_arch = "riscv32", test))]
const STACK_BTH_SDK: usize = 512;
#[cfg(any(target_arch = "riscv32", test))]
const STACK_BT_SERVICE: usize = 4_096;

#[cfg(any(target_arch = "riscv32", test))]
const PRIORITY_BT: u8 = 1;
#[cfg(any(target_arch = "riscv32", test))]
const PRIORITY_BT_SDK: u8 = 12;
#[cfg(any(target_arch = "riscv32", test))]
const PRIORITY_BTH_SDK: u8 = 13;
#[cfg(any(target_arch = "riscv32", test))]
const PRIORITY_BT_SERVICE: u8 = 12;

#[cfg(any(target_arch = "riscv32", test))]
const OWNER_BT: u32 = 0x424c_4501;
#[cfg(any(target_arch = "riscv32", test))]
const OWNER_BT_SDK: u32 = 0x424c_4502;
#[cfg(any(target_arch = "riscv32", test))]
const OWNER_BTH_SDK: u32 = 0x424c_4503;
#[cfg(any(target_arch = "riscv32", test))]
const OWNER_BT_SERVICE: u32 = 0x424c_4504;

const BLE_B2_EVENT_CAPACITY: usize = 16;
const BLE_B2_ADV_DATA_CAPACITY: usize = 31;

/// One bounded event copied out of the vendor BLE callback context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BleB2Event {
    /// The controller/host enable request completed.
    Enabled { status: u32 },
    /// Advertising data was accepted or rejected.
    AdvertisingData { adv_id: u8, status: u32 },
    /// Advertising parameters were accepted or rejected.
    AdvertisingParameters { adv_id: u8, status: u32 },
    /// Advertising entered the reported vendor state.
    AdvertisingState { adv_id: u8, status: u32 },
    /// Scan parameters were accepted or rejected.
    ScanParameters { status: u32 },
    /// A scan result copied into caller-independent bounded storage.
    ScanResult {
        address: [u8; 6],
        address_type: u8,
        rssi: i8,
        data_len: u8,
        data: [u8; BLE_B2_ADV_DATA_CAPACITY],
    },
}

impl BleB2Event {
    const EMPTY: Self = Self::Enabled { status: u32::MAX };
}

struct BleEventRing {
    events: [BleB2Event; BLE_B2_EVENT_CAPACITY],
    head: usize,
    len: usize,
}

impl BleEventRing {
    const fn new() -> Self {
        Self {
            events: [BleB2Event::EMPTY; BLE_B2_EVENT_CAPACITY],
            head: 0,
            len: 0,
        }
    }
}

struct BleEventQueue {
    ring: critical_section::Mutex<RefCell<BleEventRing>>,
    dropped: AtomicU32,
}

impl BleEventQueue {
    const fn new() -> Self {
        Self {
            ring: critical_section::Mutex::new(RefCell::new(BleEventRing::new())),
            dropped: AtomicU32::new(0),
        }
    }

    fn push(&self, event: BleB2Event) {
        let accepted = critical_section::with(|cs| {
            let mut ring = self.ring.borrow(cs).borrow_mut();
            if ring.len == BLE_B2_EVENT_CAPACITY {
                return false;
            }
            let index = (ring.head + ring.len) % BLE_B2_EVENT_CAPACITY;
            ring.events[index] = event;
            ring.len += 1;
            true
        });
        if !accepted {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn pop(&self) -> Option<BleB2Event> {
        critical_section::with(|cs| {
            let mut ring = self.ring.borrow(cs).borrow_mut();
            if ring.len == 0 {
                return None;
            }
            let event = ring.events[ring.head];
            ring.head = (ring.head + 1) % BLE_B2_EVENT_CAPACITY;
            ring.len -= 1;
            Some(event)
        })
    }
}

#[cfg(target_arch = "riscv32")]
static BLE_EVENT_QUEUE: AtomicPtr<BleEventQueue> = AtomicPtr::new(core::ptr::null_mut());

/// Caller-owned B1 allocator bytes. They may be claimed exactly once.
#[repr(C, align(64))]
pub struct BleB1ArenaStorage<const N: usize> {
    arena: UnsafeCell<[MaybeUninit<u8>; N]>,
    claimed: AtomicBool,
}

// SAFETY: the arena and crypto storage are exposed only through the one-shot
// installation path, which transfers process-lifetime ownership.
unsafe impl<const N: usize> Sync for BleB1ArenaStorage<N> {}

impl<const N: usize> BleB1ArenaStorage<N> {
    /// Construct unclaimed BLE B1 allocator storage.
    pub const fn new() -> Self {
        Self {
            arena: UnsafeCell::new([MaybeUninit::uninit(); N]),
            claimed: AtomicBool::new(false),
        }
    }
}

impl<const N: usize> Default for BleB1ArenaStorage<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Small caller-owned B1 control and crypto state.
pub struct BleB1ControlStorage {
    crypto: StaticCell<Ws63CryptoStorage>,
    events: StaticCell<BleEventQueue>,
}

impl BleB1ControlStorage {
    /// Construct uninitialized B1 control storage.
    pub const fn new() -> Self {
        Self {
            crypto: StaticCell::new(),
            events: StaticCell::new(),
        }
    }
}

impl Default for BleB1ControlStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Composition object joining B1 control state and its dedicated arena.
pub struct BleB1Storage<const N: usize> {
    control: &'static BleB1ControlStorage,
    arena: &'static BleB1ArenaStorage<N>,
}

impl<const N: usize> BleB1Storage<N> {
    /// Join statically allocated B1 control and arena storage.
    #[doc(hidden)]
    pub const fn from_parts(
        control: &'static BleB1ControlStorage,
        arena: &'static BleB1ArenaStorage<N>,
    ) -> Self {
        Self { control, arena }
    }

    /// Install the shared allocator before the RTOS is started.
    pub fn install(&'static self) -> Result<InstalledBleB1Storage, BleB1InitError> {
        if N < BLE_B1_ARENA_BYTES {
            return Err(BleB1InitError::InsufficientArena {
                required: BLE_B1_ARENA_BYTES,
                available: N,
            });
        }
        self.arena
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BleB1InitError::StorageAlreadyInstalled)?;

        // SAFETY: the successful one-shot claim transfers this static region
        // exclusively to the process-wide RF allocator.
        if unsafe { crate::alloc::install_raw_arena(self.arena.arena.get().cast(), N) }.is_err() {
            return Err(BleB1InitError::AllocatorInstall);
        }
        let crypto = self.control.crypto.init(Ws63CryptoStorage::new());
        let events = self.control.events.init(BleEventQueue::new());
        Ok(InstalledBleB1Storage { crypto, events })
    }
}

/// Proof that the B1 shared arena and crypto storage were installed.
pub struct InstalledBleB1Storage {
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    crypto: &'static mut Ws63CryptoStorage,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    events: &'static BleEventQueue,
}

impl InstalledBleB1Storage {
    /// Allocate a zeroed RTOS object or task stack from the B1 arena.
    ///
    /// # Safety
    ///
    /// The returned pointer must be released only through [`Self::deallocate`].
    pub unsafe fn allocate(size: usize) -> *mut u8 {
        crate::alloc::allocate_zeroed(size, 16).cast()
    }

    /// Release a pointer returned by [`Self::allocate`].
    ///
    /// # Safety
    ///
    /// `pointer` must be null or a live allocation from this B1 arena.
    pub unsafe fn deallocate(pointer: *mut u8) {
        crate::alloc::osal_kfree(pointer.cast());
    }
}

/// HAL capabilities consumed by BLE B1 initialization.
pub struct BleB1Resources {
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    efuse: Efuse<'static>,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    km: Km<'static>,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    spacc: Spacc<'static>,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    trng: Trng<'static>,
}

impl BleB1Resources {
    /// Bind the uniquely owned eFuse and unified-cipher capabilities.
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

/// Process-lifetime proof that the internal BLE B1 runtime is active.
#[must_use = "retain the BLE B1 controller so the eFuse capability stays owned"]
pub struct BleB1Controller {
    _efuse: Efuse<'static>,
    events: &'static BleEventQueue,
}

impl BleB1Controller {
    /// Remove and return the oldest copied vendor event, if any.
    pub fn next_event(&mut self) -> Option<BleB2Event> {
        self.events.pop()
    }

    /// Number of vendor events rejected because the bounded queue was full.
    pub fn dropped_events(&self) -> u32 {
        self.events.dropped.load(Ordering::Relaxed)
    }

    /// Configure legacy advertising data and start advertising handle zero.
    ///
    /// The buffer is process-lifetime data because the vendor API may consume
    /// it asynchronously after the command returns.
    #[cfg(target_arch = "riscv32")]
    pub fn start_advertising(&mut self, advertising_data: &'static [u8]) -> Result<(), BleB2Error> {
        if advertising_data.len() > BLE_B2_ADV_DATA_CAPACITY {
            return Err(BleB2Error::AdvertisingDataTooLong {
                length: advertising_data.len(),
            });
        }
        let data = GapBleAdvertisingData {
            advertising_length: advertising_data.len() as u16,
            advertising_data: advertising_data.as_ptr().cast_mut(),
            scan_response_length: 0,
            scan_response_data: core::ptr::null_mut(),
        };
        let status = unsafe { gap_ble_set_adv_data(0, &raw const data) };
        if status != 0 {
            return Err(BleB2Error::SetAdvertisingData(status));
        }

        let parameters = GapBleAdvertisingParameters {
            min_interval: 0x20,
            max_interval: 0x60,
            advertising_type: 0,
            own_address: BdAddr {
                addr: [0; 6],
                address_type: 0,
            },
            peer_address: BdAddr {
                addr: [0; 6],
                address_type: 0,
            },
            channel_map: 0x07,
            filter_policy: 0,
            tx_power: 0,
            duration: 0,
            max_events: 0,
        };
        let status = unsafe { gap_ble_set_adv_param(0, &raw const parameters) };
        if status != 0 {
            return Err(BleB2Error::SetAdvertisingParameters(status));
        }
        let status = unsafe { gap_ble_start_adv(0) };
        if status != 0 {
            return Err(BleB2Error::StartAdvertising(status));
        }
        Ok(())
    }

    /// Configure continuous passive 1M scanning and start the scanner.
    #[cfg(target_arch = "riscv32")]
    pub fn start_scanning(&mut self) -> Result<(), BleB2Error> {
        let parameters = GapBleScanParameters {
            interval: 0x48,
            window: 0x48,
            scan_type: 0,
            phy: 1,
            filter_policy: 0,
        };
        let status = unsafe { gap_ble_set_scan_parameters(&raw const parameters) };
        if status != 0 {
            return Err(BleB2Error::SetScanParameters(status));
        }
        let status = unsafe { gap_ble_start_scan() };
        if status != 0 {
            return Err(BleB2Error::StartScanning(status));
        }
        Ok(())
    }

    /// Host builds cannot invoke the WS63 GAP implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn start_advertising(&mut self, _: &'static [u8]) -> Result<(), BleB2Error> {
        Err(BleB2Error::UnsupportedTarget)
    }

    /// Host builds cannot invoke the WS63 GAP implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn start_scanning(&mut self) -> Result<(), BleB2Error> {
        Err(BleB2Error::UnsupportedTarget)
    }
}

/// Fail-closed errors returned while starting BLE B2 advertising or scanning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BleB2Error {
    /// Legacy advertising data is limited to 31 bytes.
    AdvertisingDataTooLong { length: usize },
    /// The vendor stack rejected advertising data synchronously.
    SetAdvertisingData(u32),
    /// The vendor stack rejected advertising parameters synchronously.
    SetAdvertisingParameters(u32),
    /// The vendor stack rejected the advertising start request synchronously.
    StartAdvertising(u32),
    /// The vendor stack rejected scan parameters synchronously.
    SetScanParameters(u32),
    /// The vendor stack rejected the scan start request synchronously.
    StartScanning(u32),
    /// BLE B2 operations require WS63 target firmware.
    UnsupportedTarget,
}

/// Fail-closed BLE B1 initialization stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BleB1InitError {
    /// Caller storage was already consumed.
    StorageAlreadyInstalled,
    /// Caller storage is smaller than the fixed B1 arena envelope.
    InsufficientArena { required: usize, available: usize },
    /// The process-wide allocator rejected the caller storage.
    AllocatorInstall,
    /// The runtime rejected the four-group atomic task plan.
    TaskPlan,
    /// Atomic task-slot/stack admission failed before any task was created.
    TaskAdmission,
    /// Scheduler locking failed.
    SchedulerLock,
    /// One admitted vendor task could not be created.
    TaskSpawn { index: usize },
    /// Scheduler unlocking failed.
    SchedulerUnlock,
    /// The cooperative runtime could not hand off to the newly ready BLE tasks.
    TaskHandoff,
    /// The WS63 hardware entropy service could not be installed.
    Crypto,
    /// `enable_ble` returned a vendor error.
    Enable(u32),
    /// Another BLE controller already owns the process-wide callback sink.
    EventSinkAlreadyInstalled,
    /// GAP callback registration returned a vendor error.
    RegisterCallbacks(u32),
    /// BLE B1 is executable only on WS63 target firmware.
    UnsupportedTarget,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
#[derive(Clone, Copy)]
struct BdAddr {
    addr: [u8; 6],
    address_type: u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GapBleAdvertisingData {
    advertising_length: u16,
    advertising_data: *mut u8,
    scan_response_length: u16,
    scan_response_data: *mut u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GapBleAdvertisingParameters {
    min_interval: u32,
    max_interval: u32,
    advertising_type: u8,
    own_address: BdAddr,
    peer_address: BdAddr,
    channel_map: u8,
    filter_policy: u8,
    tx_power: i8,
    duration: u32,
    max_events: u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GapBleScanParameters {
    interval: u16,
    window: u16,
    scan_type: u8,
    phy: u8,
    filter_policy: u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GapBleScanResult {
    event_type: u8,
    data_status: u8,
    address: BdAddr,
    primary_phy: u8,
    secondary_phy: u8,
    advertising_sid: u8,
    tx_power: i8,
    rssi: i8,
    periodic_advertising_interval: u16,
    direct_address: BdAddr,
    advertising_length: u8,
    advertising_data: *const u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GapBleCallbacks {
    enable: Option<extern "C" fn(u32)>,
    disable: *const c_void,
    set_advertising_data: Option<extern "C" fn(u8, u32)>,
    set_advertising_parameters: Option<extern "C" fn(u8, u32)>,
    set_scan_parameters: Option<extern "C" fn(u32)>,
    start_advertising: Option<extern "C" fn(u8, u32)>,
    stop_advertising: *const c_void,
    scan_result: Option<extern "C" fn(*const GapBleScanResult)>,
    connection_state: *const c_void,
    pairing_result: *const c_void,
    read_rssi: *const c_void,
    terminate_advertising: *const c_void,
    authentication_complete: *const c_void,
    connection_parameters: *const c_void,
    set_data_filter: *const c_void,
    clean_data_filter: *const c_void,
}

#[cfg(target_arch = "riscv32")]
impl GapBleCallbacks {
    const fn b2() -> Self {
        Self {
            enable: Some(ble_enable_callback),
            disable: core::ptr::null(),
            set_advertising_data: Some(ble_set_advertising_data_callback),
            set_advertising_parameters: Some(ble_set_advertising_parameters_callback),
            set_scan_parameters: Some(ble_set_scan_parameters_callback),
            start_advertising: Some(ble_start_advertising_callback),
            stop_advertising: core::ptr::null(),
            scan_result: Some(ble_scan_result_callback),
            connection_state: core::ptr::null(),
            pairing_result: core::ptr::null(),
            read_rssi: core::ptr::null(),
            terminate_advertising: core::ptr::null(),
            authentication_complete: core::ptr::null(),
            connection_parameters: core::ptr::null(),
            set_data_filter: core::ptr::null(),
            clean_data_filter: core::ptr::null(),
        }
    }
}

#[cfg(target_arch = "riscv32")]
static mut BLE_CALLBACKS: GapBleCallbacks = GapBleCallbacks::b2();

#[cfg(target_arch = "riscv32")]
fn push_ble_event(event: BleB2Event) {
    let queue = BLE_EVENT_QUEUE.load(Ordering::Acquire);
    if !queue.is_null() {
        // SAFETY: init_ble_b1 publishes process-lifetime StaticCell storage
        // before registering callbacks, and never replaces or frees it.
        unsafe { &*queue }.push(event);
    }
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_enable_callback(status: u32) {
    push_ble_event(BleB2Event::Enabled { status });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_set_advertising_data_callback(advertising_id: u8, status: u32) {
    push_ble_event(BleB2Event::AdvertisingData {
        adv_id: advertising_id,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_set_advertising_parameters_callback(advertising_id: u8, status: u32) {
    push_ble_event(BleB2Event::AdvertisingParameters {
        adv_id: advertising_id,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_set_scan_parameters_callback(status: u32) {
    push_ble_event(BleB2Event::ScanParameters { status });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_start_advertising_callback(advertising_id: u8, status: u32) {
    push_ble_event(BleB2Event::AdvertisingState {
        adv_id: advertising_id,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_scan_result_callback(result: *const GapBleScanResult) {
    let Some(result) = (unsafe { result.as_ref() }) else {
        return;
    };
    let mut data = [0; BLE_B2_ADV_DATA_CAPACITY];
    let length = usize::from(result.advertising_length).min(data.len());
    if length != 0 && !result.advertising_data.is_null() {
        // SAFETY: the vendor callback guarantees its advertising-data pointer
        // for the callback duration. Copying here prevents it escaping.
        unsafe {
            core::ptr::copy_nonoverlapping(result.advertising_data, data.as_mut_ptr(), length)
        };
    }
    push_ble_event(BleB2Event::ScanResult {
        address: result.address.addr,
        address_type: result.address.address_type,
        rssi: result.rssi,
        data_len: length as u8,
        data,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    fn bt_thread_handle(argument: *mut c_void);
    fn bt_acore_task_main();
    fn sdk_msg_thread();
    fn btsrv_task_body(argument: *const c_void);
    fn enable_ble() -> u32;
    fn gap_ble_register_callbacks(callbacks: *mut GapBleCallbacks) -> u32;
    fn gap_ble_set_adv_data(advertising_id: u8, data: *const GapBleAdvertisingData) -> u32;
    fn gap_ble_set_adv_param(
        advertising_id: u8,
        parameters: *const GapBleAdvertisingParameters,
    ) -> u32;
    fn gap_ble_start_adv(advertising_id: u8) -> u32;
    fn gap_ble_set_scan_parameters(parameters: *const GapBleScanParameters) -> u32;
    fn gap_ble_start_scan() -> u32;
}

#[cfg(target_arch = "riscv32")]
extern "C" fn bt_task(argument: *mut c_void) -> *mut c_void {
    crate::log_emit(b"RFDBG_BLE_B1_TASK_ENTER name=bt\r\n");
    unsafe { bt_thread_handle(argument) };
    crate::log_emit(b"RFDBG_BLE_B1_TASK_RETURN name=bt\r\n");
    core::ptr::null_mut()
}

#[cfg(target_arch = "riscv32")]
extern "C" fn bt_sdk_task(_: *mut c_void) -> *mut c_void {
    crate::log_emit(b"RFDBG_BLE_B1_TASK_ENTER name=bt_sdk\r\n");
    unsafe { bt_acore_task_main() };
    crate::log_emit(b"RFDBG_BLE_B1_TASK_RETURN name=bt_sdk\r\n");
    core::ptr::null_mut()
}

#[cfg(target_arch = "riscv32")]
extern "C" fn bth_sdk_task(_: *mut c_void) -> *mut c_void {
    crate::log_emit(b"RFDBG_BLE_B1_TASK_ENTER name=bth_sdk\r\n");
    unsafe { sdk_msg_thread() };
    crate::log_emit(b"RFDBG_BLE_B1_TASK_RETURN name=bth_sdk\r\n");
    core::ptr::null_mut()
}

#[cfg(target_arch = "riscv32")]
extern "C" fn bt_service_task(argument: *mut c_void) -> *mut c_void {
    crate::log_emit(b"RFDBG_BLE_B1_TASK_ENTER name=bt_service\r\n");
    unsafe { btsrv_task_body(argument.cast_const()) };
    crate::log_emit(b"RFDBG_BLE_B1_TASK_RETURN name=bt_service\r\n");
    core::ptr::null_mut()
}

#[cfg(any(target_arch = "riscv32", test))]
fn task_group(
    owner: u32,
    stack_bytes: usize,
) -> Result<hisi_rf_rtos_driver::TaskResourceGroupRequirements, BleB1InitError> {
    let owner = NonZeroU32::new(owner).ok_or(BleB1InitError::TaskPlan)?;
    let slots = NonZeroUsize::new(1).ok_or(BleB1InitError::TaskPlan)?;
    let stack = NonZeroUsize::new(stack_bytes).ok_or(BleB1InitError::TaskPlan)?;
    let resources = hisi_rf_rtos_driver::TaskResourceRequirements::new(slots, stack)
        .ok_or(BleB1InitError::TaskPlan)?;
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
    stack_bytes: usize,
    priority: u8,
) -> Result<(), BleB1InitError> {
    let reservation = reservations
        .take(index)
        .ok_or(BleB1InitError::TaskSpawn { index })?;
    let config = hisi_rf_rtos_driver::TaskConfig {
        stack_size: NonZeroUsize::new(stack_bytes).ok_or(BleB1InitError::TaskPlan)?,
        priority: hisi_rf_rtos_driver::TaskPriority::new(priority)
            .ok_or(BleB1InitError::TaskPlan)?,
    };
    hisi_rf_rtos_driver::spawn_reserved(&reservation, entry, core::ptr::null_mut(), config)
        .map(|_| ())
        .map_err(|_| BleB1InitError::TaskSpawn { index })
}

/// Start the fixed B1 BLE controller/host closure.
///
/// This remains an internal integration API until B2 provides observable BLE
/// operations and bounded events.
#[cfg(target_arch = "riscv32")]
pub fn init_ble_b1(
    resources: BleB1Resources,
    storage: InstalledBleB1Storage,
) -> Result<BleB1Controller, BleB1InitError> {
    crate::ensure_ble_init_link_contract();
    crate::log_emit(b"RFDBG_BLE_B1_LINK_CONTRACT_OK\r\n");
    // SAFETY: B1 initialization runs once before any vendor task executes and
    // owns the fixed linker regions described by the selected BLE profile.
    unsafe { crate::prepare_vendor_memory() };
    crate::log_emit(b"RFDBG_BLE_B1_VENDOR_MEMORY_OK\r\n");
    let _ = crate::uapi::initialize_rom_timebases();
    crate::log_emit(b"RFDBG_BLE_B1_TIMEBASE_OK\r\n");
    crate::uapi::enable_efuse_reads();
    crate::log_emit(b"RFDBG_BLE_B1_EFUSE_OK\r\n");
    crate::crypto::install_hardware_crypto(
        resources.km,
        resources.spacc,
        None,
        resources.trng,
        storage.crypto,
    )
    .map_err(|_| BleB1InitError::Crypto)?;
    crate::log_emit(b"RFDBG_BLE_B1_CRYPTO_OK\r\n");

    BLE_EVENT_QUEUE
        .compare_exchange(
            core::ptr::null_mut(),
            (storage.events as *const BleEventQueue).cast_mut(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| BleB1InitError::EventSinkAlreadyInstalled)?;
    let callback_status =
        unsafe { gap_ble_register_callbacks(core::ptr::addr_of_mut!(BLE_CALLBACKS)) };
    if callback_status != 0 {
        return Err(BleB1InitError::RegisterCallbacks(callback_status));
    }
    crate::log_emit(b"RFDBG_BLE_B2_CALLBACKS_OK\r\n");

    let groups: [_; TASK_COUNT] = [
        task_group(OWNER_BT, STACK_BT)?,
        task_group(OWNER_BT_SDK, STACK_BT_SDK)?,
        task_group(OWNER_BTH_SDK, STACK_BTH_SDK)?,
        task_group(OWNER_BT_SERVICE, STACK_BT_SERVICE)?,
    ];
    let plan =
        hisi_rf_rtos_driver::TaskResourcePlan::new(&groups).ok_or(BleB1InitError::TaskPlan)?;
    let mut reservations = hisi_rf_rtos_driver::reserve_task_resource_plan(plan)
        .map_err(|_| BleB1InitError::TaskAdmission)?;
    crate::log_emit(b"RFDBG_BLE_B1_ADMISSION_OK\r\n");

    hisi_rf_rtos_driver::lock_scheduler().map_err(|_| BleB1InitError::SchedulerLock)?;
    let spawn_result = (|| {
        spawn_task(&mut reservations, 0, bt_task, STACK_BT, PRIORITY_BT)?;
        spawn_task(
            &mut reservations,
            1,
            bt_sdk_task,
            STACK_BT_SDK,
            PRIORITY_BT_SDK,
        )?;
        spawn_task(
            &mut reservations,
            2,
            bth_sdk_task,
            STACK_BTH_SDK,
            PRIORITY_BTH_SDK,
        )?;
        spawn_task(
            &mut reservations,
            3,
            bt_service_task,
            STACK_BT_SERVICE,
            PRIORITY_BT_SERVICE,
        )
    })();
    crate::log_emit(b"RFDBG_BLE_B1_SPAWN_BATCH_DONE\r\n");
    let unlock_result = hisi_rf_rtos_driver::unlock_scheduler();
    spawn_result?;
    unlock_result.map_err(|_| BleB1InitError::SchedulerUnlock)?;
    crate::log_emit(b"RFDBG_BLE_B1_SCHEDULER_UNLOCKED\r\n");

    // LiteOS starts the application and BLE tasks as one initial scheduler
    // population, so the highest-priority BLE task runs before app_main. This
    // port adopts main first and adds the BLE tasks later; make that initial
    // handoff explicit while preserving Cooperative semantics for every task.
    hisi_rf_rtos_driver::yield_now().map_err(|_| BleB1InitError::TaskHandoff)?;
    crate::log_emit(b"RFDBG_BLE_B1_TASKS_PRIMED\r\n");

    crate::log_emit(b"RFDBG_BLE_B1_ENABLE_BEGIN\r\n");
    let status = unsafe { enable_ble() };
    if status != 0 {
        return Err(BleB1InitError::Enable(status));
    }
    Ok(BleB1Controller {
        _efuse: resources.efuse,
        events: storage.events,
    })
}

/// Host builds can validate the storage and task plan but cannot execute ROM.
#[cfg(not(target_arch = "riscv32"))]
pub fn init_ble_b1(
    _resources: BleB1Resources,
    _storage: InstalledBleB1Storage,
) -> Result<BleB1Controller, BleB1InitError> {
    Err(BleB1InitError::UnsupportedTarget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b1_task_inventory_matches_archive_profile() {
        assert_eq!(TASK_COUNT, 4);
        assert_eq!(
            STACK_BT + STACK_BT_SDK + STACK_BTH_SDK + STACK_BT_SERVICE,
            10_240
        );
        assert_eq!(STACK_BTH_SDK, BLE_B1_MINIMUM_TASK_STACK_BYTES);
        assert_eq!(
            [
                PRIORITY_BT,
                PRIORITY_BT_SDK,
                PRIORITY_BTH_SDK,
                PRIORITY_BT_SERVICE,
            ],
            [1, 12, 13, 12]
        );
    }

    #[test]
    fn b1_task_groups_form_one_atomic_plan() {
        let groups = [
            task_group(OWNER_BT, STACK_BT).unwrap(),
            task_group(OWNER_BT_SDK, STACK_BT_SDK).unwrap(),
            task_group(OWNER_BTH_SDK, STACK_BTH_SDK).unwrap(),
            task_group(OWNER_BT_SERVICE, STACK_BT_SERVICE).unwrap(),
        ];
        let plan = hisi_rf_rtos_driver::TaskResourcePlan::new(&groups).unwrap();
        assert_eq!(plan.total_task_slots(), TASK_COUNT);
        assert_eq!(plan.total_stack_bytes(), 10_240);
    }

    #[test]
    fn b2_event_queue_is_fifo_and_counts_overflow() {
        let queue = BleEventQueue::new();
        for status in 0..BLE_B2_EVENT_CAPACITY as u32 {
            queue.push(BleB2Event::Enabled { status });
        }
        queue.push(BleB2Event::Enabled { status: 99 });
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 1);
        for status in 0..BLE_B2_EVENT_CAPACITY as u32 {
            assert_eq!(queue.pop(), Some(BleB2Event::Enabled { status }));
        }
        assert_eq!(queue.pop(), None);
    }
}

#[cfg(target_arch = "riscv32")]
const _: () = {
    assert!(core::mem::size_of::<BdAddr>() == 7);
    assert!(core::mem::size_of::<GapBleAdvertisingData>() == 16);
    assert!(core::mem::size_of::<GapBleAdvertisingParameters>() == 36);
    assert!(core::mem::size_of::<GapBleScanParameters>() == 8);
    assert!(core::mem::size_of::<GapBleScanResult>() == 28);
    assert!(core::mem::offset_of!(GapBleScanResult, advertising_data) == 24);
    assert!(core::mem::size_of::<GapBleCallbacks>() == 64);
};
