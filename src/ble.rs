//! Internal WS63 BLE B1 controller/host initialization.
//!
//! B1 is deliberately narrower than a public BLE API: it installs the fixed
//! vendor task set, platform services, and controller/host runtime, then proves
//! that `enable_ble` completes. Advertising, scanning, GATT, and user callbacks
//! remain outside this module until B2.

use core::cell::UnsafeCell;
#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;
use core::mem::MaybeUninit;
#[cfg(any(target_arch = "riscv32", test))]
use core::num::{NonZeroU32, NonZeroUsize};

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_hal::peripherals::{Efuse, Km, Spacc, Trng};
use portable_atomic::{AtomicBool, Ordering};
use static_cell::StaticCell;

/// Caller-owned heap shared by the BLE host, controller, and RTOS objects.
pub const BLE_B1_ARENA_BYTES: usize = crate::WS63_SHARED_RADIO_ARENA_BYTES;

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
}

impl BleB1ControlStorage {
    /// Construct uninitialized B1 control storage.
    pub const fn new() -> Self {
        Self {
            crypto: StaticCell::new(),
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
        Ok(InstalledBleB1Storage { crypto })
    }
}

/// Proof that the B1 shared arena and crypto storage were installed.
pub struct InstalledBleB1Storage {
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    crypto: &'static mut Ws63CryptoStorage,
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
    /// The WS63 hardware entropy service could not be installed.
    Crypto,
    /// `enable_ble` returned a vendor error.
    Enable(u32),
    /// BLE B1 is executable only on WS63 target firmware.
    UnsupportedTarget,
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    fn bt_thread_handle(argument: *mut c_void);
    fn bt_acore_task_main();
    fn sdk_msg_thread();
    fn btsrv_task_body(argument: *const c_void);
    fn enable_ble() -> u32;
}

#[cfg(target_arch = "riscv32")]
extern "C" fn bt_task(argument: *mut c_void) -> *mut c_void {
    unsafe { bt_thread_handle(argument) };
    core::ptr::null_mut()
}

#[cfg(target_arch = "riscv32")]
extern "C" fn bt_sdk_task(_: *mut c_void) -> *mut c_void {
    unsafe { bt_acore_task_main() };
    core::ptr::null_mut()
}

#[cfg(target_arch = "riscv32")]
extern "C" fn bth_sdk_task(_: *mut c_void) -> *mut c_void {
    unsafe { sdk_msg_thread() };
    core::ptr::null_mut()
}

#[cfg(target_arch = "riscv32")]
extern "C" fn bt_service_task(argument: *mut c_void) -> *mut c_void {
    unsafe { btsrv_task_body(argument.cast_const()) };
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
    // SAFETY: B1 initialization runs once before any vendor task executes and
    // owns the fixed linker regions described by the selected BLE profile.
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
    .map_err(|_| BleB1InitError::Crypto)?;

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
    let unlock_result = hisi_rf_rtos_driver::unlock_scheduler();
    spawn_result?;
    unlock_result.map_err(|_| BleB1InitError::SchedulerUnlock)?;

    let status = unsafe { enable_ble() };
    if status != 0 {
        return Err(BleB1InitError::Enable(status));
    }
    Ok(BleB1Controller {
        _efuse: resources.efuse,
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
}
