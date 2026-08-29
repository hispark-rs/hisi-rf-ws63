use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;

use hisi_crypto_ws63::Ws63CryptoStorage;
#[cfg(feature = "legacy-blocking-backend")]
use hisi_rf_core::RadioRunner;
use hisi_rf_core::{
    BackendError, BackendErrorClass, Diagnostic, DiagnosticStage, DiagnosticTraceKind, Error,
    RadioState,
};
use hisi_rf_rtos_driver::TaskReservation;
use portable_atomic::{AtomicBool, Ordering};
use static_cell::StaticCell;

#[cfg(feature = "legacy-blocking-backend")]
use crate::hisi_rf_backend::Ws63WifiBackend;
#[cfg(feature = "incremental-embassy-wait")]
use crate::incremental_worker::IncrementalWorkerState;

#[cfg(feature = "incremental-embassy-wait")]
const PROFILE_WORKER_STACK_BYTES: usize = crate::incremental_worker::WORKER_STACK_BYTES;
#[cfg(not(feature = "incremental-embassy-wait"))]
const PROFILE_WORKER_STACK_BYTES: usize = 0;

const RESOURCE_REPORT_SCHEMA: &str = "hisi-rf-resource-report/v11";
pub(crate) const PROFILE_REVISION: &str = "ws63-radio-2026-08-29-r10";
const WIFI_PACKET_RAM_BYTES: usize = 0xc000;
const MAIN_STACK_BYTES_REQUIRED: usize = 0x8000;
const PROFILE_SHARED_ARENA_BYTES: usize = if cfg!(any(
    feature = "coexistence-wifi-ble",
    feature = "coexistence-wifi-sle"
)) {
    // The combined target closure contributes additional fixed BGLE control
    // BSS before `.hisi_shared_arenas`. A stock-rust-lld map measured 0x2480
    // fewer bytes before the fixed task stacks; reserve 16 KiB so the linker
    // remains fail-closed with explicit headroom until two-board calibration.
    276 * 1024
} else if cfg!(feature = "incremental-embassy-wait") {
    // The worker adds just under 4 KiB of bounded control state in ordinary
    // BSS. Keep the firmware's total SRAM envelope honest by returning one
    // 4 KiB page from the large shared arenas.
    292 * 1024
} else {
    crate::WS63_SHARED_RADIO_ARENA_BYTES
};
const TASK_STACK_ALLOCATOR_OVERHEAD_BYTES: usize = 512;
const RUNTIME_OBJECT_HEADROOM_BYTES: usize = 16 * 1024;
// `RadioArenaStorage<N>` carries one claim byte and has 64-byte alignment, so
// a payload whose size is itself 64-byte aligned occupies one extra cache line.
// Account for that physical object overhead in the shared-section budget.
const RADIO_ARENA_STORAGE_OVERHEAD_BYTES: usize = 64;
#[cfg(all(
    target_pointer_width = "32",
    not(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))
))]
const WS63_CONTROL_STORAGE_FIXED_BYTES: usize = if cfg!(feature = "legacy-blocking-backend") {
    // Crypto storage, reservations, claim state, and the legacy runner cell.
    6_361
} else if cfg!(feature = "incremental-embassy-wait") {
    // Crypto storage, both reservations, claim state, and the bounded worker.
    // The target-side layout assertion below keeps this measured RV32 value
    // synchronized with the actual caller-owned object.
    6_496
} else {
    // Crypto storage, the vendor reservation, and claim state.
    4_425
};
#[cfg(all(
    target_pointer_width = "32",
    not(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))
))]
const WS63_CONTROL_STORAGE_ALIGNMENT: usize = 32;
const WS63_RADIO_STATE_BASE_BYTES: usize = 0x708
    // The incremental profile adds 18 instance-owned counters published by the
    // runner for controller-side snapshots after executor task splitting.
    + if cfg!(feature = "incremental-backend-experiment") {
        18 * core::mem::size_of::<u32>()
    } else {
        0
    };
const WS63_RADIO_EVENT_SLOT_BYTES: usize = 52;

mod sealed {
    pub trait Sealed {}
}

/// Stable owner identifiers used by admission diagnostics and reports.
pub mod resource_owner {
    /// Tasks created by the pinned WS63 vendor radio payload.
    pub const VENDOR_TASKS: u32 = 1;
    /// Rust incremental backend worker.
    pub const INCREMENTAL_WORKER: u32 = 2;
    /// Shared BGLE controller task.
    pub const BGLE_CONTROLLER: u32 = 0x424c_4501;
    /// Shared BGLE controller SDK task.
    pub const BGLE_CONTROLLER_SDK: u32 = 0x424c_4502;
    /// Shared BGLE host SDK task.
    pub const BGLE_HOST_SDK: u32 = 0x424c_4503;
    /// Shared BGLE host service task.
    pub const BGLE_HOST_SERVICE: u32 = 0x424c_4504;
}

/// Exact heterogeneous task inventory shared by the pinned BLE and SLE closures.
pub const BGLE_TASK_GROUPS: [TaskGroupPlan; 4] = [
    TaskGroupPlan {
        owner: resource_owner::BGLE_CONTROLLER,
        task_slots: 1,
        stack_bytes_per_task: 3_584,
    },
    TaskGroupPlan {
        owner: resource_owner::BGLE_CONTROLLER_SDK,
        task_slots: 1,
        stack_bytes_per_task: 2_048,
    },
    TaskGroupPlan {
        owner: resource_owner::BGLE_HOST_SDK,
        task_slots: 1,
        stack_bytes_per_task: 512,
    },
    TaskGroupPlan {
        owner: resource_owner::BGLE_HOST_SERVICE,
        task_slots: 1,
        stack_bytes_per_task: 4_096,
    },
];

/// One uniform-stack child in the Wi-Fi resource tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskGroupPlan {
    /// Stable owner identity.
    pub owner: u32,
    /// Number of dynamic tasks owned by this child.
    pub task_slots: usize,
    /// Stack payload reserved for each task.
    pub stack_bytes_per_task: usize,
}

impl TaskGroupPlan {
    /// Total stack payload derived from this child.
    pub const fn total_stack_bytes(self) -> usize {
        match self.task_slots.checked_mul(self.stack_bytes_per_task) {
            Some(total) => total,
            None => panic!("task-group stack total overflow"),
        }
    }
}

const fn task_slots_for_groups(
    vendor: TaskGroupPlan,
    worker: Option<TaskGroupPlan>,
    coexistence: [Option<TaskGroupPlan>; 4],
) -> usize {
    let mut total = vendor.task_slots;
    if let Some(worker) = worker {
        total = match total.checked_add(worker.task_slots) {
            Some(total) => total,
            None => panic!("profile task-slot total overflow"),
        };
    }
    let mut index = 0;
    while index < coexistence.len() {
        if let Some(group) = coexistence[index] {
            total = match total.checked_add(group.task_slots) {
                Some(total) => total,
                None => panic!("profile task-slot total overflow"),
            };
        }
        index += 1;
    }
    total
}

const fn task_stacks_for_groups(
    vendor: TaskGroupPlan,
    worker: Option<TaskGroupPlan>,
    coexistence: [Option<TaskGroupPlan>; 4],
) -> usize {
    let mut total = vendor.total_stack_bytes();
    if let Some(worker) = worker {
        total = match total.checked_add(worker.total_stack_bytes()) {
            Some(total) => total,
            None => panic!("profile task-stack total overflow"),
        };
    }
    let mut index = 0;
    while index < coexistence.len() {
        if let Some(group) = coexistence[index] {
            total = match total.checked_add(group.total_stack_bytes()) {
                Some(total) => total,
                None => panic!("profile task-stack total overflow"),
            };
        }
        index += 1;
    }
    total
}

const fn minimum_stack_for_groups(
    vendor: TaskGroupPlan,
    worker: Option<TaskGroupPlan>,
    coexistence: [Option<TaskGroupPlan>; 4],
) -> usize {
    let mut minimum = vendor.stack_bytes_per_task;
    if let Some(worker) = worker
        && worker.stack_bytes_per_task < minimum
    {
        minimum = worker.stack_bytes_per_task;
    }
    let mut index = 0;
    while index < coexistence.len() {
        if let Some(group) = coexistence[index]
            && group.stack_bytes_per_task < minimum
        {
            minimum = group.stack_bytes_per_task;
        }
        index += 1;
    }
    minimum
}

/// Structured WS63 Wi-Fi resource tree used by reports and admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WifiResourcePlan {
    /// Pinned vendor-payload task group.
    pub vendor: TaskGroupPlan,
    /// Optional Rust incremental worker group.
    pub worker: Option<TaskGroupPlan>,
    /// Optional protocol-coexistence task groups in deterministic spawn order.
    pub coexistence: [Option<TaskGroupPlan>; 4],
    /// Bounded public event queue capacity.
    pub event_capacity: usize,
    /// RTOS object/headroom budget outside task-stack payloads.
    pub runtime_object_bytes: usize,
    /// Minimum RF/supplicant heap supplied by caller-owned storage.
    pub rf_heap_min_bytes: usize,
}

impl WifiResourcePlan {
    /// Bind the caller-selected bounded event queue to this profile plan.
    pub const fn with_event_capacity(mut self, event_capacity: usize) -> Self {
        self.event_capacity = event_capacity;
        self
    }

    /// Total dynamic slots derived exclusively from child groups.
    pub const fn total_task_slots(self) -> usize {
        let mut total = match self.worker {
            Some(worker) => match self.vendor.task_slots.checked_add(worker.task_slots) {
                Some(total) => total,
                None => panic!("task-slot total overflow"),
            },
            None => self.vendor.task_slots,
        };
        let mut index = 0;
        while index < self.coexistence.len() {
            if let Some(group) = self.coexistence[index] {
                total = match total.checked_add(group.task_slots) {
                    Some(total) => total,
                    None => panic!("task-slot total overflow"),
                };
            }
            index += 1;
        }
        total
    }

    /// Dynamic task slots contributed by the optional BGLE child groups.
    pub const fn coexistence_task_slots(self) -> usize {
        let mut total = 0usize;
        let mut index = 0;
        while index < self.coexistence.len() {
            if let Some(group) = self.coexistence[index] {
                total = match total.checked_add(group.task_slots) {
                    Some(total) => total,
                    None => panic!("coexistence task-slot total overflow"),
                };
            }
            index += 1;
        }
        total
    }

    /// Total task-stack payload derived exclusively from child groups.
    pub const fn total_stack_bytes(self) -> usize {
        let mut total = match self.worker {
            Some(worker) => match self
                .vendor
                .total_stack_bytes()
                .checked_add(worker.total_stack_bytes())
            {
                Some(total) => total,
                None => panic!("task-stack total overflow"),
            },
            None => self.vendor.total_stack_bytes(),
        };
        let mut index = 0;
        while index < self.coexistence.len() {
            if let Some(group) = self.coexistence[index] {
                total = match total.checked_add(group.total_stack_bytes()) {
                    Some(total) => total,
                    None => panic!("task-stack total overflow"),
                };
            }
            index += 1;
        }
        total
    }

    /// Stack payload contributed by the optional BGLE child groups.
    pub const fn coexistence_stack_bytes(self) -> usize {
        let mut total = 0usize;
        let mut index = 0;
        while index < self.coexistence.len() {
            if let Some(group) = self.coexistence[index] {
                total = match total.checked_add(group.total_stack_bytes()) {
                    Some(total) => total,
                    None => panic!("coexistence task-stack total overflow"),
                };
            }
            index += 1;
        }
        total
    }

    /// Smallest stack represented by the current child inventory.
    pub const fn minimum_task_stack_bytes(self) -> usize {
        let mut minimum = match self.worker {
            Some(worker) if worker.stack_bytes_per_task < self.vendor.stack_bytes_per_task => {
                worker.stack_bytes_per_task
            }
            _ => self.vendor.stack_bytes_per_task,
        };
        let mut index = 0;
        while index < self.coexistence.len() {
            if let Some(group) = self.coexistence[index]
                && group.stack_bytes_per_task < minimum
            {
                minimum = group.stack_bytes_per_task;
            }
            index += 1;
        }
        minimum
    }

    /// Scheduler arena payload derived from children plus explicit overhead.
    pub const fn runtime_arena_bytes(self) -> usize {
        let stacks = self.total_stack_bytes();
        let with_allocator = match stacks.checked_add(TASK_STACK_ALLOCATOR_OVERHEAD_BYTES) {
            Some(total) => total,
            None => panic!("runtime arena overflow"),
        };
        match with_allocator.checked_add(self.runtime_object_bytes) {
            Some(total) => total,
            None => panic!("runtime arena overflow"),
        }
    }
}

/// A named WS63 radio composition with a fixed security and network contract.
pub trait Profile: sealed::Sealed {
    /// Stable profile identifier used by build reports and diagnostics.
    const ID: &'static str;
    /// Security implementation selected by this profile.
    const SECURITY: &'static str;
    /// Pinned vendor task inventory for this profile.
    const VENDOR_TASKS: TaskGroupPlan = TaskGroupPlan {
        owner: resource_owner::VENDOR_TASKS,
        task_slots: crate::WS63_WIFI_VENDOR_DYNAMIC_TASKS_REQUIRED,
        stack_bytes_per_task: 24 * 1024,
    };
    /// Optional Rust worker inventory for the selected execution feature set.
    const WORKER_TASKS: Option<TaskGroupPlan> = if cfg!(feature = "incremental-embassy-wait") {
        Some(TaskGroupPlan {
            owner: resource_owner::INCREMENTAL_WORKER,
            task_slots: 1,
            stack_bytes_per_task: PROFILE_WORKER_STACK_BYTES,
        })
    } else {
        None
    };
    /// Optional BGLE task inventory selected by a coexistence profile.
    const COEXISTENCE_TASKS: [Option<TaskGroupPlan>; 4] = [None; 4];
    /// Caller-owned bytes reserved for RTOS-owned synchronization objects.
    const RUNTIME_OBJECT_HEADROOM_BYTES: usize = RUNTIME_OBJECT_HEADROOM_BYTES;
    /// Caller-owned shared RF arena bytes required before hardware startup.
    const RF_ARENA_BYTES: usize;
    /// Complete resource tree; all totals are derived from these children.
    const RESOURCE_PLAN: WifiResourcePlan = WifiResourcePlan {
        vendor: Self::VENDOR_TASKS,
        worker: Self::WORKER_TASKS,
        coexistence: Self::COEXISTENCE_TASKS,
        event_capacity: 0,
        runtime_object_bytes: Self::RUNTIME_OBJECT_HEADROOM_BYTES,
        rf_heap_min_bytes: Self::RF_ARENA_BYTES,
    };
    /// Dynamic task slots observed for this profile's pinned payload.
    const DYNAMIC_TASKS_REQUIRED: usize = task_slots_for_groups(
        Self::VENDOR_TASKS,
        Self::WORKER_TASKS,
        Self::COEXISTENCE_TASKS,
    );
    /// Dynamic task slots owned by the vendor payload.
    const VENDOR_DYNAMIC_TASKS_REQUIRED: usize = Self::VENDOR_TASKS.task_slots;
    /// Stack bytes reserved for each vendor task.
    const TASK_STACK_BYTES_PER_TASK: usize = Self::VENDOR_TASKS.stack_bytes_per_task;
    /// Smallest task stack admitted by this heterogeneous profile.
    const MINIMUM_TASK_STACK_BYTES: usize = minimum_stack_for_groups(
        Self::VENDOR_TASKS,
        Self::WORKER_TASKS,
        Self::COEXISTENCE_TASKS,
    );
    /// Exact total stack bytes reserved across heterogeneous profile tasks.
    const TASK_STACK_BYTES: usize = task_stacks_for_groups(
        Self::VENDOR_TASKS,
        Self::WORKER_TASKS,
        Self::COEXISTENCE_TASKS,
    );
    /// Scheduler arena derived from child stacks and explicit object budgets.
    const RUNTIME_ARENA_BYTES: usize =
        match Self::TASK_STACK_BYTES.checked_add(TASK_STACK_ALLOCATOR_OVERHEAD_BYTES) {
            Some(with_allocator) => {
                match with_allocator.checked_add(Self::RUNTIME_OBJECT_HEADROOM_BYTES) {
                    Some(total) => total,
                    None => panic!("profile runtime arena overflow"),
                }
            }
            None => panic!("profile runtime arena overflow"),
        };
    /// Whether this profile's runtime arena completed repeated-silicon calibration.
    const RUNTIME_RESOURCES_CALIBRATED: bool;
}

/// Upstream-hostap WPA2-Personal with the smoltcp L2 adapter.
pub enum WifiWpa2Smoltcp {}

impl sealed::Sealed for WifiWpa2Smoltcp {}
impl Profile for WifiWpa2Smoltcp {
    const ID: &'static str = "wifi-wpa2-smoltcp";
    const SECURITY: &'static str = "wpa2-personal";
    const RF_ARENA_BYTES: usize =
        PROFILE_SHARED_ARENA_BYTES - Self::RUNTIME_ARENA_BYTES - RADIO_ARENA_STORAGE_OVERHEAD_BYTES;
    const RUNTIME_RESOURCES_CALIBRATED: bool = !cfg!(feature = "incremental-embassy-wait");
}

/// Upstream-hostap WPA3-Personal with the smoltcp L2 adapter.
pub enum WifiWpa3Smoltcp {}

impl sealed::Sealed for WifiWpa3Smoltcp {}
impl Profile for WifiWpa3Smoltcp {
    const ID: &'static str = "wifi-wpa3-smoltcp";
    const SECURITY: &'static str = "wpa3-personal";
    const RF_ARENA_BYTES: usize =
        PROFILE_SHARED_ARENA_BYTES - Self::RUNTIME_ARENA_BYTES - RADIO_ARENA_STORAGE_OVERHEAD_BYTES;
    const RUNTIME_RESOURCES_CALIBRATED: bool = false;
}

const BGLE_COEXISTENCE_TASKS: [Option<TaskGroupPlan>; 4] = [
    Some(BGLE_TASK_GROUPS[0]),
    Some(BGLE_TASK_GROUPS[1]),
    Some(BGLE_TASK_GROUPS[2]),
    Some(BGLE_TASK_GROUPS[3]),
];

macro_rules! coexistence_profile {
    ($name:ident, $id:literal, $security:literal) => {
        #[doc = concat!("WS63 ", $id, " maintainer coexistence profile.")]
        pub enum $name {}

        impl sealed::Sealed for $name {}
        impl Profile for $name {
            const ID: &'static str = $id;
            const SECURITY: &'static str = $security;
            const COEXISTENCE_TASKS: [Option<TaskGroupPlan>; 4] = BGLE_COEXISTENCE_TASKS;
            const RF_ARENA_BYTES: usize = PROFILE_SHARED_ARENA_BYTES
                - Self::RUNTIME_ARENA_BYTES
                - RADIO_ARENA_STORAGE_OVERHEAD_BYTES;
            const RUNTIME_RESOURCES_CALIBRATED: bool = false;
        }
    };
}

coexistence_profile!(
    WifiWpa2BleCoexistence,
    "wifi-wpa2-ble-coexistence",
    "wpa2-personal"
);
coexistence_profile!(
    WifiWpa2SleCoexistence,
    "wifi-wpa2-sle-coexistence",
    "wpa2-personal"
);
coexistence_profile!(
    WifiWpa3BleCoexistence,
    "wifi-wpa3-ble-coexistence",
    "wpa3-personal"
);
coexistence_profile!(
    WifiWpa3SleCoexistence,
    "wifi-wpa3-sle-coexistence",
    "wpa3-personal"
);

/// Marker for profiles that share the Wi-Fi composition with one BGLE stack.
#[doc(hidden)]
pub trait CoexistenceProfile: Profile {}

impl CoexistenceProfile for WifiWpa2BleCoexistence {}
impl CoexistenceProfile for WifiWpa2SleCoexistence {}
impl CoexistenceProfile for WifiWpa3BleCoexistence {}
impl CoexistenceProfile for WifiWpa3SleCoexistence {}

/// Marker implemented only for the profile selected by Cargo features.
#[doc(hidden)]
pub trait ActiveProfile: Profile {}

/// Marker for profiles that do not include a second radio protocol stack.
#[doc(hidden)]
pub trait StandaloneWifiProfile: Profile {}

impl StandaloneWifiProfile for WifiWpa2Smoltcp {}
impl StandaloneWifiProfile for WifiWpa3Smoltcp {}

#[cfg(all(
    feature = "wpa2-personal",
    not(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))
))]
impl ActiveProfile for WifiWpa2Smoltcp {}

#[cfg(all(
    feature = "wpa3-personal",
    not(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))
))]
impl ActiveProfile for WifiWpa3Smoltcp {}

#[cfg(all(feature = "wpa2-personal", feature = "coexistence-wifi-ble"))]
impl ActiveProfile for WifiWpa2BleCoexistence {}
#[cfg(all(feature = "wpa2-personal", feature = "coexistence-wifi-sle"))]
impl ActiveProfile for WifiWpa2SleCoexistence {}
#[cfg(all(feature = "wpa3-personal", feature = "coexistence-wifi-ble"))]
impl ActiveProfile for WifiWpa3BleCoexistence {}
#[cfg(all(feature = "wpa3-personal", feature = "coexistence-wifi-sle"))]
impl ActiveProfile for WifiWpa3SleCoexistence {}

/// The profile selected by the current Cargo feature set.
#[cfg(all(
    feature = "wpa2-personal",
    not(feature = "wpa3-personal"),
    not(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))
))]
pub type SelectedProfile = WifiWpa2Smoltcp;

/// The profile selected by the current Cargo feature set.
#[cfg(all(
    feature = "wpa3-personal",
    not(feature = "wpa2-personal"),
    not(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))
))]
pub type SelectedProfile = WifiWpa3Smoltcp;

#[cfg(all(
    feature = "wpa2-personal",
    not(feature = "wpa3-personal"),
    feature = "coexistence-wifi-ble"
))]
pub type SelectedProfile = WifiWpa2BleCoexistence;
#[cfg(all(
    feature = "wpa2-personal",
    not(feature = "wpa3-personal"),
    feature = "coexistence-wifi-sle"
))]
pub type SelectedProfile = WifiWpa2SleCoexistence;
#[cfg(all(
    feature = "wpa3-personal",
    not(feature = "wpa2-personal"),
    feature = "coexistence-wifi-ble"
))]
pub type SelectedProfile = WifiWpa3BleCoexistence;
#[cfg(all(
    feature = "wpa3-personal",
    not(feature = "wpa2-personal"),
    feature = "coexistence-wifi-sle"
))]
pub type SelectedProfile = WifiWpa3SleCoexistence;

/// Byte capacity selected by the active named radio profile.
#[cfg(any(
    all(feature = "wpa2-personal", not(feature = "wpa3-personal")),
    all(feature = "wpa3-personal", not(feature = "wpa2-personal"))
))]
pub const SELECTED_RF_ARENA_BYTES: usize = SelectedProfile::RF_ARENA_BYTES;

/// Scheduler arena bytes required by the active named profile.
#[cfg(any(
    all(feature = "wpa2-personal", not(feature = "wpa3-personal")),
    all(feature = "wpa3-personal", not(feature = "wpa2-personal"))
))]
pub const SELECTED_RUNTIME_ARENA_BYTES: usize = SelectedProfile::RUNTIME_ARENA_BYTES;

/// RTOS minimum task-stack setting required by the active named profile.
///
/// Vendor reservations still retain their measured 24 KiB stacks. This value
/// permits the separately reserved Rust incremental worker to consume its
/// smaller typed stack without weakening any vendor reservation.
#[cfg(any(
    all(feature = "wpa2-personal", not(feature = "wpa3-personal")),
    all(feature = "wpa3-personal", not(feature = "wpa2-personal"))
))]
pub const SELECTED_MINIMUM_TASK_STACK_BYTES: usize = SelectedProfile::MINIMUM_TASK_STACK_BYTES;

/// Migration alias for [`SELECTED_RUNTIME_ARENA_BYTES`].
#[cfg(any(
    all(feature = "wpa2-personal", not(feature = "wpa3-personal")),
    all(feature = "wpa3-personal", not(feature = "wpa2-personal"))
))]
#[deprecated(
    since = "0.1.0-alpha.59",
    note = "use SELECTED_RUNTIME_ARENA_BYTES; the arena also backs RTOS objects"
)]
pub const SELECTED_TASK_STACK_ARENA_BYTES: usize = SELECTED_RUNTIME_ARENA_BYTES;

/// Caller-owned, statically allocated backing storage for the shared RF heap.
///
/// The storage is claimed exactly once and then remains exclusively owned by
/// the WS63 RF allocator for the firmware lifetime.
#[repr(C, align(64))]
pub struct RadioArenaStorage<const N: usize> {
    bytes: UnsafeCell<[MaybeUninit<u8>; N]>,
    claimed: AtomicBool,
}

// SAFETY: safe access to the backing bytes is available only through the
// one-shot `claim`; the returned token is consumed by radio initialization.
unsafe impl<const N: usize> Sync for RadioArenaStorage<N> {}

impl<const N: usize> RadioArenaStorage<N> {
    /// Construct unclaimed arena storage suitable for a `static` item.
    pub const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([MaybeUninit::uninit(); N]),
            claimed: AtomicBool::new(false),
        }
    }

    /// Claim this storage for `P` after validating its named profile envelope.
    pub fn claim_for<P: Profile>(&'static self) -> Result<RadioArena<P>, ArenaAdmissionError> {
        if N < P::RF_ARENA_BYTES {
            return Err(ArenaAdmissionError::InsufficientBytes {
                required: P::RF_ARENA_BYTES,
                available: N,
            });
        }
        if self
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ArenaAdmissionError::AlreadyClaimed);
        }
        Ok(RadioArena {
            start: self.bytes.get().cast::<u8>(),
            len: N,
            _profile: PhantomData,
        })
    }
}

impl<const N: usize> Default for RadioArenaStorage<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Opaque one-shot claim passed from caller-owned storage to radio resources.
pub struct RadioArena<P: Profile> {
    pub(crate) start: *mut u8,
    pub(crate) len: usize,
    _profile: PhantomData<P>,
}

impl<P: Profile> RadioArena<P> {
    /// Install this arena before starting the RTOS and return its capability.
    pub fn install(self) -> Result<InstalledRadioArena<P>, ArenaAdmissionError> {
        crate::alloc::install_arena(self)?;
        Ok(InstalledRadioArena {
            _profile: PhantomData,
        })
    }
}

/// Installed shared-arena capability for one named profile.
///
/// The associated allocation functions can be passed to `hisi-rtos` before
/// this token is consumed by [`crate::Resources`].
pub struct InstalledRadioArena<P: Profile> {
    _profile: PhantomData<P>,
}

impl<P: Profile> InstalledRadioArena<P> {
    /// Allocate one zeroed RTOS block from the installed shared arena.
    ///
    /// # Safety
    ///
    /// The returned pointer must be released only through [`Self::deallocate`].
    pub unsafe fn allocate(size: usize) -> *mut u8 {
        crate::alloc::allocate_zeroed(size, 16).cast()
    }

    /// Release one RTOS block returned by [`Self::allocate`].
    ///
    /// # Safety
    ///
    /// `pointer` must be null or a live allocation returned by
    /// [`Self::allocate`] that has not already been released.
    pub unsafe fn deallocate(pointer: *mut u8) {
        crate::alloc::osal_kfree(pointer.cast());
    }
}

/// Failure to admit the profile's shared RF arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArenaAdmissionError {
    /// The same caller-owned arena was already consumed.
    AlreadyClaimed,
    /// The selected profile requires more bytes than this arena provides.
    InsufficientBytes {
        /// Minimum profile requirement.
        required: usize,
        /// Bytes supplied by the caller.
        available: usize,
    },
    /// The allocator rejected the arena range.
    InvalidArena,
}

impl ArenaAdmissionError {
    /// Convert admission failure into the shared, secret-free diagnostic schema.
    pub fn diagnostic(self) -> Diagnostic {
        match self {
            Self::AlreadyClaimed => Error::AlreadyInitialized.diagnostic(),
            Self::InsufficientBytes {
                required,
                available,
            } => Error::Backend(
                BackendError::new(BackendErrorClass::ResourceUnavailable, 0x5732_b002)
                    .with_stage(DiagnosticStage::Runtime)
                    .with_profile_revision(PROFILE_REVISION)
                    .with_trace(
                        DiagnosticTraceKind::ResourceRequired,
                        required.min(u32::MAX as usize) as u32,
                    )
                    .with_trace(
                        DiagnosticTraceKind::ResourceAvailable,
                        available.min(u32::MAX as usize) as u32,
                    ),
            )
            .diagnostic(),
            Self::InvalidArena => Error::Backend(
                BackendError::new(BackendErrorClass::ResourceUnavailable, 0x5732_b003)
                    .with_stage(DiagnosticStage::Runtime)
                    .with_profile_revision(PROFILE_REVISION),
            )
            .diagnostic(),
        }
    }
}

impl fmt::Display for ArenaAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.diagnostic().fmt(formatter)
    }
}

/// Caller-owned static storage for one WS63 radio instance.
///
/// This owns bounded control/event state and SPACC DMA scratch. The bounded
/// worker is present only in the incremental profile; the synchronous runner
/// cell exists only for the explicit legacy migration feature. Packet RAM remains linker-owned. Task stacks are
/// atomically reserved through the runtime capability before hardware startup;
/// the shared RF arena is installed separately from caller-owned storage.
#[cfg_attr(feature = "incremental-embassy-wait", repr(C, align(32)))]
pub struct Storage<P: Profile, const EVENTS: usize> {
    state: RadioState<EVENTS>,
    #[cfg(feature = "coexistence-wifi-ble")]
    ble: crate::ble::BleB1ControlStorage,
    #[cfg(feature = "coexistence-wifi-sle")]
    sle: crate::sle::SleS1ControlStorage,
    #[cfg(feature = "legacy-blocking-backend")]
    runner: StaticCell<RadioRunner<Ws63WifiBackend<'static>, EVENTS>>,
    crypto: StaticCell<Ws63CryptoStorage>,
    task_reservation: StaticCell<TaskReservation>,
    #[cfg(feature = "incremental-embassy-wait")]
    worker_task_reservation: StaticCell<TaskReservation>,
    #[cfg(feature = "incremental-embassy-wait")]
    incremental_worker: StaticCell<IncrementalWorkerState>,
    claimed: AtomicBool,
    _profile: PhantomData<P>,
}

pub(crate) struct ProfileReservations {
    pub(crate) vendor: TaskReservation,
    pub(crate) worker: Option<TaskReservation>,
}

pub(crate) struct ClaimedStorage<const EVENTS: usize> {
    pub(crate) state: &'static RadioState<EVENTS>,
    pub(crate) crypto: &'static mut Ws63CryptoStorage,
    pub(crate) vendor: &'static TaskReservation,
    pub(crate) worker: Option<&'static TaskReservation>,
    #[cfg(all(target_arch = "riscv32", feature = "coexistence-wifi-ble"))]
    pub(crate) ble: &'static crate::ble::BleB1ControlStorage,
    #[cfg(all(target_arch = "riscv32", feature = "coexistence-wifi-sle"))]
    pub(crate) sle: &'static crate::sle::SleS1ControlStorage,
}

impl<P: Profile, const EVENTS: usize> Storage<P, EVENTS> {
    /// Construct unclaimed storage suitable for a `static` item.
    pub const fn new() -> Self {
        assert!(EVENTS > 0, "radio event queue must not be empty");
        Self {
            state: RadioState::new(),
            #[cfg(feature = "coexistence-wifi-ble")]
            ble: crate::ble::BleB1ControlStorage::new(),
            #[cfg(feature = "coexistence-wifi-sle")]
            sle: crate::sle::SleS1ControlStorage::new(),
            #[cfg(feature = "legacy-blocking-backend")]
            runner: StaticCell::new(),
            crypto: StaticCell::new(),
            task_reservation: StaticCell::new(),
            #[cfg(feature = "incremental-embassy-wait")]
            worker_task_reservation: StaticCell::new(),
            #[cfg(feature = "incremental-embassy-wait")]
            incremental_worker: StaticCell::new(),
            claimed: AtomicBool::new(false),
            _profile: PhantomData,
        }
    }

    /// Return the compile-time resource contract for this storage instance.
    pub const fn report(&self) -> ResourceReport {
        ResourceReport::for_profile::<P, EVENTS>(P::RF_ARENA_BYTES)
    }

    pub(crate) fn claim(
        &'static self,
        reservations: ProfileReservations,
    ) -> Result<ClaimedStorage<EVENTS>, ProfileReservations> {
        if self
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(reservations);
        }
        let crypto = self.crypto.init(Ws63CryptoStorage::new());
        let vendor = self.task_reservation.init(reservations.vendor);
        #[cfg(feature = "incremental-embassy-wait")]
        let worker = reservations
            .worker
            .map(|reservation| &*self.worker_task_reservation.init(reservation));
        #[cfg(not(feature = "incremental-embassy-wait"))]
        let worker = {
            debug_assert!(reservations.worker.is_none());
            None
        };
        Ok(ClaimedStorage {
            state: &self.state,
            crypto,
            vendor,
            worker,
            #[cfg(all(target_arch = "riscv32", feature = "coexistence-wifi-ble"))]
            ble: &self.ble,
            #[cfg(all(target_arch = "riscv32", feature = "coexistence-wifi-sle"))]
            sle: &self.sle,
        })
    }

    #[cfg(feature = "legacy-blocking-backend")]
    pub(crate) fn store_runner(
        &'static self,
        runner: RadioRunner<Ws63WifiBackend<'static>, EVENTS>,
    ) -> &'static mut RadioRunner<Ws63WifiBackend<'static>, EVENTS> {
        // `init` claims this storage exactly once and returns one non-cloneable
        // controller bound to it. Consuming that controller to start the runner
        // therefore initializes this cell at most once.
        self.runner.init(runner)
    }

    #[cfg(feature = "incremental-embassy-wait")]
    pub(crate) fn store_incremental_worker(
        &'static self,
        worker: IncrementalWorkerState,
    ) -> &'static mut IncrementalWorkerState {
        self.incremental_worker.init(worker)
    }
}

impl<P: Profile, const EVENTS: usize> Default for Storage<P, EVENTS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller-owned composition storage for one WS63 radio instance.
///
/// Use [`crate::declare_radio_storage`] to construct this type. The macro keeps
/// bounded control state in ordinary BSS while placing the large shared arena
/// in the runtime's dedicated `NOLOAD` section. Applications still own one
/// named object and perform one admission step before starting the RTOS.
pub struct RadioStorage<P: Profile + 'static, const EVENTS: usize, const ARENA_BYTES: usize> {
    control: &'static Storage<P, EVENTS>,
    arena: &'static RadioArenaStorage<ARENA_BYTES>,
}

impl<P: Profile + 'static, const EVENTS: usize, const ARENA_BYTES: usize>
    RadioStorage<P, EVENTS, ARENA_BYTES>
{
    /// Construct a composition handle from its correctly placed backing stores.
    ///
    /// This is public only so [`crate::declare_radio_storage`] can expand in a
    /// downstream crate. Applications should use that macro instead.
    #[doc(hidden)]
    pub const fn from_parts(
        control: &'static Storage<P, EVENTS>,
        arena: &'static RadioArenaStorage<ARENA_BYTES>,
    ) -> Self {
        Self { control, arena }
    }

    /// Admit and install all pre-RTOS radio storage exactly once.
    pub fn install(&'static self) -> Result<InstalledRadioStorage<P, EVENTS>, ArenaAdmissionError> {
        let arena = self.arena.claim_for::<P>()?.install()?;
        Ok(InstalledRadioStorage {
            control: self.control,
            arena,
        })
    }

    /// Return the deterministic resource contract for this composition.
    pub const fn report(&self) -> ResourceReport {
        ResourceReport::for_profile::<P, EVENTS>(ARENA_BYTES)
    }
}

/// Installed pre-RTOS storage capability for one radio composition.
///
/// The allocation functions remain available while the token is held so the
/// same arena can back `hisi-rtos`. After the RTOS starts, consume the token
/// with [`Self::into_init_parts`] to build chip resources and initialize radio.
pub struct InstalledRadioStorage<P: Profile + 'static, const EVENTS: usize> {
    control: &'static Storage<P, EVENTS>,
    arena: InstalledRadioArena<P>,
}

impl<P: Profile + 'static, const EVENTS: usize> InstalledRadioStorage<P, EVENTS> {
    /// Allocate one zeroed RTOS block from this composition's installed arena.
    ///
    /// # Safety
    ///
    /// The returned pointer must be released only through [`Self::deallocate`].
    pub unsafe fn allocate(size: usize) -> *mut u8 {
        unsafe { InstalledRadioArena::<P>::allocate(size) }
    }

    /// Release one RTOS block returned by [`Self::allocate`].
    ///
    /// # Safety
    ///
    /// `pointer` must be null or a live allocation returned by
    /// [`Self::allocate`] that has not already been released.
    pub unsafe fn deallocate(pointer: *mut u8) {
        unsafe { InstalledRadioArena::<P>::deallocate(pointer) }
    }

    /// Split the installed capability at the post-RTOS initialization boundary.
    ///
    /// The split is temporal rather than an ownership leak: the arena token is
    /// consumed by the chip resource builder, while the bounded control store
    /// remains borrowed for the firmware lifetime.
    pub fn into_init_parts(self) -> (&'static Storage<P, EVENTS>, InstalledRadioArena<P>) {
        (self.control, self.arena)
    }
}

/// Versioned, allocation-free radio resource report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceReport {
    /// Report schema consumed by CI and future tooling.
    pub schema: &'static str,
    /// Chip backend selected by this release unit.
    pub chip: &'static str,
    /// Named composition profile.
    pub profile: &'static str,
    /// Profile metadata revision.
    pub profile_revision: &'static str,
    /// Security backend selected by the profile.
    pub security: &'static str,
    /// Network adapter selected by the profile.
    pub network: &'static str,
    /// Radio integration backend selected by the profile.
    pub radio_backend: &'static str,
    /// Supplicant implementation selected by the profile.
    pub supplicant_backend: &'static str,
    /// Cryptographic backend selected by the profile.
    pub crypto_backend: &'static str,
    /// Minimum runtime contract required before radio startup.
    pub runtime_contract: &'static str,
    /// Admission mechanism protecting the profile's dynamic task slots.
    pub task_admission: &'static str,
    /// Number of bounded public radio events.
    pub event_capacity: usize,
    /// Total caller-owned bytes, including control storage and shared arena.
    pub caller_owned_bytes: usize,
    /// Bytes held in ordinary BSS by bounded control and crypto state.
    pub control_storage_bytes: usize,
    /// Target RAM bytes used by the immutable composition handle.
    ///
    /// This is zero: the handle contains only link-time references and is kept
    /// in code/rodata rather than caller-owned writable storage.
    pub composition_handle_bytes: usize,
    /// Bytes used by chip-neutral radio state within [`Storage`].
    pub radio_state_bytes: usize,
    /// Bytes used by caller-owned SPACC DMA scratch within [`Storage`].
    pub crypto_dma_bytes: usize,
    /// Total target RAM reserved by the aligned arena backing object.
    pub arena_storage_bytes: usize,
    /// Linker-owned `.wifi_pkt_ram` bytes.
    pub linker_packet_ram_bytes: usize,
    /// HIL-verified main-stack envelope required by synchronous radio bootstrap.
    pub main_stack_bytes_required: usize,
    /// Observed dynamic-task requirement for the current payload.
    pub dynamic_tasks_required: usize,
    /// Vendor task slots from the pinned archive inventory.
    pub vendor_task_slots: usize,
    /// Stack payload reserved for each pinned vendor task.
    pub vendor_stack_bytes_per_task: usize,
    /// Incremental-worker slots, when that profile is selected.
    pub worker_task_slots: Option<usize>,
    /// Stack payload reserved for each incremental worker.
    pub worker_stack_bytes_per_task: Option<usize>,
    /// Dynamic task slots owned by the coexisting BLE or SLE stack.
    pub coexistence_task_slots: usize,
    /// Exact heterogeneous stack payload owned by the coexisting stack.
    pub coexistence_stack_bytes: usize,
    /// Runtime-internal task count, once the runtime exposes admission metadata.
    pub runtime_internal_tasks: Option<usize>,
    /// Total task-stack bytes, once stacks become profile-owned.
    pub task_stack_bytes: Option<usize>,
    /// Smallest task stack admitted by the selected heterogeneous profile.
    pub minimum_task_stack_bytes: Option<usize>,
    /// Bytes reserved for RTOS-owned synchronization objects.
    pub runtime_object_headroom_bytes: Option<usize>,
    /// Scheduler arena bytes backing stacks, metadata and RTOS objects.
    pub runtime_arena_bytes: Option<usize>,
    /// Supplicant arena bytes, once its allocator storage becomes profile-owned.
    pub supplicant_arena_bytes: Option<usize>,
    /// Bytes in the caller-owned heap shared by RTOS, RF, supplicant and OSAL.
    pub shared_rf_arena_bytes: Option<usize>,
    /// Final linked flash bytes, supplied later by the firmware image report.
    pub flash_bytes: Option<usize>,
    /// Whether task/stack/arena totals have completed profile HIL calibration.
    pub runtime_resources_calibrated: bool,
}

impl ResourceReport {
    const fn for_profile<P: Profile, const EVENTS: usize>(arena_bytes: usize) -> Self {
        let plan = P::RESOURCE_PLAN.with_event_capacity(EVENTS);
        let radio_state_bytes = WS63_RADIO_STATE_BASE_BYTES + EVENTS * WS63_RADIO_EVENT_SLOT_BYTES;
        let control_storage_bytes = core::mem::size_of::<Storage<P, EVENTS>>();
        let arena_storage_bytes = align_up(arena_bytes + 1, 64);
        Self {
            schema: RESOURCE_REPORT_SCHEMA,
            chip: "ws63",
            profile: P::ID,
            profile_revision: PROFILE_REVISION,
            security: P::SECURITY,
            network: "smoltcp",
            radio_backend: "hisi-rf-ws63",
            supplicant_backend: "hostap-2.11-native",
            crypto_backend: "hisi-crypto-ws63-mixed",
            runtime_contract: if cfg!(feature = "incremental-embassy-wait") {
                "hisi-rf-rtos-driver/v1.5-ported-budgeted-worker"
            } else {
                "hisi-rf-rtos-driver/v1.4-ported-cooperative"
            },
            task_admission: "owner-bound-slot-stack-reservation",
            event_capacity: EVENTS,
            caller_owned_bytes: control_storage_bytes
                + arena_storage_bytes
                + P::RUNTIME_ARENA_BYTES,
            control_storage_bytes,
            composition_handle_bytes: 0,
            radio_state_bytes,
            crypto_dma_bytes: Ws63CryptoStorage::size_bytes(),
            arena_storage_bytes,
            linker_packet_ram_bytes: WIFI_PACKET_RAM_BYTES,
            main_stack_bytes_required: MAIN_STACK_BYTES_REQUIRED,
            dynamic_tasks_required: plan.total_task_slots(),
            vendor_task_slots: plan.vendor.task_slots,
            vendor_stack_bytes_per_task: plan.vendor.stack_bytes_per_task,
            worker_task_slots: match plan.worker {
                Some(worker) => Some(worker.task_slots),
                None => None,
            },
            worker_stack_bytes_per_task: match plan.worker {
                Some(worker) => Some(worker.stack_bytes_per_task),
                None => None,
            },
            coexistence_task_slots: plan.coexistence_task_slots(),
            coexistence_stack_bytes: plan.coexistence_stack_bytes(),
            runtime_internal_tasks: Some(2),
            task_stack_bytes: Some(P::TASK_STACK_BYTES),
            minimum_task_stack_bytes: Some(P::MINIMUM_TASK_STACK_BYTES),
            runtime_object_headroom_bytes: Some(P::RUNTIME_OBJECT_HEADROOM_BYTES),
            runtime_arena_bytes: Some(P::RUNTIME_ARENA_BYTES),
            supplicant_arena_bytes: None,
            shared_rf_arena_bytes: Some(arena_bytes),
            flash_bytes: None,
            runtime_resources_calibrated: P::RUNTIME_RESOURCES_CALIBRATED,
        }
    }

    /// Write deterministic JSON without allocation.
    pub fn write_json(self, output: &mut impl fmt::Write) -> fmt::Result {
        write!(
            output,
            concat!(
                "{{\"schema\":\"{}\",\"chip\":\"{}\",\"profile\":\"{}\",",
                "\"profile_revision\":\"{}\",\"security\":\"{}\",",
                "\"network\":\"{}\",\"radio_backend\":\"{}\",",
                "\"supplicant_backend\":\"{}\",\"crypto_backend\":\"{}\",",
                "\"runtime_contract\":\"{}\",\"task_admission\":\"{}\",",
                "\"event_capacity\":{},",
                "\"caller_owned_bytes\":{},\"control_storage_bytes\":{},",
                "\"composition_handle_bytes\":{},\"radio_state_bytes\":{},",
                "\"crypto_dma_bytes\":{},\"arena_storage_bytes\":{},",
                "\"linker_packet_ram_bytes\":{},",
                "\"main_stack_bytes_required\":{},",
                "\"dynamic_tasks_required\":{},",
                "\"vendor_task_slots\":{},\"vendor_stack_bytes_per_task\":{},",
                "\"worker_task_slots\":{},\"worker_stack_bytes_per_task\":{},",
                "\"coexistence_task_slots\":{},\"coexistence_stack_bytes\":{},",
                "\"runtime_internal_tasks\":{},\"task_stack_bytes\":{},",
                "\"minimum_task_stack_bytes\":{},",
                "\"runtime_object_headroom_bytes\":{},\"runtime_arena_bytes\":{},",
                "\"supplicant_arena_bytes\":null,\"shared_rf_arena_bytes\":{},\"flash_bytes\":null,",
                "\"runtime_resources_calibrated\":{}}}"
            ),
            self.schema,
            self.chip,
            self.profile,
            self.profile_revision,
            self.security,
            self.network,
            self.radio_backend,
            self.supplicant_backend,
            self.crypto_backend,
            self.runtime_contract,
            self.task_admission,
            self.event_capacity,
            self.caller_owned_bytes,
            self.control_storage_bytes,
            self.composition_handle_bytes,
            self.radio_state_bytes,
            self.crypto_dma_bytes,
            self.arena_storage_bytes,
            self.linker_packet_ram_bytes,
            self.main_stack_bytes_required,
            self.dynamic_tasks_required,
            self.vendor_task_slots,
            self.vendor_stack_bytes_per_task,
            self.worker_task_slots.unwrap_or(0),
            self.worker_stack_bytes_per_task.unwrap_or(0),
            self.coexistence_task_slots,
            self.coexistence_stack_bytes,
            self.runtime_internal_tasks.unwrap_or(0),
            self.task_stack_bytes.unwrap_or(0),
            self.minimum_task_stack_bytes.unwrap_or(0),
            self.runtime_object_headroom_bytes.unwrap_or(0),
            self.runtime_arena_bytes.unwrap_or(0),
            self.shared_rf_arena_bytes.unwrap_or(0),
            self.runtime_resources_calibrated,
        )
    }
}

const fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

/// Return the deterministic report for one explicit profile and event capacity.
///
/// This reads compile-time profile metadata only; it does not construct, claim,
/// or borrow radio storage.
pub const fn resource_report<P: Profile, const EVENTS: usize>() -> ResourceReport {
    ResourceReport::for_profile::<P, EVENTS>(P::RF_ARENA_BYTES)
}

/// Return the structured resource tree for one profile and event capacity.
pub const fn wifi_resource_plan<P: Profile, const EVENTS: usize>() -> WifiResourcePlan {
    P::RESOURCE_PLAN.with_event_capacity(EVENTS)
}

#[cfg(all(
    target_pointer_width = "32",
    not(any(feature = "coexistence-wifi-ble", feature = "coexistence-wifi-sle"))
))]
const _: () = {
    assert!(
        core::mem::size_of::<Storage<WifiWpa2Smoltcp, 4>>()
            == align_up(
                WS63_CONTROL_STORAGE_FIXED_BYTES
                    + WS63_RADIO_STATE_BASE_BYTES
                    + 4 * WS63_RADIO_EVENT_SLOT_BYTES,
                WS63_CONTROL_STORAGE_ALIGNMENT,
            )
    );
    assert!(
        core::mem::size_of::<Storage<WifiWpa2Smoltcp, 8>>()
            == align_up(
                WS63_CONTROL_STORAGE_FIXED_BYTES
                    + WS63_RADIO_STATE_BASE_BYTES
                    + 8 * WS63_RADIO_EVENT_SLOT_BYTES,
                WS63_CONTROL_STORAGE_ALIGNMENT,
            )
    );
    assert!(
        core::mem::size_of::<RadioState<4>>()
            == WS63_RADIO_STATE_BASE_BYTES + 4 * WS63_RADIO_EVENT_SLOT_BYTES
    );
    assert!(
        core::mem::size_of::<RadioState<8>>()
            == WS63_RADIO_STATE_BASE_BYTES + 8 * WS63_RADIO_EVENT_SLOT_BYTES
    );
    assert!(
        core::mem::size_of::<RadioArenaStorage<{ WifiWpa2Smoltcp::RF_ARENA_BYTES }>>()
            == align_up(WifiWpa2Smoltcp::RF_ARENA_BYTES + 1, 64)
    );
};

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedBuffer {
        bytes: [u8; 1536],
        len: usize,
    }

    impl FixedBuffer {
        fn new() -> Self {
            Self {
                bytes: [0; 1536],
                len: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.bytes[..self.len]).unwrap()
        }
    }

    impl fmt::Write for FixedBuffer {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let end = self.len + value.len();
            if end > self.bytes.len() {
                return Err(fmt::Error);
            }
            self.bytes[self.len..end].copy_from_slice(value.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    #[test]
    fn report_exposes_only_proven_resource_ownership() {
        let storage = Storage::<WifiWpa2Smoltcp, 4>::new();
        let report = storage.report();
        assert_eq!(report.schema, "hisi-rf-resource-report/v11");
        assert_eq!(report.chip, "ws63");
        assert_eq!(report.profile, "wifi-wpa2-smoltcp");
        assert_eq!(report.event_capacity, 4);
        assert_eq!(report.crypto_dma_bytes, 4_384);
        assert_eq!(
            report.arena_storage_bytes,
            WifiWpa2Smoltcp::RF_ARENA_BYTES + 64
        );
        assert_eq!(report.linker_packet_ram_bytes, 0xc000);
        assert_eq!(report.main_stack_bytes_required, 0x8000);
        assert_eq!(
            report.dynamic_tasks_required,
            WifiWpa2Smoltcp::RESOURCE_PLAN.total_task_slots()
        );
        assert_eq!(
            WifiWpa2Smoltcp::VENDOR_DYNAMIC_TASKS_REQUIRED,
            crate::WS63_WIFI_VENDOR_DYNAMIC_TASKS_REQUIRED
        );
        assert_eq!(report.task_admission, "owner-bound-slot-stack-reservation");
        assert_eq!(report.vendor_task_slots, 7);
        assert_eq!(report.vendor_stack_bytes_per_task, 24 * 1024);
        assert_eq!(
            report.worker_task_slots,
            cfg!(feature = "incremental-embassy-wait").then_some(1)
        );
        assert_eq!(
            report.worker_stack_bytes_per_task,
            cfg!(feature = "incremental-embassy-wait").then_some(PROFILE_WORKER_STACK_BYTES)
        );
        assert_eq!(report.coexistence_task_slots, 0);
        assert_eq!(report.coexistence_stack_bytes, 0);
        assert_eq!(report.runtime_internal_tasks, Some(2));
        assert_eq!(
            report.task_stack_bytes,
            Some(WifiWpa2Smoltcp::TASK_STACK_BYTES)
        );
        assert_eq!(
            report.minimum_task_stack_bytes,
            Some(WifiWpa2Smoltcp::MINIMUM_TASK_STACK_BYTES)
        );
        assert_eq!(
            report.runtime_object_headroom_bytes,
            Some(RUNTIME_OBJECT_HEADROOM_BYTES)
        );
        assert_eq!(
            report.runtime_arena_bytes,
            Some(
                WifiWpa2Smoltcp::TASK_STACK_BYTES
                    + TASK_STACK_ALLOCATOR_OVERHEAD_BYTES
                    + RUNTIME_OBJECT_HEADROOM_BYTES
            )
        );
        assert_eq!(report.supplicant_arena_bytes, None);
        assert_eq!(
            report.shared_rf_arena_bytes,
            Some(WifiWpa2Smoltcp::RF_ARENA_BYTES)
        );
        assert_eq!(report.flash_bytes, None);
        assert_eq!(
            report.runtime_resources_calibrated,
            !cfg!(feature = "incremental-embassy-wait")
        );
        assert_eq!(
            report.caller_owned_bytes,
            report.control_storage_bytes
                + WifiWpa2Smoltcp::RF_ARENA_BYTES
                + 64
                + WifiWpa2Smoltcp::RUNTIME_ARENA_BYTES
        );
        assert_eq!(report.composition_handle_bytes, 0);
        assert_eq!(
            report.radio_state_bytes,
            WS63_RADIO_STATE_BASE_BYTES + 4 * WS63_RADIO_EVENT_SLOT_BYTES
        );
        assert!(report.control_storage_bytes >= report.radio_state_bytes + report.crypto_dma_bytes);
    }

    #[test]
    fn structured_resource_tree_derives_every_task_total_from_children() {
        let plan = wifi_resource_plan::<WifiWpa2Smoltcp, 8>();
        assert_eq!(plan.event_capacity, 8);
        assert_eq!(plan.vendor.owner, resource_owner::VENDOR_TASKS);
        assert_eq!(plan.vendor.task_slots, 7);
        assert_eq!(plan.vendor.stack_bytes_per_task, 24 * 1024);
        assert_eq!(
            plan.total_task_slots(),
            WifiWpa2Smoltcp::DYNAMIC_TASKS_REQUIRED
        );
        assert_eq!(plan.total_stack_bytes(), WifiWpa2Smoltcp::TASK_STACK_BYTES);
        assert_eq!(
            plan.runtime_arena_bytes(),
            WifiWpa2Smoltcp::RUNTIME_ARENA_BYTES
        );
        assert_eq!(plan.rf_heap_min_bytes, WifiWpa2Smoltcp::RF_ARENA_BYTES);
        assert_eq!(
            plan.worker.map(|worker| worker.owner),
            cfg!(feature = "incremental-embassy-wait")
                .then_some(resource_owner::INCREMENTAL_WORKER)
        );
    }

    #[test]
    fn coexistence_plan_derives_exact_child_inventory() {
        let plan = wifi_resource_plan::<WifiWpa2BleCoexistence, 8>();
        assert_eq!(plan.coexistence, BGLE_COEXISTENCE_TASKS);
        assert_eq!(plan.coexistence_task_slots(), 4);
        assert_eq!(plan.coexistence_stack_bytes(), 10_240);
        assert_eq!(
            plan.total_task_slots(),
            11 + usize::from(plan.worker.is_some())
        );
        assert_eq!(
            plan.total_stack_bytes(),
            7 * 24 * 1024 + 10_240 + plan.worker.map_or(0, TaskGroupPlan::total_stack_bytes)
        );
        assert_eq!(plan.minimum_task_stack_bytes(), 512);

        let report = resource_report::<WifiWpa2BleCoexistence, 8>();
        assert_eq!(report.profile, "wifi-wpa2-ble-coexistence");
        assert_eq!(report.coexistence_task_slots, 4);
        assert_eq!(report.coexistence_stack_bytes, 10_240);
        assert!(!report.runtime_resources_calibrated);
    }

    #[test]
    fn report_json_is_deterministic_and_marks_uncalibrated_runtime_resources() {
        let report = Storage::<WifiWpa3Smoltcp, 8>::new().report();
        let mut output = FixedBuffer::new();
        report.write_json(&mut output).unwrap();
        assert!(output.as_str().starts_with(
            "{\"schema\":\"hisi-rf-resource-report/v11\",\"chip\":\"ws63\",\"profile\":\"wifi-wpa3-smoltcp\""
        ));
        assert!(
            output
                .as_str()
                .contains("\"main_stack_bytes_required\":32768")
        );
        assert!(
            output
                .as_str()
                .contains(if cfg!(feature = "incremental-embassy-wait") {
                    "\"runtime_contract\":\"hisi-rf-rtos-driver/v1.5-ported-budgeted-worker\""
                } else {
                    "\"runtime_contract\":\"hisi-rf-rtos-driver/v1.4-ported-cooperative\""
                })
        );
        assert!(
            output
                .as_str()
                .contains(if cfg!(feature = "incremental-embassy-wait") {
                    concat!(
                        "\"runtime_internal_tasks\":2,\"task_stack_bytes\":180224,",
                        "\"minimum_task_stack_bytes\":8192,",
                        "\"runtime_object_headroom_bytes\":16384,\"runtime_arena_bytes\":197120"
                    )
                } else {
                    concat!(
                        "\"runtime_internal_tasks\":2,\"task_stack_bytes\":172032,",
                        "\"minimum_task_stack_bytes\":24576,",
                        "\"runtime_object_headroom_bytes\":16384,\"runtime_arena_bytes\":188928"
                    )
                })
        );
        let shared_arena = std::format!(
            "\"shared_rf_arena_bytes\":{}",
            report
                .shared_rf_arena_bytes
                .expect("WS63 profile owns one shared RF arena")
        );
        assert!(output.as_str().contains(&shared_arena));
        assert!(
            output
                .as_str()
                .ends_with("\"runtime_resources_calibrated\":false}")
        );
    }

    #[test]
    fn composition_report_accounts_for_control_arena_and_handle() {
        static CONTROL: Storage<WifiWpa2Smoltcp, 4> = Storage::new();
        static ARENA: RadioArenaStorage<{ WifiWpa2Smoltcp::RF_ARENA_BYTES }> =
            RadioArenaStorage::new();
        static RADIO: RadioStorage<WifiWpa2Smoltcp, 4, { WifiWpa2Smoltcp::RF_ARENA_BYTES }> =
            RadioStorage::from_parts(&CONTROL, &ARENA);

        let report = RADIO.report();
        assert_eq!(
            report.caller_owned_bytes,
            report.control_storage_bytes
                + WifiWpa2Smoltcp::RF_ARENA_BYTES
                + 64
                + WifiWpa2Smoltcp::RUNTIME_ARENA_BYTES
        );
        assert_eq!(report.composition_handle_bytes, 0);
        assert_eq!(
            report.control_storage_bytes,
            core::mem::size_of::<Storage<WifiWpa2Smoltcp, 4>>()
        );
        assert_eq!(
            report.radio_state_bytes,
            WS63_RADIO_STATE_BASE_BYTES + 4 * WS63_RADIO_EVENT_SLOT_BYTES
        );
        assert_eq!(report.event_capacity, 4);
    }

    #[test]
    fn storage_claim_is_one_shot() {
        static STORAGE: Storage<WifiWpa2Smoltcp, 2> = Storage::new();
        let first =
            unsafe { TaskReservation::from_raw(core::num::NonZeroU32::new(0x101).unwrap()) };
        let second =
            unsafe { TaskReservation::from_raw(core::num::NonZeroU32::new(0x102).unwrap()) };
        assert!(
            STORAGE
                .claim(ProfileReservations {
                    vendor: first,
                    worker: None,
                })
                .is_ok()
        );
        match STORAGE.claim(ProfileReservations {
            vendor: second,
            worker: None,
        }) {
            Ok(_) => panic!("claimed storage accepted a second reservation"),
            Err(reservations) => assert_eq!(reservations.vendor.into_raw().get(), 0x102),
        }
    }

    #[test]
    fn arena_claim_checks_capacity_before_consuming_storage() {
        static SMALL: RadioArenaStorage<1024> = RadioArenaStorage::new();
        let expected = ArenaAdmissionError::InsufficientBytes {
            required: WifiWpa2Smoltcp::RF_ARENA_BYTES,
            available: 1024,
        };
        assert!(matches!(
            SMALL.claim_for::<WifiWpa2Smoltcp>(),
            Err(error) if error == expected
        ));
        assert!(matches!(
            SMALL.claim_for::<WifiWpa2Smoltcp>(),
            Err(error) if error == expected
        ));
    }

    #[test]
    fn arena_shortage_uses_actionable_public_diagnostics() {
        let diagnostic = ArenaAdmissionError::InsufficientBytes {
            required: WifiWpa2Smoltcp::RF_ARENA_BYTES,
            available: 1024,
        }
        .diagnostic();
        assert_eq!(
            diagnostic.code(),
            hisi_rf_core::DiagnosticCode::ResourceUnavailable
        );
        assert_eq!(diagnostic.stage(), DiagnosticStage::Runtime);
        assert_eq!(
            diagnostic.action(),
            hisi_rf_core::RecoveryAction::ProvideResources
        );
        assert_eq!(diagnostic.profile_revision(), Some(PROFILE_REVISION));
        assert_eq!(
            diagnostic.trace().get(0).map(|entry| entry.value()),
            Some(WifiWpa2Smoltcp::RF_ARENA_BYTES as u32)
        );
        assert_eq!(
            diagnostic.trace().get(1).map(|entry| entry.value()),
            Some(1024)
        );
    }

    #[test]
    fn arena_can_be_claimed_only_once() {
        static ARENA: RadioArenaStorage<{ WifiWpa2Smoltcp::RF_ARENA_BYTES }> =
            RadioArenaStorage::new();
        assert!(ARENA.claim_for::<WifiWpa2Smoltcp>().is_ok());
        assert!(matches!(
            ARENA.claim_for::<WifiWpa2Smoltcp>(),
            Err(ArenaAdmissionError::AlreadyClaimed)
        ));
    }
}
