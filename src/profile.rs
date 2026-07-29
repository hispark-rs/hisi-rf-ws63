use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_rf_core::{
    BackendError, BackendErrorClass, Diagnostic, DiagnosticStage, DiagnosticTraceKind, Error,
    RadioRunner, RadioState,
};
use hisi_rf_rtos_driver::TaskReservation;
use portable_atomic::{AtomicBool, Ordering};
use static_cell::StaticCell;

use crate::hisi_rf_backend::Ws63WifiBackend;

const RESOURCE_REPORT_SCHEMA: &str = "hisi-rf-resource-report/v8";
pub(crate) const PROFILE_REVISION: &str = "ws63-wifi-2026-07-30-r5";
const WIFI_PACKET_RAM_BYTES: usize = 0xc000;
const MAIN_STACK_BYTES_REQUIRED: usize = 0x8000;
const PROFILE_SHARED_ARENA_BYTES: usize = 296 * 1024;
const TASK_STACK_ALLOCATOR_OVERHEAD_BYTES: usize = 512;
const RUNTIME_OBJECT_HEADROOM_BYTES: usize = 16 * 1024;
const WS63_CONTROL_STORAGE_FIXED_BYTES: usize = 6_361;
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

/// A named WS63 radio composition with a fixed security and network contract.
pub trait Profile: sealed::Sealed {
    /// Stable profile identifier used by build reports and diagnostics.
    const ID: &'static str;
    /// Security implementation selected by this profile.
    const SECURITY: &'static str;
    /// Dynamic task slots observed for this profile's pinned payload.
    const DYNAMIC_TASKS_REQUIRED: usize;
    /// Stack bytes reserved for every dynamic task in this profile.
    const TASK_STACK_BYTES_PER_TASK: usize;
    /// Caller-owned bytes reserved for RTOS-owned synchronization objects.
    const RUNTIME_OBJECT_HEADROOM_BYTES: usize = RUNTIME_OBJECT_HEADROOM_BYTES;
    /// Caller-owned scheduler arena for task stacks, metadata and RTOS objects.
    const RUNTIME_ARENA_BYTES: usize = Self::DYNAMIC_TASKS_REQUIRED
        * Self::TASK_STACK_BYTES_PER_TASK
        + TASK_STACK_ALLOCATOR_OVERHEAD_BYTES
        + Self::RUNTIME_OBJECT_HEADROOM_BYTES;
    /// Caller-owned shared RF arena bytes required before hardware startup.
    const RF_ARENA_BYTES: usize;
}

/// Upstream-hostap WPA2-Personal with the smoltcp L2 adapter.
pub enum WifiWpa2Smoltcp {}

impl sealed::Sealed for WifiWpa2Smoltcp {}
impl Profile for WifiWpa2Smoltcp {
    const ID: &'static str = "wifi-wpa2-smoltcp";
    const SECURITY: &'static str = "wpa2-personal";
    const DYNAMIC_TASKS_REQUIRED: usize = crate::WS63_WIFI_DYNAMIC_TASKS_REQUIRED;
    const TASK_STACK_BYTES_PER_TASK: usize = 24 * 1024;
    const RF_ARENA_BYTES: usize = PROFILE_SHARED_ARENA_BYTES - Self::RUNTIME_ARENA_BYTES;
}

/// Upstream-hostap WPA3-Personal with the smoltcp L2 adapter.
pub enum WifiWpa3Smoltcp {}

impl sealed::Sealed for WifiWpa3Smoltcp {}
impl Profile for WifiWpa3Smoltcp {
    const ID: &'static str = "wifi-wpa3-smoltcp";
    const SECURITY: &'static str = "wpa3-personal";
    const DYNAMIC_TASKS_REQUIRED: usize = crate::WS63_WIFI_DYNAMIC_TASKS_REQUIRED;
    const TASK_STACK_BYTES_PER_TASK: usize = 24 * 1024;
    const RF_ARENA_BYTES: usize = PROFILE_SHARED_ARENA_BYTES - Self::RUNTIME_ARENA_BYTES;
}

/// Marker implemented only for the profile selected by Cargo features.
#[doc(hidden)]
pub trait ActiveProfile: Profile {}

#[cfg(feature = "wpa2-personal")]
impl ActiveProfile for WifiWpa2Smoltcp {}

#[cfg(feature = "wpa3-personal")]
impl ActiveProfile for WifiWpa3Smoltcp {}

/// The profile selected by the current Cargo feature set.
#[cfg(feature = "wpa2-personal")]
pub type SelectedProfile = WifiWpa2Smoltcp;

/// The profile selected by the current Cargo feature set.
#[cfg(feature = "wpa3-personal")]
pub type SelectedProfile = WifiWpa3Smoltcp;

/// Byte capacity selected by the active named radio profile.
pub const SELECTED_RF_ARENA_BYTES: usize = SelectedProfile::RF_ARENA_BYTES;

/// Scheduler arena bytes required by the active named profile.
pub const SELECTED_RUNTIME_ARENA_BYTES: usize = SelectedProfile::RUNTIME_ARENA_BYTES;

/// Migration alias for [`SELECTED_RUNTIME_ARENA_BYTES`].
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
/// This currently owns the bounded control/event state, mandatory radio runner,
/// and SPACC DMA scratch. Packet RAM remains linker-owned. Task stacks are
/// atomically reserved through the runtime capability before hardware startup;
/// the shared RF arena is installed separately from caller-owned storage.
pub struct Storage<P: Profile, const EVENTS: usize> {
    state: RadioState<EVENTS>,
    runner: StaticCell<RadioRunner<Ws63WifiBackend<'static>, EVENTS>>,
    crypto: StaticCell<Ws63CryptoStorage>,
    task_reservation: StaticCell<TaskReservation>,
    claimed: AtomicBool,
    _profile: PhantomData<P>,
}

impl<P: Profile, const EVENTS: usize> Storage<P, EVENTS> {
    /// Construct unclaimed storage suitable for a `static` item.
    pub const fn new() -> Self {
        assert!(EVENTS > 0, "radio event queue must not be empty");
        Self {
            state: RadioState::new(),
            runner: StaticCell::new(),
            crypto: StaticCell::new(),
            task_reservation: StaticCell::new(),
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
        reservation: TaskReservation,
    ) -> Result<
        (
            &'static RadioState<EVENTS>,
            &'static mut Ws63CryptoStorage,
            &'static TaskReservation,
        ),
        TaskReservation,
    > {
        if self
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(reservation);
        }
        let crypto = self.crypto.init(Ws63CryptoStorage::new());
        let reservation = self.task_reservation.init(reservation);
        Ok((&self.state, crypto, reservation))
    }

    pub(crate) fn store_runner(
        &'static self,
        runner: RadioRunner<Ws63WifiBackend<'static>, EVENTS>,
    ) -> &'static mut RadioRunner<Ws63WifiBackend<'static>, EVENTS> {
        // `init` claims this storage exactly once and returns one non-cloneable
        // controller bound to it. Consuming that controller to start the runner
        // therefore initializes this cell at most once.
        self.runner.init(runner)
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
    /// Runtime-internal task count, once the runtime exposes admission metadata.
    pub runtime_internal_tasks: Option<usize>,
    /// Total task-stack bytes, once stacks become profile-owned.
    pub task_stack_bytes: Option<usize>,
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
        let radio_state_bytes = WS63_RADIO_STATE_BASE_BYTES + EVENTS * WS63_RADIO_EVENT_SLOT_BYTES;
        let control_storage_bytes = align_up(
            WS63_CONTROL_STORAGE_FIXED_BYTES + radio_state_bytes,
            WS63_CONTROL_STORAGE_ALIGNMENT,
        );
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
            runtime_contract: "hisi-rf-rtos-driver/v1.4-ported-cooperative",
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
            dynamic_tasks_required: P::DYNAMIC_TASKS_REQUIRED,
            runtime_internal_tasks: Some(2),
            task_stack_bytes: Some(P::DYNAMIC_TASKS_REQUIRED * P::TASK_STACK_BYTES_PER_TASK),
            runtime_object_headroom_bytes: Some(P::RUNTIME_OBJECT_HEADROOM_BYTES),
            runtime_arena_bytes: Some(P::RUNTIME_ARENA_BYTES),
            supplicant_arena_bytes: None,
            shared_rf_arena_bytes: Some(arena_bytes),
            flash_bytes: None,
            runtime_resources_calibrated: false,
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
                "\"runtime_internal_tasks\":{},\"task_stack_bytes\":{},",
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
            self.runtime_internal_tasks.unwrap_or(0),
            self.task_stack_bytes.unwrap_or(0),
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

#[cfg(target_pointer_width = "32")]
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
        bytes: [u8; 1024],
        len: usize,
    }

    impl FixedBuffer {
        fn new() -> Self {
            Self {
                bytes: [0; 1024],
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
        assert_eq!(report.schema, "hisi-rf-resource-report/v8");
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
        assert_eq!(report.dynamic_tasks_required, 7);
        assert_eq!(report.task_admission, "owner-bound-slot-stack-reservation");
        assert_eq!(report.runtime_internal_tasks, Some(2));
        assert_eq!(report.task_stack_bytes, Some(7 * 24 * 1024));
        assert_eq!(
            report.runtime_object_headroom_bytes,
            Some(RUNTIME_OBJECT_HEADROOM_BYTES)
        );
        assert_eq!(
            report.runtime_arena_bytes,
            Some(
                7 * 24 * 1024 + TASK_STACK_ALLOCATOR_OVERHEAD_BYTES + RUNTIME_OBJECT_HEADROOM_BYTES
            )
        );
        assert_eq!(report.supplicant_arena_bytes, None);
        assert_eq!(
            report.shared_rf_arena_bytes,
            Some(WifiWpa2Smoltcp::RF_ARENA_BYTES)
        );
        assert_eq!(report.flash_bytes, None);
        assert!(!report.runtime_resources_calibrated);
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
    fn report_json_is_deterministic_and_marks_uncalibrated_runtime_resources() {
        let mut output = FixedBuffer::new();
        Storage::<WifiWpa3Smoltcp, 8>::new()
            .report()
            .write_json(&mut output)
            .unwrap();
        assert!(output.as_str().starts_with(
            "{\"schema\":\"hisi-rf-resource-report/v8\",\"chip\":\"ws63\",\"profile\":\"wifi-wpa3-smoltcp\""
        ));
        assert!(
            output
                .as_str()
                .contains("\"main_stack_bytes_required\":32768")
        );
        assert!(
            output
                .as_str()
                .contains("\"runtime_contract\":\"hisi-rf-rtos-driver/v1.4-ported-cooperative\"")
        );
        assert!(output.as_str().contains(concat!(
            "\"runtime_internal_tasks\":2,\"task_stack_bytes\":172032,",
            "\"runtime_object_headroom_bytes\":16384,\"runtime_arena_bytes\":188928"
        )));
        assert!(output.as_str().contains("\"shared_rf_arena_bytes\":114176"));
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
            if cfg!(feature = "incremental-backend-experiment") {
                0x2100
            } else {
                0x20c0
            }
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
        assert!(STORAGE.claim(first).is_ok());
        match STORAGE.claim(second) {
            Ok(_) => panic!("claimed storage accepted a second reservation"),
            Err(reservation) => assert_eq!(reservation.into_raw().get(), 0x102),
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
