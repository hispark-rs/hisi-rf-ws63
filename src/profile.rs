use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_rf_core::{RadioRunner, RadioState};
use hisi_rf_rtos_driver::TaskReservation;
use portable_atomic::{AtomicBool, Ordering};
use static_cell::StaticCell;

use crate::hisi_rf_backend::Ws63WifiBackend;

const RESOURCE_REPORT_SCHEMA: &str = "hisi-rf-resource-report/v5";
pub(crate) const PROFILE_REVISION: &str = "ws63-wifi-2026-07-26";
const WIFI_PACKET_RAM_BYTES: usize = 0xc000;
const MAIN_STACK_BYTES_REQUIRED: usize = 0x8000;
const PROFILE_RF_ARENA_BYTES: usize = 296 * 1024;

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
    const RF_ARENA_BYTES: usize = PROFILE_RF_ARENA_BYTES;
}

/// Upstream-hostap WPA3-Personal with the smoltcp L2 adapter.
pub enum WifiWpa3Smoltcp {}

impl sealed::Sealed for WifiWpa3Smoltcp {}
impl Profile for WifiWpa3Smoltcp {
    const ID: &'static str = "wifi-wpa3-smoltcp";
    const SECURITY: &'static str = "wpa3-personal";
    const DYNAMIC_TASKS_REQUIRED: usize = crate::WS63_WIFI_DYNAMIC_TASKS_REQUIRED;
    const TASK_STACK_BYTES_PER_TASK: usize = 24 * 1024;
    const RF_ARENA_BYTES: usize = PROFILE_RF_ARENA_BYTES;
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

/// Caller-owned static storage for one WS63 radio instance.
///
/// This currently owns the bounded control/event state, mandatory radio runner,
/// and SPACC DMA scratch. Packet RAM remains linker-owned. Task stacks are
/// atomically reserved through the runtime capability before hardware startup;
/// the remaining shared supplicant arena is still linker-owned and uncalibrated.
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
        ResourceReport::for_profile::<P, EVENTS>()
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
    /// Bytes held directly in [`Storage`].
    pub caller_owned_bytes: usize,
    /// Bytes used by chip-neutral radio state within [`Storage`].
    pub radio_state_bytes: usize,
    /// Bytes used by caller-owned SPACC DMA scratch within [`Storage`].
    pub crypto_dma_bytes: usize,
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
    const fn for_profile<P: Profile, const EVENTS: usize>() -> Self {
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
            caller_owned_bytes: core::mem::size_of::<Storage<P, EVENTS>>(),
            radio_state_bytes: core::mem::size_of::<RadioState<EVENTS>>(),
            crypto_dma_bytes: Ws63CryptoStorage::size_bytes(),
            linker_packet_ram_bytes: WIFI_PACKET_RAM_BYTES,
            main_stack_bytes_required: MAIN_STACK_BYTES_REQUIRED,
            dynamic_tasks_required: P::DYNAMIC_TASKS_REQUIRED,
            runtime_internal_tasks: Some(2),
            task_stack_bytes: Some(P::DYNAMIC_TASKS_REQUIRED * P::TASK_STACK_BYTES_PER_TASK),
            supplicant_arena_bytes: None,
            shared_rf_arena_bytes: Some(P::RF_ARENA_BYTES),
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
                "\"caller_owned_bytes\":{},\"radio_state_bytes\":{},",
                "\"crypto_dma_bytes\":{},\"linker_packet_ram_bytes\":{},",
                "\"main_stack_bytes_required\":{},",
                "\"dynamic_tasks_required\":{},",
                "\"runtime_internal_tasks\":{},\"task_stack_bytes\":{},",
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
            self.radio_state_bytes,
            self.crypto_dma_bytes,
            self.linker_packet_ram_bytes,
            self.main_stack_bytes_required,
            self.dynamic_tasks_required,
            self.runtime_internal_tasks.unwrap_or(0),
            self.task_stack_bytes.unwrap_or(0),
            self.shared_rf_arena_bytes.unwrap_or(0),
            self.runtime_resources_calibrated,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedBuffer {
        bytes: [u8; 768],
        len: usize,
    }

    impl FixedBuffer {
        fn new() -> Self {
            Self {
                bytes: [0; 768],
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
        assert_eq!(report.schema, "hisi-rf-resource-report/v5");
        assert_eq!(report.chip, "ws63");
        assert_eq!(report.profile, "wifi-wpa2-smoltcp");
        assert_eq!(report.event_capacity, 4);
        assert_eq!(report.crypto_dma_bytes, 4_384);
        assert_eq!(report.linker_packet_ram_bytes, 0xc000);
        assert_eq!(report.main_stack_bytes_required, 0x8000);
        assert_eq!(report.dynamic_tasks_required, 6);
        assert_eq!(report.task_admission, "owner-bound-slot-stack-reservation");
        assert_eq!(report.runtime_internal_tasks, Some(2));
        assert_eq!(report.task_stack_bytes, Some(6 * 24 * 1024));
        assert_eq!(report.supplicant_arena_bytes, None);
        assert_eq!(report.shared_rf_arena_bytes, Some(PROFILE_RF_ARENA_BYTES));
        assert_eq!(report.flash_bytes, None);
        assert!(!report.runtime_resources_calibrated);
        assert!(report.caller_owned_bytes >= report.radio_state_bytes + report.crypto_dma_bytes);
    }

    #[test]
    fn report_json_is_deterministic_and_marks_uncalibrated_runtime_resources() {
        let mut output = FixedBuffer::new();
        Storage::<WifiWpa3Smoltcp, 8>::new()
            .report()
            .write_json(&mut output)
            .unwrap();
        assert!(output.as_str().starts_with(
            "{\"schema\":\"hisi-rf-resource-report/v5\",\"chip\":\"ws63\",\"profile\":\"wifi-wpa3-smoltcp\""
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
        assert!(
            output
                .as_str()
                .contains("\"runtime_internal_tasks\":2,\"task_stack_bytes\":147456")
        );
        assert!(output.as_str().contains("\"shared_rf_arena_bytes\":303104"));
        assert!(
            output
                .as_str()
                .ends_with("\"runtime_resources_calibrated\":false}")
        );
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
            required: PROFILE_RF_ARENA_BYTES,
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
    fn arena_can_be_claimed_only_once() {
        static ARENA: RadioArenaStorage<{ PROFILE_RF_ARENA_BYTES }> = RadioArenaStorage::new();
        assert!(ARENA.claim_for::<WifiWpa2Smoltcp>().is_ok());
        assert!(matches!(
            ARENA.claim_for::<WifiWpa2Smoltcp>(),
            Err(ArenaAdmissionError::AlreadyClaimed)
        ));
    }
}
