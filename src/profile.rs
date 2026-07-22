use core::fmt;
use core::marker::PhantomData;

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_rf_core::RadioState;
use portable_atomic::{AtomicBool, Ordering};
use static_cell::StaticCell;

const RESOURCE_REPORT_SCHEMA: &str = "hisi-rf-resource-report/v1";
pub(crate) const PROFILE_REVISION: &str = "ws63-wifi-2026-07-20";
const WIFI_PACKET_RAM_BYTES: usize = 0xc000;

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
}

/// Upstream-hostap WPA2-Personal with the smoltcp L2 adapter.
pub enum WifiWpa2Smoltcp {}

impl sealed::Sealed for WifiWpa2Smoltcp {}
impl Profile for WifiWpa2Smoltcp {
    const ID: &'static str = "wifi-wpa2-smoltcp";
    const SECURITY: &'static str = "wpa2-personal";
    const DYNAMIC_TASKS_REQUIRED: usize = crate::WS63_WIFI_DYNAMIC_TASKS_REQUIRED;
}

/// Upstream-hostap WPA3-Personal with the smoltcp L2 adapter.
pub enum WifiWpa3Smoltcp {}

impl sealed::Sealed for WifiWpa3Smoltcp {}
impl Profile for WifiWpa3Smoltcp {
    const ID: &'static str = "wifi-wpa3-smoltcp";
    const SECURITY: &'static str = "wpa3-personal";
    const DYNAMIC_TASKS_REQUIRED: usize = crate::WS63_WIFI_DYNAMIC_TASKS_REQUIRED;
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

/// Caller-owned static storage for one WS63 radio instance.
///
/// This currently owns the bounded control/event state and SPACC DMA scratch.
/// Packet RAM remains linker-owned, while task stacks and the supplicant arena
/// remain runtime-owned and are reported as uncalibrated rather than hidden in
/// this type. Those resources move here only after their ownership contracts
/// can be enforced before initialization.
pub struct Storage<P: Profile, const EVENTS: usize> {
    state: RadioState<EVENTS>,
    crypto: StaticCell<Ws63CryptoStorage>,
    claimed: AtomicBool,
    _profile: PhantomData<P>,
}

impl<P: Profile, const EVENTS: usize> Storage<P, EVENTS> {
    /// Construct unclaimed storage suitable for a `static` item.
    pub const fn new() -> Self {
        assert!(EVENTS > 0, "radio event queue must not be empty");
        Self {
            state: RadioState::new(),
            crypto: StaticCell::new(),
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
    ) -> Option<(&'static RadioState<EVENTS>, &'static mut Ws63CryptoStorage)> {
        if self
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        let crypto = self.crypto.try_init(Ws63CryptoStorage::new())?;
        Some((&self.state, crypto))
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
    /// Observed dynamic-task requirement for the current payload.
    pub dynamic_tasks_required: usize,
    /// Runtime-internal task count, once the runtime exposes admission metadata.
    pub runtime_internal_tasks: Option<usize>,
    /// Total task-stack bytes, once stacks become profile-owned.
    pub task_stack_bytes: Option<usize>,
    /// Supplicant arena bytes, once its allocator storage becomes profile-owned.
    pub supplicant_arena_bytes: Option<usize>,
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
            runtime_contract: "hisi-rf-rtos-driver/v1.2-ported-cooperative",
            event_capacity: EVENTS,
            caller_owned_bytes: core::mem::size_of::<Storage<P, EVENTS>>(),
            radio_state_bytes: core::mem::size_of::<RadioState<EVENTS>>(),
            crypto_dma_bytes: Ws63CryptoStorage::size_bytes(),
            linker_packet_ram_bytes: WIFI_PACKET_RAM_BYTES,
            dynamic_tasks_required: P::DYNAMIC_TASKS_REQUIRED,
            runtime_internal_tasks: None,
            task_stack_bytes: None,
            supplicant_arena_bytes: None,
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
                "\"runtime_contract\":\"{}\",\"event_capacity\":{},",
                "\"caller_owned_bytes\":{},\"radio_state_bytes\":{},",
                "\"crypto_dma_bytes\":{},\"linker_packet_ram_bytes\":{},",
                "\"dynamic_tasks_required\":{},",
                "\"runtime_internal_tasks\":null,\"task_stack_bytes\":null,",
                "\"supplicant_arena_bytes\":null,\"flash_bytes\":null,",
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
            self.event_capacity,
            self.caller_owned_bytes,
            self.radio_state_bytes,
            self.crypto_dma_bytes,
            self.linker_packet_ram_bytes,
            self.dynamic_tasks_required,
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
        assert_eq!(report.schema, "hisi-rf-resource-report/v1");
        assert_eq!(report.chip, "ws63");
        assert_eq!(report.profile, "wifi-wpa2-smoltcp");
        assert_eq!(report.event_capacity, 4);
        assert_eq!(report.crypto_dma_bytes, 4_384);
        assert_eq!(report.linker_packet_ram_bytes, 0xc000);
        assert_eq!(report.dynamic_tasks_required, 5);
        assert_eq!(report.runtime_internal_tasks, None);
        assert_eq!(report.task_stack_bytes, None);
        assert_eq!(report.supplicant_arena_bytes, None);
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
            "{\"schema\":\"hisi-rf-resource-report/v1\",\"chip\":\"ws63\",\"profile\":\"wifi-wpa3-smoltcp\""
        ));
        assert!(
            output
                .as_str()
                .contains("\"runtime_contract\":\"hisi-rf-rtos-driver/v1.2-ported-cooperative\"")
        );
        assert!(
            output
                .as_str()
                .ends_with("\"runtime_resources_calibrated\":false}")
        );
    }

    #[test]
    fn storage_claim_is_one_shot() {
        static STORAGE: Storage<WifiWpa2Smoltcp, 2> = Storage::new();
        assert!(STORAGE.claim().is_some());
        assert!(STORAGE.claim().is_none());
    }
}
