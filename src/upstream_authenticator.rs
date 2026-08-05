//! Native WS63 hooks for the pinned upstream hostapd authenticator.
//!
//! This module is intentionally role-specific. AP and STA target archives are
//! mutually exclusive, while both use the same native RTOS, allocator, clock,
//! entropy, and WAL contracts.

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::num::{NonZeroU32, NonZeroUsize};
use core::ptr::NonNull;

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_hal::peripherals::{Efuse, Km, Pke, Spacc, Trng};
use hisi_rf_rtos_driver::{Semaphore, WaitOutcome, WaitTimeout};
use portable_atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
use static_cell::StaticCell;
use ws63_radio_sys::authenticator::{
    ABI_VERSION as AP_ABI_VERSION, Beacon, Config, Context, DriverHooks, HardwareFeatures,
    Security, hisi_wpa_ap_configure, hisi_wpa_ap_context_align, hisi_wpa_ap_context_size,
    hisi_wpa_ap_create, hisi_wpa_ap_destroy, hisi_wpa_ap_driver_install, hisi_wpa_ap_poll,
    hisi_wpa_ap_start, hisi_wpa_ap_stop,
};
use ws63_radio_sys::supplicant::{
    ABI_VERSION as HOSTAP_ABI_VERSION, Key, OsHooks, PollResult, cipher, hisi_wpa_os_install,
    hisi_wpa_os_uninstall, key_flag,
};

const IFNAME_CAPACITY: usize = 17;
const ETHERNET_HEADER_LEN: usize = 14;
const MAX_EAPOL_PAYLOAD_LEN: usize = 800;
const IOCTL_SET_AP: u32 = 0;
const IOCTL_NEW_KEY: u32 = 1;
const IOCTL_DEL_KEY: u32 = 2;
const IOCTL_SET_KEY: u32 = 3;
const IOCTL_SEND_MLME: u32 = 4;
const IOCTL_SEND_EAPOL: u32 = 5;
const IOCTL_GET_ADDRESS: u32 = 9;
const IOCTL_GET_HW_FEATURES: u32 = 13;
const IOCTL_DEL_BEACON: u32 = 12;
const IOCTL_SET_NETDEV: u32 = 17;
const IOCTL_CHANGE_BEACON: u32 = 18;
const IOCTL_STA_REMOVE: u32 = 20;

const PORT_FREE: u8 = 0;
const PORT_INSTALLING: u8 = 1;
const PORT_READY: u8 = 2;
const PORT_POISONED: u8 = 3;
const AP_INTERFACE_TYPE: u8 = 3;
const MODE_11B_G_N_AX: u32 = 4;
const EVENT_NEW_STATION: c_int = 0;
const EVENT_DEL_STATION: c_int = 1;
const EVENT_RX_MGMT: c_int = 2;
const IOCTL_RECEIVE_EAPOL: u32 = 6;
const IOCTL_ENABLE_EAPOL: u32 = 7;
const VENDOR_TASK_OWNER: u32 = 1;
const VENDOR_TASK_STACK_BYTES: usize = 24 * 1024;
const MAX_MGMT_FRAME_LEN: usize = 2304;
const MGMT_QUEUE_CAPACITY: usize = 2;
const STATION_ADDRESS_VALID: u64 = 1 << 63;

/// Caller-owned SRAM required by the initial WS63 WPA2 SoftAP profile.
pub const ACCESS_POINT_ARENA_BYTES: usize = crate::WS63_SHARED_RADIO_ARENA_BYTES;

static RUNNER_WAKE: Semaphore = Semaphore::new(0);
static PORT_STATE: AtomicU8 = AtomicU8::new(PORT_FREE);
static PORT_IDENTITY: u8 = 0;
static DRIVER_CONTEXT: DriverContext = DriverContext::new();
static AP_CLAIMED: AtomicBool = AtomicBool::new(false);
static EAPOL_PENDING: AtomicU32 = AtomicU32::new(0);
static MGMT_RX: [MgmtSlot; MGMT_QUEUE_CAPACITY] = [const { MgmtSlot::new() }; MGMT_QUEUE_CAPACITY];
static AP_DIAGNOSTICS: AccessPointDiagnosticCounters = AccessPointDiagnosticCounters::new();

const SLOT_FREE: u8 = 0;
const SLOT_WRITING: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_READING: u8 = 3;

struct AccessPointDiagnosticCounters {
    events: AtomicU32,
    last_event: AtomicI32,
    last_event_length: AtomicU32,
    invalid_events: AtomicU32,
    management_queued: AtomicU32,
    management_dropped: AtomicU32,
    management_fed: AtomicU32,
    management_feed_errors: AtomicU32,
    stations_associated: AtomicU32,
    stations_disassociated: AtomicU32,
    station_address: AtomicU64,
    station_feed_errors: AtomicU32,
    eapol_polls: AtomicU32,
    eapol_received: AtomicU32,
    eapol_fed: AtomicU32,
    eapol_errors: AtomicU32,
    management_transmits: AtomicU32,
    last_management_status: AtomicI32,
    eapol_transmits: AtomicU32,
    last_eapol_status: AtomicI32,
    key_installs: AtomicU32,
    last_key_status: AtomicI32,
}

impl AccessPointDiagnosticCounters {
    const fn new() -> Self {
        Self {
            events: AtomicU32::new(0),
            last_event: AtomicI32::new(0),
            last_event_length: AtomicU32::new(0),
            invalid_events: AtomicU32::new(0),
            management_queued: AtomicU32::new(0),
            management_dropped: AtomicU32::new(0),
            management_fed: AtomicU32::new(0),
            management_feed_errors: AtomicU32::new(0),
            stations_associated: AtomicU32::new(0),
            stations_disassociated: AtomicU32::new(0),
            station_address: AtomicU64::new(0),
            station_feed_errors: AtomicU32::new(0),
            eapol_polls: AtomicU32::new(0),
            eapol_received: AtomicU32::new(0),
            eapol_fed: AtomicU32::new(0),
            eapol_errors: AtomicU32::new(0),
            management_transmits: AtomicU32::new(0),
            last_management_status: AtomicI32::new(0),
            eapol_transmits: AtomicU32::new(0),
            last_eapol_status: AtomicI32::new(0),
            key_installs: AtomicU32::new(0),
            last_key_status: AtomicI32::new(0),
        }
    }

    fn snapshot(&self) -> AccessPointDiagnostics {
        #[cfg(feature = "data-path-diag")]
        let mac = crate::wlmac_diag::snapshot();
        AccessPointDiagnostics {
            events: self.events.load(Ordering::Acquire),
            last_event: self.last_event.load(Ordering::Acquire),
            last_event_length: self.last_event_length.load(Ordering::Acquire),
            invalid_events: self.invalid_events.load(Ordering::Acquire),
            management_queued: self.management_queued.load(Ordering::Acquire),
            management_dropped: self.management_dropped.load(Ordering::Acquire),
            management_fed: self.management_fed.load(Ordering::Acquire),
            management_feed_errors: self.management_feed_errors.load(Ordering::Acquire),
            stations_associated: self.stations_associated.load(Ordering::Acquire),
            stations_disassociated: self.stations_disassociated.load(Ordering::Acquire),
            station_feed_errors: self.station_feed_errors.load(Ordering::Acquire),
            eapol_polls: self.eapol_polls.load(Ordering::Acquire),
            eapol_received: self.eapol_received.load(Ordering::Acquire),
            eapol_fed: self.eapol_fed.load(Ordering::Acquire),
            eapol_errors: self.eapol_errors.load(Ordering::Acquire),
            management_transmits: self.management_transmits.load(Ordering::Acquire),
            last_management_status: self.last_management_status.load(Ordering::Acquire),
            eapol_transmits: self.eapol_transmits.load(Ordering::Acquire),
            last_eapol_status: self.last_eapol_status.load(Ordering::Acquire),
            key_installs: self.key_installs.load(Ordering::Acquire),
            last_key_status: self.last_key_status.load(Ordering::Acquire),
            #[cfg(feature = "data-path-diag")]
            data_tx_frames: crate::netif_smoltcp::tx_count(),
            #[cfg(feature = "data-path-diag")]
            data_tx_failed: crate::netif::tx_failed(),
            #[cfg(feature = "data-path-diag")]
            data_vendor_tx_frames: crate::netif::tx_submitted(),
            #[cfg(feature = "data-path-diag")]
            data_tx_reference_diagnostics: crate::netif::tx_reference_diagnostics(),
            #[cfg(feature = "data-path-diag")]
            data_tx_completions: crate::data_path_diag::tx_completions(),
            #[cfg(feature = "data-path-diag")]
            data_tx_completion_status: crate::data_path_diag::tx_completion_status(),
            #[cfg(feature = "data-path-diag")]
            data_tx_completion_trace: crate::data_path_diag::tx_completion_trace(),
            #[cfg(feature = "data-path-diag")]
            data_tx_timeline: crate::data_path_diag::tx_timeline(),
            #[cfg(feature = "data-path-diag")]
            data_dmac_rx_prepares: crate::data_path_diag::rx_prepares(),
            #[cfg(feature = "data-path-diag")]
            data_hmac_rx_event_calls: crate::data_path_diag::rx_pipeline_stages()[0],
            #[cfg(feature = "data-path-diag")]
            data_hmac_rx_msg_calls: crate::data_path_diag::rx_pipeline_stages()[1],
            #[cfg(feature = "data-path-diag")]
            data_hmac_rx_calls: crate::data_path_diag::rx_pipeline_stages()[2],
            #[cfg(feature = "data-path-diag")]
            data_hmac_tx: crate::data_path_diag::hmac_tx_diagnostics(),
            #[cfg(feature = "data-path-diag")]
            data_hmac_tx_process: crate::data_path_diag::hmac_tx_process_diagnostics(),
            #[cfg(feature = "data-path-diag")]
            data_hmac_tx_data_send: crate::data_path_diag::hmac_tx_data_send_diagnostics(),
            #[cfg(feature = "data-path-diag")]
            data_frw_hmac_send: crate::data_path_diag::frw_hmac_send_data_diagnostics(),
            #[cfg(feature = "data-path-diag")]
            data_dmac_tx_event: crate::data_path_diag::dmac_tx_data_event_diagnostics(),
            #[cfg(feature = "data-path-diag")]
            data_psm: crate::data_path_diag::associated_station_ps(self.station_address()),
            #[cfg(feature = "data-path-diag")]
            data_vendor_rx_frames: crate::netif::rx_received(),
            #[cfg(feature = "data-path-diag")]
            mac_ccmp_replay_failures: u32::from(mac.security.ccmp_replay_failures),
            #[cfg(feature = "data-path-diag")]
            mac_ccmp_mic_failures: u32::from(mac.security.ccmp_mic_failures),
            #[cfg(feature = "data-path-diag")]
            mac_key_search_failures: u32::from(mac.security.key_search_failures),
            #[cfg(feature = "data-path-diag")]
            wlmac_irqs: crate::osal::irq_dispatch_count(45),
            #[cfg(feature = "data-path-diag")]
            wlmac_irq_lifecycle: crate::osal::irq_lifecycle_diagnostics(45),
            #[cfg(feature = "data-path-diag")]
            mac_tx_high_priority_mpdu: mac.tx.high_priority_mpdu,
            #[cfg(feature = "data-path-diag")]
            mac_tx_normal_priority_mpdu: mac.tx.normal_priority_mpdu,
            #[cfg(feature = "data-path-diag")]
            mac_tx_mpdu_in_ampdu: mac.tx.mpdu_in_ampdu,
            #[cfg(feature = "data-path-diag")]
            mac_tx_ampdu: mac.tx.ampdu,
            #[cfg(feature = "data-path-diag")]
            mac_tx_complete_interrupts: mac.tx.complete_interrupts,
        }
    }

    fn set_station_address(&self, address: [u8; 6]) {
        let packed = u64::from_le_bytes([
            address[0], address[1], address[2], address[3], address[4], address[5], 0, 0,
        ]);
        self.station_address
            .store(packed | STATION_ADDRESS_VALID, Ordering::Release);
    }

    fn clear_station_address(&self, address: [u8; 6]) {
        let packed = u64::from_le_bytes([
            address[0], address[1], address[2], address[3], address[4], address[5], 0, 0,
        ]) | STATION_ADDRESS_VALID;
        let _ =
            self.station_address
                .compare_exchange(packed, 0, Ordering::AcqRel, Ordering::Acquire);
    }

    fn station_address(&self) -> Option<[u8; 6]> {
        let packed = self.station_address.load(Ordering::Acquire);
        if packed & STATION_ADDRESS_VALID == 0 {
            return None;
        }
        let bytes = packed.to_le_bytes();
        Some([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
    }
}

/// Secret-free, bounded diagnostic snapshot for the native WS63 SoftAP path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccessPointDiagnostics {
    pub events: u32,
    pub last_event: i32,
    pub last_event_length: u32,
    pub invalid_events: u32,
    pub management_queued: u32,
    pub management_dropped: u32,
    pub management_fed: u32,
    pub management_feed_errors: u32,
    pub stations_associated: u32,
    pub stations_disassociated: u32,
    pub station_feed_errors: u32,
    pub eapol_polls: u32,
    pub eapol_received: u32,
    pub eapol_fed: u32,
    pub eapol_errors: u32,
    pub management_transmits: u32,
    pub last_management_status: i32,
    pub eapol_transmits: u32,
    pub last_eapol_status: i32,
    pub key_installs: u32,
    pub last_key_status: i32,
    #[cfg(feature = "data-path-diag")]
    pub data_tx_frames: u32,
    #[cfg(feature = "data-path-diag")]
    pub data_tx_failed: u32,
    #[cfg(feature = "data-path-diag")]
    pub data_vendor_tx_frames: u32,
    #[cfg(feature = "data-path-diag")]
    pub data_tx_reference_diagnostics: [u32; 3],
    #[cfg(feature = "data-path-diag")]
    pub data_tx_completions: u32,
    #[cfg(feature = "data-path-diag")]
    pub data_tx_completion_status: [u32; 16],
    /// Bounded `(total, packed entries)` completion ring. Each entry stores
    /// status in bits 31:28, sequence-valid in bit 27, TID in bits 26:23,
    /// queue in bits 22:20, and the 12-bit MAC sequence in bits 11:0.
    #[cfg(feature = "data-path-diag")]
    pub data_tx_completion_trace: (u32, [u32; 18], [u32; 18]),
    #[cfg(feature = "data-path-diag")]
    pub data_tx_timeline: crate::TxTimelineDiagnostics,
    #[cfg(feature = "data-path-diag")]
    pub data_dmac_rx_prepares: u32,
    #[cfg(feature = "data-path-diag")]
    pub data_hmac_rx_event_calls: u32,
    #[cfg(feature = "data-path-diag")]
    pub data_hmac_rx_msg_calls: u32,
    #[cfg(feature = "data-path-diag")]
    pub data_hmac_rx_calls: u32,
    #[cfg(feature = "data-path-diag")]
    pub data_hmac_tx: (u32, u32, [u32; 16]),
    #[cfg(feature = "data-path-diag")]
    pub data_hmac_tx_process: (u32, u32, [u32; 16]),
    #[cfg(feature = "data-path-diag")]
    pub data_hmac_tx_data_send: [u32; 2],
    #[cfg(feature = "data-path-diag")]
    pub data_frw_hmac_send: (u32, u32, [u32; 16]),
    #[cfg(feature = "data-path-diag")]
    pub data_dmac_tx_event: (u32, u32, [u32; 16]),
    #[cfg(feature = "data-path-diag")]
    pub data_psm: [u32; 5],
    #[cfg(feature = "data-path-diag")]
    pub data_vendor_rx_frames: u32,
    #[cfg(feature = "data-path-diag")]
    pub mac_ccmp_replay_failures: u32,
    #[cfg(feature = "data-path-diag")]
    pub mac_ccmp_mic_failures: u32,
    #[cfg(feature = "data-path-diag")]
    pub mac_key_search_failures: u32,
    #[cfg(feature = "data-path-diag")]
    pub wlmac_irqs: u32,
    #[cfg(feature = "data-path-diag")]
    pub wlmac_irq_lifecycle: [u32; 6],
    #[cfg(feature = "data-path-diag")]
    pub mac_tx_high_priority_mpdu: u32,
    #[cfg(feature = "data-path-diag")]
    pub mac_tx_normal_priority_mpdu: u32,
    #[cfg(feature = "data-path-diag")]
    pub mac_tx_mpdu_in_ampdu: u32,
    #[cfg(feature = "data-path-diag")]
    pub mac_tx_ampdu: u32,
    #[cfg(feature = "data-path-diag")]
    pub mac_tx_complete_interrupts: u32,
}

struct MgmtFrame {
    event: c_int,
    frequency_mhz: u32,
    rssi_dbm: i32,
    reassociated: u8,
    address: [u8; 6],
    len: usize,
    bytes: [u8; MAX_MGMT_FRAME_LEN],
}

struct MgmtSlot {
    state: AtomicU8,
    frame: UnsafeCell<MgmtFrame>,
}

// SAFETY: state transitions grant one callback writer or one runner reader
// exclusive access to the frame storage at a time.
unsafe impl Sync for MgmtSlot {}

impl MgmtSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(SLOT_FREE),
            frame: UnsafeCell::new(MgmtFrame {
                event: EVENT_RX_MGMT,
                frequency_mhz: 0,
                rssi_dbm: 0,
                reassociated: 0,
                address: [0; 6],
                len: 0,
                bytes: [0; MAX_MGMT_FRAME_LEN],
            }),
        }
    }
}

/// Control-plane storage for one WS63 SoftAP instance.
pub struct AccessPointControlStorage {
    crypto: StaticCell<Ws63CryptoStorage>,
    task_reservation: StaticCell<hisi_rf_rtos_driver::TaskReservation>,
    claimed: AtomicBool,
}

impl AccessPointControlStorage {
    pub const fn new() -> Self {
        Self {
            crypto: StaticCell::new(),
            task_reservation: StaticCell::new(),
            claimed: AtomicBool::new(false),
        }
    }
}

impl Default for AccessPointControlStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Large caller-owned arena shared by RTOS task stacks and native hostap.
#[repr(C, align(64))]
pub struct AccessPointArenaStorage<const N: usize> {
    bytes: UnsafeCell<[MaybeUninit<u8>; N]>,
    claimed: AtomicBool,
}

// SAFETY: the backing bytes are exposed only by the one-shot installation
// capability and remain owned by the process-wide allocator thereafter.
unsafe impl<const N: usize> Sync for AccessPointArenaStorage<N> {}

impl<const N: usize> AccessPointArenaStorage<N> {
    pub const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([MaybeUninit::uninit(); N]),
            claimed: AtomicBool::new(false),
        }
    }
}

impl<const N: usize> Default for AccessPointArenaStorage<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// One application-owned SoftAP composition object.
pub struct AccessPointStorage<const N: usize> {
    control: &'static AccessPointControlStorage,
    arena: &'static AccessPointArenaStorage<N>,
}

impl<const N: usize> AccessPointStorage<N> {
    #[doc(hidden)]
    pub const fn from_parts(
        control: &'static AccessPointControlStorage,
        arena: &'static AccessPointArenaStorage<N>,
    ) -> Self {
        Self { control, arena }
    }

    /// Install the shared allocator before starting hisi-rtos.
    pub fn install(&'static self) -> Result<InstalledAccessPointStorage<N>, AccessPointInitError> {
        if N < ACCESS_POINT_ARENA_BYTES {
            return Err(AccessPointInitError::InsufficientArena {
                required: ACCESS_POINT_ARENA_BYTES,
                available: N,
            });
        }
        if self
            .arena
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(AccessPointInitError::StorageAlreadyClaimed);
        }
        unsafe { crate::alloc::install_raw_arena(self.arena.bytes.get().cast(), N) }
            .map_err(|()| AccessPointInitError::Allocator)?;
        Ok(InstalledAccessPointStorage {
            control: self.control,
            _arena: PhantomData,
        })
    }
}

/// Installed SoftAP storage passed across the RTOS startup boundary.
pub struct InstalledAccessPointStorage<const N: usize> {
    control: &'static AccessPointControlStorage,
    _arena: PhantomData<&'static mut [u8; N]>,
}

impl<const N: usize> InstalledAccessPointStorage<N> {
    /// Allocate zeroed RTOS storage from the same caller-owned arena.
    ///
    /// # Safety
    ///
    /// The returned pointer must be released only through [`Self::deallocate`].
    pub unsafe fn allocate(size: usize) -> *mut u8 {
        crate::alloc::allocate_zeroed(size, 16).cast()
    }

    /// Release storage returned by [`Self::allocate`].
    ///
    /// # Safety
    ///
    /// `pointer` must be null or a live allocation returned by
    /// [`Self::allocate`] that has not already been released.
    pub unsafe fn deallocate(pointer: *mut u8) {
        crate::alloc::osal_kfree(pointer.cast());
    }
}

/// Declare caller-owned storage for one WPA2 SoftAP firmware image.
#[macro_export]
macro_rules! declare_access_point_storage {
    ($(#[$meta:meta])* $vis:vis static $name:ident) => {
        $(#[$meta])*
        $vis static $name: $crate::AccessPointStorage<
            { $crate::ACCESS_POINT_ARENA_BYTES }
        > = {
            static CONTROL: $crate::AccessPointControlStorage =
                $crate::AccessPointControlStorage::new();
            #[cfg_attr(
                target_arch = "riscv32",
                unsafe(link_section = ".hisi.shared-arena")
            )]
            static ARENA: $crate::AccessPointArenaStorage<
                { $crate::ACCESS_POINT_ARENA_BYTES }
            > = $crate::AccessPointArenaStorage::new();
            $crate::AccessPointStorage::from_parts(&CONTROL, &ARENA)
        };
    };
}

struct DriverContext {
    ifname: UnsafeCell<[u8; IFNAME_CAPACITY]>,
    beacon_configured: AtomicU8,
    send_action_cookie: UnsafeCell<u64>,
}

// SAFETY: interface initialization is guarded by PORT_STATE. Thereafter the
// name is immutable and the unique RadioRunner serializes mutable WAL payloads.
unsafe impl Sync for DriverContext {}

impl DriverContext {
    const fn new() -> Self {
        Self {
            ifname: UnsafeCell::new([0; IFNAME_CAPACITY]),
            beacon_configured: AtomicU8::new(0),
            send_action_cookie: UnsafeCell::new(0),
        }
    }

    fn initialize(&self, ifname: &[u8]) -> bool {
        if ifname.is_empty() || ifname.len() >= IFNAME_CAPACITY || ifname.contains(&0) {
            return false;
        }
        // SAFETY: PORT_INSTALLING grants this call the only write before the
        // context is published as PORT_READY.
        let storage = unsafe { &mut *self.ifname.get() };
        storage.fill(0);
        storage[..ifname.len()].copy_from_slice(ifname);
        self.beacon_configured.store(0, Ordering::Release);
        true
    }

    fn matches(&self, ifname: &[u8]) -> bool {
        let current = self.ifname();
        current.len().checked_sub(1) == Some(ifname.len()) && &current[..ifname.len()] == ifname
    }

    fn ifname(&self) -> &'static [u8] {
        // SAFETY: the array is immutable after PORT_READY. Find the terminator
        // inside the fixed bound and include it for the vendor C API.
        let storage = unsafe { &*self.ifname.get() };
        let length = storage
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(storage.len() - 1);
        &storage[..=length]
    }
}

/// Secret-free AP configuration consumed by the native hostapd context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessPointConfig<'a> {
    pub ssid: &'a [u8],
    pub passphrase: &'a [u8],
    pub channel: u8,
    pub hidden: bool,
    pub max_stations: u8,
    sae_pwe: u8,
}

/// Uniquely owned hardware and storage consumed by one SoftAP instance.
pub struct AccessPointResources<const N: usize> {
    efuse: Efuse<'static>,
    km: Km<'static>,
    spacc: Spacc<'static>,
    pke: Option<Pke<'static>>,
    trng: Trng<'static>,
    storage: InstalledAccessPointStorage<N>,
}

impl<const N: usize> AccessPointResources<N> {
    #[cfg(feature = "upstream-authenticator-wpa2")]
    pub fn new(
        efuse: Efuse<'static>,
        km: Km<'static>,
        spacc: Spacc<'static>,
        trng: Trng<'static>,
        storage: InstalledAccessPointStorage<N>,
    ) -> Self {
        Self {
            efuse,
            km,
            spacc,
            pke: None,
            trng,
            storage,
        }
    }

    #[cfg(feature = "upstream-authenticator-wpa3")]
    pub fn new(
        efuse: Efuse<'static>,
        km: Km<'static>,
        spacc: Spacc<'static>,
        pke: Pke<'static>,
        trng: Trng<'static>,
        storage: InstalledAccessPointStorage<N>,
    ) -> Self {
        Self {
            efuse,
            km,
            spacc,
            pke: Some(pke),
            trng,
            storage,
        }
    }
}

/// Failure while admitting and starting the WS63 SoftAP composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessPointInitError {
    UnsupportedTarget,
    StorageAlreadyClaimed,
    InsufficientArena { required: usize, available: usize },
    Allocator,
    Runtime(hisi_rf_rtos_driver::Error),
    TaskAdmission(hisi_rf_rtos_driver::TaskAdmissionError),
    Crypto(u32),
    Timebase(u32),
    WifiInitialize(u32),
    CreateInterface(c_int),
    RegisterEvents(c_int),
    Authenticator(NativeAuthenticatorError),
}

/// Running native authenticator and its vendor AP interface.
pub struct AccessPoint {
    authenticator: NativeAuthenticator,
    network_device_taken: bool,
}

impl AccessPoint {
    /// Advance bounded authenticator work in ordinary task context.
    pub fn poll(
        &mut self,
        work_budget: NonZeroU32,
    ) -> Result<PollResult, NativeAuthenticatorError> {
        self.authenticator.poll(work_budget)
    }

    /// Block the runner task until driver input or a bounded timeout.
    pub fn wait_for_work(&self, timeout_ms: u32) -> Result<WaitOutcome, NativeAuthenticatorError> {
        RUNNER_WAKE
            .down_timeout(WaitTimeout::from_millis(timeout_ms))
            .map_err(NativeAuthenticatorError::Runtime)
    }

    /// Return bounded counters for AP management and EAPOL driver traffic.
    ///
    /// The snapshot contains no SSID, station address, frame, or key material.
    pub fn diagnostics(&self) -> AccessPointDiagnostics {
        AP_DIAGNOSTICS.snapshot()
    }

    /// Take the AP's Rust-visible L2 device and hardware address.
    ///
    /// The network stack is owned by the application. This method succeeds
    /// once so two independent stacks cannot drain the process-wide WS63 RX
    /// queue at the same time.
    pub fn take_network_device(&mut self) -> Option<AccessPointNetworkDevice> {
        if self.network_device_taken {
            return None;
        }
        let hardware_address = crate::netif::hardware_address()?;
        self.network_device_taken = true;
        Some(AccessPointNetworkDevice {
            hardware_address,
            device: crate::netif_smoltcp::Ws63Device,
        })
    }

    /// Stop beaconing and release the native authenticator context.
    pub fn stop(&mut self) -> Result<(), NativeAuthenticatorError> {
        self.authenticator.stop()
    }
}

/// L2 resources owned by the application-side SoftAP network stack.
pub struct AccessPointNetworkDevice {
    /// MAC address assigned to the vendor AP netdev.
    pub hardware_address: [u8; 6],
    /// Rust-visible Ethernet device backed by the WS63 data path.
    pub device: crate::netif_smoltcp::Ws63Device,
}

impl<'a> AccessPointConfig<'a> {
    #[cfg(feature = "upstream-authenticator-wpa2")]
    pub const fn wpa2_personal(ssid: &'a [u8], passphrase: &'a [u8], channel: u8) -> Self {
        Self {
            ssid,
            passphrase,
            channel,
            hidden: false,
            max_stations: 4,
            sae_pwe: 0,
        }
    }

    /// Construct a pure WPA3-SAE AP with protected management frames required.
    #[cfg(feature = "upstream-authenticator-wpa3")]
    pub const fn wpa3_sae(ssid: &'a [u8], passphrase: &'a [u8], channel: u8) -> Self {
        Self {
            ssid,
            passphrase,
            channel,
            hidden: false,
            max_stations: 4,
            // Accept both hunting-and-pecking and hash-to-element peers while
            // the profile remains WPA3-only and PMF-required.
            sae_pwe: 2,
        }
    }

    fn as_raw(&self) -> Result<Config, NativeAuthenticatorError> {
        if self.ssid.is_empty()
            || self.ssid.len() > 32
            || !(8..=63).contains(&self.passphrase.len())
            || !(1..=13).contains(&self.channel)
            || self.max_stations == 0
        {
            return Err(NativeAuthenticatorError::InvalidConfig);
        }
        #[cfg(feature = "upstream-authenticator-wpa2")]
        let (security, pmf, sae_pwe) = (Security::Wpa2Psk as u8, 0, 0);
        #[cfg(feature = "upstream-authenticator-wpa3")]
        let (security, pmf, sae_pwe) = (Security::Wpa3Sae as u8, 2, self.sae_pwe);
        let mut raw = Config {
            abi_version: AP_ABI_VERSION,
            security,
            pmf,
            ssid_len: self.ssid.len() as u8,
            sae_pwe,
            channel: self.channel,
            hidden_ssid: u8::from(self.hidden),
            beacon_interval: 100,
            dtim_period: 2,
            max_stations: self.max_stations,
            reserved: [0; 4],
            ssid: [0; 32],
        };
        raw.ssid[..self.ssid.len()].copy_from_slice(self.ssid);
        Ok(raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAuthenticatorError {
    Busy,
    Poisoned,
    InvalidInterfaceName,
    InterfaceConflict,
    InvalidConfig,
    Runtime(hisi_rf_rtos_driver::Error),
    Abi(c_int),
    Allocate,
    Create,
    Configure(c_int),
    Start(c_int),
    Poll(c_int),
    Stop(c_int),
}

/// Unique owner of one upstream hostapd AP context.
pub struct NativeAuthenticator {
    context: NonNull<Context>,
    storage: NonNull<c_void>,
}

impl NativeAuthenticator {
    pub fn new(config: AccessPointConfig<'_>) -> Result<Self, NativeAuthenticatorError> {
        if PORT_STATE.load(Ordering::Acquire) != PORT_READY {
            return Err(NativeAuthenticatorError::Poisoned);
        }
        let raw = config.as_raw()?;
        // SAFETY: these target-archive accessors are pure constants.
        let (size, alignment) =
            unsafe { (hisi_wpa_ap_context_size(), hisi_wpa_ap_context_align()) };
        if size == 0 || alignment < core::mem::align_of::<usize>() || !alignment.is_power_of_two() {
            return Err(NativeAuthenticatorError::Abi(-1));
        }
        let storage = NonNull::new(crate::alloc::allocate_zeroed(size, alignment))
            .ok_or(NativeAuthenticatorError::Allocate)?;
        let hooks = driver_hooks();
        // SAFETY: storage has the exact queried size/alignment and hooks are
        // copied synchronously by the versioned C boundary.
        let context = unsafe { hisi_wpa_ap_create(storage.as_ptr(), size, &raw const hooks) };
        let Some(context) = NonNull::new(context) else {
            crate::alloc::osal_kfree(storage.as_ptr());
            return Err(NativeAuthenticatorError::Create);
        };
        // SAFETY: context is uniquely owned and all borrowed bytes remain live
        // for this synchronous configuration call.
        let status = unsafe {
            hisi_wpa_ap_configure(
                context.as_ptr(),
                &raw const raw,
                config.passphrase.as_ptr(),
                config.passphrase.len(),
            )
        };
        if status != 0 {
            unsafe { hisi_wpa_ap_destroy(context.as_ptr()) };
            crate::alloc::osal_kfree(storage.as_ptr());
            return Err(NativeAuthenticatorError::Configure(status));
        }
        Ok(Self { context, storage })
    }

    pub fn start(&mut self) -> Result<(), NativeAuthenticatorError> {
        let status = unsafe { hisi_wpa_ap_start(self.context.as_ptr()) };
        (status == 0)
            .then_some(())
            .ok_or(NativeAuthenticatorError::Start(status))
    }

    pub fn poll(
        &mut self,
        work_budget: NonZeroU32,
    ) -> Result<PollResult, NativeAuthenticatorError> {
        self.drain_driver_input()?;
        let result = unsafe {
            hisi_wpa_ap_poll(
                self.context.as_ptr(),
                crate::uapi::monotonic_ms(),
                work_budget.get(),
            )
        };
        (result.status == 0)
            .then_some(result)
            .ok_or(NativeAuthenticatorError::Poll(result.status))
    }

    fn drain_driver_input(&mut self) -> Result<(), NativeAuthenticatorError> {
        for slot in &MGMT_RX {
            if slot
                .state
                .compare_exchange(
                    SLOT_READY,
                    SLOT_READING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            // SAFETY: SLOT_READING grants this runner exclusive access until
            // it publishes SLOT_FREE below.
            let frame = unsafe { &*slot.frame.get() };
            let event = frame.event;
            let status = match event {
                EVENT_NEW_STATION => unsafe {
                    ws63_radio_sys::authenticator::hisi_wpa_ap_feed_associated(
                        self.context.as_ptr(),
                        frame.address.as_ptr(),
                        frame.bytes.as_ptr(),
                        frame.len,
                        frame.reassociated,
                    )
                },
                EVENT_DEL_STATION => unsafe {
                    ws63_radio_sys::authenticator::hisi_wpa_ap_feed_disassociated(
                        self.context.as_ptr(),
                        frame.address.as_ptr(),
                    )
                },
                EVENT_RX_MGMT => unsafe {
                    ws63_radio_sys::authenticator::hisi_wpa_ap_feed_mgmt(
                        self.context.as_ptr(),
                        frame.frequency_mhz,
                        frame.rssi_dbm,
                        frame.bytes.as_ptr(),
                        frame.len,
                    )
                },
                _ => -1,
            };
            slot.state.store(SLOT_FREE, Ordering::Release);
            match event {
                EVENT_NEW_STATION => {
                    AP_DIAGNOSTICS
                        .stations_associated
                        .fetch_add(1, Ordering::Relaxed);
                }
                EVENT_DEL_STATION => {
                    AP_DIAGNOSTICS
                        .stations_disassociated
                        .fetch_add(1, Ordering::Relaxed);
                }
                EVENT_RX_MGMT => {
                    AP_DIAGNOSTICS
                        .management_fed
                        .fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
            if status != 0 {
                if event == EVENT_RX_MGMT {
                    AP_DIAGNOSTICS
                        .management_feed_errors
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    AP_DIAGNOSTICS
                        .station_feed_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Err(NativeAuthenticatorError::Poll(status));
            }
        }

        if EAPOL_PENDING.swap(0, Ordering::AcqRel) == 0 {
            return Ok(());
        }
        let mut ethernet = [0_u8; ETHERNET_HEADER_LEN + MAX_EAPOL_PAYLOAD_LEN];
        loop {
            AP_DIAGNOSTICS.eapol_polls.fetch_add(1, Ordering::Relaxed);
            let mut receive = RxEapol {
                buffer: ethernet.as_mut_ptr(),
                length: ethernet.len() as u32,
            };
            let status = crate::wal::ioctl(
                DRIVER_CONTEXT.ifname(),
                IOCTL_RECEIVE_EAPOL,
                (&mut receive as *mut RxEapol).cast(),
            );
            if status != 0 {
                break;
            }
            if (receive.length as usize) < ETHERNET_HEADER_LEN {
                AP_DIAGNOSTICS.eapol_errors.fetch_add(1, Ordering::Relaxed);
                return Err(NativeAuthenticatorError::Poll(-1));
            }
            AP_DIAGNOSTICS
                .eapol_received
                .fetch_add(1, Ordering::Relaxed);
            let length = (receive.length as usize).min(ethernet.len());
            let status = unsafe {
                ws63_radio_sys::authenticator::hisi_wpa_ap_feed_eapol(
                    self.context.as_ptr(),
                    ethernet[6..12].as_ptr(),
                    ethernet[ETHERNET_HEADER_LEN..length].as_ptr(),
                    length - ETHERNET_HEADER_LEN,
                )
            };
            if status != 0 {
                AP_DIAGNOSTICS.eapol_errors.fetch_add(1, Ordering::Relaxed);
                return Err(NativeAuthenticatorError::Poll(status));
            }
            AP_DIAGNOSTICS.eapol_fed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), NativeAuthenticatorError> {
        let status = unsafe { hisi_wpa_ap_stop(self.context.as_ptr()) };
        (status == 0)
            .then_some(())
            .ok_or(NativeAuthenticatorError::Stop(status))
    }
}

impl Drop for NativeAuthenticator {
    fn drop(&mut self) {
        unsafe { hisi_wpa_ap_destroy(self.context.as_ptr()) };
        crate::alloc::osal_kfree(self.storage.as_ptr());
    }
}

/// Install the native RTOS/OS and WS63 AP driver callbacks.
pub fn prepare_upstream_authenticator_port(ifname: &[u8]) -> Result<(), NativeAuthenticatorError> {
    RUNNER_WAKE
        .try_init()
        .map_err(NativeAuthenticatorError::Runtime)?;
    match PORT_STATE.compare_exchange(
        PORT_FREE,
        PORT_INSTALLING,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {}
        Err(PORT_READY) if DRIVER_CONTEXT.matches(ifname) => return Ok(()),
        Err(PORT_READY) => return Err(NativeAuthenticatorError::InterfaceConflict),
        Err(PORT_INSTALLING) => return Err(NativeAuthenticatorError::Busy),
        Err(_) => return Err(NativeAuthenticatorError::Poisoned),
    }
    if !DRIVER_CONTEXT.initialize(ifname) {
        PORT_STATE.store(PORT_FREE, Ordering::Release);
        return Err(NativeAuthenticatorError::InvalidInterfaceName);
    }

    let os_hooks = os_hooks();
    let driver_hooks = driver_hooks();
    let os_status = unsafe { hisi_wpa_os_install(&raw const os_hooks) };
    if os_status != 0 {
        PORT_STATE.store(PORT_FREE, Ordering::Release);
        return Err(NativeAuthenticatorError::Abi(os_status));
    }
    let driver_status = unsafe { hisi_wpa_ap_driver_install(&raw const driver_hooks) };
    if driver_status == 0 {
        PORT_STATE.store(PORT_READY, Ordering::Release);
        return Ok(());
    }
    let rollback = unsafe { hisi_wpa_os_uninstall(os_hooks.context) };
    PORT_STATE.store(
        if rollback == 0 {
            PORT_FREE
        } else {
            PORT_POISONED
        },
        Ordering::Release,
    );
    Err(NativeAuthenticatorError::Abi(driver_status))
}

/// Initialize the WS63 vendor runtime, create an AP netdev, and start hostapd.
pub fn init_access_point<const N: usize>(
    config: AccessPointConfig<'_>,
    resources: AccessPointResources<N>,
) -> Result<AccessPoint, AccessPointInitError> {
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (config, resources);
        Err(AccessPointInitError::UnsupportedTarget)
    }
    #[cfg(target_arch = "riscv32")]
    {
        crate::link_contract::ensure();
        hisi_rf_rtos_driver::require_runtime(
            hisi_rf_rtos_driver::RuntimeRequirements::V1_6_PORTED_COOPERATIVE,
        )
        .map_err(AccessPointInitError::Runtime)?;
        hisi_rf_rtos_driver::current_task().map_err(AccessPointInitError::Runtime)?;
        if AP_CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(AccessPointInitError::StorageAlreadyClaimed);
        }

        let control = resources.storage.control;
        if control
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(AccessPointInitError::StorageAlreadyClaimed);
        }
        let reservation = reserve_vendor_tasks().map_err(AccessPointInitError::TaskAdmission)?;
        let reservation = &*control.task_reservation.init(reservation);
        if let Err(error) = crate::runtime::install_task_reservation(reservation) {
            let _ = hisi_rf_rtos_driver::release_task_reservation(reservation);
            return Err(AccessPointInitError::Runtime(error));
        }

        crate::force_link_contract();
        unsafe { crate::prepare_vendor_memory() };
        let timebase = crate::uapi::initialize_rom_timebases();
        if timebase != 0 {
            return Err(AccessPointInitError::Timebase(timebase));
        }
        let _efuse = resources.efuse;
        crate::uapi::enable_efuse_reads();
        let crypto = control.crypto.init(Ws63CryptoStorage::new());
        crate::crypto::install_hardware_crypto(
            resources.km,
            resources.spacc,
            resources.pke,
            resources.trng,
            crypto,
        )
        .map_err(|_| AccessPointInitError::Crypto(0xffff_2001))?;
        #[cfg(feature = "upstream-authenticator-wpa3")]
        crate::crypto::ws63_p256_self_test()
            .map_err(|_| AccessPointInitError::Crypto(0xffff_2002))?;

        let init = unsafe { uapi_wifi_init(2, 7) };
        if init != 0 {
            return Err(AccessPointInitError::WifiInitialize(init));
        }
        let mut ifname = [0_u8; IFNAME_CAPACITY];
        let mut length = (IFNAME_CAPACITY - 1) as u32;
        let create = unsafe {
            wal_init_drv_wlan_netdev(
                AP_INTERFACE_TYPE,
                MODE_11B_G_N_AX,
                ifname.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if create != 0
            || length == 0
            || length as usize >= IFNAME_CAPACITY
            || ifname[length as usize] != 0
        {
            return Err(AccessPointInitError::CreateInterface(create));
        }
        let register = unsafe { drv_soc_register_send_event_cb(Some(ap_event)) };
        if register != 0 {
            return Err(AccessPointInitError::RegisterEvents(register));
        }
        prepare_upstream_authenticator_port(&ifname[..length as usize])
            .map_err(AccessPointInitError::Authenticator)?;
        let mut eapol = EnableEapol {
            callback: Some(eapol_event),
            context: core::ptr::null_mut(),
        };
        let enable = crate::wal::ioctl(
            DRIVER_CONTEXT.ifname(),
            IOCTL_ENABLE_EAPOL,
            (&mut eapol as *mut EnableEapol).cast(),
        );
        if enable != 0 {
            return Err(AccessPointInitError::Authenticator(
                NativeAuthenticatorError::Abi(enable),
            ));
        }
        let mut authenticator =
            NativeAuthenticator::new(config).map_err(AccessPointInitError::Authenticator)?;
        authenticator
            .start()
            .map_err(AccessPointInitError::Authenticator)?;
        crate::netif_smoltcp::set_tx_sink(crate::netif::vendor_tx_sink);
        Ok(AccessPoint {
            authenticator,
            network_device_taken: false,
        })
    }
}

#[cfg(target_arch = "riscv32")]
fn reserve_vendor_tasks()
-> Result<hisi_rf_rtos_driver::TaskReservation, hisi_rf_rtos_driver::TaskAdmissionError> {
    let owner =
        hisi_rf_rtos_driver::TaskResourceOwner::new(NonZeroU32::new(VENDOR_TASK_OWNER).unwrap());
    let resources = hisi_rf_rtos_driver::TaskResourceRequirements::new(
        NonZeroUsize::new(crate::WS63_WIFI_VENDOR_DYNAMIC_TASKS_REQUIRED).unwrap(),
        NonZeroUsize::new(VENDOR_TASK_STACK_BYTES).unwrap(),
    )
    .ok_or(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
        hisi_rf_rtos_driver::Error::ResourceExhausted,
    ))?;
    let groups = [hisi_rf_rtos_driver::TaskResourceGroupRequirements::new(
        owner, resources,
    )];
    let plan = hisi_rf_rtos_driver::TaskResourcePlan::new(&groups).ok_or(
        hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
            hisi_rf_rtos_driver::Error::ResourceExhausted,
        ),
    )?;
    let mut reservations = hisi_rf_rtos_driver::reserve_task_resource_plan(plan)?;
    reservations
        .take(0)
        .ok_or(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
            hisi_rf_rtos_driver::Error::Runtime,
        ))
}

fn os_hooks() -> OsHooks {
    OsHooks {
        abi_version: HOSTAP_ABI_VERSION,
        reserved: 0,
        context: core::ptr::addr_of!(PORT_IDENTITY).cast_mut().cast(),
        allocate_zeroed: Some(allocate_zeroed),
        reallocate_zeroed: Some(reallocate_zeroed),
        deallocate: Some(deallocate),
        monotonic_us: Some(monotonic_us),
        wall_clock_us: None,
        sleep_ms: Some(sleep_ms),
        fill_entropy: Some(fill_entropy),
        wait_for_work: Some(wait_for_work),
        wake_runner: Some(wake_runner),
    }
}

fn driver_hooks() -> DriverHooks {
    DriverHooks {
        abi_version: AP_ABI_VERSION,
        reserved: 0,
        driver: core::ptr::addr_of!(DRIVER_CONTEXT).cast_mut().cast(),
        get_own_address: Some(get_own_address),
        get_hw_features: Some(get_hw_features),
        set_netdev_enabled: Some(set_netdev_enabled),
        configure_beacon: Some(configure_beacon),
        send_eapol: Some(send_eapol),
        send_mgmt: Some(send_mgmt),
        install_key: Some(install_key),
        remove_key: Some(remove_key),
        remove_station: Some(remove_station),
    }
}

fn driver_context(driver: *mut c_void) -> Option<&'static DriverContext> {
    (driver == core::ptr::addr_of!(DRIVER_CONTEXT).cast_mut().cast()).then_some(&DRIVER_CONTEXT)
}

unsafe extern "C" fn get_own_address(driver: *mut c_void, address: *mut u8) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    if address.is_null() {
        return -1;
    }
    if let Some(live) = crate::netif::hardware_address() {
        unsafe { core::ptr::copy_nonoverlapping(live.as_ptr(), address, live.len()) };
        0
    } else {
        crate::wal::ioctl(driver.ifname(), IOCTL_GET_ADDRESS, address.cast())
    }
}

unsafe extern "C" fn get_hw_features(
    driver: *mut c_void,
    features: *mut HardwareFeatures,
) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    if features.is_null() {
        return -1;
    }
    crate::wal::ioctl(driver.ifname(), IOCTL_GET_HW_FEATURES, features.cast())
}

unsafe extern "C" fn set_netdev_enabled(driver: *mut c_void, enabled: u8) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    if enabled > 1 {
        return -1;
    }
    if enabled == 0 && driver.beacon_configured.swap(0, Ordering::AcqRel) != 0 {
        let mut unused = 0_i32;
        let status = crate::wal::ioctl(
            driver.ifname(),
            IOCTL_DEL_BEACON,
            (&mut unused as *mut i32).cast(),
        );
        if status != 0 {
            return status;
        }
    }
    let mut enabled = enabled;
    crate::wal::ioctl(
        driver.ifname(),
        IOCTL_SET_NETDEV,
        (&mut enabled as *mut u8).cast(),
    )
}

#[repr(C)]
struct FrequencyParameters {
    mode: i32,
    frequency_mhz: i32,
    channel: i32,
    ht_enabled: i32,
    secondary_channel_offset: i32,
    vht_enabled: i32,
    center_frequency1_mhz: i32,
    center_frequency2_mhz: i32,
    bandwidth: i32,
}

#[repr(C)]
struct BeaconData {
    head_len: u32,
    tail_len: u32,
    head: *mut u8,
    tail: *mut u8,
}

#[repr(C)]
struct ApSettings {
    frequency: FrequencyParameters,
    beacon: BeaconData,
    ssid_len: u32,
    beacon_interval: i32,
    dtim_period: i32,
    ssid: *mut u8,
    hidden_ssid: u8,
    auth_type: u8,
    reserved: [u8; 2],
    mesh_ssid_len: u32,
    mesh_ssid: *mut u8,
    sae_pwe: i32,
}

unsafe extern "C" fn configure_beacon(driver: *mut c_void, beacon: *const Beacon) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    let Some(beacon) = (unsafe { beacon.as_ref() }) else {
        return -1;
    };
    let ssid_len = beacon.ssid_len as usize;
    if beacon.abi_version != AP_ABI_VERSION
        || ssid_len == 0
        || ssid_len > beacon.ssid.len()
        || beacon.head_len > u32::MAX as usize
        || beacon.tail_len > u32::MAX as usize
        || (beacon.head_len != 0 && beacon.head.is_null())
        || (beacon.tail_len != 0 && beacon.tail.is_null())
    {
        return -1;
    }
    let mut settings = ApSettings {
        frequency: FrequencyParameters {
            mode: 0,
            frequency_mhz: beacon.frequency_mhz as i32,
            channel: i32::from(beacon.channel),
            ht_enabled: 1,
            secondary_channel_offset: 0,
            vht_enabled: 0,
            center_frequency1_mhz: beacon.frequency_mhz as i32,
            center_frequency2_mhz: 0,
            bandwidth: 0,
        },
        beacon: BeaconData {
            head_len: beacon.head_len as u32,
            tail_len: beacon.tail_len as u32,
            head: beacon.head.cast_mut(),
            tail: beacon.tail.cast_mut(),
        },
        ssid_len: ssid_len as u32,
        beacon_interval: i32::from(beacon.beacon_interval),
        dtim_period: i32::from(beacon.dtim_period),
        ssid: beacon.ssid.as_ptr().cast_mut(),
        hidden_ssid: beacon.hidden_ssid,
        auth_type: 0,
        reserved: [0; 2],
        mesh_ssid_len: 0,
        mesh_ssid: core::ptr::null_mut(),
        sae_pwe: i32::from(beacon.sae_pwe),
    };
    let command = if driver.beacon_configured.load(Ordering::Acquire) == 0 {
        IOCTL_SET_AP
    } else {
        IOCTL_CHANGE_BEACON
    };
    let status = crate::wal::ioctl(
        driver.ifname(),
        command,
        (&mut settings as *mut ApSettings).cast(),
    );
    if status == 0 {
        driver.beacon_configured.store(1, Ordering::Release);
    }
    status
}

#[repr(C)]
struct TxEapol {
    buffer: *mut u8,
    length: u32,
}

#[repr(C)]
struct RxEapol {
    buffer: *mut u8,
    length: u32,
}

#[repr(C)]
struct EnableEapol {
    callback: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
}

#[repr(C)]
struct MlmeData {
    frequency_mhz: u32,
    data_len: u32,
    data: *mut u8,
    send_action_cookie: *mut u64,
}

unsafe extern "C" fn send_eapol(
    driver: *mut c_void,
    destination: *const u8,
    payload: *const u8,
    payload_len: usize,
) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    if destination.is_null()
        || payload.is_null()
        || payload_len == 0
        || payload_len > MAX_EAPOL_PAYLOAD_LEN
    {
        return -1;
    }
    let mut source = [0; 6];
    if unsafe {
        get_own_address(
            driver as *const DriverContext as *mut c_void,
            source.as_mut_ptr(),
        )
    } != 0
    {
        return -1;
    }
    let mut frame = [0_u8; ETHERNET_HEADER_LEN + MAX_EAPOL_PAYLOAD_LEN];
    unsafe { core::ptr::copy_nonoverlapping(destination, frame.as_mut_ptr(), 6) };
    frame[6..12].copy_from_slice(&source);
    frame[12..14].copy_from_slice(&[0x88, 0x8e]);
    unsafe {
        core::ptr::copy_nonoverlapping(
            payload,
            frame.as_mut_ptr().add(ETHERNET_HEADER_LEN),
            payload_len,
        )
    };
    let mut request = TxEapol {
        buffer: frame.as_mut_ptr(),
        length: (ETHERNET_HEADER_LEN + payload_len) as u32,
    };
    AP_DIAGNOSTICS
        .eapol_transmits
        .fetch_add(1, Ordering::Relaxed);
    let status = crate::wal::ioctl(
        driver.ifname(),
        IOCTL_SEND_EAPOL,
        (&mut request as *mut TxEapol).cast(),
    );
    AP_DIAGNOSTICS
        .last_eapol_status
        .store(status, Ordering::Release);
    status
}

unsafe extern "C" fn send_mgmt(
    driver: *mut c_void,
    frequency_mhz: u32,
    frame: *const u8,
    frame_len: usize,
) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    if frame.is_null() || frame_len == 0 || frame_len > u32::MAX as usize {
        return -1;
    }
    let mut request = MlmeData {
        frequency_mhz,
        data_len: frame_len as u32,
        data: frame.cast_mut(),
        send_action_cookie: driver.send_action_cookie.get(),
    };
    AP_DIAGNOSTICS
        .management_transmits
        .fetch_add(1, Ordering::Relaxed);
    let status = crate::wal::ioctl(
        driver.ifname(),
        IOCTL_SEND_MLME,
        (&mut request as *mut MlmeData).cast(),
    );
    AP_DIAGNOSTICS
        .last_management_status
        .store(status, Ordering::Release);
    status
}

#[repr(C)]
struct KeyExtension {
    key_type: i32,
    key_index: u32,
    key_len: u32,
    sequence_len: u32,
    cipher: u32,
    address: *mut u8,
    material: *mut u8,
    sequence: *mut u8,
    default_data: u8,
    default_management: u8,
    default_types: u8,
    reserved: u8,
}

fn key_request(key: &Key, material: *mut u8, material_len: usize) -> Option<KeyExtension> {
    let pairwise = key.flags & key_flag::PAIRWISE != 0;
    let group = key.flags & key_flag::GROUP != 0;
    if key.abi_version != HOSTAP_ABI_VERSION
        || pairwise == group
        || key.sequence_len as usize > key.sequence.len()
        || key.peer_present > 1
        || material_len > u32::MAX as usize
    {
        return None;
    }
    let suite = match (key.cipher, material_len) {
        (cipher::NONE, 0) => 0,
        (cipher::WEP, 5) => 0x000f_ac01,
        (cipher::WEP, 13) => 0x000f_ac05,
        (cipher::TKIP, 32) => 0x000f_ac02,
        (cipher::CCMP, 16) => 0x000f_ac04,
        (cipher::BIP_CMAC_128, 16) => 0x000f_ac06,
        _ => return None,
    };
    Some(KeyExtension {
        key_type: if pairwise { 1 } else { 0 },
        key_index: u32::from(key.key_index),
        key_len: material_len as u32,
        sequence_len: u32::from(key.sequence_len),
        cipher: suite,
        address: if pairwise {
            key.peer.as_ptr().cast_mut()
        } else {
            core::ptr::null_mut()
        },
        material,
        sequence: if key.sequence_len == 0 {
            core::ptr::null_mut()
        } else {
            key.sequence.as_ptr().cast_mut()
        },
        default_data: 1,
        default_management: 0,
        default_types: if pairwise { 1 } else { 2 },
        reserved: 0,
    })
}

fn should_select_default_key(key: &Key) -> bool {
    key.flags & key_flag::PAIRWISE == 0 && key.flags & key_flag::TX != 0
}

unsafe extern "C" fn install_key(
    driver: *mut c_void,
    key: *const Key,
    material: *const u8,
    material_len: usize,
) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    let Some(key) = (unsafe { key.as_ref() }) else {
        return -1;
    };
    if material.is_null() {
        return -1;
    }
    let Some(mut request) = key_request(key, material.cast_mut(), material_len) else {
        return -1;
    };
    AP_DIAGNOSTICS.key_installs.fetch_add(1, Ordering::Relaxed);
    let status = crate::wal::ioctl(
        driver.ifname(),
        IOCTL_NEW_KEY,
        (&mut request as *mut KeyExtension).cast(),
    );
    AP_DIAGNOSTICS
        .last_key_status
        .store(status, Ordering::Release);
    // The WS63 AP driver installs pairwise keys with NEW_KEY only. SET_KEY
    // selects the interface default TX key and is reserved for group keys.
    if status != 0 || !should_select_default_key(key) {
        return status;
    }
    let status = crate::wal::ioctl(
        driver.ifname(),
        IOCTL_SET_KEY,
        (&mut request as *mut KeyExtension).cast(),
    );
    AP_DIAGNOSTICS
        .last_key_status
        .store(status, Ordering::Release);
    status
}

unsafe extern "C" fn remove_key(driver: *mut c_void, key: *const Key) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    let Some(key) = (unsafe { key.as_ref() }) else {
        return -1;
    };
    let Some(mut request) = key_request(key, core::ptr::null_mut(), 0) else {
        return -1;
    };
    crate::wal::ioctl(
        driver.ifname(),
        IOCTL_DEL_KEY,
        (&mut request as *mut KeyExtension).cast(),
    )
}

unsafe extern "C" fn remove_station(driver: *mut c_void, address: *const u8) -> c_int {
    let Some(driver) = driver_context(driver) else {
        return -1;
    };
    if address.is_null() {
        return -1;
    }
    crate::wal::ioctl(driver.ifname(), IOCTL_STA_REMOVE, address.cast_mut().cast())
}

unsafe extern "C" fn allocate_zeroed(_: *mut c_void, size: usize, alignment: usize) -> *mut c_void {
    crate::alloc::allocate_zeroed(size, alignment)
}

unsafe extern "C" fn reallocate_zeroed(
    _: *mut c_void,
    pointer: *mut c_void,
    size: usize,
    alignment: usize,
) -> *mut c_void {
    unsafe { crate::alloc::reallocate_zeroed(pointer, size, alignment) }
}

unsafe extern "C" fn deallocate(_: *mut c_void, pointer: *mut c_void) {
    crate::alloc::osal_kfree(pointer);
}

unsafe extern "C" fn monotonic_us(_: *mut c_void, value: *mut u64) -> c_int {
    let Some(value) = (unsafe { value.as_mut() }) else {
        return -1;
    };
    *value = crate::uapi::monotonic_us();
    0
}

unsafe extern "C" fn sleep_ms(_: *mut c_void, milliseconds: u32) -> c_int {
    let result = if let Some(milliseconds) = NonZeroU32::new(milliseconds) {
        hisi_rf_rtos_driver::sleep_ms(milliseconds)
    } else {
        hisi_rf_rtos_driver::yield_now()
    };
    result.map(|()| 0).unwrap_or(-1)
}

unsafe extern "C" fn fill_entropy(_: *mut c_void, output: *mut u8, output_len: usize) -> c_int {
    if output_len == 0 {
        return 0;
    }
    if output.is_null() {
        return -1;
    }
    let output = unsafe { core::slice::from_raw_parts_mut(output, output_len) };
    crate::crypto::fill_hardware_entropy(output)
        .map(|()| 0)
        .unwrap_or(-1)
}

unsafe extern "C" fn wait_for_work(_: *mut c_void, timeout_ms: u32) -> c_int {
    match RUNNER_WAKE.down_timeout(WaitTimeout::from_millis(timeout_ms)) {
        Ok(WaitOutcome::Acquired) | Ok(WaitOutcome::TimedOut) => 0,
        Err(_) => -1,
    }
}

unsafe extern "C" fn wake_runner(_: *mut c_void) {
    let _ = RUNNER_WAKE.up();
}

unsafe extern "C" fn eapol_event(_: *mut c_void, _: *mut c_void) {
    EAPOL_PENDING.fetch_add(1, Ordering::Release);
    let _ = RUNNER_WAKE.up();
}

#[repr(C)]
struct VendorNewStation {
    reassociated: i32,
    information_elements_len: usize,
    information_elements: *const u8,
    address: [u8; 6],
    reserved: [u8; 2],
}

#[repr(C)]
struct VendorRxMgmt {
    frame: *const u8,
    frame_len: u32,
    signal_mbm: i32,
    frequency_mhz: i32,
}

fn claim_driver_event_slot() -> Option<&'static MgmtSlot> {
    MGMT_RX.iter().find(|slot| {
        slot.state
            .compare_exchange(SLOT_FREE, SLOT_WRITING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    })
}

fn release_vendor_buffer(pointer: *const u8) {
    if !pointer.is_null() {
        crate::alloc::osal_kfree(pointer.cast_mut().cast());
    }
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ap_event(
    ifname: *const c_char,
    event: c_int,
    data: *mut u8,
    length: u32,
) -> c_int {
    AP_DIAGNOSTICS.events.fetch_add(1, Ordering::Relaxed);
    AP_DIAGNOSTICS.last_event.store(event, Ordering::Release);
    AP_DIAGNOSTICS
        .last_event_length
        .store(length, Ordering::Release);
    if ifname.is_null() || data.is_null() {
        AP_DIAGNOSTICS
            .invalid_events
            .fetch_add(1, Ordering::Relaxed);
        return 0;
    }
    match event {
        EVENT_NEW_STATION if length as usize == core::mem::size_of::<VendorNewStation>() => {
            let input = unsafe { &*data.cast::<VendorNewStation>() };
            AP_DIAGNOSTICS.set_station_address(input.address);
            let ies_len = input.information_elements_len;
            if ies_len > MAX_MGMT_FRAME_LEN
                || (ies_len != 0 && input.information_elements.is_null())
            {
                release_vendor_buffer(input.information_elements);
                AP_DIAGNOSTICS
                    .station_feed_errors
                    .fetch_add(1, Ordering::Relaxed);
                return -1;
            }
            let Some(slot) = claim_driver_event_slot() else {
                release_vendor_buffer(input.information_elements);
                AP_DIAGNOSTICS
                    .station_feed_errors
                    .fetch_add(1, Ordering::Relaxed);
                return -1;
            };
            let output = unsafe { &mut *slot.frame.get() };
            output.event = EVENT_NEW_STATION;
            output.reassociated = u8::from(input.reassociated != 0);
            output.address = input.address;
            output.len = ies_len;
            if ies_len != 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        input.information_elements,
                        output.bytes.as_mut_ptr(),
                        ies_len,
                    );
                }
            }
            release_vendor_buffer(input.information_elements);
            slot.state.store(SLOT_READY, Ordering::Release);
        }
        EVENT_DEL_STATION if length == 6 => {
            let address = unsafe { core::ptr::read_unaligned(data.cast::<[u8; 6]>()) };
            AP_DIAGNOSTICS.clear_station_address(address);
            let Some(slot) = claim_driver_event_slot() else {
                AP_DIAGNOSTICS
                    .station_feed_errors
                    .fetch_add(1, Ordering::Relaxed);
                return -1;
            };
            let output = unsafe { &mut *slot.frame.get() };
            output.event = EVENT_DEL_STATION;
            unsafe { core::ptr::copy_nonoverlapping(data, output.address.as_mut_ptr(), 6) };
            output.len = 0;
            slot.state.store(SLOT_READY, Ordering::Release);
        }
        EVENT_RX_MGMT if length as usize == core::mem::size_of::<VendorRxMgmt>() => {
            let input = unsafe { &*data.cast::<VendorRxMgmt>() };
            let frame_len = input.frame_len as usize;
            if input.frame.is_null() || frame_len == 0 || frame_len > MAX_MGMT_FRAME_LEN {
                release_vendor_buffer(input.frame);
                AP_DIAGNOSTICS
                    .management_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return -1;
            }
            let Some(slot) = claim_driver_event_slot() else {
                release_vendor_buffer(input.frame);
                AP_DIAGNOSTICS
                    .management_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return -1;
            };
            let output = unsafe { &mut *slot.frame.get() };
            output.event = EVENT_RX_MGMT;
            output.frequency_mhz = input.frequency_mhz.max(0) as u32;
            output.rssi_dbm = input.signal_mbm / 100;
            output.len = frame_len;
            unsafe {
                core::ptr::copy_nonoverlapping(input.frame, output.bytes.as_mut_ptr(), frame_len);
            }
            release_vendor_buffer(input.frame);
            slot.state.store(SLOT_READY, Ordering::Release);
            AP_DIAGNOSTICS
                .management_queued
                .fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            AP_DIAGNOSTICS
                .invalid_events
                .fetch_add(1, Ordering::Relaxed);
            return 0;
        }
    }
    let _ = RUNNER_WAKE.up();
    0
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" {
    fn uapi_wifi_init(vap_res_num: u8, user_res_num: u8) -> u32;
    fn wal_init_drv_wlan_netdev(
        interface_type: u8,
        mode: c_uint,
        ifname: *mut c_char,
        length: *mut u32,
    ) -> c_int;
    fn drv_soc_register_send_event_cb(
        callback: Option<unsafe extern "C" fn(*const c_char, c_int, *mut u8, c_uint) -> c_int>,
    ) -> c_int;
}

#[cfg(target_arch = "riscv32")]
const _: () = {
    assert!(core::mem::size_of::<VendorRxMgmt>() == 16);
    assert!(core::mem::size_of::<VendorNewStation>() == 20);
    assert!(core::mem::size_of::<FrequencyParameters>() == 36);
    assert!(core::mem::size_of::<BeaconData>() == 16);
    assert!(core::mem::size_of::<ApSettings>() == 84);
    assert!(core::mem::size_of::<TxEapol>() == 8);
    assert!(core::mem::size_of::<EnableEapol>() == 8);
    assert!(core::mem::size_of::<MlmeData>() == 16);
    assert!(core::mem::size_of::<KeyExtension>() == 36);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(flags: u32) -> Key {
        Key {
            abi_version: HOSTAP_ABI_VERSION,
            cipher: cipher::CCMP,
            key_index: 0,
            flags,
            peer_present: 1,
            sequence_len: 0,
            peer: [0; 6],
            sequence: [0; 16],
        }
    }

    #[test]
    fn selects_only_group_tx_keys_as_interface_default() {
        assert!(!should_select_default_key(&test_key(
            key_flag::PAIRWISE | key_flag::TX
        )));
        assert!(should_select_default_key(&test_key(
            key_flag::GROUP | key_flag::TX
        )));
        assert!(!should_select_default_key(&test_key(key_flag::GROUP)));
    }

    #[test]
    fn station_diagnostics_publish_and_clear_one_address_atomically() {
        let diagnostics = AccessPointDiagnosticCounters::new();
        let first = [0x02, 0, 0, 0, 0, 1];
        let second = [0x02, 0, 0, 0, 0, 2];

        assert_eq!(diagnostics.station_address(), None);
        diagnostics.set_station_address(first);
        assert_eq!(diagnostics.station_address(), Some(first));
        diagnostics.set_station_address(second);
        diagnostics.clear_station_address(first);
        assert_eq!(diagnostics.station_address(), Some(second));
        diagnostics.clear_station_address(second);
        assert_eq!(diagnostics.station_address(), None);
    }

    #[test]
    #[cfg(feature = "upstream-authenticator-wpa2")]
    fn validates_bounded_wpa2_config() {
        assert!(
            AccessPointConfig::wpa2_personal(b"ws63-test", b"test-only-pass", 6)
                .as_raw()
                .is_ok()
        );
        assert!(matches!(
            AccessPointConfig::wpa2_personal(b"", b"test-only-pass", 6).as_raw(),
            Err(NativeAuthenticatorError::InvalidConfig)
        ));
        assert!(matches!(
            AccessPointConfig::wpa2_personal(b"ws63-test", b"short", 6).as_raw(),
            Err(NativeAuthenticatorError::InvalidConfig)
        ));
    }

    #[test]
    #[cfg(feature = "upstream-authenticator-wpa3")]
    fn emits_pure_wpa3_sae_with_required_pmf() {
        let raw = AccessPointConfig::wpa3_sae(b"ws63-test", b"test-only-pass", 6)
            .as_raw()
            .unwrap();
        assert_eq!(raw.security, Security::Wpa3Sae as u8);
        assert_eq!(raw.pmf, 2);
        assert_eq!(raw.sae_pwe, 2);
        assert!(matches!(
            AccessPointConfig::wpa3_sae(b"ws63-test", b"short", 6).as_raw(),
            Err(NativeAuthenticatorError::InvalidConfig)
        ));
    }
}
