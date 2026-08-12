//! Internal WS63 BLE controller/host initialization and bounded GAP/GATT slice.
//!
//! B1 is deliberately narrower than a public BLE API: it installs the fixed
//! vendor task set, platform services, and controller/host runtime, then proves
//! that `enable_ble` completes. B2 adds advertising, scanning, and a bounded
//! copied-event queue. B3 adds an unpaired GATT client/server smoke contract.
//! U5A adds a typed pairing/bond-control boundary and copies secret-free
//! completion metadata out of vendor callbacks. Hardware crypto integration,
//! persistent bond storage, pairing responders, and pairing HIL remain gated.

use core::cell::{RefCell, UnsafeCell};
#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;
use core::mem::MaybeUninit;
#[cfg(any(target_arch = "riscv32", test))]
use core::num::{NonZeroU32, NonZeroUsize};

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_hal::peripherals::{Efuse, Km, Pke, Spacc, Trng};
#[cfg(target_arch = "riscv32")]
use hisi_rf_core::ble::{AddressType, ScanMode};
use hisi_rf_core::ble::{
    AdvertisingConfig, BluetoothAddress, GattServerDefinition, PairingState, ScanConfig,
    SecurityConfig,
};
#[cfg(any(target_arch = "riscv32", test))]
use hisi_rf_core::ble::{
    Bonding, GattPermissions, GattProperties, GattUuid, IoCapability, SecurityRequirement,
};
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

const BLE_B2_EVENT_CAPACITY: usize = 32;
const BLE_B2_ADV_DATA_CAPACITY: usize = 31;
const BLE_B3_VALUE_CAPACITY: usize = 32;

#[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
struct BleB2OperationStorage {
    advertising_data: [u8; BLE_B2_ADV_DATA_CAPACITY],
    advertising_len: u8,
    gatt_characteristic_value: [u8; BLE_B3_VALUE_CAPACITY],
    gatt_descriptor_value: [u8; BLE_B3_VALUE_CAPACITY],
    #[cfg(target_arch = "riscv32")]
    advertising_parameters: GapBleAdvertisingParameters,
    #[cfg(target_arch = "riscv32")]
    scan_parameters: GapBleScanParameters,
}

impl BleB2OperationStorage {
    const fn new() -> Self {
        Self {
            advertising_data: [0; BLE_B2_ADV_DATA_CAPACITY],
            advertising_len: 0,
            gatt_characteristic_value: [0; BLE_B3_VALUE_CAPACITY],
            gatt_descriptor_value: [0; BLE_B3_VALUE_CAPACITY],
            #[cfg(target_arch = "riscv32")]
            advertising_parameters: GapBleAdvertisingParameters {
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
            },
            #[cfg(target_arch = "riscv32")]
            scan_parameters: GapBleScanParameters {
                interval: 0x48,
                window: 0x48,
                scan_type: 0,
                phy: 1,
                filter_policy: 0,
            },
        }
    }

    #[cfg_attr(not(any(target_arch = "riscv32", test)), allow(dead_code))]
    fn store_advertising_payload(&mut self, config: &AdvertisingConfig) {
        let payload = config.payload().as_bytes();
        self.advertising_data[..payload.len()].copy_from_slice(payload);
        self.advertising_len = payload.len() as u8;
    }

    #[cfg(any(target_arch = "riscv32", test))]
    fn store_gatt_values(
        &mut self,
        characteristic: &[u8],
        descriptor: &[u8],
    ) -> Result<(), BleB3Error> {
        if characteristic.len() > BLE_B3_VALUE_CAPACITY {
            return Err(BleB3Error::ValueTooLong {
                length: characteristic.len(),
            });
        }
        if descriptor.len() > BLE_B3_VALUE_CAPACITY {
            return Err(BleB3Error::ValueTooLong {
                length: descriptor.len(),
            });
        }
        self.gatt_characteristic_value.fill(0);
        self.gatt_characteristic_value[..characteristic.len()].copy_from_slice(characteristic);
        self.gatt_descriptor_value.fill(0);
        self.gatt_descriptor_value[..descriptor.len()].copy_from_slice(descriptor);
        Ok(())
    }
}

/// UUID used by the bounded B3 interoperability service.
pub const BLE_B3_SERVICE_UUID: u16 = 0xABCD;
/// UUID used by the bounded B3 read/write/notify/indicate characteristic.
pub const BLE_B3_CHARACTERISTIC_UUID: u16 = 0xCDEF;
/// Standard Client Characteristic Configuration descriptor UUID.
pub const BLE_B3_CCC_UUID: u16 = 0x2902;

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
    /// Advertising stopped for the reported handle.
    AdvertisingStopped { adv_id: u8, status: u32 },
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
    /// A peer connected or disconnected. Vendor-owned address bytes are copied.
    ConnectionState {
        conn_id: u16,
        address: [u8; 6],
        address_type: u8,
        connected: bool,
        pair_state: u32,
        reason: u32,
    },
    /// Pairing reached a terminal vendor result. No key bytes are exposed.
    PairingComplete {
        conn_id: u16,
        address: [u8; 6],
        address_type: u8,
        status: u32,
    },
    /// Link authentication completed. LTK bytes remain inside the backend.
    AuthenticationComplete {
        conn_id: u16,
        address: [u8; 6],
        address_type: u8,
        status: u32,
        ltk_present: bool,
    },
    /// The local B3 service start request completed.
    GattServiceStarted {
        server_id: u8,
        service_handle: u16,
        status: u32,
    },
    /// A bounded write request arrived at the B3 server.
    GattServerWrite {
        server_id: u8,
        conn_id: u16,
        handle: u16,
        status: u32,
        value_len: u8,
        value: [u8; BLE_B3_VALUE_CAPACITY],
    },
    /// The peer confirmed a server indication.
    GattIndicationConfirmed {
        server_id: u8,
        conn_id: u16,
        status: u32,
    },
    /// A service matching a client discovery request was copied.
    GattServiceDiscovered {
        client_id: u8,
        conn_id: u16,
        start_handle: u16,
        end_handle: u16,
        uuid: u16,
        status: u32,
    },
    /// A characteristic matching a client discovery request was copied.
    GattCharacteristicDiscovered {
        client_id: u8,
        conn_id: u16,
        declaration_handle: u16,
        value_handle: u16,
        properties: u8,
        uuid: u16,
        status: u32,
    },
    /// A characteristic descriptor was copied.
    GattDescriptorDiscovered {
        client_id: u8,
        conn_id: u16,
        handle: u16,
        uuid: u16,
        status: u32,
    },
    /// A client write request completed.
    GattWriteCompleted {
        client_id: u8,
        conn_id: u16,
        handle: u16,
        status: u32,
    },
    /// A bounded notification payload arrived at the client.
    GattNotification {
        client_id: u8,
        conn_id: u16,
        handle: u16,
        status: u32,
        value_len: u8,
        value: [u8; BLE_B3_VALUE_CAPACITY],
    },
    /// A bounded indication payload arrived at the client.
    GattIndication {
        client_id: u8,
        conn_id: u16,
        handle: u16,
        status: u32,
        value_len: u8,
        value: [u8; BLE_B3_VALUE_CAPACITY],
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
    enable_seen: AtomicBool,
    enable_status: AtomicU32,
}

impl BleEventQueue {
    const fn new() -> Self {
        Self {
            ring: critical_section::Mutex::new(RefCell::new(BleEventRing::new())),
            dropped: AtomicU32::new(0),
            enable_seen: AtomicBool::new(false),
            enable_status: AtomicU32::new(0),
        }
    }

    fn enable_status(&self) -> Option<u32> {
        self.enable_seen
            .load(Ordering::Acquire)
            .then(|| self.enable_status.load(Ordering::Relaxed))
    }

    #[cfg_attr(not(any(target_arch = "riscv32", test)), allow(dead_code))]
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
    operations: StaticCell<BleB2OperationStorage>,
}

impl BleB1ControlStorage {
    /// Construct uninitialized B1 control storage.
    pub const fn new() -> Self {
        Self {
            crypto: StaticCell::new(),
            events: StaticCell::new(),
            operations: StaticCell::new(),
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
        let operations = self.control.operations.init(BleB2OperationStorage::new());
        Ok(InstalledBleB1Storage {
            crypto,
            events,
            operations,
        })
    }
}

/// Proof that the B1 shared arena and crypto storage were installed.
pub struct InstalledBleB1Storage {
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    crypto: &'static mut Ws63CryptoStorage,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    events: &'static BleEventQueue,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    operations: &'static mut BleB2OperationStorage,
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
    pke: Pke<'static>,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    trng: Trng<'static>,
}

impl BleB1Resources {
    /// Bind the uniquely owned eFuse and unified-cipher capabilities.
    pub const fn new(
        efuse: Efuse<'static>,
        km: Km<'static>,
        spacc: Spacc<'static>,
        pke: Pke<'static>,
        trng: Trng<'static>,
    ) -> Self {
        Self {
            efuse,
            km,
            spacc,
            pke,
            trng,
        }
    }
}

/// Process-lifetime proof that the internal BLE B1 runtime is active.
#[must_use = "retain the BLE B1 controller so the eFuse capability stays owned"]
pub struct BleB1Controller {
    _efuse: Efuse<'static>,
    events: &'static BleEventQueue,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    operations: &'static mut BleB2OperationStorage,
}

/// Handles allocated by the pinned WS63 GATT server for the B3 service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BleGattServer {
    /// Vendor server identifier.
    pub server_id: u8,
    /// Primary service handle.
    pub service_handle: u16,
    /// Characteristic value handle used for writes and outbound values.
    pub value_handle: u16,
    /// Client Characteristic Configuration descriptor handle.
    pub ccc_handle: u16,
}

/// Identifier allocated by the pinned WS63 GATT client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BleGattClient {
    /// Vendor client identifier.
    pub client_id: u8,
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

    /// Return the asynchronous vendor enable result without consuming its event.
    #[doc(hidden)]
    pub fn enable_status(&self) -> Option<u32> {
        self.events.enable_status()
    }

    /// Start advertising from an owned, validated U2 request.
    ///
    /// The request is copied into process-lifetime backend storage before any
    /// pointer is handed to the vendor stack.
    #[cfg(target_arch = "riscv32")]
    pub fn start_advertising_config(
        &mut self,
        config: AdvertisingConfig,
    ) -> Result<(), BleB2Error> {
        self.operations.store_advertising_payload(&config);
        let timing = config.timing();
        self.operations.advertising_parameters.min_interval = timing.minimum().as_units().into();
        self.operations.advertising_parameters.max_interval = timing.maximum().as_units().into();
        self.operations.advertising_parameters.channel_map = config.channels().bits();
        self.start_advertising_stored()
    }

    /// Start scanning from an owned, validated U2 request.
    #[cfg(target_arch = "riscv32")]
    pub fn start_scanning_config(&mut self, config: ScanConfig) -> Result<(), BleB2Error> {
        if config.filter_duplicates() {
            return Err(BleB2Error::DuplicateFilteringUnsupported);
        }
        let timing = config.timing();
        self.operations.scan_parameters.interval = timing.interval().as_units();
        self.operations.scan_parameters.window = timing.window().as_units();
        self.operations.scan_parameters.scan_type = match config.mode() {
            ScanMode::Passive => 0,
            ScanMode::Active => 1,
        };
        self.start_scanning_stored()
    }

    /// Configure legacy advertising data and start advertising handle zero.
    ///
    /// The buffer is process-lifetime data because the vendor API may consume
    /// it asynchronously after the command returns.
    #[cfg(target_arch = "riscv32")]
    pub fn start_advertising(&mut self, advertising_data: &'static [u8]) -> Result<(), BleB2Error> {
        let payload = hisi_rf_core::ble::AdvertisingPayload::try_from_slice(advertising_data)
            .ok_or(BleB2Error::AdvertisingDataTooLong {
                length: advertising_data.len(),
            })?;
        let timing = hisi_rf_core::ble::AdvertisingTiming::try_new(
            hisi_rf_core::ble::AdvertisingInterval::try_from_units(0x20).unwrap(),
            hisi_rf_core::ble::AdvertisingInterval::try_from_units(0x60).unwrap(),
        )
        .unwrap();
        self.start_advertising_config(AdvertisingConfig::new(
            timing,
            hisi_rf_core::ble::AdvertisingChannels::ALL,
            payload,
        ))
    }

    #[cfg(target_arch = "riscv32")]
    fn start_advertising_stored(&mut self) -> Result<(), BleB2Error> {
        let data = GapBleAdvertisingData {
            advertising_length: self.operations.advertising_len.into(),
            advertising_data: self.operations.advertising_data.as_mut_ptr(),
            scan_response_length: 0,
            scan_response_data: core::ptr::null_mut(),
        };
        let status = unsafe { gap_ble_set_adv_data(0, &raw const data) };
        if status != 0 {
            return Err(BleB2Error::SetAdvertisingData(status));
        }

        let status =
            unsafe { gap_ble_set_adv_param(0, &raw const self.operations.advertising_parameters) };
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
        let interval = hisi_rf_core::ble::ScanInterval::try_from_units(0x48).unwrap();
        self.start_scanning_config(ScanConfig::new(
            hisi_rf_core::ble::ScanTiming::try_new(interval, interval).unwrap(),
            ScanMode::Passive,
            false,
        ))
    }

    #[cfg(target_arch = "riscv32")]
    fn start_scanning_stored(&mut self) -> Result<(), BleB2Error> {
        let status =
            unsafe { gap_ble_set_scan_parameters(&raw const self.operations.scan_parameters) };
        if status != 0 {
            return Err(BleB2Error::SetScanParameters(status));
        }
        let status = unsafe { gap_ble_start_scan() };
        if status != 0 {
            return Err(BleB2Error::StartScanning(status));
        }
        Ok(())
    }

    /// Stop advertising handle zero.
    #[cfg(target_arch = "riscv32")]
    pub fn stop_advertising(&mut self) -> Result<(), BleB2Error> {
        let status = unsafe { gap_ble_stop_adv(0) };
        if status != 0 {
            return Err(BleB2Error::StopAdvertising(status));
        }
        Ok(())
    }

    /// Stop the active scan. The vendor API has no separate stop callback.
    #[cfg(target_arch = "riscv32")]
    pub fn stop_scanning(&mut self) -> Result<(), BleB2Error> {
        let status = unsafe { gap_ble_stop_scan() };
        if status != 0 {
            return Err(BleB2Error::StopScanning(status));
        }
        Ok(())
    }

    /// Stop scanning and connect to one copied scan-result address.
    #[cfg(target_arch = "riscv32")]
    pub fn connect(&mut self, address: [u8; 6], address_type: u8) -> Result<(), BleB3Error> {
        let stop_status = unsafe { gap_ble_stop_scan() };
        if stop_status != 0 {
            return Err(BleB3Error::StopScanning(stop_status));
        }
        let address = BdAddr {
            addr: address,
            address_type,
        };
        let status = unsafe { gap_ble_connect_remote_device(&raw const address) };
        if status != 0 {
            return Err(BleB3Error::Connect(status));
        }
        Ok(())
    }

    /// Register and start the fixed B3 primary service.
    #[cfg(target_arch = "riscv32")]
    pub fn register_gatt_server(&mut self) -> Result<BleGattServer, BleB3Error> {
        const CCC: hisi_rf_core::ble::GattDescriptorDefinition =
            hisi_rf_core::ble::GattDescriptorDefinition::try_new(
                GattUuid::Uuid16(BLE_B3_CCC_UUID),
                GattPermissions::READ.union(GattPermissions::WRITE),
                &[0, 0],
                2,
            )
            .unwrap();
        const CHARACTERISTIC: hisi_rf_core::ble::GattCharacteristicDefinition =
            hisi_rf_core::ble::GattCharacteristicDefinition::try_new(
                GattUuid::Uuid16(BLE_B3_CHARACTERISTIC_UUID),
                GattPermissions::READ.union(GattPermissions::WRITE),
                GattProperties::READ
                    .union(GattProperties::WRITE)
                    .union(GattProperties::NOTIFY)
                    .union(GattProperties::INDICATE),
                b"B3",
                BLE_B3_VALUE_CAPACITY as u16,
                &[CCC],
            )
            .unwrap();
        const SERVICE: hisi_rf_core::ble::GattServiceDefinition =
            hisi_rf_core::ble::GattServiceDefinition::try_new(
                GattUuid::Uuid16(BLE_B3_SERVICE_UUID),
                true,
                &[CHARACTERISTIC],
            )
            .unwrap();
        const DATABASE: GattServerDefinition =
            GattServerDefinition::try_new(GattUuid::Uuid16(0xB301), &[SERVICE]).unwrap();
        self.register_gatt_server_definition(DATABASE)
    }

    /// Register one static database within the reviewed WS63 U3 capacity.
    #[cfg(target_arch = "riscv32")]
    pub fn register_gatt_server_definition(
        &mut self,
        definition: GattServerDefinition,
    ) -> Result<BleGattServer, BleB3Error> {
        let [service] = definition.services() else {
            return Err(BleB3Error::UnsupportedDatabase);
        };
        let [characteristic] = service.characteristics() else {
            return Err(BleB3Error::UnsupportedDatabase);
        };
        let [descriptor] = characteristic.descriptors() else {
            return Err(BleB3Error::UnsupportedDatabase);
        };
        if characteristic.maximum_len() as usize > BLE_B3_VALUE_CAPACITY
            || descriptor.maximum_len() as usize > BLE_B3_VALUE_CAPACITY
        {
            return Err(BleB3Error::UnsupportedDatabase);
        }
        self.operations
            .store_gatt_values(characteristic.initial_value(), descriptor.initial_value())?;

        let mut server_id = 0;
        let mut app_uuid = BtUuid::from_core(definition.app_uuid());
        let status = unsafe { gatts_register_server(&raw mut app_uuid, &raw mut server_id) };
        if status != 0 {
            return Err(BleB3Error::RegisterServer(status));
        }

        let mut service_handle = 0;
        let mut service_uuid = BtUuid::from_core(service.uuid());
        let status = unsafe {
            gatts_add_service_sync(
                server_id,
                &raw mut service_uuid,
                service.is_primary(),
                &raw mut service_handle,
            )
        };
        if status != 0 {
            return Err(BleB3Error::AddService(status));
        }

        let mut characteristic = GattsAddCharacteristic {
            uuid: BtUuid::from_core(characteristic.uuid()),
            permissions: map_gatt_permissions(characteristic.permissions()),
            properties: map_gatt_properties(characteristic.properties()),
            value_len: characteristic.initial_value().len() as u16,
            value: self.operations.gatt_characteristic_value.as_mut_ptr(),
        };
        let mut characteristic_result = GattsAddCharacteristicResult {
            declaration_handle: 0,
            value_handle: 0,
        };
        let status = unsafe {
            gatts_add_characteristic_sync(
                server_id,
                service_handle,
                &raw mut characteristic,
                &raw mut characteristic_result,
            )
        };
        if status != 0 {
            return Err(BleB3Error::AddCharacteristic(status));
        }

        let mut descriptor = GattsAddDescriptor {
            uuid: BtUuid::from_core(descriptor.uuid()),
            permissions: map_gatt_permissions(descriptor.permissions()),
            value_len: descriptor.initial_value().len() as u16,
            value: self.operations.gatt_descriptor_value.as_mut_ptr(),
        };
        let mut ccc_handle = 0;
        let status = unsafe {
            gatts_add_descriptor_sync(
                server_id,
                service_handle,
                &raw mut descriptor,
                &raw mut ccc_handle,
            )
        };
        if status != 0 {
            return Err(BleB3Error::AddDescriptor(status));
        }
        let status = unsafe { gatts_start_service(server_id, service_handle) };
        if status != 0 {
            return Err(BleB3Error::StartService(status));
        }
        Ok(BleGattServer {
            server_id,
            service_handle,
            value_handle: characteristic_result.value_handle,
            ccc_handle,
        })
    }

    /// Register one fixed GATT client before initiating discovery.
    #[cfg(target_arch = "riscv32")]
    pub fn register_gatt_client(&mut self) -> Result<BleGattClient, BleB3Error> {
        let mut client_id = 0;
        let mut app_uuid = BtUuid::from_u16(0xB302);
        let status = unsafe { gattc_register_client(&raw mut app_uuid, &raw mut client_id) };
        if status != 0 {
            return Err(BleB3Error::RegisterClient(status));
        }
        Ok(BleGattClient { client_id })
    }

    /// Discover the fixed B3 service on a connected peer.
    #[cfg(target_arch = "riscv32")]
    pub fn discover_b3_service(
        &mut self,
        client: BleGattClient,
        conn_id: u16,
    ) -> Result<(), BleB3Error> {
        let mut uuid = BtUuid::from_u16(BLE_B3_SERVICE_UUID);
        let status = unsafe { gattc_discovery_service(client.client_id, conn_id, &raw mut uuid) };
        if status != 0 {
            return Err(BleB3Error::DiscoverService(status));
        }
        Ok(())
    }

    /// Discover the fixed B3 characteristic within a discovered service.
    #[cfg(target_arch = "riscv32")]
    pub fn discover_b3_characteristic(
        &mut self,
        client: BleGattClient,
        conn_id: u16,
        service_handle: u16,
    ) -> Result<(), BleB3Error> {
        let mut parameters = GattcDiscoverCharacteristic {
            service_handle,
            uuid: BtUuid::from_u16(BLE_B3_CHARACTERISTIC_UUID),
        };
        let status =
            unsafe { gattc_discovery_character(client.client_id, conn_id, &raw mut parameters) };
        if status != 0 {
            return Err(BleB3Error::DiscoverCharacteristic(status));
        }
        Ok(())
    }

    /// Discover descriptors attached to a characteristic declaration.
    #[cfg(target_arch = "riscv32")]
    pub fn discover_descriptors(
        &mut self,
        client: BleGattClient,
        conn_id: u16,
        declaration_handle: u16,
    ) -> Result<(), BleB3Error> {
        let status =
            unsafe { gattc_discovery_descriptor(client.client_id, conn_id, declaration_handle) };
        if status != 0 {
            return Err(BleB3Error::DiscoverDescriptor(status));
        }
        Ok(())
    }

    /// Submit one bounded GATT write request.
    #[cfg(target_arch = "riscv32")]
    pub fn gatt_write(
        &mut self,
        client: BleGattClient,
        conn_id: u16,
        handle: u16,
        value: &'static mut [u8],
    ) -> Result<(), BleB3Error> {
        if value.len() > BLE_B3_VALUE_CAPACITY {
            return Err(BleB3Error::ValueTooLong {
                length: value.len(),
            });
        }
        let mut parameters = GattcHandleValue {
            handle,
            data_len: value.len() as u16,
            data: value.as_mut_ptr(),
        };
        let status = unsafe { gattc_write_req(client.client_id, conn_id, &raw mut parameters) };
        if status != 0 {
            return Err(BleB3Error::Write(status));
        }
        Ok(())
    }

    /// Send a notification or indication according to the peer CCC value.
    #[cfg(target_arch = "riscv32")]
    pub fn gatt_notify_or_indicate(
        &mut self,
        server: BleGattServer,
        conn_id: u16,
        value: &'static mut [u8],
    ) -> Result<(), BleB3Error> {
        if value.len() > BLE_B3_VALUE_CAPACITY {
            return Err(BleB3Error::ValueTooLong {
                length: value.len(),
            });
        }
        let mut parameters = GattsNotification {
            attr_handle: server.value_handle,
            value_len: value.len() as u16,
            value: value.as_mut_ptr(),
        };
        let status =
            unsafe { gatts_notify_indicate(server.server_id, conn_id, &raw mut parameters) };
        if status != 0 {
            return Err(BleB3Error::NotifyOrIndicate(status));
        }
        Ok(())
    }

    /// Disconnect one peer and rely on the copied GAP event for cleanup proof.
    #[cfg(target_arch = "riscv32")]
    pub fn disconnect(&mut self, address: [u8; 6], address_type: u8) -> Result<(), BleB3Error> {
        let address = BdAddr {
            addr: address,
            address_type,
        };
        let status = unsafe { gap_ble_disconnect_remote_device(&raw const address) };
        if status != 0 {
            return Err(BleB3Error::Disconnect(status));
        }
        Ok(())
    }

    /// Configure the vendor GAP host from a chip-neutral pairing policy.
    #[cfg(target_arch = "riscv32")]
    pub fn configure_security(&mut self, config: SecurityConfig) -> Result<(), BleSecurityError> {
        let mut parameters = GapBleSecurityParameters::from_config(config);
        let status = unsafe { gap_ble_set_sec_param(&raw mut parameters) };
        if status != 0 {
            return Err(BleSecurityError::Configure(status));
        }
        Ok(())
    }

    /// Start pairing with one validated peer address.
    #[cfg(target_arch = "riscv32")]
    pub fn pair(&mut self, peer: BluetoothAddress) -> Result<(), BleSecurityError> {
        let address = BdAddr::from_typed(peer);
        let status = unsafe { gap_ble_pair_remote_device(&raw const address) };
        if status != 0 {
            return Err(BleSecurityError::Pair(status));
        }
        Ok(())
    }

    /// Query the current pairing state without exposing vendor values.
    #[cfg(target_arch = "riscv32")]
    pub fn pairing_state(
        &mut self,
        peer: BluetoothAddress,
    ) -> Result<PairingState, BleSecurityError> {
        let address = BdAddr::from_typed(peer);
        let mut state = 0u32;
        let status = unsafe { gap_ble_get_pair_state(&raw const address, &raw mut state) };
        if status != 0 {
            return Err(BleSecurityError::Query(status));
        }
        match state {
            1 => Ok(PairingState::NotPaired),
            2 => Ok(PairingState::Pairing),
            3 => Ok(PairingState::Paired),
            value => Err(BleSecurityError::UnknownPairingState(value)),
        }
    }

    /// Remove the stored relationship with one peer.
    #[cfg(target_arch = "riscv32")]
    pub fn remove_bond(&mut self, peer: BluetoothAddress) -> Result<(), BleSecurityError> {
        let address = BdAddr::from_typed(peer);
        let status = unsafe { gap_ble_remove_pair(&raw const address) };
        if status != 0 {
            return Err(BleSecurityError::RemoveBond(status));
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

    /// Host builds cannot invoke the WS63 typed GAP implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn start_advertising_config(&mut self, _: AdvertisingConfig) -> Result<(), BleB2Error> {
        Err(BleB2Error::UnsupportedTarget)
    }

    /// Host builds cannot invoke the WS63 typed GAP implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn start_scanning_config(&mut self, _: ScanConfig) -> Result<(), BleB2Error> {
        Err(BleB2Error::UnsupportedTarget)
    }

    /// Host builds cannot invoke the WS63 advertising stop implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn stop_advertising(&mut self) -> Result<(), BleB2Error> {
        Err(BleB2Error::UnsupportedTarget)
    }

    /// Host builds cannot invoke the WS63 scan stop implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn stop_scanning(&mut self) -> Result<(), BleB2Error> {
        Err(BleB2Error::UnsupportedTarget)
    }

    /// Host builds cannot invoke the WS63 GAP/GATT implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn register_gatt_server(&mut self) -> Result<BleGattServer, BleB3Error> {
        Err(BleB3Error::UnsupportedTarget)
    }

    /// Host builds cannot invoke the WS63 typed GATT implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn register_gatt_server_definition(
        &mut self,
        _: GattServerDefinition,
    ) -> Result<BleGattServer, BleB3Error> {
        Err(BleB3Error::UnsupportedTarget)
    }

    /// Host builds cannot invoke the WS63 GAP/GATT implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn register_gatt_client(&mut self) -> Result<BleGattClient, BleB3Error> {
        Err(BleB3Error::UnsupportedTarget)
    }

    /// Host builds cannot configure the WS63 GAP security host.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn configure_security(&mut self, _: SecurityConfig) -> Result<(), BleSecurityError> {
        Err(BleSecurityError::UnsupportedTarget)
    }

    /// Host builds cannot start WS63 pairing.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn pair(&mut self, _: BluetoothAddress) -> Result<(), BleSecurityError> {
        Err(BleSecurityError::UnsupportedTarget)
    }

    /// Host builds cannot query WS63 pairing state.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn pairing_state(&mut self, _: BluetoothAddress) -> Result<PairingState, BleSecurityError> {
        Err(BleSecurityError::UnsupportedTarget)
    }

    /// Host builds cannot remove WS63 bonds.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn remove_bond(&mut self, _: BluetoothAddress) -> Result<(), BleSecurityError> {
        Err(BleSecurityError::UnsupportedTarget)
    }
}

/// Fail-closed errors from the bounded BLE pairing contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BleSecurityError {
    /// The vendor host rejected the security policy.
    Configure(u32),
    /// The vendor host rejected the pairing request.
    Pair(u32),
    /// Querying pairing state failed.
    Query(u32),
    /// The vendor host returned a pairing-state value outside its reviewed ABI.
    UnknownPairingState(u32),
    /// Removing the stored peer relationship failed.
    RemoveBond(u32),
    /// The operation is unavailable outside WS63 target firmware.
    UnsupportedTarget,
}

/// Fail-closed errors from the bounded B3 GATT contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BleB3Error {
    /// Stopping the active scan failed.
    StopScanning(u32),
    /// Starting an ACL connection failed.
    Connect(u32),
    /// Registering the GATT server application failed.
    RegisterServer(u32),
    /// Adding the primary service failed.
    AddService(u32),
    /// Adding the B3 characteristic failed.
    AddCharacteristic(u32),
    /// Adding the CCC descriptor failed.
    AddDescriptor(u32),
    /// Starting the primary service failed.
    StartService(u32),
    /// Registering the GATT client application failed.
    RegisterClient(u32),
    /// Starting service discovery failed.
    DiscoverService(u32),
    /// Starting characteristic discovery failed.
    DiscoverCharacteristic(u32),
    /// Starting descriptor discovery failed.
    DiscoverDescriptor(u32),
    /// Submitting a GATT write request failed.
    Write(u32),
    /// Submitting a notification or indication failed.
    NotifyOrIndicate(u32),
    /// Disconnecting the peer failed.
    Disconnect(u32),
    /// A payload exceeded the bounded B3 event/value capacity.
    ValueTooLong { length: usize },
    /// The definition exceeds the reviewed one-service U3 profile.
    UnsupportedDatabase,
    /// The operation is unavailable outside WS63 target firmware.
    UnsupportedTarget,
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
    /// The vendor stack rejected the advertising stop request synchronously.
    StopAdvertising(u32),
    /// The vendor stack rejected the scan stop request synchronously.
    StopScanning(u32),
    /// This WS63 ABI slice does not expose duplicate filtering yet.
    DuplicateFilteringUnsupported,
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
    /// GATT server callback registration returned a vendor error.
    RegisterGattServerCallbacks(u32),
    /// GATT client callback registration returned a vendor error.
    RegisterGattClientCallbacks(u32),
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
impl BdAddr {
    fn from_typed(address: BluetoothAddress) -> Self {
        Self {
            addr: address.bytes(),
            address_type: match address.address_type() {
                AddressType::Public => 0,
                AddressType::RandomStatic => 1,
            },
        }
    }
}

#[cfg(any(target_arch = "riscv32", test))]
#[repr(C)]
struct GapBleSecurityParameters {
    bondable: u8,
    io_capability: u8,
    secure_connections: u8,
    security_mode: u8,
}

#[cfg(any(target_arch = "riscv32", test))]
impl GapBleSecurityParameters {
    fn from_config(config: SecurityConfig) -> Self {
        Self {
            bondable: u8::from(matches!(config.bonding(), Bonding::Enabled)),
            io_capability: match config.io_capability() {
                IoCapability::DisplayOnly => 0,
                IoCapability::DisplayYesNo => 1,
                IoCapability::KeyboardOnly => 2,
                IoCapability::NoInputNoOutput => 3,
                IoCapability::KeyboardDisplay => 4,
            },
            secure_connections: u8::from(matches!(
                config.requirement(),
                SecurityRequirement::SecureConnectionsAuthenticated
            )),
            security_mode: match config.requirement() {
                SecurityRequirement::Encrypted => 1,
                SecurityRequirement::Authenticated => 2,
                SecurityRequirement::SecureConnectionsAuthenticated => 3,
            },
        }
    }
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct BleAuthInfoEvent {
    ltk_len: u8,
    ltk: [u8; 16],
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

#[cfg(any(target_arch = "riscv32", test))]
#[repr(C)]
#[derive(Clone, Copy)]
struct BtUuid {
    length: u8,
    bytes: [u8; 16],
}

#[cfg(any(target_arch = "riscv32", test))]
impl BtUuid {
    const fn from_u16(value: u16) -> Self {
        let mut bytes = [0; 16];
        bytes[0] = (value >> 8) as u8;
        bytes[1] = value as u8;
        Self { length: 2, bytes }
    }

    const fn from_core(uuid: GattUuid) -> Self {
        match uuid {
            GattUuid::Uuid16(value) => Self::from_u16(value),
            GattUuid::Uuid128(bytes) => Self { length: 16, bytes },
        }
    }

    #[cfg(target_arch = "riscv32")]
    fn as_u16(&self) -> u16 {
        if self.length != 2 {
            return 0;
        }
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }
}

#[cfg(any(target_arch = "riscv32", test))]
const fn map_gatt_permissions(permissions: GattPermissions) -> u8 {
    let mut raw = 0;
    if permissions.contains(GattPermissions::READ) {
        raw |= 0x01;
    }
    if permissions.contains(GattPermissions::WRITE) {
        raw |= 0x02;
    }
    raw
}

#[cfg(any(target_arch = "riscv32", test))]
const fn map_gatt_properties(properties: GattProperties) -> u8 {
    let mut raw = 0;
    if properties.contains(GattProperties::READ) {
        raw |= 0x02;
    }
    if properties.contains(GattProperties::WRITE_WITHOUT_RESPONSE) {
        raw |= 0x04;
    }
    if properties.contains(GattProperties::WRITE) {
        raw |= 0x08;
    }
    if properties.contains(GattProperties::NOTIFY) {
        raw |= 0x10;
    }
    if properties.contains(GattProperties::INDICATE) {
        raw |= 0x20;
    }
    raw
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattsAddCharacteristic {
    uuid: BtUuid,
    permissions: u8,
    properties: u8,
    value_len: u16,
    value: *mut u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattsAddCharacteristicResult {
    declaration_handle: u16,
    value_handle: u16,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattsAddDescriptor {
    uuid: BtUuid,
    permissions: u8,
    value_len: u16,
    value: *mut u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattsWriteRequest {
    request_id: u16,
    handle: u16,
    offset: u16,
    need_response: bool,
    need_authorize: bool,
    is_prepare: bool,
    length: u16,
    value: *const u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattsNotification {
    attr_handle: u16,
    value_len: u16,
    value: *mut u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattcHandleValue {
    handle: u16,
    data_len: u16,
    data: *mut u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattcDiscoverServiceResult {
    start_handle: u16,
    end_handle: u16,
    uuid: BtUuid,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattcDiscoverCharacteristic {
    service_handle: u16,
    uuid: BtUuid,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattcDiscoverCharacteristicResult {
    uuid: BtUuid,
    declaration_handle: u16,
    value_handle: u16,
    properties: u8,
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattcDiscoverDescriptorResult {
    handle: u16,
    uuid: BtUuid,
}

#[cfg(target_arch = "riscv32")]
const _: () = {
    use core::mem::{offset_of, size_of};

    assert!(size_of::<BtUuid>() == 17);
    assert!(size_of::<GattsAddCharacteristic>() == 28);
    assert!(offset_of!(GattsAddCharacteristic, value_len) == 20);
    assert!(offset_of!(GattsAddCharacteristic, value) == 24);
    assert!(size_of::<GattsAddCharacteristicResult>() == 4);
    assert!(size_of::<GattsAddDescriptor>() == 24);
    assert!(offset_of!(GattsAddDescriptor, value) == 20);
    assert!(size_of::<GattsWriteRequest>() == 16);
    assert!(offset_of!(GattsWriteRequest, length) == 10);
    assert!(offset_of!(GattsWriteRequest, value) == 12);
    assert!(size_of::<GattsNotification>() == 8);
    assert!(size_of::<GattcHandleValue>() == 8);
    assert!(size_of::<GattcDiscoverServiceResult>() == 22);
    assert!(size_of::<GattcDiscoverCharacteristic>() == 20);
    assert!(size_of::<GattcDiscoverCharacteristicResult>() == 24);
    assert!(offset_of!(GattcDiscoverCharacteristicResult, declaration_handle) == 18);
    assert!(size_of::<GattcDiscoverDescriptorResult>() == 20);
};

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GapBleCallbacks {
    enable: Option<extern "C" fn(u32)>,
    disable: *const c_void,
    set_advertising_data: Option<extern "C" fn(u8, u32)>,
    set_advertising_parameters: Option<extern "C" fn(u8, u32)>,
    set_scan_parameters: Option<extern "C" fn(u32)>,
    start_advertising: Option<extern "C" fn(u8, u32)>,
    stop_advertising: Option<extern "C" fn(u8, u32)>,
    scan_result: Option<extern "C" fn(*const GapBleScanResult)>,
    connection_state: Option<extern "C" fn(u16, *const BdAddr, u32, u32, u32)>,
    pairing_result: Option<extern "C" fn(u16, *const BdAddr, u32)>,
    read_rssi: *const c_void,
    terminate_advertising: *const c_void,
    authentication_complete:
        Option<extern "C" fn(u16, *const BdAddr, u32, *const BleAuthInfoEvent)>,
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
            stop_advertising: Some(ble_stop_advertising_callback),
            scan_result: Some(ble_scan_result_callback),
            connection_state: Some(ble_connection_state_callback),
            pairing_result: Some(ble_pairing_result_callback),
            read_rssi: core::ptr::null(),
            terminate_advertising: core::ptr::null(),
            authentication_complete: Some(ble_authentication_complete_callback),
            connection_parameters: core::ptr::null(),
            set_data_filter: core::ptr::null(),
            clean_data_filter: core::ptr::null(),
        }
    }
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattsCallbacks {
    add_service: *const c_void,
    add_characteristic: *const c_void,
    add_descriptor: *const c_void,
    start_service: Option<extern "C" fn(u8, u16, u32)>,
    stop_service: *const c_void,
    delete_service: *const c_void,
    read_request: *const c_void,
    write_request: Option<extern "C" fn(u8, u16, *const GattsWriteRequest, u32)>,
    mtu_changed: *const c_void,
    indication_confirm: Option<extern "C" fn(u8, u16, u32)>,
}

#[cfg(target_arch = "riscv32")]
impl GattsCallbacks {
    const fn b3() -> Self {
        Self {
            add_service: core::ptr::null(),
            add_characteristic: core::ptr::null(),
            add_descriptor: core::ptr::null(),
            start_service: Some(ble_gatts_service_started_callback),
            stop_service: core::ptr::null(),
            delete_service: core::ptr::null(),
            read_request: core::ptr::null(),
            write_request: Some(ble_gatts_write_callback),
            mtu_changed: core::ptr::null(),
            indication_confirm: Some(ble_gatts_indication_confirmed_callback),
        }
    }
}

#[cfg(target_arch = "riscv32")]
#[repr(C)]
struct GattcCallbacks {
    discover_service: Option<extern "C" fn(u8, u16, *const GattcDiscoverServiceResult, u32)>,
    discover_service_complete: *const c_void,
    discover_characteristic:
        Option<extern "C" fn(u8, u16, *const GattcDiscoverCharacteristicResult, u32)>,
    discover_characteristic_complete: *const c_void,
    discover_descriptor: Option<extern "C" fn(u8, u16, *const GattcDiscoverDescriptorResult, u32)>,
    discover_descriptor_complete: *const c_void,
    read: *const c_void,
    read_complete: *const c_void,
    write: Option<extern "C" fn(u8, u16, u16, u32)>,
    mtu_changed: *const c_void,
    notification: Option<extern "C" fn(u8, u16, *const GattcHandleValue, u32)>,
    indication: Option<extern "C" fn(u8, u16, *const GattcHandleValue, u32)>,
}

#[cfg(target_arch = "riscv32")]
impl GattcCallbacks {
    const fn b3() -> Self {
        Self {
            discover_service: Some(ble_gattc_service_callback),
            discover_service_complete: core::ptr::null(),
            discover_characteristic: Some(ble_gattc_characteristic_callback),
            discover_characteristic_complete: core::ptr::null(),
            discover_descriptor: Some(ble_gattc_descriptor_callback),
            discover_descriptor_complete: core::ptr::null(),
            read: core::ptr::null(),
            read_complete: core::ptr::null(),
            write: Some(ble_gattc_write_callback),
            mtu_changed: core::ptr::null(),
            notification: Some(ble_gattc_notification_callback),
            indication: Some(ble_gattc_indication_callback),
        }
    }
}

#[cfg(target_arch = "riscv32")]
const _: () = {
    use core::mem::size_of;

    assert!(size_of::<GattsCallbacks>() == 10 * size_of::<usize>());
    assert!(size_of::<GattcCallbacks>() == 12 * size_of::<usize>());
};

#[cfg(target_arch = "riscv32")]
static mut BLE_CALLBACKS: GapBleCallbacks = GapBleCallbacks::b2();
#[cfg(target_arch = "riscv32")]
static mut GATTS_CALLBACKS: GattsCallbacks = GattsCallbacks::b3();
#[cfg(target_arch = "riscv32")]
static mut GATTC_CALLBACKS: GattcCallbacks = GattcCallbacks::b3();

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
    let queue = BLE_EVENT_QUEUE.load(Ordering::Acquire);
    if !queue.is_null() {
        // SAFETY: initialization publishes process-lifetime queue storage.
        let queue = unsafe { &*queue };
        queue.enable_status.store(status, Ordering::Relaxed);
        queue.enable_seen.store(true, Ordering::Release);
    }
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
extern "C" fn ble_stop_advertising_callback(advertising_id: u8, status: u32) {
    push_ble_event(BleB2Event::AdvertisingStopped {
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
extern "C" fn ble_connection_state_callback(
    conn_id: u16,
    address: *const BdAddr,
    state: u32,
    pair_state: u32,
    reason: u32,
) {
    let Some(address) = (unsafe { address.as_ref() }) else {
        return;
    };
    push_ble_event(BleB2Event::ConnectionState {
        conn_id,
        address: address.addr,
        address_type: address.address_type,
        connected: state == 1,
        pair_state,
        reason,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_pairing_result_callback(conn_id: u16, address: *const BdAddr, status: u32) {
    let Some(address) = (unsafe { address.as_ref() }) else {
        return;
    };
    push_ble_event(BleB2Event::PairingComplete {
        conn_id,
        address: address.addr,
        address_type: address.address_type,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_authentication_complete_callback(
    conn_id: u16,
    address: *const BdAddr,
    status: u32,
    authentication: *const BleAuthInfoEvent,
) {
    let Some(address) = (unsafe { address.as_ref() }) else {
        return;
    };
    let ltk_present = unsafe { authentication.as_ref() }.is_some_and(|event| event.ltk_len != 0);
    push_ble_event(BleB2Event::AuthenticationComplete {
        conn_id,
        address: address.addr,
        address_type: address.address_type,
        status,
        ltk_present,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gatts_service_started_callback(server_id: u8, service_handle: u16, status: u32) {
    push_ble_event(BleB2Event::GattServiceStarted {
        server_id,
        service_handle,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gatts_write_callback(
    server_id: u8,
    conn_id: u16,
    request: *const GattsWriteRequest,
    status: u32,
) {
    let Some(request) = (unsafe { request.as_ref() }) else {
        return;
    };
    let mut value = [0; BLE_B3_VALUE_CAPACITY];
    let length = usize::from(request.length).min(value.len());
    if length != 0 && !request.value.is_null() {
        // SAFETY: the vendor owns the request payload for the callback only;
        // copy it before returning so no borrowed pointer escapes.
        unsafe { core::ptr::copy_nonoverlapping(request.value, value.as_mut_ptr(), length) };
    }
    push_ble_event(BleB2Event::GattServerWrite {
        server_id,
        conn_id,
        handle: request.handle,
        status,
        value_len: length as u8,
        value,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gatts_indication_confirmed_callback(server_id: u8, conn_id: u16, status: u32) {
    push_ble_event(BleB2Event::GattIndicationConfirmed {
        server_id,
        conn_id,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gattc_service_callback(
    client_id: u8,
    conn_id: u16,
    service: *const GattcDiscoverServiceResult,
    status: u32,
) {
    let Some(service) = (unsafe { service.as_ref() }) else {
        return;
    };
    push_ble_event(BleB2Event::GattServiceDiscovered {
        client_id,
        conn_id,
        start_handle: service.start_handle,
        end_handle: service.end_handle,
        uuid: service.uuid.as_u16(),
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gattc_characteristic_callback(
    client_id: u8,
    conn_id: u16,
    characteristic: *const GattcDiscoverCharacteristicResult,
    status: u32,
) {
    let Some(characteristic) = (unsafe { characteristic.as_ref() }) else {
        return;
    };
    push_ble_event(BleB2Event::GattCharacteristicDiscovered {
        client_id,
        conn_id,
        declaration_handle: characteristic.declaration_handle,
        value_handle: characteristic.value_handle,
        properties: characteristic.properties,
        uuid: characteristic.uuid.as_u16(),
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gattc_descriptor_callback(
    client_id: u8,
    conn_id: u16,
    descriptor: *const GattcDiscoverDescriptorResult,
    status: u32,
) {
    let Some(descriptor) = (unsafe { descriptor.as_ref() }) else {
        return;
    };
    push_ble_event(BleB2Event::GattDescriptorDiscovered {
        client_id,
        conn_id,
        handle: descriptor.handle,
        uuid: descriptor.uuid.as_u16(),
        status,
    });
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gattc_write_callback(client_id: u8, conn_id: u16, handle: u16, status: u32) {
    push_ble_event(BleB2Event::GattWriteCompleted {
        client_id,
        conn_id,
        handle,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
fn push_gattc_value(
    client_id: u8,
    conn_id: u16,
    raw: *const GattcHandleValue,
    status: u32,
    indication: bool,
) {
    let Some(raw) = (unsafe { raw.as_ref() }) else {
        return;
    };
    let mut value = [0; BLE_B3_VALUE_CAPACITY];
    let length = usize::from(raw.data_len).min(value.len());
    if length != 0 && !raw.data.is_null() {
        // SAFETY: callback payload storage is vendor-owned for this callback;
        // copy it into the bounded event before returning.
        unsafe { core::ptr::copy_nonoverlapping(raw.data, value.as_mut_ptr(), length) };
    }
    let event = if indication {
        BleB2Event::GattIndication {
            client_id,
            conn_id,
            handle: raw.handle,
            status,
            value_len: length as u8,
            value,
        }
    } else {
        BleB2Event::GattNotification {
            client_id,
            conn_id,
            handle: raw.handle,
            status,
            value_len: length as u8,
            value,
        }
    };
    push_ble_event(event);
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gattc_notification_callback(
    client_id: u8,
    conn_id: u16,
    value: *const GattcHandleValue,
    status: u32,
) {
    push_gattc_value(client_id, conn_id, value, status, false);
}

#[cfg(target_arch = "riscv32")]
extern "C" fn ble_gattc_indication_callback(
    client_id: u8,
    conn_id: u16,
    value: *const GattcHandleValue,
    status: u32,
) {
    push_gattc_value(client_id, conn_id, value, status, true);
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
    fn gap_ble_stop_adv(advertising_id: u8) -> u32;
    fn gap_ble_set_scan_parameters(parameters: *const GapBleScanParameters) -> u32;
    fn gap_ble_start_scan() -> u32;
    fn gap_ble_stop_scan() -> u32;
    fn gap_ble_connect_remote_device(address: *const BdAddr) -> u32;
    fn gap_ble_disconnect_remote_device(address: *const BdAddr) -> u32;
    fn gap_ble_set_sec_param(parameters: *mut GapBleSecurityParameters) -> u32;
    fn gap_ble_pair_remote_device(address: *const BdAddr) -> u32;
    fn gap_ble_get_pair_state(address: *const BdAddr, state: *mut u32) -> u32;
    fn gap_ble_remove_pair(address: *const BdAddr) -> u32;
    fn gatts_register_callbacks(callbacks: *mut GattsCallbacks) -> u32;
    fn gatts_register_server(app_uuid: *mut BtUuid, server_id: *mut u8) -> u32;
    fn gatts_add_service_sync(
        server_id: u8,
        service_uuid: *mut BtUuid,
        is_primary: bool,
        handle: *mut u16,
    ) -> u32;
    fn gatts_add_characteristic_sync(
        server_id: u8,
        service_handle: u16,
        characteristic: *mut GattsAddCharacteristic,
        result: *mut GattsAddCharacteristicResult,
    ) -> u32;
    fn gatts_add_descriptor_sync(
        server_id: u8,
        service_handle: u16,
        descriptor: *mut GattsAddDescriptor,
        handle: *mut u16,
    ) -> u32;
    fn gatts_start_service(server_id: u8, service_handle: u16) -> u32;
    fn gatts_notify_indicate(
        server_id: u8,
        conn_id: u16,
        notification: *mut GattsNotification,
    ) -> u32;
    fn gattc_register_callbacks(callbacks: *mut GattcCallbacks) -> u32;
    fn gattc_register_client(app_uuid: *mut BtUuid, client_id: *mut u8) -> u32;
    fn gattc_discovery_service(client_id: u8, conn_id: u16, uuid: *mut BtUuid) -> u32;
    fn gattc_discovery_character(
        client_id: u8,
        conn_id: u16,
        parameters: *mut GattcDiscoverCharacteristic,
    ) -> u32;
    fn gattc_discovery_descriptor(client_id: u8, conn_id: u16, declaration_handle: u16) -> u32;
    fn gattc_write_req(client_id: u8, conn_id: u16, value: *mut GattcHandleValue) -> u32;
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
        Some(resources.pke),
        resources.trng,
        storage.crypto,
    )
    .map_err(|_| BleB1InitError::Crypto)?;
    crate::log_emit(b"RFDBG_BLE_B1_CRYPTO_OK\r\n");
    #[cfg(feature = "ble-init-diag")]
    if crate::ble_compat::ble_crypto_compat_self_test() {
        crate::log_emit(b"RFDBG_BLE_U5B_CRYPTO_COMPAT_OK\r\n");
    } else {
        crate::log_emit(b"RFDBG_BLE_U5B_CRYPTO_COMPAT_ERR\r\n");
        return Err(BleB1InitError::Crypto);
    }

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
    let callback_status =
        unsafe { gatts_register_callbacks(core::ptr::addr_of_mut!(GATTS_CALLBACKS)) };
    if callback_status != 0 {
        return Err(BleB1InitError::RegisterGattServerCallbacks(callback_status));
    }
    let callback_status =
        unsafe { gattc_register_callbacks(core::ptr::addr_of_mut!(GATTC_CALLBACKS)) };
    if callback_status != 0 {
        return Err(BleB1InitError::RegisterGattClientCallbacks(callback_status));
    }
    crate::log_emit(b"RFDBG_BLE_B3_CALLBACKS_OK\r\n");

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
        operations: storage.operations,
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
    extern crate std;

    use super::*;
    use std::boxed::Box;

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
    fn typed_advertising_payload_moves_into_backend_storage() {
        let payload = hisi_rf_core::ble::AdvertisingPayload::try_from_slice(b"u2-payload").unwrap();
        let interval = hisi_rf_core::ble::AdvertisingInterval::try_from_units(0x20).unwrap();
        let mut storage = BleB2OperationStorage::new();
        {
            let config = AdvertisingConfig::new(
                hisi_rf_core::ble::AdvertisingTiming::try_new(interval, interval).unwrap(),
                hisi_rf_core::ble::AdvertisingChannels::ALL,
                payload,
            );
            storage.store_advertising_payload(&config);
        }

        assert_eq!(storage.advertising_len, 10);
        assert_eq!(&storage.advertising_data[..10], b"u2-payload");
    }

    #[test]
    fn typed_gatt_values_and_bits_match_the_ws63_abi() {
        let mut storage = BleB2OperationStorage::new();
        storage.store_gatt_values(b"value", &[1, 2]).unwrap();
        assert_eq!(&storage.gatt_characteristic_value[..5], b"value");
        assert_eq!(&storage.gatt_descriptor_value[..2], &[1, 2]);
        assert_eq!(
            map_gatt_permissions(GattPermissions::READ.union(GattPermissions::WRITE)),
            0x03
        );
        assert_eq!(
            map_gatt_properties(
                GattProperties::READ
                    .union(GattProperties::WRITE)
                    .union(GattProperties::NOTIFY)
                    .union(GattProperties::INDICATE)
            ),
            0x3a
        );
        assert_eq!(
            BtUuid::from_core(GattUuid::Uuid16(0xabcd)).bytes[..2],
            [0xab, 0xcd]
        );
        assert_eq!(
            storage.store_gatt_values(&[0; BLE_B3_VALUE_CAPACITY + 1], &[]),
            Err(BleB3Error::ValueTooLong {
                length: BLE_B3_VALUE_CAPACITY + 1
            })
        );
    }

    #[test]
    fn typed_security_policy_maps_to_the_reviewed_ws63_gap_abi() {
        let parameters = GapBleSecurityParameters::from_config(SecurityConfig::new(
            Bonding::Enabled,
            IoCapability::NoInputNoOutput,
            SecurityRequirement::SecureConnectionsAuthenticated,
        ));
        assert_eq!(core::mem::size_of::<GapBleSecurityParameters>(), 4);
        assert_eq!(parameters.bondable, 1);
        assert_eq!(parameters.io_capability, 3);
        assert_eq!(parameters.secure_connections, 1);
        assert_eq!(parameters.security_mode, 3);
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

    #[test]
    fn enable_status_does_not_consume_the_public_event() {
        let queue = BleEventQueue::new();
        assert_eq!(queue.enable_status(), None);
        queue.enable_status.store(0, Ordering::Relaxed);
        queue.enable_seen.store(true, Ordering::Release);
        queue.push(BleB2Event::Enabled { status: 0 });
        assert_eq!(queue.enable_status(), Some(0));
        assert_eq!(queue.pop(), Some(BleB2Event::Enabled { status: 0 }));
        assert_eq!(queue.enable_status(), Some(0));
    }

    #[test]
    fn b3_payload_event_is_copied_through_the_bounded_queue() {
        let queue = BleEventQueue::new();
        let mut value = [0; BLE_B3_VALUE_CAPACITY];
        value[..2].copy_from_slice(b"B3");
        let event = BleB2Event::GattNotification {
            client_id: 1,
            conn_id: 2,
            handle: 3,
            status: 0,
            value_len: 2,
            value,
        };
        queue.push(event);
        assert_eq!(queue.pop(), Some(event));
        assert_eq!(queue.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn host_stop_operations_fail_closed() {
        let events = Box::leak(Box::new(BleEventQueue::new()));
        let operations = Box::leak(Box::new(BleB2OperationStorage::new()));
        let mut controller = BleB1Controller {
            _efuse: unsafe { Efuse::steal() },
            events,
            operations,
        };
        assert_eq!(
            controller.stop_advertising(),
            Err(BleB2Error::UnsupportedTarget)
        );
        assert_eq!(
            controller.stop_scanning(),
            Err(BleB2Error::UnsupportedTarget)
        );
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
    assert!(core::mem::size_of::<GapBleSecurityParameters>() == 4);
    assert!(core::mem::size_of::<BleAuthInfoEvent>() == 17);
    assert!(core::mem::size_of::<GapBleCallbacks>() == 64);
};
