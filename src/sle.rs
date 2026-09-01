//! Internal WS63 SLE S1 initialization and bounded announce/seek slice.

use core::cell::{RefCell, UnsafeCell};
#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;
use core::mem::MaybeUninit;
#[cfg(any(target_arch = "riscv32", test))]
use core::num::{NonZeroU32, NonZeroUsize};

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_hal::peripherals::{Efuse, Km, Spacc, Trng};
use hisi_rf_core::control::EventQueueDiagnostics;
use hisi_rf_core::sle::{AnnounceConfig, SeekConfig, SsapServerDefinition};
#[cfg(any(target_arch = "riscv32", test))]
use hisi_rf_core::sle::{SsapOperations, SsapPermissions, SsapUuid};
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
use ws63_radio_sys::ssap::Uuid;
#[cfg(target_arch = "riscv32")]
use ws63_radio_sys::ssap::{
    ClientCallbacks, ClientHandleValue, ClientWriteParameters, ClientWriteResult, ExchangeInfo,
    FindServiceResult, FindStructureParameters, FindStructureResult, NotifyIndicate,
    ServerCallbacks, ServerDescriptorInfo, ServerPropertyInfo, ServerReadRequest,
    ServerWriteRequest,
};

/// Caller-owned heap shared by the SLE host, controller, and RTOS objects.
pub const SLE_S1_ARENA_BYTES: usize = crate::WS63_SHARED_RADIO_ARENA_BYTES;
/// Smallest stack in the pinned heterogeneous SLE S1 task profile.
pub const SLE_S1_MINIMUM_TASK_STACK_BYTES: usize = 512;
/// Dynamic task slots reserved by the pinned SLE host/controller profile.
pub const SLE_S1_TASK_COUNT: usize = 4;
/// Total stack bytes reserved by the pinned heterogeneous SLE task profile.
pub const SLE_S1_TASK_STACK_BYTES: usize = 10_240;
/// Vendor lifecycle events retained by the SLE backend queue.
pub const SLE_S1_EVENT_CAPACITY: usize = 32;
/// Maximum payload copied from one vendor seek callback.
pub const SLE_S1_EVENT_DATA_CAPACITY: usize = 64;

const EVENT_CAPACITY: usize = SLE_S1_EVENT_CAPACITY;
const SLE_S3_VALUE_CAPACITY: usize = 64;

#[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
struct SleS1OperationStorage {
    announce_data: [u8; SLE_S1_EVENT_DATA_CAPACITY],
    announce_len: u16,
    seek_response_data: [u8; SLE_S1_EVENT_DATA_CAPACITY],
    seek_response_len: u16,
    ssap_property_value: [u8; SLE_S3_VALUE_CAPACITY],
    ssap_descriptor_value: [u8; SLE_S3_VALUE_CAPACITY],
    #[cfg(target_arch = "riscv32")]
    announce_parameters: AnnounceParameters,
    #[cfg(target_arch = "riscv32")]
    seek_parameters: SeekParameters,
}

impl SleS1OperationStorage {
    const fn new() -> Self {
        Self {
            announce_data: [0; SLE_S1_EVENT_DATA_CAPACITY],
            announce_len: 0,
            seek_response_data: [0; SLE_S1_EVENT_DATA_CAPACITY],
            seek_response_len: 0,
            ssap_property_value: [0; SLE_S3_VALUE_CAPACITY],
            ssap_descriptor_value: [0; SLE_S3_VALUE_CAPACITY],
            #[cfg(target_arch = "riscv32")]
            announce_parameters: AnnounceParameters {
                announce_handle: 1,
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
            },
            #[cfg(target_arch = "riscv32")]
            seek_parameters: SeekParameters {
                own_address_type: 0,
                filter_duplicates: 0,
                filter_policy: 0,
                phys: 1,
                seek_type: [0, 0, 0],
                interval: [100, 0, 0],
                window: [100, 0, 0],
            },
        }
    }

    #[cfg_attr(not(any(target_arch = "riscv32", test)), allow(dead_code))]
    fn store_announce_payloads(&mut self, config: &AnnounceConfig) {
        let data = config.data().as_bytes();
        let seek_response = config.seek_response().as_bytes();
        self.announce_data[..data.len()].copy_from_slice(data);
        self.announce_len = data.len() as u16;
        self.seek_response_data[..seek_response.len()].copy_from_slice(seek_response);
        self.seek_response_len = seek_response.len() as u16;
    }

    #[cfg(any(target_arch = "riscv32", test))]
    fn store_ssap_values(
        &mut self,
        property: &[u8],
        descriptor: &[u8],
    ) -> Result<(), SleS1OperationError> {
        if property.len() > SLE_S3_VALUE_CAPACITY {
            return Err(SleS1OperationError::SsapValueTooLong {
                length: property.len(),
            });
        }
        if descriptor.len() > SLE_S3_VALUE_CAPACITY {
            return Err(SleS1OperationError::SsapValueTooLong {
                length: descriptor.len(),
            });
        }
        self.ssap_property_value.fill(0);
        self.ssap_property_value[..property.len()].copy_from_slice(property);
        self.ssap_descriptor_value.fill(0);
        self.ssap_descriptor_value[..descriptor.len()].copy_from_slice(descriptor);
        Ok(())
    }
}
#[cfg(any(target_arch = "riscv32", test))]
const TASK_COUNT: usize = SLE_S1_TASK_COUNT;
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
    PairComplete {
        connection_id: u16,
        address: Address,
        status: u32,
    },
    AuthenticationComplete {
        connection_id: u16,
        address: Address,
        status: u32,
    },
    SsapServiceStarted {
        server_id: u8,
        service_handle: u16,
        status: u32,
    },
    SsapExchangeComplete {
        client_id: u8,
        connection_id: u16,
        mtu_size: u32,
        version: u16,
        status: u32,
    },
    SsapServiceFound {
        client_id: u8,
        connection_id: u16,
        start_handle: u16,
        end_handle: u16,
        uuid: Uuid,
        status: u32,
    },
    SsapDiscoveryComplete {
        client_id: u8,
        connection_id: u16,
        status: u32,
    },
    SsapReadRequested {
        server_id: u8,
        connection_id: u16,
        request_id: u16,
        handle: u16,
        property_type: u8,
        status: u32,
    },
    SsapWriteComplete {
        client_id: u8,
        connection_id: u16,
        handle: u16,
        property_type: u8,
        status: u32,
    },
    SsapWriteRequested {
        server_id: u8,
        connection_id: u16,
        request_id: u16,
        handle: u16,
        property_type: u8,
        status: u32,
    },
    SsapNotification {
        client_id: u8,
        connection_id: u16,
        handle: u16,
        property_type: u8,
        status: u32,
        data_len: u8,
        truncated: bool,
        data: [u8; SLE_S1_EVENT_DATA_CAPACITY],
    },
}

impl SleS1Event {
    const EMPTY: Self = Self::Enabled { status: u32::MAX };
}

struct EventRing {
    events: [SleS1Event; EVENT_CAPACITY],
    head: usize,
    len: usize,
    accepted: u32,
    consumed: u32,
    dropped: u32,
    high_water: usize,
}

impl EventRing {
    const fn new() -> Self {
        Self {
            events: [SleS1Event::EMPTY; EVENT_CAPACITY],
            head: 0,
            len: 0,
            accepted: 0,
            consumed: 0,
            dropped: 0,
            high_water: 0,
        }
    }
}

struct EventQueue {
    ring: critical_section::Mutex<RefCell<EventRing>>,
    enable_seen: AtomicBool,
    enable_status: AtomicU32,
}

impl EventQueue {
    const fn new() -> Self {
        Self {
            ring: critical_section::Mutex::new(RefCell::new(EventRing::new())),
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
    fn push(&self, event: SleS1Event) {
        critical_section::with(|cs| {
            let mut ring = self.ring.borrow(cs).borrow_mut();
            if ring.len == EVENT_CAPACITY {
                ring.dropped = ring.dropped.saturating_add(1);
                return;
            }
            let index = (ring.head + ring.len) % EVENT_CAPACITY;
            ring.events[index] = event;
            ring.len += 1;
            ring.accepted = ring.accepted.saturating_add(1);
            ring.high_water = ring.high_water.max(ring.len);
        });
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
            ring.consumed = ring.consumed.saturating_add(1);
            Some(event)
        })
    }

    fn diagnostics(&self) -> EventQueueDiagnostics {
        critical_section::with(|cs| {
            let ring = self.ring.borrow(cs).borrow();
            EventQueueDiagnostics {
                accepted: ring.accepted,
                consumed: ring.consumed,
                dropped: ring.dropped,
                pending: ring.len,
                high_water: ring.high_water,
            }
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
    operations: StaticCell<SleS1OperationStorage>,
}

impl SleS1ControlStorage {
    pub const fn new() -> Self {
        Self {
            crypto: StaticCell::new(),
            events: StaticCell::new(),
            operations: StaticCell::new(),
        }
    }
}

impl Default for SleS1ControlStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SleS1ControlStorage {
    #[cfg(target_arch = "riscv32")]
    pub(crate) fn install_coexisting(&'static self) -> InstalledSleS1Storage {
        InstalledSleS1Storage {
            crypto: None,
            events: self.events.init(EventQueue::new()),
            operations: self.operations.init(SleS1OperationStorage::new()),
        }
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
            crypto: Some(self.control.crypto.init(Ws63CryptoStorage::new())),
            events: self.control.events.init(EventQueue::new()),
            operations: self.control.operations.init(SleS1OperationStorage::new()),
        })
    }
}

/// Proof that the SLE S1 arena and control storage were installed.
pub struct InstalledSleS1Storage {
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    crypto: Option<&'static mut Ws63CryptoStorage>,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    events: &'static EventQueue,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    operations: &'static mut SleS1OperationStorage,
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
    _efuse: Option<Efuse<'static>>,
    events: &'static EventQueue,
    #[cfg_attr(not(target_arch = "riscv32"), allow(dead_code))]
    operations: &'static mut SleS1OperationStorage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SsapServerHandles {
    pub server_id: u8,
    pub service_handle: u16,
    pub property_handle: u16,
}

impl SleS1Controller {
    pub fn next_event(&mut self) -> Option<SleS1Event> {
        self.events.pop()
    }

    pub fn dropped_events(&self) -> u32 {
        self.event_diagnostics().dropped
    }

    /// Return one linearizable snapshot of the bounded vendor event queue.
    #[doc(hidden)]
    pub fn event_diagnostics(&self) -> EventQueueDiagnostics {
        self.events.diagnostics()
    }

    /// Return the asynchronous vendor enable result without consuming its event.
    #[doc(hidden)]
    pub fn enable_status(&self) -> Option<u32> {
        self.events.enable_status()
    }

    /// Start announcing from an owned, validated U2 request.
    ///
    /// Payloads and raw parameter blocks are copied into process-lifetime
    /// backend storage before the vendor stack receives their pointers.
    #[cfg(target_arch = "riscv32")]
    pub fn start_announce_config(
        &mut self,
        config: AnnounceConfig,
    ) -> Result<(), SleS1OperationError> {
        self.operations.store_announce_payloads(&config);
        let timing = config.timing();
        self.operations.announce_parameters.announce_interval_min = timing.minimum().as_units();
        self.operations.announce_parameters.announce_interval_max = timing.maximum().as_units();
        self.operations.announce_parameters.announce_channel_map = config.channels().bits();
        self.start_announce_stored()
    }

    /// Start seeking from an owned, validated U2 request.
    #[cfg(target_arch = "riscv32")]
    pub fn start_seek_config(&mut self, config: SeekConfig) -> Result<(), SleS1OperationError> {
        let timing = config.timing();
        self.operations.seek_parameters.filter_duplicates = u8::from(config.filter_duplicates());
        self.operations.seek_parameters.interval[0] = timing.interval().as_units();
        self.operations.seek_parameters.window[0] = timing.window().as_units();
        self.start_seek_stored()
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
        let data = hisi_rf_core::sle::AnnouncePayload::try_from_slice(announce_data).ok_or(
            SleS1OperationError::AnnounceDataTooLong {
                length: announce_data.len(),
            },
        )?;
        let seek_response = hisi_rf_core::sle::AnnouncePayload::try_from_slice(seek_response_data)
            .ok_or(SleS1OperationError::SeekResponseDataTooLong {
                length: seek_response_data.len(),
            })?;
        let interval = hisi_rf_core::sle::AnnounceInterval::try_from_units(0xc8).unwrap();
        self.start_announce_config(AnnounceConfig::new(
            hisi_rf_core::sle::AnnounceTiming::try_new(interval, interval).unwrap(),
            hisi_rf_core::sle::AnnounceChannels::ALL,
            data,
            seek_response,
        ))
    }

    #[cfg(target_arch = "riscv32")]
    fn start_announce_stored(&mut self) -> Result<(), SleS1OperationError> {
        const HANDLE: u8 = 1;
        let status = unsafe {
            ws63_radio_sys::sle::sle_set_announce_param(
                HANDLE,
                &self.operations.announce_parameters,
            )
        };
        if status != 0 {
            return Err(SleS1OperationError::SetAnnounceParameters(status));
        }
        let data = AnnounceData {
            announce_data_len: self.operations.announce_len,
            seek_response_data_len: self.operations.seek_response_len,
            announce_data: self.operations.announce_data.as_mut_ptr(),
            seek_response_data: self.operations.seek_response_data.as_mut_ptr(),
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

    /// Stop announce handle one.
    #[cfg(target_arch = "riscv32")]
    pub fn stop_announce(&mut self) -> Result<(), SleS1OperationError> {
        let status = unsafe { ws63_radio_sys::sle::sle_stop_announce(1) };
        if status != 0 {
            return Err(SleS1OperationError::StopAnnounce(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn start_seek(&mut self) -> Result<(), SleS1OperationError> {
        let interval = hisi_rf_core::sle::SeekInterval::try_from_units(100).unwrap();
        self.start_seek_config(SeekConfig::new(
            hisi_rf_core::sle::SeekTiming::try_new(interval, interval).unwrap(),
            false,
        ))
    }

    #[cfg(target_arch = "riscv32")]
    fn start_seek_stored(&mut self) -> Result<(), SleS1OperationError> {
        let status = unsafe {
            ws63_radio_sys::sle::sle_set_seek_param(&raw mut self.operations.seek_parameters)
        };
        if status != 0 {
            return Err(SleS1OperationError::SetSeekParameters(status));
        }
        let status = unsafe { ws63_radio_sys::sle::sle_start_seek() };
        if status != 0 {
            return Err(SleS1OperationError::StartSeek(status));
        }
        Ok(())
    }

    #[cfg(not(target_arch = "riscv32"))]
    pub fn start_announce_config(&mut self, _: AnnounceConfig) -> Result<(), SleS1OperationError> {
        Err(SleS1OperationError::UnsupportedTarget)
    }

    #[cfg(not(target_arch = "riscv32"))]
    pub fn start_seek_config(&mut self, _: SeekConfig) -> Result<(), SleS1OperationError> {
        Err(SleS1OperationError::UnsupportedTarget)
    }

    #[cfg(not(target_arch = "riscv32"))]
    pub fn stop_announce(&mut self) -> Result<(), SleS1OperationError> {
        Err(SleS1OperationError::UnsupportedTarget)
    }

    #[cfg(not(target_arch = "riscv32"))]
    pub fn stop_seek(&mut self) -> Result<(), SleS1OperationError> {
        Err(SleS1OperationError::UnsupportedTarget)
    }

    /// Host builds cannot invoke the WS63 typed SSAP implementation.
    #[cfg(not(target_arch = "riscv32"))]
    pub fn configure_ssap_server_definition(
        &mut self,
        _: SsapServerDefinition,
    ) -> Result<SsapServerHandles, SleS1OperationError> {
        Err(SleS1OperationError::UnsupportedTarget)
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

    #[cfg(target_arch = "riscv32")]
    pub fn pair(&mut self, address: &Address) -> Result<(), SleS1OperationError> {
        let status = unsafe { ws63_radio_sys::sle::sle_pair_remote_device(address) };
        if status != 0 {
            return Err(SleS1OperationError::Pair(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn configure_ssap_server(
        &mut self,
        property_value: &'static mut [u8],
        descriptor_value: &'static mut [u8],
    ) -> Result<SsapServerHandles, SleS1OperationError> {
        Self::configure_ssap_server_raw(
            short_uuid(0),
            short_uuid(0x060b),
            short_uuid(0x1122),
            ws63_radio_sys::ssap::PERMISSION_READ_WRITE,
            ws63_radio_sys::ssap::OPERATE_READ_NOTIFY,
            property_value,
            short_uuid(0),
            ws63_radio_sys::ssap::PERMISSION_READ_WRITE,
            ws63_radio_sys::ssap::OPERATE_READ_WRITE,
            descriptor_value,
        )
    }

    /// Configure one static SSAP database within the reviewed WS63 U3 capacity.
    #[cfg(target_arch = "riscv32")]
    pub fn configure_ssap_server_definition(
        &mut self,
        definition: SsapServerDefinition,
    ) -> Result<SsapServerHandles, SleS1OperationError> {
        let [service] = definition.services() else {
            return Err(SleS1OperationError::UnsupportedDatabase);
        };
        let [property] = service.properties() else {
            return Err(SleS1OperationError::UnsupportedDatabase);
        };
        let [descriptor] = property.descriptors() else {
            return Err(SleS1OperationError::UnsupportedDatabase);
        };
        if property.maximum_len() as usize > SLE_S3_VALUE_CAPACITY
            || descriptor.maximum_len() as usize > SLE_S3_VALUE_CAPACITY
        {
            return Err(SleS1OperationError::UnsupportedDatabase);
        }
        self.operations
            .store_ssap_values(property.initial_value(), descriptor.initial_value())?;
        let property_len = property.initial_value().len();
        let descriptor_len = descriptor.initial_value().len();

        Self::configure_ssap_server_raw(
            ssap_uuid(definition.app_uuid()),
            ssap_uuid(service.uuid()),
            ssap_uuid(property.uuid()),
            map_ssap_permissions(property.permissions()),
            map_ssap_operations(property.operations()),
            &mut self.operations.ssap_property_value[..property_len],
            ssap_uuid(descriptor.uuid()),
            map_ssap_permissions(descriptor.permissions()),
            map_ssap_descriptor_operations(descriptor.permissions()),
            &mut self.operations.ssap_descriptor_value[..descriptor_len],
        )
    }

    #[cfg(target_arch = "riscv32")]
    #[allow(clippy::too_many_arguments)]
    fn configure_ssap_server_raw(
        mut app_uuid: Uuid,
        mut service_uuid: Uuid,
        property_uuid: Uuid,
        property_permissions: u16,
        property_operations: u32,
        property_value: &mut [u8],
        descriptor_uuid: Uuid,
        descriptor_permissions: u16,
        descriptor_operations: u32,
        descriptor_value: &mut [u8],
    ) -> Result<SsapServerHandles, SleS1OperationError> {
        let mut server_id = 0;
        let status = unsafe {
            ws63_radio_sys::ssap::ssaps_register_server(&raw mut app_uuid, &raw mut server_id)
        };
        if status != 0 {
            return Err(SleS1OperationError::RegisterSsapServer(status));
        }
        let mut service_handle = 0;
        let status = unsafe {
            ws63_radio_sys::ssap::ssaps_add_service_sync(
                server_id,
                &raw mut service_uuid,
                true,
                &raw mut service_handle,
            )
        };
        if status != 0 {
            return Err(SleS1OperationError::AddSsapService(status));
        }
        let value_len =
            property_value
                .len()
                .try_into()
                .map_err(|_| SleS1OperationError::SsapValueTooLong {
                    length: property_value.len(),
                })?;
        let mut property = ServerPropertyInfo {
            uuid: property_uuid,
            permissions: property_permissions,
            operate_indication: property_operations,
            value_len,
            value: property_value.as_mut_ptr(),
        };
        let mut property_handle = 0;
        let status = unsafe {
            ws63_radio_sys::ssap::ssaps_add_property_sync(
                server_id,
                service_handle,
                &raw mut property,
                &raw mut property_handle,
            )
        };
        if status != 0 {
            return Err(SleS1OperationError::AddSsapProperty(status));
        }
        let descriptor_len = descriptor_value.len().try_into().map_err(|_| {
            SleS1OperationError::SsapValueTooLong {
                length: descriptor_value.len(),
            }
        })?;
        let mut descriptor = ServerDescriptorInfo {
            uuid: descriptor_uuid,
            permissions: descriptor_permissions,
            operate_indication: descriptor_operations,
            descriptor_type: ws63_radio_sys::ssap::DESCRIPTOR_USER_DESCRIPTION,
            value_len: descriptor_len,
            value: descriptor_value.as_mut_ptr(),
        };
        let status = unsafe {
            ws63_radio_sys::ssap::ssaps_add_descriptor_sync(
                server_id,
                service_handle,
                property_handle,
                &raw mut descriptor,
            )
        };
        if status != 0 {
            return Err(SleS1OperationError::AddSsapDescriptor(status));
        }
        let mut exchange = ExchangeInfo {
            mtu_size: 1_500,
            version: 1,
        };
        let status = unsafe { ws63_radio_sys::ssap::ssaps_set_info(server_id, &raw mut exchange) };
        if status != 0 {
            return Err(SleS1OperationError::SetSsapInfo(status));
        }
        let status =
            unsafe { ws63_radio_sys::ssap::ssaps_start_service(server_id, service_handle) };
        if status != 0 {
            return Err(SleS1OperationError::StartSsapService(status));
        }
        Ok(SsapServerHandles {
            server_id,
            service_handle,
            property_handle,
        })
    }

    #[cfg(target_arch = "riscv32")]
    pub fn notify_ssap(
        &mut self,
        handles: SsapServerHandles,
        connection_id: u16,
        data: &'static mut [u8],
    ) -> Result<(), SleS1OperationError> {
        let value_len = data
            .len()
            .try_into()
            .map_err(|_| SleS1OperationError::SsapValueTooLong { length: data.len() })?;
        let mut parameters = NotifyIndicate {
            handle: handles.property_handle,
            property_type: ws63_radio_sys::ssap::PROPERTY_TYPE_VALUE,
            value_len,
            value: data.as_mut_ptr(),
        };
        let status = unsafe {
            ws63_radio_sys::ssap::ssaps_notify_indicate(
                handles.server_id,
                connection_id,
                &raw mut parameters,
            )
        };
        if status != 0 {
            return Err(SleS1OperationError::NotifySsap(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn exchange_ssap_info(&mut self, connection_id: u16) -> Result<(), SleS1OperationError> {
        let mut exchange = ExchangeInfo {
            mtu_size: 1_500,
            version: 1,
        };
        let status = unsafe {
            ws63_radio_sys::ssap::ssapc_exchange_info_req(1, connection_id, &raw mut exchange)
        };
        if status != 0 {
            return Err(SleS1OperationError::ExchangeSsapInfo(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn discover_ssap_services(
        &mut self,
        connection_id: u16,
    ) -> Result<(), SleS1OperationError> {
        let mut parameters = FindStructureParameters {
            find_type: ws63_radio_sys::ssap::FIND_TYPE_PRIMARY_SERVICE,
            start_handle: 1,
            end_handle: u16::MAX,
            uuid: Uuid {
                len: 0,
                bytes: [0; ws63_radio_sys::ssap::UUID_BYTES],
            },
            reserved: 0,
        };
        let status = unsafe {
            ws63_radio_sys::ssap::ssapc_find_structure(0, connection_id, &raw mut parameters)
        };
        if status != 0 {
            return Err(SleS1OperationError::DiscoverSsapServices(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn read_ssap(
        &mut self,
        connection_id: u16,
        handle: u16,
    ) -> Result<(), SleS1OperationError> {
        let status = unsafe {
            ws63_radio_sys::ssap::ssapc_read_req(
                0,
                connection_id,
                handle,
                ws63_radio_sys::ssap::PROPERTY_TYPE_VALUE,
            )
        };
        if status != 0 {
            return Err(SleS1OperationError::ReadSsap(status));
        }
        Ok(())
    }

    #[cfg(target_arch = "riscv32")]
    pub fn write_ssap(
        &mut self,
        connection_id: u16,
        handle: u16,
        data: &'static mut [u8],
    ) -> Result<(), SleS1OperationError> {
        let data_len = data
            .len()
            .try_into()
            .map_err(|_| SleS1OperationError::SsapValueTooLong { length: data.len() })?;
        let mut parameters = ClientWriteParameters {
            handle,
            property_type: ws63_radio_sys::ssap::PROPERTY_TYPE_VALUE,
            data_len,
            data: data.as_mut_ptr(),
        };
        let status =
            unsafe { ws63_radio_sys::ssap::ssapc_write_req(0, connection_id, &raw mut parameters) };
        if status != 0 {
            return Err(SleS1OperationError::WriteSsap(status));
        }
        Ok(())
    }
}

#[cfg(any(target_arch = "riscv32", test))]
fn short_uuid(value: u16) -> Uuid {
    let mut bytes = [
        0x37, 0xbe, 0xa8, 0x80, 0xfc, 0x70, 0x11, 0xea, 0xb7, 0x20, 0, 0, 0, 0, 0, 0,
    ];
    bytes[14..].copy_from_slice(&value.to_le_bytes());
    Uuid { len: 2, bytes }
}

#[cfg(any(target_arch = "riscv32", test))]
fn ssap_uuid(uuid: SsapUuid) -> Uuid {
    match uuid {
        SsapUuid::Uuid16(value) => short_uuid(value),
        SsapUuid::Uuid128(bytes) => Uuid { len: 16, bytes },
    }
}

#[cfg(any(target_arch = "riscv32", test))]
const fn map_ssap_permissions(permissions: SsapPermissions) -> u16 {
    let mut raw = 0;
    if permissions.contains(SsapPermissions::READ) {
        raw |= 0x01;
    }
    if permissions.contains(SsapPermissions::WRITE) {
        raw |= 0x02;
    }
    raw
}

#[cfg(any(target_arch = "riscv32", test))]
const fn map_ssap_operations(operations: SsapOperations) -> u32 {
    let mut raw = 0;
    if operations.contains(SsapOperations::READ) {
        raw |= 0x01;
    }
    if operations.contains(SsapOperations::WRITE) {
        raw |= 0x04;
    }
    if operations.contains(SsapOperations::NOTIFY) {
        raw |= 0x08;
    }
    if operations.contains(SsapOperations::INDICATE) {
        raw |= 0x10;
    }
    raw
}

#[cfg(any(target_arch = "riscv32", test))]
const fn map_ssap_descriptor_operations(permissions: SsapPermissions) -> u32 {
    let mut raw = 0;
    if permissions.contains(SsapPermissions::READ) {
        raw |= 0x01;
    }
    if permissions.contains(SsapPermissions::WRITE) {
        raw |= 0x04;
    }
    raw
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SleS1OperationError {
    AnnounceDataTooLong {
        length: usize,
    },
    SeekResponseDataTooLong {
        length: usize,
    },
    SetAnnounceParameters(u32),
    SetAnnounceData(u32),
    StartAnnounce(u32),
    StopAnnounce(u32),
    SetSeekParameters(u32),
    StartSeek(u32),
    StopSeek(u32),
    SetLocalAddress(u32),
    SetConnectionParameters(u32),
    Connect(u32),
    Disconnect(u32),
    Pair(u32),
    SsapValueTooLong {
        length: usize,
    },
    /// The definition exceeds the reviewed one-service U3 profile.
    UnsupportedDatabase,
    RegisterSsapServer(u32),
    AddSsapService(u32),
    AddSsapProperty(u32),
    AddSsapDescriptor(u32),
    SetSsapInfo(u32),
    StartSsapService(u32),
    NotifySsap(u32),
    ExchangeSsapInfo(u32),
    DiscoverSsapServices(u32),
    ReadSsap(u32),
    WriteSsap(u32),
    UnsupportedTarget,
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
    RegisterSsapServerCallbacks(u32),
    RegisterSsapClientCallbacks(u32),
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
    let queue = EVENT_QUEUE.load(Ordering::Acquire);
    if !queue.is_null() {
        // SAFETY: initialization publishes process-lifetime queue storage.
        let queue = unsafe { &*queue };
        queue.enable_status.store(status, Ordering::Relaxed);
        queue.enable_seen.store(true, Ordering::Release);
    }
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
unsafe extern "C" fn pair_complete(connection_id: u16, address: *const Address, status: u32) {
    let Some(address) = (unsafe { address.as_ref() }).copied() else {
        return;
    };
    push_event(SleS1Event::PairComplete {
        connection_id,
        address,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn authentication_complete(
    connection_id: u16,
    address: *const Address,
    status: u32,
    _event: *const c_void,
) {
    let Some(address) = (unsafe { address.as_ref() }).copied() else {
        return;
    };
    push_event(SleS1Event::AuthenticationComplete {
        connection_id,
        address,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ssap_service_started(server_id: u8, service_handle: u16, status: u32) {
    push_event(SleS1Event::SsapServiceStarted {
        server_id,
        service_handle,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ssap_notification(
    client_id: u8,
    connection_id: u16,
    value: *mut ClientHandleValue,
    status: u32,
) {
    let Some(value) = (unsafe { value.as_ref() }) else {
        return;
    };
    let source_len = usize::from(value.data_len);
    let copy_len = source_len.min(SLE_S1_EVENT_DATA_CAPACITY);
    let mut data = [0; SLE_S1_EVENT_DATA_CAPACITY];
    if copy_len != 0 && !value.data.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(value.data, data.as_mut_ptr(), copy_len) };
    }
    push_event(SleS1Event::SsapNotification {
        client_id,
        connection_id,
        handle: value.handle,
        property_type: value.property_type,
        status,
        data_len: copy_len as u8,
        truncated: copy_len != source_len,
        data,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ssap_exchange_complete(
    client_id: u8,
    connection_id: u16,
    parameters: *mut ExchangeInfo,
    status: u32,
) {
    let parameters = unsafe { parameters.as_ref() }
        .copied()
        .unwrap_or(ExchangeInfo {
            mtu_size: 0,
            version: 0,
        });
    push_event(SleS1Event::SsapExchangeComplete {
        client_id,
        connection_id,
        mtu_size: parameters.mtu_size,
        version: parameters.version,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ssap_service_found(
    client_id: u8,
    connection_id: u16,
    service: *mut FindServiceResult,
    status: u32,
) {
    let Some(service) = (unsafe { service.as_ref() }).copied() else {
        return;
    };
    push_event(SleS1Event::SsapServiceFound {
        client_id,
        connection_id,
        start_handle: service.start_handle,
        end_handle: service.end_handle,
        uuid: service.uuid,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ssap_discovery_complete(
    client_id: u8,
    connection_id: u16,
    _result: *mut FindStructureResult,
    status: u32,
) {
    push_event(SleS1Event::SsapDiscoveryComplete {
        client_id,
        connection_id,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ssap_read_requested(
    server_id: u8,
    connection_id: u16,
    request: *mut ServerReadRequest,
    status: u32,
) {
    let Some(request) = (unsafe { request.as_ref() }).copied() else {
        return;
    };
    push_event(SleS1Event::SsapReadRequested {
        server_id,
        connection_id,
        request_id: request.request_id,
        handle: request.handle,
        property_type: request.property_type,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ssap_write_complete(
    client_id: u8,
    connection_id: u16,
    result: *mut ClientWriteResult,
    status: u32,
) {
    let Some(result) = (unsafe { result.as_ref() }) else {
        return;
    };
    push_event(SleS1Event::SsapWriteComplete {
        client_id,
        connection_id,
        handle: result.handle,
        property_type: result.property_type,
        status,
    });
}

#[cfg(target_arch = "riscv32")]
unsafe extern "C" fn ssap_write_requested(
    server_id: u8,
    connection_id: u16,
    request: *mut ServerWriteRequest,
    status: u32,
) {
    let Some(request) = (unsafe { request.as_ref() }) else {
        return;
    };
    push_event(SleS1Event::SsapWriteRequested {
        server_id,
        connection_id,
        request_id: request.request_id,
        handle: request.handle,
        property_type: request.property_type,
        status,
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
    authentication_complete: Some(authentication_complete),
    pair_complete: Some(pair_complete),
    read_rssi: None,
    low_latency: None,
    set_phy: None,
    pair_remove: None,
};

#[cfg(target_arch = "riscv32")]
static mut SSAP_SERVER_CALLBACKS: ServerCallbacks = ServerCallbacks {
    add_service: None,
    add_property: None,
    add_descriptor: None,
    start_service: Some(ssap_service_started),
    delete_all_services: None,
    read_request: Some(ssap_read_requested),
    read_by_uuid_request: None,
    write_request: Some(ssap_write_requested),
    mtu_changed: None,
    indicate_confirmed: None,
};

#[cfg(target_arch = "riscv32")]
static mut SSAP_CLIENT_CALLBACKS: ClientCallbacks = ClientCallbacks {
    find_structure: Some(ssap_service_found),
    find_property: None,
    find_structure_complete: Some(ssap_discovery_complete),
    read_confirmed: None,
    read_by_uuid_complete: None,
    write_confirmed: Some(ssap_write_complete),
    exchange_info: Some(ssap_exchange_complete),
    notification: Some(ssap_notification),
    indication: None,
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
    reservation_index: usize,
    task_index: usize,
    entry: hisi_rf_rtos_driver::TaskEntry,
) -> Result<(), SleS1InitError> {
    let reservation = reservations
        .take(reservation_index)
        .ok_or(SleS1InitError::TaskSpawn { index: task_index })?;
    let config = task_config(task_index)?;
    hisi_rf_rtos_driver::spawn_reserved(&reservation, entry, core::ptr::null_mut(), config)
        .map(|_| ())
        .map_err(|_| SleS1InitError::TaskSpawn { index: task_index })
}

#[cfg(any(target_arch = "riscv32", test))]
fn task_config(index: usize) -> Result<hisi_rf_rtos_driver::TaskConfig, SleS1InitError> {
    let stack_size = STACKS.get(index).copied().ok_or(SleS1InitError::TaskPlan)?;
    let priority = PRIORITIES
        .get(index)
        .copied()
        .ok_or(SleS1InitError::TaskPlan)?;
    Ok(hisi_rf_rtos_driver::TaskConfig {
        stack_size: NonZeroUsize::new(stack_size).ok_or(SleS1InitError::TaskPlan)?,
        priority: hisi_rf_rtos_driver::TaskPriority::new(priority)
            .ok_or(SleS1InitError::TaskPlan)?,
    })
}

#[cfg(target_arch = "riscv32")]
pub fn init_sle_s1(
    resources: SleS1Resources,
    storage: InstalledSleS1Storage,
) -> Result<SleS1Controller, SleS1InitError> {
    init_sle_s1_with_platform(Some(resources), storage, None, 0)
}

#[cfg(target_arch = "riscv32")]
pub(crate) fn init_sle_s1_coexisting(
    storage: &'static SleS1ControlStorage,
    reservations: hisi_rf_rtos_driver::TaskReservationBatch,
    reservation_offset: usize,
) -> Result<SleS1Controller, SleS1InitError> {
    init_sle_s1_with_platform(
        None,
        storage.install_coexisting(),
        Some(reservations),
        reservation_offset,
    )
}

#[cfg(target_arch = "riscv32")]
fn init_sle_s1_with_platform(
    resources: Option<SleS1Resources>,
    mut storage: InstalledSleS1Storage,
    admitted_reservations: Option<hisi_rf_rtos_driver::TaskReservationBatch>,
    reservation_offset: usize,
) -> Result<SleS1Controller, SleS1InitError> {
    crate::ensure_sle_init_link_contract();
    let retained_efuse = if let Some(resources) = resources {
        unsafe { crate::prepare_vendor_memory() };
        let _ = crate::uapi::initialize_rom_timebases();
        crate::uapi::enable_efuse_reads();
        let crypto = storage.crypto.take().ok_or(SleS1InitError::Crypto)?;
        crate::crypto::install_hardware_crypto(
            resources.km,
            resources.spacc,
            None,
            resources.trng,
            crypto,
        )
        .map_err(|_| SleS1InitError::Crypto)?;
        Some(resources.efuse)
    } else {
        debug_assert!(storage.crypto.is_none());
        crate::log_emit(b"RFDBG_SLE_S1_SHARED_PLATFORM_OK\r\n");
        None
    };
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
    let status =
        unsafe { ws63_radio_sys::ssap::ssaps_register_callbacks(&raw mut SSAP_SERVER_CALLBACKS) };
    if status != 0 {
        return Err(SleS1InitError::RegisterSsapServerCallbacks(status));
    }
    let status =
        unsafe { ws63_radio_sys::ssap::ssapc_register_callbacks(&raw mut SSAP_CLIENT_CALLBACKS) };
    if status != 0 {
        return Err(SleS1InitError::RegisterSsapClientCallbacks(status));
    }

    let mut reservations = match admitted_reservations {
        Some(reservations) => reservations,
        None => {
            let groups = [
                task_group(0)?,
                task_group(1)?,
                task_group(2)?,
                task_group(3)?,
            ];
            let plan = hisi_rf_rtos_driver::TaskResourcePlan::new(&groups)
                .ok_or(SleS1InitError::TaskPlan)?;
            hisi_rf_rtos_driver::reserve_task_resource_plan(plan)
                .map_err(|_| SleS1InitError::TaskAdmission)?
        }
    };
    hisi_rf_rtos_driver::lock_scheduler().map_err(|_| SleS1InitError::SchedulerLock)?;
    let spawn_result = (|| {
        spawn_task(&mut reservations, reservation_offset, 0, task_bt)?;
        spawn_task(&mut reservations, reservation_offset + 1, 1, task_bt_sdk)?;
        spawn_task(&mut reservations, reservation_offset + 2, 2, task_bth_sdk)?;
        spawn_task(&mut reservations, reservation_offset + 3, 3, task_service)
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
        _efuse: retained_efuse,
        events: storage.events,
        operations: storage.operations,
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
    extern crate std;

    use super::*;
    use std::boxed::Box;

    #[test]
    fn task_inventory_matches_shared_bgle_controller_profile() {
        assert_eq!(TASK_COUNT, 4);
        assert_eq!(STACKS.iter().sum::<usize>(), SLE_S1_TASK_STACK_BYTES);
        assert_eq!(STACKS.iter().sum::<usize>(), 10_240);
        assert_eq!(STACKS[2], SLE_S1_MINIMUM_TASK_STACK_BYTES);
        assert_eq!(PRIORITIES, [1, 12, 13, 12]);
        for index in 0..TASK_COUNT {
            let config = task_config(index).unwrap();
            assert_eq!(config.stack_size.get(), STACKS[index]);
            assert_eq!(config.priority.into_raw(), PRIORITIES[index]);
        }
        assert_eq!(task_config(TASK_COUNT), Err(SleS1InitError::TaskPlan));
    }

    #[test]
    fn typed_announce_payloads_move_into_backend_storage() {
        let data = hisi_rf_core::sle::AnnouncePayload::try_from_slice(b"announce").unwrap();
        let response = hisi_rf_core::sle::AnnouncePayload::try_from_slice(b"response").unwrap();
        let interval = hisi_rf_core::sle::AnnounceInterval::try_from_units(0x20).unwrap();
        let mut storage = SleS1OperationStorage::new();
        {
            let config = AnnounceConfig::new(
                hisi_rf_core::sle::AnnounceTiming::try_new(interval, interval).unwrap(),
                hisi_rf_core::sle::AnnounceChannels::ALL,
                data,
                response,
            );
            storage.store_announce_payloads(&config);
        }

        assert_eq!(&storage.announce_data[..8], b"announce");
        assert_eq!(&storage.seek_response_data[..8], b"response");
    }

    #[test]
    fn typed_ssap_values_and_bits_match_the_ws63_abi() {
        let mut storage = SleS1OperationStorage::new();
        storage
            .store_ssap_values(b"property", b"descriptor")
            .unwrap();
        assert_eq!(&storage.ssap_property_value[..8], b"property");
        assert_eq!(&storage.ssap_descriptor_value[..10], b"descriptor");
        let permissions = SsapPermissions::READ.union(SsapPermissions::WRITE);
        assert_eq!(map_ssap_permissions(permissions), 0x03);
        assert_eq!(map_ssap_descriptor_operations(permissions), 0x05);
        assert_eq!(
            map_ssap_operations(
                SsapOperations::READ
                    .union(SsapOperations::WRITE)
                    .union(SsapOperations::NOTIFY)
                    .union(SsapOperations::INDICATE)
            ),
            0x1d
        );
        assert_eq!(
            ssap_uuid(SsapUuid::Uuid16(0x600b)).bytes[14..],
            [0x0b, 0x60]
        );
        assert_eq!(
            storage.store_ssap_values(&[0; SLE_S3_VALUE_CAPACITY + 1], &[]),
            Err(SleS1OperationError::SsapValueTooLong {
                length: SLE_S3_VALUE_CAPACITY + 1
            })
        );
    }

    #[test]
    fn event_queue_is_bounded_and_fifo() {
        let queue = EventQueue::new();
        for status in 0..EVENT_CAPACITY as u32 {
            queue.push(SleS1Event::Enabled { status });
        }
        queue.push(SleS1Event::Enabled { status: 99 });
        assert_eq!(
            queue.diagnostics(),
            EventQueueDiagnostics {
                accepted: EVENT_CAPACITY as u32,
                consumed: 0,
                dropped: 1,
                pending: EVENT_CAPACITY,
                high_water: EVENT_CAPACITY,
            }
        );
        for status in 0..EVENT_CAPACITY as u32 {
            assert_eq!(queue.pop(), Some(SleS1Event::Enabled { status }));
        }
        assert_eq!(queue.pop(), None);
        let diagnostics = queue.diagnostics();
        assert_eq!(diagnostics.accepted, diagnostics.consumed);
        assert_eq!(diagnostics.pending, 0);
        assert_eq!(diagnostics.dropped, 1);
        assert_eq!(diagnostics.high_water, EVENT_CAPACITY);
    }

    #[test]
    fn enable_status_does_not_consume_the_public_event() {
        let queue = EventQueue::new();
        assert_eq!(queue.enable_status(), None);
        queue.enable_status.store(0, Ordering::Relaxed);
        queue.enable_seen.store(true, Ordering::Release);
        queue.push(SleS1Event::Enabled { status: 0 });
        assert_eq!(queue.enable_status(), Some(0));
        assert_eq!(queue.pop(), Some(SleS1Event::Enabled { status: 0 }));
        assert_eq!(queue.enable_status(), Some(0));
    }

    #[test]
    fn host_stop_operations_fail_closed() {
        let events = Box::leak(Box::new(EventQueue::new()));
        let operations = Box::leak(Box::new(SleS1OperationStorage::new()));
        let mut controller = SleS1Controller {
            _efuse: Some(unsafe { Efuse::steal() }),
            events,
            operations,
        };
        assert_eq!(
            controller.stop_announce(),
            Err(SleS1OperationError::UnsupportedTarget)
        );
        assert_eq!(
            controller.stop_seek(),
            Err(SleS1OperationError::UnsupportedTarget)
        );
    }
}
