use core::ffi::c_void;
use core::fmt;
use core::num::{NonZeroU32, NonZeroUsize};
use hisi_hal::peripherals::{Efuse, Km, Pke, Spacc, Trng};
use hisi_rf_core::{
    BackendError, BackendErrorClass, Diagnostic, DiagnosticStage, DiagnosticTraceKind, Error,
    RadioConfig,
};

#[cfg(feature = "incremental-embassy-wait")]
use hisi_rf_core::{
    IncrementalDriverEvent, IncrementalRadioRunnerError, IncrementalRunnerDiagnostics,
    IncrementalWaitError, IncrementalWaitIntent, IncrementalWaitPlatform, WaitSet, WorkBudget,
};
#[cfg(feature = "incremental-backend-experiment")]
use hisi_rf_core::{RadioResources, WifiBackend};

#[cfg(all(
    feature = "incremental-backend-experiment",
    not(feature = "incremental-embassy-wait")
))]
use crate::hisi_rf_backend::OwnedIncrementalSupplicantBackend;
use crate::hisi_rf_backend::Ws63WifiBackend;
#[cfg(feature = "incremental-embassy-wait")]
use crate::incremental_wait::{Ws63IncrementalWaitDiagnostics, Ws63IncrementalWaitPlatform};
#[cfg(feature = "incremental-embassy-wait")]
use crate::incremental_worker::{IncrementalWorkerState, WorkerBackedIncrementalBackend};
use crate::netif_smoltcp::Ws63Device;
pub use crate::netif_smoltcp::{DhcpDiagnostics, L2ProtocolDiagnostics, RxQueueDiagnostics};
use crate::profile::{
    ActiveProfile, InstalledRadioArena, Profile, ProfileReservations, Storage, WifiWpa2Smoltcp,
    WifiWpa3Smoltcp,
};

/// WS63 radio resources assembled from uniquely owned HAL peripheral tokens.
pub struct Resources<P: Profile> {
    efuse: Efuse<'static>,
    km: Km<'static>,
    spacc: Spacc<'static>,
    pke: Option<Pke<'static>>,
    trng: Trng<'static>,
    _arena: InstalledRadioArena<P>,
}

impl<P: Profile> Resources<P> {
    /// Assemble all WS63 crypto capabilities without touching hardware.
    ///
    /// New code should use the profile-aware [`ResourcesBuilder`]. This
    /// compatibility constructor keeps the pre-A5UX shape for one alpha
    /// migration cycle and always consumes PKE, even for WPA2.
    #[deprecated(
        since = "0.1.0-alpha.39",
        note = "use Resources::<SelectedProfile>::builder(...).crypto(...), then build() or pke(...).build()"
    )]
    pub fn new(
        efuse: Efuse<'static>,
        km: Km<'static>,
        spacc: Spacc<'static>,
        pke: Pke<'static>,
        trng: Trng<'static>,
        arena: InstalledRadioArena<P>,
    ) -> Self {
        Self {
            efuse,
            km,
            spacc,
            pke: Some(pke),
            trng,
            _arena: arena,
        }
    }
}

/// Type state: KM/SPACC/TRNG have not been supplied.
#[doc(hidden)]
pub struct MissingCrypto;

/// Type state: KM/SPACC/TRNG are uniquely owned by the resource builder.
#[doc(hidden)]
pub struct CryptoReady {
    km: Km<'static>,
    spacc: Spacc<'static>,
    trng: Trng<'static>,
}

/// Type state: the selected profile does not need PKE.
#[doc(hidden)]
pub struct PkeNotRequired;

/// Type state: the selected profile requires a PKE token.
#[doc(hidden)]
pub struct MissingPke;

/// Type state: PKE is uniquely owned by the resource builder.
#[doc(hidden)]
pub struct PkeReady(Pke<'static>);

/// Profile-aware builder for uniquely owned WS63 radio capabilities.
///
/// The builder never touches hardware. Its type state makes the selected
/// profile's required capabilities explicit: WPA2 needs KM/SPACC/TRNG, while
/// WPA3 additionally requires PKE.
pub struct ResourcesBuilder<P: Profile, C, E> {
    efuse: Efuse<'static>,
    crypto: C,
    pke: E,
    arena: InstalledRadioArena<P>,
}

impl Resources<WifiWpa2Smoltcp> {
    /// Start assembling the capabilities required by the WPA2 profile.
    pub fn builder(
        efuse: Efuse<'static>,
        arena: InstalledRadioArena<WifiWpa2Smoltcp>,
    ) -> ResourcesBuilder<WifiWpa2Smoltcp, MissingCrypto, PkeNotRequired> {
        ResourcesBuilder {
            efuse,
            crypto: MissingCrypto,
            pke: PkeNotRequired,
            arena,
        }
    }
}

impl Resources<WifiWpa3Smoltcp> {
    /// Start assembling the capabilities required by the WPA3 profile.
    pub fn builder(
        efuse: Efuse<'static>,
        arena: InstalledRadioArena<WifiWpa3Smoltcp>,
    ) -> ResourcesBuilder<WifiWpa3Smoltcp, MissingCrypto, MissingPke> {
        ResourcesBuilder {
            efuse,
            crypto: MissingCrypto,
            pke: MissingPke,
            arena,
        }
    }
}

impl<P: Profile, E> ResourcesBuilder<P, MissingCrypto, E> {
    /// Supply the KM, SPACC and TRNG capabilities shared by Personal profiles.
    pub fn crypto(
        self,
        km: Km<'static>,
        spacc: Spacc<'static>,
        trng: Trng<'static>,
    ) -> ResourcesBuilder<P, CryptoReady, E> {
        ResourcesBuilder {
            efuse: self.efuse,
            crypto: CryptoReady { km, spacc, trng },
            pke: self.pke,
            arena: self.arena,
        }
    }
}

impl<C> ResourcesBuilder<WifiWpa3Smoltcp, C, MissingPke> {
    /// Supply the PKE capability required by SAE/P-256.
    pub fn pke(self, pke: Pke<'static>) -> ResourcesBuilder<WifiWpa3Smoltcp, C, PkeReady> {
        ResourcesBuilder {
            efuse: self.efuse,
            crypto: self.crypto,
            pke: PkeReady(pke),
            arena: self.arena,
        }
    }
}

impl ResourcesBuilder<WifiWpa2Smoltcp, CryptoReady, PkeNotRequired> {
    /// Finish the WPA2 resources without consuming an unused PKE token.
    pub fn build(self) -> Resources<WifiWpa2Smoltcp> {
        Resources {
            efuse: self.efuse,
            km: self.crypto.km,
            spacc: self.crypto.spacc,
            pke: None,
            trng: self.crypto.trng,
            _arena: self.arena,
        }
    }
}

impl ResourcesBuilder<WifiWpa3Smoltcp, CryptoReady, PkeReady> {
    /// Finish the WPA3 resources after all required capabilities are present.
    pub fn build(self) -> Resources<WifiWpa3Smoltcp> {
        Resources {
            efuse: self.efuse,
            km: self.crypto.km,
            spacc: self.crypto.spacc,
            pke: Some(self.pke.0),
            trng: self.crypto.trng,
            _arena: self.arena,
        }
    }
}

/// Failure before the WS63 radio backend starts executing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitError {
    kind: InitErrorKind,
    diagnostic: Diagnostic,
}

/// Stable category of a WS63 radio initialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitErrorKind {
    /// The installed runtime cannot satisfy the profile contract.
    Runtime,
    /// The runtime could not atomically reserve the profile's task slots.
    TaskAdmission,
    /// The caller-owned storage was already consumed by an earlier init.
    StorageAlreadyClaimed,
    /// The chip-neutral controller rejected initialization.
    Core,
}

impl InitError {
    fn runtime(error: hisi_rf_rtos_driver::Error) -> Self {
        Self {
            kind: InitErrorKind::Runtime,
            diagnostic: runtime_diagnostic(error),
        }
    }

    fn task_admission(error: hisi_rf_rtos_driver::TaskAdmissionError) -> Self {
        Self {
            kind: InitErrorKind::TaskAdmission,
            diagnostic: task_admission_diagnostic(error),
        }
    }

    fn storage_already_claimed() -> Self {
        Self {
            kind: InitErrorKind::StorageAlreadyClaimed,
            diagnostic: Error::AlreadyInitialized.diagnostic(),
        }
    }

    fn core(error: Error) -> Self {
        Self {
            kind: InitErrorKind::Core,
            diagnostic: error.diagnostic(),
        }
    }

    /// Return the stable failure category without exposing the runtime backend.
    pub const fn kind(self) -> InitErrorKind {
        self.kind
    }

    /// Convert an initialization failure into the shared, secret-free schema.
    pub const fn diagnostic(self) -> Diagnostic {
        self.diagnostic
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.diagnostic().fmt(formatter)
    }
}

const RADIO_RUNNER_STACK_BYTES: usize = 8 * 1024;
const RADIO_RUNNER_PRIORITY: u8 = 10;

type CoreRadioController<const EVENTS: usize> =
    hisi_rf_core::RadioController<Ws63WifiBackend<'static>, Ws63Device, EVENTS>;

#[cfg(feature = "incremental-backend-experiment")]
#[cfg(feature = "incremental-embassy-wait")]
type ActiveIncrementalBackend = WorkerBackedIncrementalBackend;
#[cfg(all(
    feature = "incremental-backend-experiment",
    not(feature = "incremental-embassy-wait")
))]
type ActiveIncrementalBackend = OwnedIncrementalSupplicantBackend;

#[cfg(feature = "incremental-backend-experiment")]
type CoreIncrementalRadioController<const EVENTS: usize> =
    hisi_rf_core::RadioController<ActiveIncrementalBackend, Ws63Device, EVENTS>;

/// WS63 controller bound to the caller-owned storage that will hold its runner.
pub struct RadioController<P: Profile + 'static, const EVENTS: usize> {
    inner: CoreRadioController<EVENTS>,
    storage: &'static Storage<P, EVENTS>,
}

/// WS63 L2 device exposed only through the standard smoltcp device contract.
pub struct WifiDevice(hisi_rf_core::WifiDevice<Ws63Device>);

/// Secret-free counters spanning the Rust L2 bridge and vendor IRQ boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[doc(hidden)]
pub struct DataPathDiagnostics {
    /// Instrumented stages: bit 0 vendor TX submission, bit 1 vendor RX
    /// boundary, bit 2 MAC RX counters, bit 3 DMAC TX completion, bit 4 DMAC
    /// RX preparation, bit 5 MAC receive-filter state.
    pub instrumented_capabilities: u32,
    /// Frames emitted by smoltcp into the vendor TX sink.
    pub tx_frames: u32,
    /// Frames rejected before the vendor TX callback could accept them.
    pub tx_failed: u32,
    /// Frames converted by the vendor host bridge for MAC transmission.
    pub vendor_tx_frames: u32,
    /// DMAC transmit completions observed after vendor submission.
    pub tx_completions: u32,
    /// Calls entering the DMAC receive preparation path.
    ///
    /// This includes management and internal driver traffic; it is not a count
    /// of Ethernet frames delivered to the Rust L2 device.
    pub dmac_rx_prepares: u32,
    /// DMAC RX preparation calls returning zero/non-zero and the last result.
    pub dmac_rx_prepare_zero: u32,
    pub dmac_rx_prepare_nonzero: u32,
    pub dmac_rx_prepare_last_result: u32,
    /// Calls crossing successive host-side RX pipeline stages.
    pub hmac_rx_data_event_adapt_calls: u32,
    pub hmac_rx_process_data_msg_calls: u32,
    pub hmac_rx_data_calls: u32,
    /// Frames reaching the final vendor host-RX boundary.
    pub vendor_rx_frames: u32,
    /// Valid Ethernet frames delivered by the vendor RX callback.
    pub rx_frames: u32,
    /// Successful MPDUs counted by the MAC receive engine.
    pub mac_rx_successful_mpdu: u32,
    /// Failed MPDUs counted by the MAC receive engine.
    pub mac_rx_failed_mpdu: u32,
    /// MPDUs rejected by the MAC receive filter.
    pub mac_rx_filtered_mpdu: u32,
    /// Packed receive-filter control state active when this snapshot was taken.
    pub mac_rx_filter_control: u32,
    /// Whether the VAP0 station address matches this L2 device's identity.
    pub mac_station_address_matches_device: bool,
    /// Whether the VAP0 BSSID register contains a non-zero address.
    pub mac_bssid_programmed: bool,
    /// Coexistence WLAN interrupt dispatches.
    pub coex_wlan_irqs: u32,
    /// WLAN PHY interrupt dispatches.
    pub wlphy_irqs: u32,
    /// WLAN MAC interrupt dispatches.
    pub wlmac_irqs: u32,
}

#[cfg(any(feature = "data-path-diag", feature = "rf-eloop-diag"))]
const DATA_PATH_CAP_VENDOR_TX_SUBMISSION: u32 = 1 << 0;
#[cfg(any(feature = "data-path-diag", feature = "rf-eloop-diag"))]
const DATA_PATH_CAP_VENDOR_RX_BOUNDARY: u32 = 1 << 1;
#[cfg(any(feature = "data-path-diag", feature = "rf-eloop-diag"))]
const DATA_PATH_CAP_MAC_RX_COUNTERS: u32 = 1 << 2;
#[cfg(any(feature = "data-path-diag", feature = "rf-eloop-diag"))]
const DATA_PATH_CAP_DMAC_TX_COMPLETION: u32 = 1 << 3;
#[cfg(any(feature = "data-path-diag", feature = "rf-eloop-diag"))]
const DATA_PATH_CAP_DMAC_RX_PREPARE: u32 = 1 << 4;
#[cfg(any(feature = "data-path-diag", feature = "rf-eloop-diag"))]
const DATA_PATH_CAP_MAC_FILTER_STATE: u32 = 1 << 5;
#[cfg(any(feature = "data-path-diag", feature = "rf-eloop-diag"))]
const DATA_PATH_DIAG_CAPABILITIES: u32 = DATA_PATH_CAP_VENDOR_TX_SUBMISSION
    | DATA_PATH_CAP_VENDOR_RX_BOUNDARY
    | DATA_PATH_CAP_MAC_RX_COUNTERS
    | DATA_PATH_CAP_DMAC_TX_COMPLETION
    | DATA_PATH_CAP_DMAC_RX_PREPARE
    | DATA_PATH_CAP_MAC_FILTER_STATE;

impl WifiDevice {
    /// Snapshot immutable L2 identity owned by this initialized radio instance.
    pub fn l2_capabilities(&self) -> Option<hisi_rf_core::WifiL2Capabilities> {
        self.0.l2_capabilities()
    }

    /// Return this initialized radio instance's station MAC address.
    pub fn station_mac_address(&self) -> Option<[u8; 6]> {
        self.0.station_mac_address()
    }

    /// Snapshot bounded L2 receive-queue occupancy and loss counters.
    ///
    /// The snapshot contains counters only; it never exposes received frame
    /// contents. Applications can use it to distinguish radio/network
    /// starvation from an upstream connectivity failure.
    pub fn rx_queue_diagnostics(&self) -> RxQueueDiagnostics {
        crate::netif_smoltcp::rx_queue_diagnostics()
    }

    /// Start a new L2 receive-queue diagnostic window.
    ///
    /// Pending frames are preserved. Only the loss, high-watermark, and ICMP
    /// observation counters are reset.
    pub fn reset_rx_queue_diagnostics(&self) {
        crate::netif_smoltcp::reset_rx_queue_diagnostics();
    }

    /// Snapshot Ethernet protocol counters at the Rust-visible L2 seam.
    pub fn l2_protocol_diagnostics(&self) -> L2ProtocolDiagnostics {
        crate::netif_smoltcp::l2_protocol_diagnostics()
    }

    /// Start a new Ethernet protocol diagnostic window.
    pub fn reset_l2_protocol_diagnostics(&self) {
        crate::netif_smoltcp::reset_l2_protocol_diagnostics();
    }

    /// Snapshot DHCP client/server packets crossing the Rust-visible L2 seam.
    pub fn dhcp_diagnostics(&self) -> DhcpDiagnostics {
        crate::netif_smoltcp::dhcp_diagnostics()
    }

    /// Snapshot aggregate data-path and radio-interrupt counters.
    #[doc(hidden)]
    pub fn data_path_diagnostics(&self) -> DataPathDiagnostics {
        #[cfg(feature = "rf-eloop-diag")]
        let (
            instrumented_capabilities,
            vendor_tx_frames,
            tx_completions,
            dmac_rx_prepares,
            dmac_rx_prepare_zero,
            dmac_rx_prepare_nonzero,
            dmac_rx_prepare_last_result,
            hmac_rx_data_event_adapt_calls,
            hmac_rx_process_data_msg_calls,
            hmac_rx_data_calls,
            vendor_rx_frames,
            mac_rx_successful_mpdu,
            mac_rx_failed_mpdu,
            mac_rx_filtered_mpdu,
            mac_rx_filter_control,
            mac_station_address_matches_device,
            mac_bssid_programmed,
        ) = {
            let vendor = crate::eloop_diag::auth();
            let mac = crate::wlmac_diag::snapshot();
            let station_address = self.station_mac_address();
            (
                DATA_PATH_DIAG_CAPABILITIES,
                vendor.bridge_xmit_calls,
                vendor.tx_complete_calls,
                vendor.dmac_rx_calls,
                0,
                0,
                0,
                0,
                0,
                0,
                vendor.netif_rx_calls,
                mac.rx.rx_success_mpdu,
                mac.rx.rx_failed_mpdu,
                u32::from(mac.rx.rx_filtered_mpdu),
                mac.filter.rx_filter_control,
                station_address == Some(mac.filter.station_address),
                mac.filter.bssid != [0; 6],
            )
        };
        #[cfg(all(feature = "data-path-diag", not(feature = "rf-eloop-diag")))]
        let (
            instrumented_capabilities,
            vendor_tx_frames,
            tx_completions,
            dmac_rx_prepares,
            dmac_rx_prepare_zero,
            dmac_rx_prepare_nonzero,
            dmac_rx_prepare_last_result,
            hmac_rx_data_event_adapt_calls,
            hmac_rx_process_data_msg_calls,
            hmac_rx_data_calls,
            vendor_rx_frames,
            mac_rx_successful_mpdu,
            mac_rx_failed_mpdu,
            mac_rx_filtered_mpdu,
            mac_rx_filter_control,
            mac_station_address_matches_device,
            mac_bssid_programmed,
        ) = {
            let mac = crate::wlmac_diag::snapshot();
            let station_address = self.station_mac_address();
            let rx_prepare = crate::data_path_diag::rx_prepare_results();
            let rx_pipeline = crate::data_path_diag::rx_pipeline_stages();
            (
                DATA_PATH_DIAG_CAPABILITIES,
                crate::netif::tx_submitted(),
                crate::data_path_diag::tx_completions(),
                crate::data_path_diag::rx_prepares(),
                rx_prepare[0],
                rx_prepare[1],
                rx_prepare[2],
                rx_pipeline[0],
                rx_pipeline[1],
                rx_pipeline[2],
                crate::netif::rx_received(),
                mac.rx.rx_success_mpdu,
                mac.rx.rx_failed_mpdu,
                u32::from(mac.rx.rx_filtered_mpdu),
                mac.filter.rx_filter_control,
                station_address == Some(mac.filter.station_address),
                mac.filter.bssid != [0; 6],
            )
        };
        #[cfg(not(any(feature = "rf-eloop-diag", feature = "data-path-diag")))]
        let (
            instrumented_capabilities,
            vendor_tx_frames,
            tx_completions,
            dmac_rx_prepares,
            dmac_rx_prepare_zero,
            dmac_rx_prepare_nonzero,
            dmac_rx_prepare_last_result,
            hmac_rx_data_event_adapt_calls,
            hmac_rx_process_data_msg_calls,
            hmac_rx_data_calls,
            vendor_rx_frames,
            mac_rx_successful_mpdu,
            mac_rx_failed_mpdu,
            mac_rx_filtered_mpdu,
            mac_rx_filter_control,
            mac_station_address_matches_device,
            mac_bssid_programmed,
        ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, false);
        DataPathDiagnostics {
            instrumented_capabilities,
            tx_frames: crate::netif_smoltcp::tx_count(),
            tx_failed: crate::netif::tx_failed(),
            vendor_tx_frames,
            tx_completions,
            dmac_rx_prepares,
            dmac_rx_prepare_zero,
            dmac_rx_prepare_nonzero,
            dmac_rx_prepare_last_result,
            hmac_rx_data_event_adapt_calls,
            hmac_rx_process_data_msg_calls,
            hmac_rx_data_calls,
            vendor_rx_frames,
            rx_frames: crate::netif::rx_received(),
            mac_rx_successful_mpdu,
            mac_rx_failed_mpdu,
            mac_rx_filtered_mpdu,
            mac_rx_filter_control,
            mac_station_address_matches_device,
            mac_bssid_programmed,
            coex_wlan_irqs: crate::osal::irq_dispatch_count(40),
            wlphy_irqs: crate::osal::irq_dispatch_count(44),
            wlmac_irqs: crate::osal::irq_dispatch_count(45),
        }
    }
}

/// Opaque receive token for [`WifiDevice`].
pub struct WifiRxToken(
    <hisi_rf_core::WifiDevice<Ws63Device> as smoltcp::phy::Device>::RxToken<'static>,
);

/// Opaque transmit token for [`WifiDevice`].
pub struct WifiTxToken(
    <hisi_rf_core::WifiDevice<Ws63Device> as smoltcp::phy::Device>::TxToken<'static>,
);

impl smoltcp::phy::RxToken for WifiRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, consume: F) -> R {
        smoltcp::phy::RxToken::consume(self.0, consume)
    }
}

impl smoltcp::phy::TxToken for WifiTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, consume: F) -> R {
        smoltcp::phy::TxToken::consume(self.0, len, consume)
    }
}

impl smoltcp::phy::Device for WifiDevice {
    type RxToken<'a> = WifiRxToken;
    type TxToken<'a> = WifiTxToken;

    fn receive(
        &mut self,
        timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.0
            .receive(timestamp)
            .map(|(rx, tx)| (WifiRxToken(rx), WifiTxToken(tx)))
    }

    fn transmit(&mut self, timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        self.0.transmit(timestamp).map(WifiTxToken)
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        self.0.capabilities()
    }
}

/// WS63 Wi-Fi control and L2 handles without exposing backend implementation types.
pub struct WifiParts<const EVENTS: usize> {
    /// Chip-neutral async control plane.
    pub controller: hisi_rf_core::WifiController<EVENTS>,
    /// Opaque WS63 L2 device implementing [`smoltcp::phy::Device`].
    pub device: WifiDevice,
}

fn wrap_wifi_parts<const EVENTS: usize>(
    parts: hisi_rf_core::WifiParts<Ws63Device, EVENTS>,
) -> WifiParts<EVENTS> {
    WifiParts {
        controller: parts.controller,
        device: WifiDevice(parts.device),
    }
}

/// WS63 controller whose vendor bootstrap has completed before construction.
///
/// This type is available only through the non-default A5B experiment. Its
/// scan/connect/disconnect work is bounded, but construction remains a
/// synchronous prerequisite until the vendor initialization boundary itself
/// can be split or assigned a measured worst-case latency.
#[cfg(feature = "incremental-backend-experiment")]
pub struct IncrementalRadioController<P: Profile + 'static, const EVENTS: usize> {
    #[cfg_attr(not(feature = "incremental-embassy-wait"), allow(dead_code))]
    inner: CoreIncrementalRadioController<EVENTS>,
    #[cfg(feature = "incremental-embassy-wait")]
    worker: &'static IncrementalWorkerState,
    _profile: core::marker::PhantomData<P>,
}

/// WS63-specific diagnostics for the stale-completion contract fixture.
#[cfg(feature = "incremental-late-completion-profile")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncrementalWorkerDiagnostics {
    /// Responses carrying an operation generation older than the active one.
    pub stale_responses_dropped: u32,
    /// Diagnostic stale responses injected after a replacement started.
    pub stale_responses_injected: u32,
}

/// Wi-Fi handles and the explicit A5B bounded runner.
#[cfg(feature = "incremental-embassy-wait")]
pub struct IncrementalRadioParts<const EVENTS: usize> {
    /// Existing async Wi-Fi controller and WS63 L2 device.
    pub wifi: WifiParts<EVENTS>,
    /// Runner that advances at most one budgeted backend action per call.
    pub runner: IncrementalRadioRunner<EVENTS>,
}

/// Opaque WS63 runner over the owned initialized backend.
#[cfg(feature = "incremental-embassy-wait")]
pub struct IncrementalRadioRunner<const EVENTS: usize> {
    inner: hisi_rf_core::IncrementalRadioRunner<ActiveIncrementalBackend, EVENTS>,
    platform: Ws63IncrementalWaitPlatform,
    #[cfg_attr(not(feature = "incremental-late-completion-profile"), allow(dead_code))]
    worker: &'static IncrementalWorkerState,
}

#[cfg(feature = "incremental-embassy-wait")]
impl<P: Profile + 'static, const EVENTS: usize> IncrementalRadioController<P, EVENTS> {
    /// Split into the stable Wi-Fi handles and an opt-in bounded runner.
    pub fn split(self, budget: WorkBudget) -> IncrementalRadioParts<EVENTS> {
        let hisi_rf_core::IncrementalRadioParts { wifi, runner } =
            self.inner.split_incremental(budget);
        IncrementalRadioParts {
            wifi: wrap_wifi_parts(wifi),
            runner: IncrementalRadioRunner {
                inner: runner,
                platform: Ws63IncrementalWaitPlatform::new(),
                worker: self.worker,
            },
        }
    }
}

#[cfg(feature = "incremental-embassy-wait")]
impl<const EVENTS: usize> IncrementalRadioRunner<EVENTS> {
    /// Advance at most one bounded driver action.
    pub fn run_once(
        &mut self,
        ready: WaitSet,
    ) -> Result<IncrementalDriverEvent, IncrementalRadioRunnerError> {
        self.inner.run_once(ready)
    }

    /// Snapshot immediate work, wake subscriptions, and the next deadline.
    pub fn wait_intent(&self) -> IncrementalWaitIntent {
        self.inner.wait_intent()
    }

    /// Wait for one subscribed source without consuming a control command.
    pub async fn wait_ready(
        &mut self,
    ) -> Result<WaitSet, IncrementalWaitError<core::convert::Infallible>> {
        self.inner.wait_ready(&mut self.platform).await
    }

    /// Wait through an explicitly supplied platform adapter.
    ///
    /// This is retained for conformance fixtures. Applications should use
    /// [`Self::wait_ready`], which owns the WS63 callback/L2/timer bridge.
    #[doc(hidden)]
    pub async fn wait_ready_with<P: IncrementalWaitPlatform>(
        &self,
        platform: &mut P,
    ) -> Result<WaitSet, IncrementalWaitError<P::Error>> {
        self.inner.wait_ready(platform).await
    }

    /// Monotonic deadline requested by the active operation.
    pub fn next_deadline_us(&self) -> Option<u64> {
        self.inner.next_deadline_us()
    }

    /// Snapshot chip-neutral runner workload and selected wake sources.
    pub fn diagnostics(&self) -> IncrementalRunnerDiagnostics {
        self.inner.diagnostics()
    }

    /// Snapshot raw WS63 callback/L2/timer wait-bridge activity.
    pub fn wait_diagnostics(&self) -> Ws63IncrementalWaitDiagnostics {
        self.platform.diagnostics()
    }

    /// Snapshot stale-generation handling in the RTOS worker proxy.
    #[cfg(feature = "incremental-late-completion-profile")]
    pub fn worker_diagnostics(&self) -> IncrementalWorkerDiagnostics {
        let (stale_responses_dropped, stale_responses_injected) = self.worker.diagnostics();
        IncrementalWorkerDiagnostics {
            stale_responses_dropped,
            stale_responses_injected,
        }
    }

    /// Arm one stale-success response after the next replacement starts.
    ///
    /// This exists only for the credential-free A5B silicon contract fixture.
    #[cfg(feature = "incremental-late-completion-profile")]
    #[doc(hidden)]
    pub fn arm_stale_completion_injection(&self) -> Result<(), BackendError> {
        self.worker.arm_stale_completion_injection()
    }
}

impl<P: Profile + 'static, const EVENTS: usize> RadioController<P, EVENTS> {
    /// Start the mandatory bounded-work runner and return Wi-Fi control/L2 handles.
    pub fn start_runner(self) -> Result<WifiParts<EVENTS>, InitError> {
        let hisi_rf_core::RadioParts { wifi, runner } = self.inner.split();
        let runner = self.storage.store_runner(runner);
        crate::runtime::spawn_vendor_task(
            radio_runner_task::<EVENTS>,
            (runner as *mut hisi_rf_core::RadioRunner<Ws63WifiBackend<'static>, EVENTS>).cast(),
            RADIO_RUNNER_STACK_BYTES,
            RADIO_RUNNER_PRIORITY,
        )
        .map_err(InitError::runtime)?;
        Ok(wrap_wifi_parts(wifi))
    }
}

/// Claim one WS63 radio instance using caller-owned state and resources.
pub fn init<P: Profile + ActiveProfile + 'static, const EVENTS: usize>(
    config: RadioConfig,
    resources: Resources<P>,
    storage: &'static Storage<P, EVENTS>,
) -> Result<RadioController<P, EVENTS>, InitError> {
    let claimed = claim_profile_storage::<P, EVENTS>(storage)?;
    let inner = crate::hisi_rf_backend::resources(
        resources.efuse,
        resources.km,
        resources.spacc,
        resources.pke,
        resources.trng,
        claimed.crypto,
    );
    match hisi_rf_core::init(config, inner, claimed.state) {
        Ok(controller) => Ok(RadioController {
            inner: controller,
            storage,
        }),
        Err(error) => {
            release_profile_reservation(claimed.vendor)?;
            if let Some(worker_reservation) = claimed.worker {
                release_profile_reservation(worker_reservation)?;
            }
            Err(InitError::core(error))
        }
    }
}

/// Complete the vendor bootstrap, then transfer ownership to the bounded
/// incremental runner.
///
/// Vendor initialization remains synchronous; only operations after the
/// returned controller is split use [`hisi_rf_core::WorkBudget`]. A bootstrap
/// failure consumes the one-shot storage and resources because vendor tasks may
/// already own the installed task reservation; retry with fresh firmware state
/// rather than reusing this storage.
#[cfg(feature = "incremental-backend-experiment")]
pub fn init_incremental<P: Profile + ActiveProfile + 'static, const EVENTS: usize>(
    config: RadioConfig,
    resources: Resources<P>,
    storage: &'static Storage<P, EVENTS>,
) -> Result<IncrementalRadioController<P, EVENTS>, InitError> {
    #[cfg(feature = "incremental-embassy-wait")]
    hisi_rf_rtos_driver::require_runtime(hisi_rf_rtos_driver::RuntimeRequirements::V1_6_BUDGETED)
        .map_err(InitError::runtime)?;
    let claimed = claim_profile_storage::<P, EVENTS>(storage)?;
    let RadioResources {
        mut backend,
        device,
    } = crate::hisi_rf_backend::resources(
        resources.efuse,
        resources.km,
        resources.spacc,
        resources.pke,
        resources.trng,
        claimed.crypto,
    );
    #[cfg(feature = "incremental-embassy-wait")]
    let worker_reservation = claimed.worker;
    if let Err(error) = backend.initialize(&config.wifi) {
        // The vendor bootstrap may already have spawned tasks through this
        // reservation. It is installed in the process-wide compatibility
        // adapter and cannot be safely detached or reused after a partial
        // failure, so this one-shot storage remains claimed.
        #[cfg(feature = "incremental-embassy-wait")]
        if let Some(worker_reservation) = worker_reservation {
            release_profile_reservation(worker_reservation)?;
        }
        return Err(InitError::core(Error::Backend(error)));
    }
    let backend = match backend.into_incremental() {
        Ok(backend) => backend,
        Err(error) => {
            #[cfg(feature = "incremental-embassy-wait")]
            if let Some(worker_reservation) = worker_reservation {
                release_profile_reservation(worker_reservation)?;
            }
            return Err(InitError::core(Error::Backend(error)));
        }
    };
    #[cfg(feature = "incremental-embassy-wait")]
    let (backend, worker) = {
        let worker_reservation = worker_reservation.ok_or_else(|| {
            InitError::task_admission(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
                hisi_rf_rtos_driver::Error::Runtime,
            ))
        })?;
        let worker = storage.store_incremental_worker(IncrementalWorkerState::new(backend));
        match worker.start(worker_reservation) {
            Ok(backend) => (backend, &*worker),
            Err(error) => {
                release_profile_reservation(worker_reservation)?;
                return Err(InitError::runtime(error));
            }
        }
    };
    match hisi_rf_core::init(config, RadioResources { backend, device }, claimed.state) {
        Ok(controller) => Ok(IncrementalRadioController {
            inner: controller,
            #[cfg(feature = "incremental-embassy-wait")]
            worker,
            _profile: core::marker::PhantomData,
        }),
        Err(error) => Err(InitError::core(error)),
    }
}

/// Migration alias for [`init_incremental`].
///
/// The old name exposed an implementation prerequisite in application code.
/// Use the selected composition root's `init` entry instead.
#[cfg(feature = "incremental-backend-experiment")]
#[deprecated(
    since = "0.1.0-alpha.41",
    note = "use hisi_rf::ws63::init, or hisi_rf_ws63::init_incremental in backend-specific code"
)]
pub fn init_incremental_after_blocking_bootstrap<
    P: Profile + ActiveProfile + 'static,
    const EVENTS: usize,
>(
    config: RadioConfig,
    resources: Resources<P>,
    storage: &'static Storage<P, EVENTS>,
) -> Result<IncrementalRadioController<P, EVENTS>, InitError> {
    init_incremental(config, resources, storage)
}

fn claim_profile_storage<P: Profile + ActiveProfile + 'static, const EVENTS: usize>(
    storage: &'static Storage<P, EVENTS>,
) -> Result<crate::profile::ClaimedStorage<EVENTS>, InitError> {
    #[cfg(target_arch = "riscv32")]
    crate::link_contract::ensure();
    hisi_rf_rtos_driver::require_runtime(
        hisi_rf_rtos_driver::RuntimeRequirements::V1_6_PORTED_COOPERATIVE,
    )
    .map_err(InitError::runtime)?;
    hisi_rf_rtos_driver::current_task().map_err(InitError::runtime)?;
    let vendor = task_resource_group(P::VENDOR_TASKS)?;
    #[cfg(feature = "incremental-embassy-wait")]
    let groups = [
        vendor,
        task_resource_group(P::WORKER_TASKS.ok_or_else(|| {
            InitError::task_admission(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
                hisi_rf_rtos_driver::Error::Runtime,
            ))
        })?)?,
    ];
    #[cfg(not(feature = "incremental-embassy-wait"))]
    let groups = [vendor];
    let plan = hisi_rf_rtos_driver::TaskResourcePlan::new(&groups).ok_or_else(|| {
        InitError::task_admission(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
            hisi_rf_rtos_driver::Error::ResourceExhausted,
        ))
    })?;
    let mut reservations =
        hisi_rf_rtos_driver::reserve_task_resource_plan(plan).map_err(InitError::task_admission)?;
    let reservation = reservations.take(0).ok_or_else(|| {
        InitError::task_admission(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
            hisi_rf_rtos_driver::Error::Runtime,
        ))
    })?;
    #[cfg(feature = "incremental-embassy-wait")]
    let worker_reservation = match reservations.take(1) {
        Some(reservation) => Some(reservation),
        None => {
            hisi_rf_rtos_driver::release_task_reservation(&reservation)
                .map_err(InitError::runtime)?;
            return Err(InitError::task_admission(
                hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
                    hisi_rf_rtos_driver::Error::Runtime,
                ),
            ));
        }
    };
    #[cfg(not(feature = "incremental-embassy-wait"))]
    let worker_reservation = None;
    let claimed = match storage.claim(ProfileReservations {
        vendor: reservation,
        worker: worker_reservation,
    }) {
        Ok(claimed) => claimed,
        Err(reservations) => {
            hisi_rf_rtos_driver::release_task_reservation(&reservations.vendor)
                .map_err(InitError::runtime)?;
            if let Some(worker_reservation) = reservations.worker.as_ref() {
                hisi_rf_rtos_driver::release_task_reservation(worker_reservation)
                    .map_err(InitError::runtime)?;
            }
            return Err(InitError::storage_already_claimed());
        }
    };
    if let Err(error) = crate::runtime::install_task_reservation(claimed.vendor) {
        hisi_rf_rtos_driver::release_task_reservation(claimed.vendor)
            .map_err(InitError::runtime)?;
        if let Some(worker_reservation) = claimed.worker {
            hisi_rf_rtos_driver::release_task_reservation(worker_reservation)
                .map_err(InitError::runtime)?;
        }
        return Err(InitError::runtime(error));
    }
    Ok(claimed)
}

fn task_resource_group(
    group: crate::profile::TaskGroupPlan,
) -> Result<hisi_rf_rtos_driver::TaskResourceGroupRequirements, InitError> {
    let owner = NonZeroU32::new(group.owner).ok_or_else(|| {
        InitError::task_admission(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
            hisi_rf_rtos_driver::Error::Runtime,
        ))
    })?;
    let slots = NonZeroUsize::new(group.task_slots).ok_or_else(|| {
        InitError::task_admission(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
            hisi_rf_rtos_driver::Error::Runtime,
        ))
    })?;
    let stack_bytes = NonZeroUsize::new(group.stack_bytes_per_task).ok_or_else(|| {
        InitError::task_admission(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
            hisi_rf_rtos_driver::Error::Runtime,
        ))
    })?;
    let resources = hisi_rf_rtos_driver::TaskResourceRequirements::new(slots, stack_bytes)
        .ok_or_else(|| {
            InitError::task_admission(hisi_rf_rtos_driver::TaskAdmissionError::Runtime(
                hisi_rf_rtos_driver::Error::ResourceExhausted,
            ))
        })?;
    Ok(hisi_rf_rtos_driver::TaskResourceGroupRequirements::new(
        hisi_rf_rtos_driver::TaskResourceOwner::new(owner),
        resources,
    ))
}

fn release_profile_reservation(
    reservation: &'static hisi_rf_rtos_driver::TaskReservation,
) -> Result<(), InitError> {
    hisi_rf_rtos_driver::release_task_reservation(reservation).map_err(InitError::runtime)
}

extern "C" fn radio_runner_task<const EVENTS: usize>(argument: *mut c_void) -> *mut c_void {
    // SAFETY: `start_runner` passes the unique runner stored for the entire
    // firmware lifetime. The task is the only code that mutates it.
    let runner = unsafe {
        &mut *argument.cast::<hisi_rf_core::RadioRunner<Ws63WifiBackend<'static>, EVENTS>>()
    };
    loop {
        let _ = runner.run_once();
        crate::runtime::yield_now();
    }
}

fn runtime_diagnostic(error: hisi_rf_rtos_driver::Error) -> Diagnostic {
    let class = match error {
        hisi_rf_rtos_driver::Error::ResourceExhausted | hisi_rf_rtos_driver::Error::NoTaskSlots => {
            BackendErrorClass::ResourceUnavailable
        }
        hisi_rf_rtos_driver::Error::TimedOut => BackendErrorClass::BackendTimeout,
        _ => BackendErrorClass::Other,
    };
    let code = crate::hisi_rf_backend::runtime_code(error);
    Error::Backend(
        BackendError::new(class, 0x5732_e000 | code)
            .with_stage(DiagnosticStage::Runtime)
            .with_profile_revision(crate::profile::PROFILE_REVISION)
            .with_trace(DiagnosticTraceKind::RuntimeCode, code),
    )
    .diagnostic()
}

fn task_admission_diagnostic(error: hisi_rf_rtos_driver::TaskAdmissionError) -> Diagnostic {
    let code = crate::hisi_rf_backend::task_admission_code(error);
    let mut backend = match error {
        hisi_rf_rtos_driver::TaskAdmissionError::Runtime(runtime) => {
            let class = match runtime {
                hisi_rf_rtos_driver::Error::ResourceExhausted
                | hisi_rf_rtos_driver::Error::NoTaskSlots => BackendErrorClass::ResourceUnavailable,
                hisi_rf_rtos_driver::Error::TimedOut => BackendErrorClass::BackendTimeout,
                _ => BackendErrorClass::Other,
            };
            BackendError::new(class, 0x5732_a000 | code).with_trace(
                DiagnosticTraceKind::RuntimeCode,
                crate::hisi_rf_backend::runtime_code(runtime),
            )
        }
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskSlots {
            required,
            available,
        } => BackendError::new(BackendErrorClass::ResourceUnavailable, 0x5732_a000 | code)
            .with_trace(
                DiagnosticTraceKind::ResourceRequired,
                required.min(u32::MAX as usize) as u32,
            )
            .with_trace(
                DiagnosticTraceKind::ResourceAvailable,
                available.min(u32::MAX as usize) as u32,
            ),
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskStackMemory {
            required,
            available,
        } => BackendError::new(BackendErrorClass::ResourceUnavailable, 0x5732_a000 | code)
            .with_trace(
                DiagnosticTraceKind::ResourceRequired,
                required.min(u32::MAX as usize) as u32,
            )
            .with_trace(
                DiagnosticTraceKind::ResourceAvailable,
                available.min(u32::MAX as usize) as u32,
            ),
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskGroupSlots {
            owner,
            required,
            available,
        } => BackendError::new(BackendErrorClass::ResourceUnavailable, 0x5732_a000 | code)
            .with_trace(DiagnosticTraceKind::ResourceOwner, owner.into_raw().get())
            .with_trace(
                DiagnosticTraceKind::ResourceRequired,
                required.min(u32::MAX as usize) as u32,
            )
            .with_trace(
                DiagnosticTraceKind::ResourceAvailable,
                available.min(u32::MAX as usize) as u32,
            ),
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskGroupStackMemory {
            owner,
            required,
            available,
            largest_contiguous,
        } => BackendError::new(BackendErrorClass::ResourceUnavailable, 0x5732_a000 | code)
            .with_trace(DiagnosticTraceKind::ResourceOwner, owner.into_raw().get())
            .with_trace(
                DiagnosticTraceKind::ResourceRequired,
                required.min(u32::MAX as usize) as u32,
            )
            .with_trace(
                DiagnosticTraceKind::ResourceAvailable,
                available.min(u32::MAX as usize) as u32,
            )
            .with_trace(
                DiagnosticTraceKind::LargestContiguous,
                largest_contiguous.min(u32::MAX as usize) as u32,
            ),
    };
    backend = backend
        .with_stage(DiagnosticStage::Runtime)
        .with_profile_revision(crate::profile::PROFILE_REVISION);
    Error::Backend(backend).diagnostic()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use hisi_rf_core::{DiagnosticCode, RecoveryAction};

    use super::*;

    #[test]
    fn task_admission_error_is_actionable_and_lossless() {
        let error = InitError::task_admission(
            hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskSlots {
                required: 7,
                available: 3,
            },
        );
        assert_eq!(error.kind(), InitErrorKind::TaskAdmission);
        let diagnostic = error.diagnostic();

        assert_eq!(diagnostic.code(), DiagnosticCode::ResourceUnavailable);
        assert_eq!(diagnostic.stage(), DiagnosticStage::Runtime);
        assert_eq!(diagnostic.action(), RecoveryAction::ProvideResources);
        assert_eq!(
            diagnostic.profile_revision(),
            Some(crate::profile::PROFILE_REVISION)
        );
        assert_eq!(
            diagnostic.trace().get(0).map(|entry| entry.value()),
            Some(7)
        );
        assert_eq!(
            diagnostic.trace().get(1).map(|entry| entry.value()),
            Some(3)
        );
    }

    #[test]
    fn task_stack_admission_error_reports_exact_bytes_without_secrets() {
        let diagnostic = InitError::task_admission(
            hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskStackMemory {
                required: 144 * 1024,
                available: 120 * 1024,
            },
        )
        .diagnostic();

        assert_eq!(diagnostic.code(), DiagnosticCode::ResourceUnavailable);
        assert_eq!(diagnostic.stage(), DiagnosticStage::Runtime);
        assert_eq!(diagnostic.action(), RecoveryAction::ProvideResources);
        assert_eq!(
            diagnostic.trace().get(0).map(|entry| entry.value()),
            Some(144 * 1024)
        );
        assert_eq!(
            diagnostic.trace().get(1).map(|entry| entry.value()),
            Some(120 * 1024)
        );
    }

    #[test]
    fn grouped_stack_error_reports_owner_and_largest_contiguous_block() {
        let owner = hisi_rf_rtos_driver::TaskResourceOwner::new(
            NonZeroU32::new(crate::profile::resource_owner::INCREMENTAL_WORKER).unwrap(),
        );
        let diagnostic = InitError::task_admission(
            hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskGroupStackMemory {
                owner,
                required: 8 * 1024,
                available: 0,
                largest_contiguous: 7 * 1024,
            },
        )
        .diagnostic();

        assert_eq!(diagnostic.code(), DiagnosticCode::ResourceUnavailable);
        let trace = diagnostic.trace();
        assert_eq!(
            trace.get(0).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::ResourceOwner)
        );
        assert_eq!(
            trace.get(0).map(|entry| entry.value()),
            Some(owner.into_raw().get())
        );
        assert_eq!(
            trace.get(1).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::ResourceRequired)
        );
        assert_eq!(trace.get(1).map(|entry| entry.value()), Some(8 * 1024));
        assert_eq!(
            trace.get(2).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::ResourceAvailable)
        );
        assert_eq!(trace.get(2).map(|entry| entry.value()), Some(0));
        assert_eq!(
            trace.get(3).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::LargestContiguous)
        );
        assert_eq!(trace.get(3).map(|entry| entry.value()), Some(7 * 1024));
    }

    #[test]
    fn runtime_and_storage_failures_share_the_public_schema() {
        let timeout = InitError::runtime(hisi_rf_rtos_driver::Error::TimedOut).diagnostic();
        assert_eq!(timeout.code(), DiagnosticCode::BackendTimeout);
        assert_eq!(timeout.stage(), DiagnosticStage::Runtime);

        let claimed = InitError::storage_already_claimed().diagnostic();
        assert_eq!(claimed.code(), DiagnosticCode::AlreadyInitialized);
    }

    #[test]
    fn initialization_json_never_contains_configuration_secrets() {
        let mut json = String::new();
        InitError::task_admission(
            hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskSlots {
                required: 7,
                available: 3,
            },
        )
        .diagnostic()
        .write_json(&mut json)
        .unwrap();

        assert!(json.contains("resource.unavailable"));
        assert!(!json.contains("ssid"));
        assert!(!json.contains("passphrase"));
        assert!(!json.contains("secret"));
    }

    #[cfg(all(feature = "data-path-diag", not(feature = "rf-eloop-diag")))]
    #[test]
    fn data_path_diagnostics_claim_all_bounded_boundaries() {
        assert_eq!(DATA_PATH_DIAG_CAPABILITIES, 0x3f);
    }

    #[cfg(feature = "rf-eloop-diag")]
    #[test]
    fn full_data_path_diagnostics_claim_every_returned_boundary() {
        assert_eq!(DATA_PATH_DIAG_CAPABILITIES, 0x3f);
    }
}
