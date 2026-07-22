//! WS63 implementation of the chip-neutral `hisi-rf` control contract.

use hisi_crypto_ws63::Ws63CryptoStorage;
use hisi_hal::peripherals::{Efuse, Km, Pke, Spacc, Trng};
use hisi_rf_core::{
    BackendError, BackendErrorClass, ConnectionInfo, DiagnosticStage, DiagnosticTraceKind,
    ScanConfig, ScanOutcome, ScanResult, Security, Ssid, StationConfig, WifiBackend,
};

fn backend_error(class: BackendErrorClass, code: u32) -> BackendError {
    BackendError::new(class, code).with_profile_revision(crate::profile::PROFILE_REVISION)
}

fn staged_error(class: BackendErrorClass, code: u32, stage: DiagnosticStage) -> BackendError {
    backend_error(class, code).with_stage(stage)
}

#[cfg(feature = "upstream-supplicant-port")]
const NATIVE_EVENT_AUTHORIZED: u8 = 3;
#[cfg(feature = "upstream-supplicant-port")]
const NATIVE_EVENT_DISCONNECTED: u8 = 4;
#[cfg(feature = "upstream-supplicant-port")]
const NATIVE_EVENT_FAILED: u8 = 5;

#[cfg(feature = "upstream-supplicant-port")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeConnectEvent {
    Progress,
    Authorized,
    Disconnected,
    Failed,
}

#[cfg(feature = "upstream-supplicant-port")]
const fn classify_native_connect_event(kind: u8) -> NativeConnectEvent {
    match kind {
        NATIVE_EVENT_AUTHORIZED => NativeConnectEvent::Authorized,
        NATIVE_EVENT_DISCONNECTED => NativeConnectEvent::Disconnected,
        NATIVE_EVENT_FAILED => NativeConnectEvent::Failed,
        _ => NativeConnectEvent::Progress,
    }
}

#[cfg(feature = "net")]
use crate::netif_smoltcp::Ws63Device;
#[cfg(not(feature = "upstream-supplicant-port"))]
use crate::wifi::{ConnectionInfo as Ws63ConnectionInfo, PersonalNetwork, WpaWifi as ActiveWifi};
use crate::wifi::{
    Error as Ws63Error, MAX_SCAN_RESULTS, ScanResult as Ws63ScanResult, ScanSecurity,
};
#[cfg(feature = "upstream-supplicant-port")]
use crate::{
    upstream_supplicant::{NativeSupplicant, NativeSupplicantError},
    wifi::Wifi as ActiveWifi,
};
#[cfg(feature = "net")]
use hisi_rf_core::RadioResources;

/// WS63 control-plane resources before the vendor runtime is initialized.
pub struct Ws63WifiBackend<'d> {
    efuse: Option<Efuse<'d>>,
    km: Option<Km<'d>>,
    spacc: Option<Spacc<'d>>,
    pke: Option<Pke<'d>>,
    trng: Option<Trng<'d>>,
    crypto_storage: Option<&'static mut Ws63CryptoStorage>,
    wifi: Option<ActiveWifi<'d>>,
    #[cfg(feature = "upstream-supplicant-port")]
    supplicant: Option<NativeSupplicant>,
    scans: [Ws63ScanResult; MAX_SCAN_RESULTS],
    scan_count: usize,
}

impl<'d> Ws63WifiBackend<'d> {
    /// Bind the one-shot eFuse token needed by the WS63 vendor runtime.
    pub fn new(
        efuse: Efuse<'d>,
        km: Km<'d>,
        spacc: Spacc<'d>,
        pke: Pke<'d>,
        trng: Trng<'d>,
        crypto_storage: &'static mut Ws63CryptoStorage,
    ) -> Self {
        Self {
            efuse: Some(efuse),
            km: Some(km),
            spacc: Some(spacc),
            pke: Some(pke),
            trng: Some(trng),
            crypto_storage: Some(crypto_storage),
            wifi: None,
            #[cfg(feature = "upstream-supplicant-port")]
            supplicant: None,
            scans: [Ws63ScanResult::empty(); MAX_SCAN_RESULTS],
            scan_count: 0,
        }
    }
}

impl WifiBackend for Ws63WifiBackend<'static> {
    fn initialize(&mut self, _: &hisi_rf_core::WifiConfig) -> Result<(), BackendError> {
        if self.wifi.is_some() {
            return Ok(());
        }
        let efuse = self
            .efuse
            .take()
            .ok_or_else(|| backend_error(BackendErrorClass::Initialize, 0x1000_0001))?;
        let trng = self
            .trng
            .take()
            .ok_or_else(|| backend_error(BackendErrorClass::Initialize, 0x1000_0004))?;
        let km = self
            .km
            .take()
            .ok_or_else(|| backend_error(BackendErrorClass::Initialize, 0x1000_0005))?;
        let spacc = self
            .spacc
            .take()
            .ok_or_else(|| backend_error(BackendErrorClass::Initialize, 0x1000_0006))?;
        let pke = self
            .pke
            .take()
            .ok_or_else(|| backend_error(BackendErrorClass::Initialize, 0x1000_0007))?;
        let crypto_storage = self
            .crypto_storage
            .take()
            .ok_or_else(|| backend_error(BackendErrorClass::Initialize, 0x1000_0008))?;
        crate::crypto::install_hardware_crypto(km, spacc, pke, trng, crypto_storage)
            .map_err(|error| backend_error(BackendErrorClass::Initialize, error.code()))?;
        #[cfg(target_arch = "riscv32")]
        crate::crypto::ws63_pbkdf2_self_test()
            .map_err(|error| backend_error(BackendErrorClass::Initialize, error.code()))?;
        #[cfg(target_arch = "riscv32")]
        crate::crypto::ws63_hash_self_test()
            .map_err(|error| backend_error(BackendErrorClass::Initialize, error.code()))?;
        #[cfg(all(target_arch = "riscv32", feature = "upstream-supplicant-wpa3"))]
        crate::crypto::ws63_p256_self_test()
            .map_err(|error| backend_error(BackendErrorClass::Initialize, error.code()))?;
        #[cfg(all(target_arch = "riscv32", feature = "rf-eloop-diag"))]
        crate::crypto::ws63_hash_fault_recovery_self_test()
            .map_err(|error| backend_error(BackendErrorClass::Initialize, error.code()))?;
        #[cfg(all(target_arch = "riscv32", feature = "rf-eloop-diag"))]
        crate::crypto::ws63_cipher_fault_recovery_self_test()
            .map_err(|error| backend_error(BackendErrorClass::Initialize, error.code()))?;
        #[cfg(all(target_arch = "riscv32", feature = "rf-crypto-contention-diag"))]
        crate::crypto::ws63_crypto_contention_self_test()
            .map_err(|error| backend_error(BackendErrorClass::Initialize, error.code()))?;
        let wifi = ActiveWifi::initialize(efuse).map_err(map_error)?;
        #[cfg(feature = "upstream-supplicant-port")]
        {
            self.supplicant =
                Some(NativeSupplicant::create(wifi.interface_name()).map_err(map_native_error)?);
        }
        self.wifi = Some(wifi);
        Ok(())
    }

    fn scan(
        &mut self,
        config: ScanConfig,
        output: &mut [ScanResult],
    ) -> Result<ScanOutcome, BackendError> {
        #[cfg(feature = "upstream-supplicant-port")]
        self.supplicant
            .as_mut()
            .ok_or(not_initialized())?
            .begin_scan_cache_capture()
            .map_err(map_native_error)?;

        let scan = match self.wifi.as_mut() {
            Some(wifi) => wifi.scan(&mut self.scans, config.timeout_ms()),
            None => {
                #[cfg(feature = "upstream-supplicant-port")]
                if let Some(supplicant) = self.supplicant.as_mut() {
                    supplicant.cancel_scan_cache_capture();
                }
                return Err(not_initialized());
            }
        };
        self.scan_count = match scan {
            Ok(count) => count,
            Err(error) => {
                #[cfg(feature = "upstream-supplicant-port")]
                if let Some(supplicant) = self.supplicant.as_mut() {
                    supplicant.cancel_scan_cache_capture();
                }
                return Err(map_error(error));
            }
        };

        #[cfg(feature = "upstream-supplicant-port")]
        match self.supplicant.as_mut() {
            Some(supplicant) => supplicant
                .finish_scan_cache_capture()
                .map_err(map_native_error)?,
            None => return Err(not_initialized()),
        }

        let mut written = 0;
        for scan in &self.scans[..self.scan_count] {
            let Some(ssid) = Ssid::try_from_bytes(scan.ssid()) else {
                continue;
            };
            if written == output.len() {
                break;
            }
            output[written] = ScanResult {
                ssid,
                bssid: scan.bssid,
                frequency_mhz: scan.frequency_mhz,
                rssi_dbm: scan.rssi_dbm,
                security: match scan.security() {
                    ScanSecurity::Open => Security::Open,
                    #[cfg(any(
                        feature = "wifi-wpa3-personal",
                        feature = "upstream-supplicant-wpa3"
                    ))]
                    ScanSecurity::Protected if scan.supports_wpa2_wpa3_transition() => {
                        Security::Wpa2Wpa3PersonalTransition
                    }
                    #[cfg(any(
                        feature = "wifi-wpa3-personal",
                        feature = "upstream-supplicant-wpa3"
                    ))]
                    ScanSecurity::Protected if scan.supports_wpa3_personal() => {
                        Security::Wpa3Personal
                    }
                    ScanSecurity::Protected if scan.supports_wpa2_personal() => {
                        Security::Wpa2Personal
                    }
                    ScanSecurity::Protected => Security::OtherProtected,
                },
                channel: scan.channel(),
            };
            written += 1;
        }
        Ok(ScanOutcome {
            count: written,
            truncated: written < self.scan_count,
        })
    }

    fn connect(&mut self, config: &StationConfig) -> Result<ConnectionInfo, BackendError> {
        #[cfg(feature = "upstream-supplicant-port")]
        {
            let supplicant = self.supplicant.as_mut().ok_or(not_initialized())?;
            supplicant.configure(config).map_err(map_native_error)?;
            supplicant.connect().map_err(map_native_error)?;
            let started_at = crate::uapi::monotonic_ms();
            let mut last_event_kind = 0_u8;
            let mut last_disconnect_status = None;
            loop {
                supplicant
                    .poll(core::num::NonZeroU32::new(32).unwrap())
                    .map_err(map_native_error)?;
                while let Some(event) = supplicant.next_event().map_err(map_native_error)? {
                    last_event_kind = event.kind;
                    match classify_native_connect_event(event.kind) {
                        NativeConnectEvent::Progress => {}
                        NativeConnectEvent::Authorized => {
                            return Ok(ConnectionInfo {
                                bssid: config.bssid,
                                frequency_mhz: channel_to_frequency(config.channel),
                            });
                        }
                        NativeConnectEvent::Disconnected => {
                            // DISCONNECTED is an intermediate supplicant state,
                            // not a terminal connect result. In particular,
                            // hostap retries association after temporary PMF
                            // rejection and other recoverable driver failures.
                            // Keep driving its event loop until AUTHORIZED or
                            // the caller's overall connect deadline expires.
                            if event.status != 0 {
                                last_disconnect_status = Some(event.status);
                            }
                        }
                        NativeConnectEvent::Failed => {
                            return Err(emit_backend_failure(supplicant, event.status));
                        }
                    }
                }
                if crate::uapi::monotonic_ms().wrapping_sub(started_at)
                    >= config.timeout_ms() as u64
                {
                    if let Some(status) = last_disconnect_status {
                        let error = emit_backend_failure(supplicant, status);
                        let _ = supplicant.disconnect();
                        return Err(error);
                    }
                    let context_diagnostic = supplicant.context_diagnostic_word();
                    let port_diagnostic = crate::upstream_supplicant::diagnostic_word();
                    let eapol = crate::upstream_supplicant::eapol_diagnostic_snapshot();
                    let mut attempts =
                        [crate::upstream_supplicant::AssociationAttemptDiagnostic::default(); 8];
                    let attempt_count =
                        crate::upstream_supplicant::association_attempt_diagnostics(&mut attempts);
                    let latest_attempt = attempt_count.checked_sub(1).map(|index| attempts[index]);
                    let _ = supplicant.disconnect();
                    return Err(connect_timeout_error(
                        last_event_kind,
                        context_diagnostic,
                        port_diagnostic,
                        latest_attempt,
                        eapol[2],
                    ));
                }
                hisi_rf_rtos_driver::sleep_ms(core::num::NonZeroU32::new(1).unwrap()).map_err(
                    |error| {
                        let code = runtime_code(error);
                        staged_error(
                            BackendErrorClass::Other,
                            0x5732_e000 | code,
                            DiagnosticStage::Runtime,
                        )
                        .with_trace(DiagnosticTraceKind::RuntimeCode, code)
                    },
                )?;
            }
        }
        #[cfg(not(feature = "upstream-supplicant-port"))]
        {
            let wifi = self.wifi.as_mut().ok_or(not_initialized())?;
            let scan = self.scans[..self.scan_count]
                .iter()
                .find(|scan| {
                    scan.ssid() == config.ssid.as_bytes()
                        && scan.bssid == config.bssid
                        && scan.channel() == config.channel
                })
                .ok_or_else(|| {
                    staged_error(
                        BackendErrorClass::Connect,
                        0x1000_0002,
                        DiagnosticStage::Associate,
                    )
                })?;
            let network = PersonalNetwork::from_scan_with_security(
                scan,
                config.passphrase.expose_secret(),
                config.security(),
            )
            .map_err(map_error)?;
            wifi.connect(&network, config.timeout_ms())
                .map(to_connection_info)
                .map_err(map_error)
        }
    }

    fn disconnect(&mut self, config: &hisi_rf_core::WifiConfig) -> Result<(), BackendError> {
        #[cfg(feature = "upstream-supplicant-port")]
        {
            let supplicant = self.supplicant.as_mut().ok_or(not_initialized())?;
            supplicant.disconnect().map_err(map_native_error)?;
            let started_at = crate::uapi::monotonic_ms();
            loop {
                supplicant
                    .poll(core::num::NonZeroU32::new(32).unwrap())
                    .map_err(map_native_error)?;
                while let Some(event) = supplicant.next_event().map_err(map_native_error)? {
                    match event.kind {
                        NATIVE_EVENT_DISCONNECTED => return Ok(()),
                        NATIVE_EVENT_FAILED => {
                            return Err(staged_error(
                                BackendErrorClass::Connect,
                                event.status as u32,
                                DiagnosticStage::Disconnect,
                            )
                            .with_trace(
                                DiagnosticTraceKind::DisconnectReason,
                                event.status as u32,
                            ));
                        }
                        _ => {}
                    }
                }
                if crate::uapi::monotonic_ms().wrapping_sub(started_at)
                    >= config.disconnect_timeout_ms as u64
                {
                    return Err(staged_error(
                        BackendErrorClass::Timeout,
                        2,
                        DiagnosticStage::Disconnect,
                    ));
                }
                hisi_rf_rtos_driver::sleep_ms(core::num::NonZeroU32::new(1).unwrap()).map_err(
                    |error| {
                        let code = runtime_code(error);
                        staged_error(
                            BackendErrorClass::Other,
                            0x5732_e000 | code,
                            DiagnosticStage::Runtime,
                        )
                        .with_trace(DiagnosticTraceKind::RuntimeCode, code)
                    },
                )?;
            }
        }
        #[cfg(not(feature = "upstream-supplicant-port"))]
        {
            self.wifi
                .as_mut()
                .ok_or(not_initialized())?
                .disconnect(config.disconnect_timeout_ms)
                .map_err(map_error)
        }
    }

    fn poll(&mut self) -> Result<bool, BackendError> {
        #[cfg(feature = "upstream-supplicant-port")]
        {
            let Some(supplicant) = self.supplicant.as_mut() else {
                return Ok(false);
            };
            let result = supplicant
                .poll(core::num::NonZeroU32::new(32).unwrap())
                .map_err(map_native_error)?;
            Ok(result.work_pending != 0)
        }
        #[cfg(not(feature = "upstream-supplicant-port"))]
        {
            Ok(false)
        }
    }
}

#[cfg(feature = "upstream-supplicant-port")]
fn emit_backend_failure(supplicant: &NativeSupplicant, status: i32) -> BackendError {
    let context_diagnostic = supplicant.context_diagnostic_word();
    let port_diagnostic = crate::upstream_supplicant::diagnostic_word();
    crate::log_emit(b"RFDBG_WPA_BACKEND_ERR status=");
    crate::upstream_supplicant::emit_diagnostic_hex(status as u32);
    crate::log_emit(b" context=");
    crate::upstream_supplicant::emit_diagnostic_hex(context_diagnostic);
    crate::log_emit(b" port=");
    crate::upstream_supplicant::emit_diagnostic_hex(port_diagnostic);
    crate::log_emit(b"\r\n");
    // The UART sink is best-effort while the radio runner and vendor workers
    // are active. Preserve the raw status and the same bounded snapshots in
    // the public error so machine diagnostics never depend on that log.
    backend_failure_error(status, context_diagnostic, port_diagnostic)
}

#[cfg(feature = "upstream-supplicant-port")]
fn backend_failure_error(
    status: i32,
    context_diagnostic: u32,
    port_diagnostic: u32,
) -> BackendError {
    staged_error(
        BackendErrorClass::Connect,
        status as u32,
        terminal_connect_stage(status),
    )
    .with_trace(DiagnosticTraceKind::IeeeStatus, status as u32)
    .with_trace(DiagnosticTraceKind::SupplicantContext, context_diagnostic)
    .with_trace(DiagnosticTraceKind::DriverContext, port_diagnostic)
}

#[cfg(feature = "upstream-supplicant-port")]
const fn terminal_connect_stage(status: i32) -> DiagnosticStage {
    if status == 30 {
        // IEEE 802.11 status 30 is a temporary association rejection. On the
        // required-PMF path hostap handles it through SA Query/comeback logic.
        DiagnosticStage::Pmf
    } else {
        DiagnosticStage::Associate
    }
}

#[cfg(feature = "upstream-supplicant-port")]
fn classify_connect_timeout_stage(
    latest: Option<crate::upstream_supplicant::AssociationAttemptDiagnostic>,
    eapol_received: u32,
) -> DiagnosticStage {
    match latest {
        Some(attempt) if attempt.status == 0 && eapol_received == 0 => DiagnosticStage::Eapol,
        Some(attempt) if attempt.status == 30 => DiagnosticStage::Pmf,
        _ => DiagnosticStage::Connect,
    }
}

#[cfg(feature = "upstream-supplicant-port")]
fn connect_timeout_error(
    last_event_kind: u8,
    context_diagnostic: u32,
    port_diagnostic: u32,
    latest_attempt: Option<crate::upstream_supplicant::AssociationAttemptDiagnostic>,
    eapol_received: u32,
) -> BackendError {
    let mut error = staged_error(
        BackendErrorClass::Timeout,
        0x8000_0000
            | ((last_event_kind as u32 & 0x7) << 28)
            | ((context_diagnostic & 0x0fff) << 16)
            | port_diagnostic,
        classify_connect_timeout_stage(latest_attempt, eapol_received),
    )
    .with_trace(DiagnosticTraceKind::SupplicantContext, context_diagnostic)
    .with_trace(DiagnosticTraceKind::DriverContext, port_diagnostic);
    if let Some(attempt) = latest_attempt {
        error = error
            .with_trace(DiagnosticTraceKind::VendorStatus, attempt.raw_status)
            .with_trace(DiagnosticTraceKind::IeeeStatus, attempt.status);
    }
    error
}

/// Build the WS63 resources consumed by `hisi_rf_core::init`.
#[cfg(feature = "net")]
pub fn resources(
    efuse: Efuse<'static>,
    km: Km<'static>,
    spacc: Spacc<'static>,
    pke: Pke<'static>,
    trng: Trng<'static>,
    crypto_storage: &'static mut Ws63CryptoStorage,
) -> RadioResources<Ws63WifiBackend<'static>, Ws63Device> {
    RadioResources {
        backend: Ws63WifiBackend::new(efuse, km, spacc, pke, trng, crypto_storage),
        device: Ws63Device,
    }
}

#[cfg(not(feature = "upstream-supplicant-port"))]
fn to_connection_info(info: Ws63ConnectionInfo) -> ConnectionInfo {
    ConnectionInfo {
        bssid: info.bssid,
        frequency_mhz: info.frequency_mhz,
    }
}

fn not_initialized() -> BackendError {
    backend_error(BackendErrorClass::Initialize, 0x1000_0003)
}

fn map_error(error: Ws63Error) -> BackendError {
    let raw = ws63_error_trace(error);
    let (class, code, stage) = match error {
        Ws63Error::Initialize(code) => (
            BackendErrorClass::Initialize,
            code,
            DiagnosticStage::Initialize,
        ),
        Ws63Error::Busy => (BackendErrorClass::Busy, 1, DiagnosticStage::Operation),
        Ws63Error::Timeout => (BackendErrorClass::Timeout, 1, DiagnosticStage::Operation),
        Ws63Error::UnsupportedSecurity(mode) => (
            BackendErrorClass::UnsupportedSecurity,
            mode as u32,
            DiagnosticStage::Connect,
        ),
        Ws63Error::ConnectFailed(status) => (
            BackendErrorClass::Connect,
            status as u32,
            DiagnosticStage::Associate,
        ),
        Ws63Error::Disconnected(reason) => (
            BackendErrorClass::Connect,
            reason as u32,
            DiagnosticStage::Disconnect,
        ),
        Ws63Error::ConfigureSecurity(code) | Ws63Error::StartConnect(code) => (
            BackendErrorClass::Connect,
            code as u32,
            DiagnosticStage::Connect,
        ),
        Ws63Error::StartDisconnect(code) => (
            BackendErrorClass::Connect,
            code as u32,
            DiagnosticStage::Disconnect,
        ),
        Ws63Error::Runtime(code) => (
            BackendErrorClass::Other,
            0x2000_0000 | runtime_code(code),
            DiagnosticStage::Runtime,
        ),
        Ws63Error::TaskAdmission(error) => (
            BackendErrorClass::Initialize,
            0x2100_0000 | task_admission_code(error),
            DiagnosticStage::Runtime,
        ),
        Ws63Error::AlreadyInitialized => (
            BackendErrorClass::Initialize,
            2,
            DiagnosticStage::Initialize,
        ),
        #[cfg(feature = "upstream-supplicant-port")]
        Ws63Error::SupplicantPort(_) => (
            BackendErrorClass::Initialize,
            3,
            DiagnosticStage::Initialize,
        ),
        Ws63Error::CreateStation(code)
        | Ws63Error::RegisterEvents(code)
        | Ws63Error::OpenStation(code) => (
            BackendErrorClass::Other,
            code as u32,
            DiagnosticStage::Initialize,
        ),
        Ws63Error::StartScan(code) => {
            (BackendErrorClass::Other, code as u32, DiagnosticStage::Scan)
        }
        Ws63Error::CryptoInitialize(code) => (
            BackendErrorClass::Initialize,
            code as u32,
            DiagnosticStage::Initialize,
        ),
        Ws63Error::Timebase(code) => (BackendErrorClass::Other, code, DiagnosticStage::Runtime),
        Ws63Error::Crypto(code) => (BackendErrorClass::Other, code, DiagnosticStage::Connect),
        Ws63Error::ScanFailed(status) => (
            BackendErrorClass::Other,
            scan_status_code(status),
            DiagnosticStage::Scan,
        ),
        Ws63Error::InvalidSsid => (BackendErrorClass::Other, 0x100, DiagnosticStage::Scan),
        Ws63Error::ProtectedNetwork | Ws63Error::OpenNetwork | Ws63Error::InvalidPassphrase => (
            BackendErrorClass::UnsupportedSecurity,
            0x101,
            DiagnosticStage::Connect,
        ),
        Ws63Error::UnsupportedTarget => (
            BackendErrorClass::Other,
            u32::MAX,
            DiagnosticStage::Initialize,
        ),
    };
    let mapped = staged_error(class, code, stage);
    match raw {
        Some((kind, value)) => mapped.with_trace(kind, value),
        None => mapped,
    }
}

fn ws63_error_trace(error: Ws63Error) -> Option<(DiagnosticTraceKind, u32)> {
    let vendor = |value| Some((DiagnosticTraceKind::VendorStatus, value));
    match error {
        Ws63Error::Initialize(code) | Ws63Error::Timebase(code) | Ws63Error::Crypto(code) => {
            vendor(code)
        }
        Ws63Error::CreateStation(code)
        | Ws63Error::RegisterEvents(code)
        | Ws63Error::OpenStation(code)
        | Ws63Error::UnsupportedSecurity(code)
        | Ws63Error::CryptoInitialize(code)
        | Ws63Error::StartScan(code)
        | Ws63Error::ConfigureSecurity(code)
        | Ws63Error::StartConnect(code)
        | Ws63Error::StartDisconnect(code) => vendor(code as u32),
        Ws63Error::ScanFailed(status) => vendor(scan_status_code(status)),
        Ws63Error::ConnectFailed(status) => {
            Some((DiagnosticTraceKind::IeeeStatus, u32::from(status)))
        }
        Ws63Error::Disconnected(reason) => {
            Some((DiagnosticTraceKind::DisconnectReason, u32::from(reason)))
        }
        _ => None,
    }
}

#[cfg(feature = "upstream-supplicant-port")]
fn map_native_error(error: NativeSupplicantError) -> BackendError {
    let raw_status = match error {
        NativeSupplicantError::InitializeFailed(status)
        | NativeSupplicantError::EnableEapolFailed(status)
        | NativeSupplicantError::FeedMgmtFailed(status)
        | NativeSupplicantError::FeedScanFailed(status)
        | NativeSupplicantError::FeedLinkFailed(status)
        | NativeSupplicantError::FeedExternalAuthFailed(status)
        | NativeSupplicantError::FeedEapolFailed(status)
        | NativeSupplicantError::ConfigureFailed(status)
        | NativeSupplicantError::ConnectFailed(status)
        | NativeSupplicantError::DisconnectFailed(status)
        | NativeSupplicantError::PollFailed(status) => Some(status as u32),
        NativeSupplicantError::MgmtQueueOverflow(count)
        | NativeSupplicantError::ScanQueueOverflow(count)
        | NativeSupplicantError::LinkQueueOverflow(count)
        | NativeSupplicantError::ExternalAuthQueueOverflow(count) => Some(count),
        NativeSupplicantError::Port(_)
        | NativeSupplicantError::InvalidContextLayout
        | NativeSupplicantError::AllocationFailed
        | NativeSupplicantError::CreateFailed
        | NativeSupplicantError::InvalidResult => None,
    };
    let (class, code, stage) = match error {
        NativeSupplicantError::Port(_) => (
            BackendErrorClass::Initialize,
            1,
            DiagnosticStage::Initialize,
        ),
        NativeSupplicantError::InvalidContextLayout => (
            BackendErrorClass::Initialize,
            2,
            DiagnosticStage::Initialize,
        ),
        NativeSupplicantError::AllocationFailed => (
            BackendErrorClass::Initialize,
            3,
            DiagnosticStage::Initialize,
        ),
        NativeSupplicantError::CreateFailed => (
            BackendErrorClass::Initialize,
            4,
            DiagnosticStage::Initialize,
        ),
        NativeSupplicantError::InitializeFailed(status) => (
            BackendErrorClass::Initialize,
            0x1000 | status as u32 & 0xfff,
            DiagnosticStage::Initialize,
        ),
        NativeSupplicantError::EnableEapolFailed(status) => (
            BackendErrorClass::Initialize,
            0x2000 | status as u32 & 0xfff,
            DiagnosticStage::Eapol,
        ),
        NativeSupplicantError::FeedMgmtFailed(status) => (
            BackendErrorClass::Other,
            0x3000 | status as u32 & 0xfff,
            DiagnosticStage::Authenticate,
        ),
        NativeSupplicantError::FeedEapolFailed(status) => (
            BackendErrorClass::Other,
            0x4000 | status as u32 & 0xfff,
            DiagnosticStage::Eapol,
        ),
        NativeSupplicantError::MgmtQueueOverflow(count) => (
            BackendErrorClass::Other,
            0x6000 | count.min(0xfff),
            DiagnosticStage::Authenticate,
        ),
        NativeSupplicantError::FeedScanFailed(status) => (
            BackendErrorClass::Other,
            0x7000 | status as u32 & 0xfff,
            DiagnosticStage::Scan,
        ),
        NativeSupplicantError::ScanQueueOverflow(count) => (
            BackendErrorClass::Other,
            0x8000 | count.min(0xfff),
            DiagnosticStage::Scan,
        ),
        NativeSupplicantError::FeedLinkFailed(status) => (
            BackendErrorClass::Connect,
            0x9000 | status as u32 & 0xfff,
            DiagnosticStage::Associate,
        ),
        NativeSupplicantError::LinkQueueOverflow(count) => (
            BackendErrorClass::Connect,
            0xa000 | count.min(0xfff),
            DiagnosticStage::Associate,
        ),
        NativeSupplicantError::FeedExternalAuthFailed(status) => (
            BackendErrorClass::Connect,
            0xe000 | status as u32 & 0xfff,
            DiagnosticStage::Sae,
        ),
        NativeSupplicantError::ExternalAuthQueueOverflow(count) => (
            BackendErrorClass::Connect,
            0xf000 | count.min(0xfff),
            DiagnosticStage::Sae,
        ),
        NativeSupplicantError::ConfigureFailed(status) => (
            BackendErrorClass::Connect,
            0xb000 | status as u32 & 0xfff,
            DiagnosticStage::Connect,
        ),
        NativeSupplicantError::ConnectFailed(status) => (
            BackendErrorClass::Connect,
            0xc000 | status as u32 & 0xfff,
            DiagnosticStage::Associate,
        ),
        NativeSupplicantError::DisconnectFailed(status) => (
            BackendErrorClass::Connect,
            0xd000 | status as u32 & 0xfff,
            DiagnosticStage::Disconnect,
        ),
        NativeSupplicantError::InvalidResult => {
            (BackendErrorClass::Other, 5, DiagnosticStage::Backend)
        }
        NativeSupplicantError::PollFailed(status) => (
            BackendErrorClass::Other,
            0x5000 | status as u32 & 0xfff,
            DiagnosticStage::Runtime,
        ),
    };
    let mapped = staged_error(class, 0x5732_0000 | code, stage);
    let status_kind = match error {
        NativeSupplicantError::MgmtQueueOverflow(_)
        | NativeSupplicantError::ScanQueueOverflow(_)
        | NativeSupplicantError::LinkQueueOverflow(_)
        | NativeSupplicantError::ExternalAuthQueueOverflow(_) => DiagnosticTraceKind::BackendStatus,
        _ => DiagnosticTraceKind::HostapStatus,
    };
    match raw_status {
        Some(status) => mapped.with_trace(status_kind, status),
        None => mapped,
    }
}

#[cfg(feature = "upstream-supplicant-port")]
const fn channel_to_frequency(channel: u8) -> u16 {
    if channel == 14 {
        2484
    } else if channel >= 1 && channel <= 13 {
        2407 + channel as u16 * 5
    } else {
        0
    }
}

pub(crate) fn runtime_code(error: hisi_rf_rtos_driver::Error) -> u32 {
    use hisi_rf_rtos_driver::Error;
    match error {
        Error::NotInstalled => 1,
        Error::AlreadyInstalled => 2,
        Error::ResourceExhausted => 3,
        Error::NoTaskSlots => 4,
        Error::InvalidHandle => 5,
        Error::InvalidContext => 6,
        Error::TimedOut => 7,
        Error::Runtime => 8,
        Error::IncompatibleContract => 9,
        Error::IncompatibleExecutionProfile => 10,
    }
}

pub(crate) fn task_admission_code(error: hisi_rf_rtos_driver::TaskAdmissionError) -> u32 {
    match error {
        hisi_rf_rtos_driver::TaskAdmissionError::Runtime(error) => 0x1_0000 | runtime_code(error),
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskSlots {
            required,
            available,
        } => {
            let required = required.min(u8::MAX as usize) as u32;
            let available = available.min(u8::MAX as usize) as u32;
            (required << 8) | available
        }
    }
}

fn scan_status_code(status: crate::wifi::ScanStatus) -> u32 {
    use crate::wifi::ScanStatus;
    match status {
        ScanStatus::Success => 0,
        ScanStatus::Failed => 1,
        ScanStatus::Refused => 2,
        ScanStatus::Timeout => 3,
        ScanStatus::Unknown(code) => code,
    }
}

#[cfg(all(test, feature = "upstream-supplicant-port"))]
mod tests {
    use super::{
        NATIVE_EVENT_AUTHORIZED, NATIVE_EVENT_DISCONNECTED, NATIVE_EVENT_FAILED,
        NativeConnectEvent, backend_failure_error, classify_connect_timeout_stage,
        classify_native_connect_event, connect_timeout_error, map_error, map_native_error,
        task_admission_code, terminal_connect_stage,
    };
    use crate::upstream_supplicant::NativeSupplicantError;
    use crate::wifi::{Error as Ws63Error, ScanStatus};
    use hisi_rf_core::{DiagnosticCode, DiagnosticStage, DiagnosticTraceKind, RecoveryAction};

    #[test]
    fn disconnected_is_recoverable_until_the_overall_connect_deadline() {
        assert_eq!(
            classify_native_connect_event(NATIVE_EVENT_DISCONNECTED),
            NativeConnectEvent::Disconnected
        );
        assert_eq!(
            classify_native_connect_event(NATIVE_EVENT_FAILED),
            NativeConnectEvent::Failed
        );
        assert_eq!(
            classify_native_connect_event(NATIVE_EVENT_AUTHORIZED),
            NativeConnectEvent::Authorized
        );
        assert_eq!(
            classify_native_connect_event(1),
            NativeConnectEvent::Progress
        );
        assert_eq!(
            classify_native_connect_event(2),
            NativeConnectEvent::Progress
        );
    }

    #[test]
    fn admission_error_code_retains_required_and_available_slots() {
        assert_eq!(
            task_admission_code(
                hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskSlots {
                    required: 5,
                    available: 3,
                }
            ),
            0x0503
        );
    }

    #[test]
    fn native_error_mapping_preserves_stage_profile_and_raw_status() {
        let error = map_native_error(NativeSupplicantError::FeedExternalAuthFailed(-17));
        let diagnostic = error.diagnostic();

        assert_eq!(diagnostic.stage(), DiagnosticStage::Sae);
        assert_eq!(
            diagnostic.profile_revision(),
            Some(crate::profile::PROFILE_REVISION)
        );
        assert_eq!(diagnostic.backend_code(), Some(0x5732_efef));
        assert_eq!(diagnostic.trace().len(), 1);
        let trace = diagnostic.trace().get(0).unwrap();
        assert_eq!(trace.kind(), DiagnosticTraceKind::HostapStatus);
        assert_eq!(trace.value(), (-17_i32) as u32);
    }

    #[test]
    fn diagnostic_source_matrix_preserves_unknown_numeric_statuses() {
        let vendor =
            map_error(Ws63Error::ScanFailed(ScanStatus::Unknown(0xdead_beef))).diagnostic();
        let ieee = map_error(Ws63Error::ConnectFailed(221)).diagnostic();
        let hostap = map_native_error(NativeSupplicantError::PollFailed(-117)).diagnostic();

        assert_eq!(vendor.code(), DiagnosticCode::BackendOther);
        assert_eq!(
            vendor.trace().get(0).unwrap().kind(),
            DiagnosticTraceKind::VendorStatus
        );
        assert_eq!(vendor.trace().get(0).unwrap().value(), 0xdead_beef);
        assert_eq!(ieee.code(), DiagnosticCode::ConnectionFailed);
        assert_eq!(
            ieee.trace().get(0).unwrap().kind(),
            DiagnosticTraceKind::IeeeStatus
        );
        assert_eq!(ieee.trace().get(0).unwrap().value(), 221);
        assert_eq!(hostap.code(), DiagnosticCode::BackendOther);
        assert_eq!(
            hostap.trace().get(0).unwrap().kind(),
            DiagnosticTraceKind::HostapStatus
        );
        assert_eq!(hostap.trace().get(0).unwrap().value(), (-117_i32) as u32);
    }

    #[test]
    fn connection_timeout_stage_uses_association_and_eapol_evidence() {
        let attempt = |status| crate::upstream_supplicant::AssociationAttemptDiagnostic {
            status,
            ..Default::default()
        };

        assert_eq!(
            classify_connect_timeout_stage(Some(attempt(0)), 0),
            DiagnosticStage::Eapol
        );
        assert_eq!(
            classify_connect_timeout_stage(Some(attempt(0)), 1),
            DiagnosticStage::Connect
        );
        assert_eq!(
            classify_connect_timeout_stage(Some(attempt(30)), 0),
            DiagnosticStage::Pmf
        );
        assert_eq!(
            classify_connect_timeout_stage(Some(attempt(221)), 0),
            DiagnosticStage::Connect
        );
        assert_eq!(
            classify_connect_timeout_stage(None, 0),
            DiagnosticStage::Connect
        );
    }

    #[test]
    fn ieee_temporary_rejection_is_classified_as_pmf() {
        assert_eq!(terminal_connect_stage(30), DiagnosticStage::Pmf);
        assert_eq!(terminal_connect_stage(0), DiagnosticStage::Associate);
        assert_eq!(terminal_connect_stage(17), DiagnosticStage::Associate);
    }

    #[test]
    fn production_connect_errors_preserve_association_and_first_eapol_evidence() {
        let rejected = backend_failure_error(30, 0x445, 0x123).diagnostic();
        assert_eq!(rejected.code(), DiagnosticCode::ConnectionFailed);
        assert_eq!(rejected.stage(), DiagnosticStage::Pmf);
        assert_eq!(rejected.action(), RecoveryAction::InspectNetworkAndRetry);
        assert_eq!(rejected.backend_code(), Some(30));
        assert_eq!(
            rejected.trace().get(0).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::IeeeStatus)
        );
        assert_eq!(rejected.trace().get(0).map(|entry| entry.value()), Some(30));

        let associated = crate::upstream_supplicant::AssociationAttemptDiagnostic {
            raw_status: 0,
            status: 0,
            ..Default::default()
        };
        let eapol_stall = connect_timeout_error(3, 0x423, 0x55, Some(associated), 0).diagnostic();
        assert_eq!(eapol_stall.code(), DiagnosticCode::BackendTimeout);
        assert_eq!(eapol_stall.stage(), DiagnosticStage::Eapol);
        assert_eq!(eapol_stall.action(), RecoveryAction::RetryOperation);
        assert_eq!(
            eapol_stall.profile_revision(),
            Some(crate::profile::PROFILE_REVISION)
        );
        assert_eq!(eapol_stall.trace().len(), 4);
        assert_eq!(
            eapol_stall.trace().get(0).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::SupplicantContext)
        );
        assert_eq!(
            eapol_stall.trace().get(1).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::DriverContext)
        );
        assert_eq!(
            eapol_stall.trace().get(2).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::VendorStatus)
        );
        assert_eq!(
            eapol_stall.trace().get(3).map(|entry| entry.kind()),
            Some(DiagnosticTraceKind::IeeeStatus)
        );
    }
}
