//! # hisi-rf-ws63 — WS63 radio backend and composition root
//!
//! The WS63 Wi-Fi/BLE/SLE radio ships as closed-source vendor static libraries
//! in the [`ws63-RF`] delivery (`libwifi_driver_dmac.a`, `libbg_common.a`, …)
//! plus the **runtime-agnostic porting contract** in `ws63-radio-sys/ws63-RF/include/port/`:
//! ~77 C functions any host runtime must implement (OSAL, OAL, FRW, HCC, WLAN,
//! log, UAPI) so the blobs can run on it.
//!
//! This crate is the **Rust implementation of that contract** for the `ws63-rs`
//! runtime — analogous to esp-hal's `esp-radio` OS-adapter. It defines the
//! contract functions as `#[unsafe(no_mangle)] extern "C"` symbols; when a
//! firmware links a vendor blob, the linker resolves the blob's undefined
//! `osal_* / oal_* / log_* / uapi_*` references to these Rust implementations.
//! It does **not** put any Rust into `ws63-RF` (that delivery stays
//! language-neutral so it can be ported to any runtime).
//!
//! ## Status — upstream WPA2/WPA3 connectivity verified on real WS63
//!
//! Implemented for real (usable today):
//! - **Memory** — `osal_kmalloc`/`osal_kfree` over a real heap ([`alloc`]);
//!   `malloc`/`free`/`memalign`/`oal_mem_*` back onto it ([`libc`], [`oal`]).
//! - **Scheduler** — `osal_kthread_*`, semaphores, mutexes and timed waits are
//!   adapters over the runtime-neutral `hisi-rf-rtos-driver` contract. The
//!   current WS63 firmware installs the native `hisi-rtos` backend.
//! - **Sync** — spinlocks + atomics ([`osal_sync`]); IRQ lock/restore (real
//!   `mstatus` CSR) + the bounded WS63 runtime ABI compatibility layer
//!   (`ArchIntLock`/`ArchIntRestore`, scheduler lock and diagnostics).
//! - **Timers** — a real ms software-timer service ([`timer`]):
//!   `osal_adapt_timer_*` / `frw_dmac_timer_*`, fired from the FRW worker loop.
//! - **FRW/HCC data path** ([`frw`], [`hcc`]) — a real message-node pool, the
//!   WiFi worker thread (on `sched`) and the host↔device message FIFO; the
//!   blob's protocol half drives them. Validated by `frw_hcc_selftest`.
//! - **netif → smoltcp** (`netif_smoltcp`, feature `net`) — a real
//!   `smoltcp::phy::Device` behind the netif seam: `driverif_input` feeds the RX
//!   queue, `TxToken` calls the TX sink. Validated by `netif_smoltcp_selftest`
//!   (an ARP request round-trips driver→smoltcp→driver).
//! - **Logging / securec** — `osal_printk`, `log_event_*`, `memset_s`/`memcpy_s`
//!   ([`log`]); string/time leaves ([`osal_ext`]).
//! - **Adaptation** — the full `osal_adapt_*` shim ([`osal_adapt`]).
//! - **ROM state** — `g_dmac_alg_main` / `g_mac_res_etc` resolve to their
//!   mask-ROM BSS addresses from `ws63_acore_rom.lds`; Rust must not shadow
//!   these fixed objects with guessed storage.
//!
//! Current connectivity path:
//! - **netif pbuf/TX/RX** ([`netif`]) — generated layout assertions and the
//!   Rust-visible L2 queue have passed DHCP, ARP and repeated ICMP HIL.
//! - **NVS/TRNG/crypto** — NVS reads use the read-only ACPU KV parser; upstream
//!   Personal profiles explicitly inject the WS63 TRNG and fallible
//!   KM/RKP/SPACC/PKE capabilities without silent software fallback.
//!
//! **What "symbol closure" means here.** The vendor blobs
//! (`libwifi_driver_{hmac,dmac,tcm}.a`, `libbg_common.a`, `libwifi_alg_*.a`,
//! `libwifi_rom_data.a`) link as one relocatable object against this crate, the
//! WS63 mask-ROM symbol table (`ws63-radio-sys/ws63-RF/rom/ws63_acore_rom.lds`) and compiler-rt
//! with **zero duplicate symbols**, and a `--gc-sections` link rooted at
//! `uapi_wifi_init` leaves a **residual of just two symbols**
//! (`__wifi_pkt_ram_begin__`/`__wifi_pkt_ram_end__` — firmware linker region
//! bounds, supplied by hisi-riscv-rt or an equivalent downstream layout). Reproduce with
//! `ws63-rf-rs/tools/mac-link-residual.sh`. The earlier "~96 missing" figure was
//! a whole-archive upper bound dominated by **off-path** BT-coexistence and
//! alternate-OS-adapter code that Wi-Fi init never reaches (0 BT symbols on the
//! reachability path).
//!
//! **Why a runnable Wi-Fi image is still hardware-in-the-loop:** the ROM symbols
//! are **real-silicon addresses** (an emulator without a populated mask ROM
//! cannot execute them). The original HiSilicon-toolchain blobs carry custom
//! relocations; the published `ws63-radio-blob` artifacts normalize those into
//! standard RISC-V relocations ahead of release, and `ws63-radio-sys` contributes
//! a relocatable ROM patch table. Stock `rust-lld` therefore completes the
//! firmware in one ordinary Cargo link. The runtime + data-path
//! plumbing (runtime adapter, FRW/HCC, timers and L2 device) is implemented and
//! self-tested standalone. Real silicon has completed upstream WPA2 and
//! transition-mode WPA3 association, DHCP, ARP, repeated ICMP and lease renewal.
//! The remaining W2 gates are tracked only in
//! `docs/plan/hisi-connectivity-stack.md`.
//!
//! [`ws63-RF`]: https://github.com/hispark-rs/ws63-RF

#![no_std]
#![feature(c_variadic)]
#![allow(non_upper_case_globals)] // contract symbols must match the C names exactly

#[cfg(test)]
extern crate std;

#[cfg(all(
    feature = "incremental-backend-experiment",
    not(feature = "upstream-supplicant-port")
))]
compile_error!("incremental-backend-experiment requires the upstream supplicant profile");

#[cfg(all(
    feature = "legacy-blocking-backend",
    feature = "incremental-backend-experiment"
))]
compile_error!("select either the bounded backend or the legacy blocking backend");

#[cfg(all(feature = "wifi-personal", feature = "upstream-supplicant-port"))]
compile_error!("select either a vendor supplicant profile or an upstream supplicant profile");

#[cfg(all(
    any(
        feature = "upstream-authenticator-wpa2",
        feature = "upstream-authenticator-wpa3"
    ),
    any(feature = "wifi-personal", feature = "upstream-supplicant-port")
))]
compile_error!("select either the AP authenticator or a STA supplicant profile");

#[cfg(all(
    feature = "upstream-authenticator-wpa2",
    feature = "upstream-authenticator-wpa3"
))]
compile_error!("select exactly one AP authenticator security profile");

#[cfg(all(feature = "wpa2-personal", feature = "wpa3-personal"))]
compile_error!("select exactly one WS63 Personal profile");

#[cfg(all(
    any(feature = "ble-init", feature = "sle-init"),
    any(
        feature = "wifi",
        feature = "wifi-personal",
        feature = "upstream-supplicant-port",
        feature = "upstream-authenticator-wpa2",
        feature = "upstream-authenticator-wpa3"
    )
))]
compile_error!(
    "the BLE B1 init profile is standalone; SLE S1 is also standalone until coexistence resources are proven"
);

#[cfg(all(feature = "ble-init", feature = "sle-init"))]
compile_error!("select exactly one standalone WS63 BGLE protocol profile");

#[cfg(all(
    feature = "net",
    feature = "upstream-supplicant-port",
    not(any(feature = "wpa2-personal", feature = "wpa3-personal"))
))]
compile_error!("select exactly one WS63 station profile: `wpa2-personal` or `wpa3-personal`");

#[cfg(all(test, not(target_arch = "riscv32")))]
mod host_test_support {
    use core::ffi::c_void;

    use ws63_radio_sys::supplicant::{DriverHooks, OsHooks};

    #[unsafe(no_mangle)]
    extern "C" fn hisi_wpa_os_install(_: *const OsHooks) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    extern "C" fn hisi_wpa_os_uninstall(_: *mut c_void) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    extern "C" fn hisi_wpa_driver_install(_: *const DriverHooks) -> i32 {
        0
    }
}

use core::cell::Cell;
use critical_section::Mutex;

#[cfg(all(
    target_arch = "riscv32",
    any(
        feature = "wifi-personal",
        feature = "upstream-supplicant-port",
        feature = "upstream-authenticator-wpa2",
        feature = "upstream-authenticator-wpa3",
        feature = "ble-init",
        feature = "sle-init"
    )
))]
mod link_contract {
    core::arch::global_asm!(include_str!(concat!(
        env!("OUT_DIR"),
        "/ws63-radio-link-contract.S"
    )));

    unsafe extern "C" {
        static __hisi_ws63_rf_link_roots: u8;
    }

    #[inline(never)]
    pub fn ensure() {
        // Keep the root-reference section in the final firmware so rust-lld
        // extracts the complete profile-selected native closure.
        unsafe { core::ptr::read_volatile(&raw const __hisi_ws63_rf_link_roots) };
    }
}

/// Force the internal BLE B1 archive and ROM contract into a firmware link.
///
/// This is a bring-up hook for the B1 link fixture, not a user-facing BLE API.
#[cfg(all(target_arch = "riscv32", feature = "ble-init"))]
#[doc(hidden)]
pub fn ensure_ble_init_link_contract() {
    link_contract::ensure();
}

/// Force the internal SLE S1/S2 archive and ROM contract into a firmware link.
#[cfg(all(target_arch = "riscv32", feature = "sle-init"))]
#[doc(hidden)]
pub fn ensure_sle_init_link_contract() {
    link_contract::ensure();
}

pub mod alloc;
#[cfg(feature = "ble-init")]
mod ble;
#[cfg(any(feature = "ble-init", feature = "sle-init"))]
mod ble_compat;
#[cfg(all(target_arch = "riscv32", feature = "ble-init-diag"))]
mod ble_init_diag;
#[cfg(any(
    target_arch = "riscv32",
    feature = "wifi-personal",
    feature = "upstream-supplicant-port"
))]
#[cfg_attr(
    all(
        target_arch = "riscv32",
        not(feature = "wifi-personal"),
        not(feature = "upstream-supplicant-port")
    ),
    allow(dead_code)
)]
mod blocking_diagnostics;
mod compiler_rt;
#[cfg(any(
    feature = "ble-init",
    feature = "sle-init",
    feature = "wifi-wpa2-personal",
    feature = "upstream-supplicant-port",
    feature = "upstream-authenticator-wpa2",
    feature = "upstream-authenticator-wpa3"
))]
#[cfg_attr(
    all(
        feature = "sle-init",
        not(feature = "ble-init"),
        not(feature = "wifi-wpa2-personal"),
        not(feature = "upstream-supplicant-port"),
        not(feature = "upstream-authenticator-wpa2"),
        not(feature = "upstream-authenticator-wpa3")
    ),
    allow(dead_code)
)]
mod crypto;
#[cfg(feature = "rf-eloop-diag")]
#[doc(hidden)]
pub mod eloop_diag;
pub mod error;
pub mod frw;
pub mod hcc;
#[cfg(any(feature = "wifi-personal", feature = "upstream-supplicant-port"))]
mod hisi_rf_backend;
pub mod libc;
pub mod log;
pub mod netif;
/// netif→smoltcp bridge (feature `net`): a Rust TCP/IP stack behind the netif
/// seam. Optional so the bare porting layer stays lean.
#[cfg(feature = "net")]
pub mod netif_smoltcp;
pub mod oal;
pub mod osal;
pub mod osal_adapt;
pub mod osal_ext;
pub mod osal_queue;
pub mod osal_sync;
pub mod osal_wait;
mod pmp;
#[cfg(feature = "rf-init-diag")]
#[doc(hidden)]
pub mod rf_init_diag;
#[cfg(feature = "sle-init")]
mod sle;
#[cfg(feature = "station-pm-diag")]
#[doc(hidden)]
mod station_pm_diag;
pub mod timer;
pub mod uapi;

/// Secret-free TX timeline used to bind one-byte HIL echo traffic to MAC
/// completion sequence and CCMP packet numbers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[doc(hidden)]
pub struct TxTimelineDiagnostics {
    pub submission_total: u32,
    pub completion_total: u32,
    pub callback_total: u32,
    /// Packed submission entries: bit 31 valid, bits 29:28 direction
    /// (request=1, reply=2), low byte application sequence.
    pub submissions: [u32; 18],
    pub submission_time_ms: [u32; 18],
    /// Packed completion status/TID/queue/MAC sequence entries.
    pub completions: [u32; 18],
    pub packet_number_lsb: [u32; 18],
    pub completion_time_ms: [u32; 18],
    /// Submission identity matched through the vendor skb mapping, or zero.
    pub completion_echo: [u32; 18],
}
#[cfg(any(
    feature = "upstream-authenticator-wpa2",
    feature = "upstream-authenticator-wpa3"
))]
#[cfg_attr(not(target_arch = "riscv32"), allow(dead_code, unused_imports))]
mod upstream_authenticator;
#[cfg(feature = "upstream-supplicant-port")]
mod upstream_supplicant;

#[cfg(any(feature = "wifi-personal", feature = "upstream-supplicant-port"))]
#[doc(hidden)]
pub use blocking_diagnostics::{
    AssociationIoctlMetrics, AssociationTimingDiagnostics, BlockingBackendMetrics,
    BlockingBootstrapMetrics, BlockingOperationMetrics, BootstrapStage, BootstrapStageMetrics,
    FrwSyncPostMetrics,
};

/// Return a secret-free snapshot of the current blocking backend workload.
///
/// This migration diagnostic remains available while the validated blocking
/// backend is compared with the opt-in incremental implementation.
#[cfg(any(feature = "wifi-personal", feature = "upstream-supplicant-port"))]
#[doc(hidden)]
pub fn blocking_backend_metrics() -> BlockingBackendMetrics {
    blocking_diagnostics::snapshot()
}

/// Return the bounded upstream-supplicant bring-up snapshot.
///
/// This is a diagnostic contract for the WS63 connectivity smoke, not a user
/// radio API. The caller emits it after the worker has returned so UART output
/// cannot perturb RF scheduling.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_diagnostic_snapshot() -> [u32; 11] {
    upstream_supplicant::diagnostic_snapshot()
}

/// Return secret-free crypto counters for the native AP HIL fixture.
#[cfg(all(
    target_arch = "riscv32",
    any(
        feature = "upstream-authenticator-wpa2",
        feature = "upstream-authenticator-wpa3"
    )
))]
#[doc(hidden)]
pub fn upstream_authenticator_crypto_diagnostic_snapshot() -> [u32; 25] {
    let entropy = crypto::hardware_entropy_diagnostic_snapshot();
    let pbkdf2 = crypto::hardware_pbkdf2_diagnostic_snapshot();
    let hash = crypto::hardware_hash_diagnostic_snapshot();
    let cipher = crypto::hardware_cipher_diagnostic_snapshot();
    let mut output = [0; 25];
    output[..4].copy_from_slice(&entropy);
    output[4..9].copy_from_slice(&pbkdf2);
    output[9..19].copy_from_slice(&hash);
    output[19..25].copy_from_slice(&cipher);
    output
}

/// Return call counts plus last/max latency for association-related WAL ioctls.
///
/// The four triplets describe initial associate, stale-state disconnect,
/// bounded associate retry, and normal deauthenticate respectively.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_association_ioctl_diagnostic_snapshot() -> [u32; 12] {
    upstream_supplicant::association_ioctl_diagnostic_snapshot()
}

/// Return counter-only timing evidence for native association-control calls.
#[cfg(feature = "upstream-supplicant-port")]
pub fn association_timing_diagnostics() -> AssociationTimingDiagnostics {
    upstream_supplicant::association_timing_diagnostics()
}

/// Return bounded WS63 external-auth status retry diagnostics.
#[cfg(feature = "upstream-supplicant-port")]
pub fn upstream_supplicant_external_auth_retry_diagnostic_snapshot() -> [u32; 2] {
    upstream_supplicant::external_auth_retry_diagnostic_snapshot()
}

/// Return secret-free scan queue and callback diagnostics.
#[cfg(all(feature = "upstream-supplicant-port", target_arch = "riscv32"))]
#[doc(hidden)]
pub fn upstream_supplicant_scan_diagnostic_snapshot() -> [u32; 13] {
    let native = upstream_supplicant::scan_diagnostic_snapshot();
    let wifi = wifi::scan_diagnostic_snapshot();
    [
        native[0], native[1], native[2], native[3], native[4], native[5], native[6], native[7],
        wifi[0], wifi[1], wifi[2], wifi[3], wifi[4],
    ]
}

/// Secret-free scan/callback state captured at an operation boundary.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanDiagnostics {
    /// Native supplicant scan requests started.
    pub native_starts: u32,
    /// Native supplicant scan-result events accepted.
    pub native_results: u32,
    /// Native supplicant scan-done events accepted.
    pub native_done: u32,
    /// Whether the native scan capture remains active.
    pub native_active: bool,
    /// Whether the native scan-event queue contains pending work.
    pub queue_pending: bool,
    /// Native scan events dropped because the bounded queue was full.
    pub queue_dropped: u32,
    /// Monotonic millisecond timestamp when the scan transaction started.
    pub native_start_ms: u32,
    /// Monotonic millisecond timestamp when the runner first observed native completion.
    pub native_done_ms: u32,
    /// Whether the vendor driver scan state remains active.
    pub driver_active: bool,
    /// Whether the vendor driver published scan completion.
    pub driver_done: bool,
    /// Results retained by the vendor driver callback.
    pub driver_results: u32,
    /// Raw vendor scan completion status.
    pub driver_status: u32,
    /// Monotonic millisecond timestamp when the runner first observed driver completion.
    pub driver_done_ms: u32,
}

/// Return a typed, secret-free scan diagnostic snapshot.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_scan_diagnostics() -> ScanDiagnostics {
    #[cfg(target_arch = "riscv32")]
    {
        let values = upstream_supplicant_scan_diagnostic_snapshot();
        ScanDiagnostics {
            native_starts: values[0],
            native_results: values[1],
            native_done: values[2],
            native_active: values[3] != 0,
            queue_pending: values[4] != 0,
            queue_dropped: values[5],
            native_start_ms: values[6],
            native_done_ms: values[7],
            driver_active: values[8] != 0,
            driver_done: values[9] != 0,
            driver_results: values[10],
            driver_status: values[11],
            driver_done_ms: values[12],
        }
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        ScanDiagnostics::default()
    }
}

/// Return public IEEE 802.11 Authentication header diagnostics.
///
/// The snapshot intentionally excludes frame bodies and cryptographic payloads.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_authentication_diagnostic_snapshot() -> [u32; 12] {
    upstream_supplicant::authentication_diagnostic_snapshot()
}

/// Return sequence/timing diagnostics for the external-auth transaction.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_authentication_progress_snapshot() -> [u32; 10] {
    upstream_supplicant::authentication_progress_snapshot()
}

/// Return notification, receive, transmit, and key-install EAPOL counters.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_eapol_diagnostic_snapshot() -> [u32; 8] {
    upstream_supplicant::eapol_diagnostic_snapshot()
}

#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub use upstream_supplicant::AssociationAttemptDiagnostic;

/// Credential-free production diagnostic fixtures used by target parity tests.
///
/// These fixtures call the same builders as the WS63 connect loop. They are
/// intentionally available only to firmware examples and are not part of the
/// normal backend API.
#[cfg(all(feature = "firmware-example", feature = "upstream-supplicant-port"))]
#[doc(hidden)]
pub mod firmware_diagnostic_fixtures {
    use hisi_rf_core::Diagnostic;

    /// IEEE 802.11 status 30 from the production terminal-connect path.
    pub fn association_rejection() -> Diagnostic {
        crate::hisi_rf_backend::association_rejection_diagnostic_fixture()
    }

    /// Association success followed by a first-EAPOL deadline expiry.
    pub fn first_eapol_timeout() -> Diagnostic {
        crate::hisi_rf_backend::first_eapol_timeout_diagnostic_fixture()
    }

    /// Run cancellation and timeout through the incremental driver/backend.
    #[cfg(feature = "incremental-backend-experiment")]
    pub fn operation_error_injection() -> Option<(Diagnostic, Diagnostic)> {
        crate::hisi_rf_backend::operation_error_injection_fixture()
    }
}

/// Copy the retained association-result timeline into `output`.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_association_attempt_diagnostics(
    output: &mut [AssociationAttemptDiagnostic],
) -> usize {
    upstream_supplicant::association_attempt_diagnostics(output)
}

/// Return native event-ring and last-event diagnostics.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_event_diagnostic_snapshot() -> [u32; 6] {
    upstream_supplicant::event_diagnostic_snapshot()
}

/// Return the low-level vendor driver callback boundary diagnostics.
#[cfg(all(feature = "upstream-supplicant-port", target_arch = "riscv32"))]
#[doc(hidden)]
pub fn upstream_supplicant_driver_event_diagnostic_snapshot() -> [u32; 6] {
    wifi::driver_event_diagnostic_snapshot()
}

/// Return first-EAPOL timeout and reassociation recovery counters.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_recovery_diagnostic_word() -> u32 {
    upstream_supplicant::recovery_diagnostic_word()
}

/// Return bounded reconnect counts for first-EAPOL and external-auth stalls.
#[cfg(all(
    feature = "incremental-backend-experiment",
    feature = "upstream-supplicant-port"
))]
#[doc(hidden)]
pub fn incremental_reconnect_diagnostic_snapshot() -> [u32; 2] {
    hisi_rf_backend::reconnect_diagnostic_snapshot()
}

/// Return status-30 stale-association clear counters.
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub fn upstream_supplicant_temporary_reject_recovery_diagnostic_snapshot() -> [u32; 4] {
    upstream_supplicant::temporary_reject_recovery_diagnostic_snapshot()
}

/// Return non-secret hardware entropy health counters.
#[cfg(all(feature = "upstream-supplicant-port", target_arch = "riscv32"))]
#[doc(hidden)]
pub fn hardware_entropy_diagnostic_snapshot() -> [u32; 4] {
    crypto::hardware_entropy_diagnostic_snapshot()
}
/// Return non-secret hardware PBKDF2 health counters.
#[cfg(all(feature = "upstream-supplicant-port", target_arch = "riscv32"))]
#[doc(hidden)]
pub fn hardware_pbkdf2_diagnostic_snapshot() -> [u32; 5] {
    crypto::hardware_pbkdf2_diagnostic_snapshot()
}
/// Return non-secret SPACC hash and HMAC health counters.
#[cfg(all(feature = "upstream-supplicant-port", target_arch = "riscv32"))]
#[doc(hidden)]
pub fn hardware_hash_diagnostic_snapshot() -> [u32; 10] {
    crypto::hardware_hash_diagnostic_snapshot()
}

/// Return non-secret SPACC AES request, failure, timing, and recovery counters.
#[cfg(any(
    feature = "wifi-wpa2-personal",
    feature = "upstream-supplicant-port",
    feature = "upstream-authenticator-wpa2",
    feature = "upstream-authenticator-wpa3"
))]
pub fn hardware_cipher_diagnostic_snapshot() -> [u32; 6] {
    crypto::hardware_cipher_diagnostic_snapshot()
}

/// Return non-secret WS63 PKE P-256 point-operation counters.
#[cfg(any(
    feature = "wifi-wpa2-personal",
    feature = "upstream-supplicant-port",
    feature = "wpa3-crypto"
))]
pub fn hardware_p256_diagnostic_snapshot() -> [u32; 8] {
    crypto::hardware_p256_diagnostic_snapshot()
}

/// Return non-secret WS63 PKE P-256 fixed-field-operation counters.
#[cfg(any(
    feature = "wifi-wpa2-personal",
    feature = "upstream-supplicant-port",
    feature = "wpa3-crypto"
))]
pub fn hardware_p256_field_diagnostic_snapshot() -> [u32; 10] {
    crypto::hardware_p256_field_diagnostic_snapshot()
}

/// Return non-secret fixed P-256 curve-composition counters.
#[cfg(any(
    feature = "wifi-wpa2-personal",
    feature = "upstream-supplicant-port",
    feature = "wpa3-crypto"
))]
pub fn hardware_p256_curve_diagnostic_snapshot() -> [u32; 10] {
    crypto::hardware_p256_curve_diagnostic_snapshot()
}

/// Return diagnostic-only cross-task crypto contention evidence.
#[cfg(all(target_arch = "riscv32", feature = "rf-crypto-contention-diag"))]
#[doc(hidden)]
pub fn hardware_crypto_contention_diagnostic_snapshot() -> [u32; 5] {
    crypto::hardware_crypto_contention_diagnostic_snapshot()
}
#[cfg(any(
    test,
    target_arch = "riscv32",
    feature = "wifi-personal",
    feature = "upstream-supplicant-port",
    feature = "upstream-authenticator-wpa2",
    feature = "upstream-authenticator-wpa3"
))]
mod wal;
pub mod wifi;

/// Allocation-free snapshot of the linker-owned WS63 RF heap.
///
/// This heap is shared by the native supplicant, vendor queues, and OSAL
/// objects. The values are runtime observations for diagnostics and HIL
/// calibration; `free_bytes` is not a contiguous-allocation guarantee and the
/// snapshot does not replace profile admission.
pub use hisi_alloc::HeapMetrics as RfHeapMetrics;

/// Observe current and peak WS63 RF heap use without allocating.
pub fn rf_heap_metrics() -> RfHeapMetrics {
    alloc::heap_metrics()
}

#[cfg(feature = "station-pm-diag")]
#[doc(hidden)]
pub use station_pm_diag::{
    StationPowerSaveDiagnosticError, disable_station_power_save_for_diagnostics,
};

/// Dynamic task slots required by the pinned WS63 vendor bootstrap.
///
/// The optional Rust incremental worker is reserved separately by the public
/// composition root and must not be included in the vendor bootstrap's
/// remaining-capacity check.
#[cfg(any(
    target_arch = "riscv32",
    all(
        feature = "net",
        any(feature = "wifi-personal", feature = "upstream-supplicant-port")
    )
))]
pub(crate) const WS63_WIFI_VENDOR_DYNAMIC_TASKS_REQUIRED: usize = 7;

/// Total caller-owned SRAM envelope shared by the WS63 radio runtime.
///
/// STA and AP compositions divide this same physical envelope between RTOS
/// task stacks and the RF/hostap heap. Keeping the value here prevents the two
/// firmware roles from silently drifting apart.
pub const WS63_SHARED_RADIO_ARENA_BYTES: usize = 296 * 1024;

#[cfg(any(feature = "data-path-diag", feature = "rf-eloop-diag"))]
mod wlmac_diag;
#[cfg(any(feature = "wifi-personal", feature = "ble-init", feature = "sle-init"))]
mod wpa_compat;
mod ws63_runtime_compat;

#[cfg(feature = "ble-init")]
#[doc(hidden)]
pub use ble::{
    BLE_B1_ARENA_BYTES, BLE_B1_MINIMUM_TASK_STACK_BYTES, BLE_B3_CCC_UUID,
    BLE_B3_CHARACTERISTIC_UUID, BLE_B3_SERVICE_UUID, BleB1ArenaStorage, BleB1ControlStorage,
    BleB1Controller, BleB1InitError, BleB1Resources, BleB1Storage, BleB2Error, BleB2Event,
    BleB3Error, BleGattClient, BleGattServer, BleSecurityError, BleVendorBondError,
    InstalledBleB1Storage, init_ble_b1,
};
pub use pmp::prepare_vendor_memory;
#[cfg(feature = "sle-init")]
#[doc(hidden)]
pub use sle::{
    InstalledSleS1Storage, SLE_S1_ARENA_BYTES, SLE_S1_EVENT_DATA_CAPACITY,
    SLE_S1_MINIMUM_TASK_STACK_BYTES, SleS1ArenaStorage, SleS1ControlStorage, SleS1Controller,
    SleS1Event, SleS1InitError, SleS1OperationError, SleS1Resources, SleS1Storage,
    SsapServerHandles, init_sle_s1,
};

/// Declare caller-owned storage for the internal BLE B1 init profile.
#[cfg(feature = "ble-init")]
#[macro_export]
macro_rules! declare_ble_b1_storage {
    ($(#[$meta:meta])* $vis:vis static $name:ident) => {
        $(#[$meta])*
        $vis static $name: $crate::BleB1Storage<{ $crate::BLE_B1_ARENA_BYTES }> = {
            static CONTROL: $crate::BleB1ControlStorage = $crate::BleB1ControlStorage::new();
            #[cfg_attr(
                target_arch = "riscv32",
                unsafe(link_section = ".hisi.shared-arena")
            )]
            static ARENA: $crate::BleB1ArenaStorage<{ $crate::BLE_B1_ARENA_BYTES }> =
                $crate::BleB1ArenaStorage::new();
            $crate::BleB1Storage::from_parts(&CONTROL, &ARENA)
        };
    };
}

/// Declare caller-owned storage for the internal SLE S1 init profile.
#[cfg(feature = "sle-init")]
#[macro_export]
macro_rules! declare_sle_s1_storage {
    ($(#[$meta:meta])* $vis:vis static $name:ident) => {
        $(#[$meta])*
        $vis static $name: $crate::SleS1Storage<{ $crate::SLE_S1_ARENA_BYTES }> = {
            static CONTROL: $crate::SleS1ControlStorage = $crate::SleS1ControlStorage::new();
            #[cfg_attr(
                target_arch = "riscv32",
                unsafe(link_section = ".hisi.shared-arena")
            )]
            static ARENA: $crate::SleS1ArenaStorage<{ $crate::SLE_S1_ARENA_BYTES }> =
                $crate::SleS1ArenaStorage::new();
            $crate::SleS1Storage::from_parts(&CONTROL, &ARENA)
        };
    };
}
#[cfg(any(
    feature = "upstream-authenticator-wpa2",
    feature = "upstream-authenticator-wpa3"
))]
#[doc(hidden)]
pub use upstream_authenticator::{
    ACCESS_POINT_ARENA_BYTES, AccessPoint, AccessPointArenaStorage, AccessPointConfig,
    AccessPointControlStorage, AccessPointDiagnostics, AccessPointInitError,
    AccessPointNetworkDevice, AccessPointResources, AccessPointStorage,
    InstalledAccessPointStorage, NativeAuthenticator, NativeAuthenticatorError, init_access_point,
    prepare_upstream_authenticator_port,
};
#[cfg(feature = "upstream-supplicant-port")]
#[doc(hidden)]
pub use upstream_supplicant::{UpstreamSupplicantPortError, prepare_upstream_supplicant_port};

#[cfg(all(
    feature = "net",
    any(feature = "wifi-personal", feature = "upstream-supplicant-port")
))]
mod composition;
#[cfg(all(feature = "data-path-diag", not(feature = "rf-eloop-diag")))]
#[allow(dead_code)] // STA and AP diagnostic fixtures consume different counters.
mod data_path_diag;
#[cfg(all(
    feature = "net",
    feature = "incremental-backend-experiment",
    feature = "incremental-embassy-wait",
    feature = "upstream-supplicant-port"
))]
mod incremental_wait;
#[cfg(all(
    feature = "net",
    feature = "incremental-backend-experiment",
    feature = "incremental-embassy-wait",
    feature = "upstream-supplicant-port"
))]
mod incremental_worker;
#[cfg(feature = "incremental-embassy-wait")]
#[doc(hidden)]
pub use incremental_wait::{Ws63IncrementalWaitDiagnostics, incremental_wait_diagnostics};
#[cfg(all(
    feature = "net",
    any(feature = "wifi-personal", feature = "upstream-supplicant-port")
))]
mod profile;
#[cfg(all(
    feature = "net",
    feature = "incremental-late-completion-profile",
    feature = "upstream-supplicant-port"
))]
pub use composition::IncrementalWorkerDiagnostics;
#[cfg(all(
    feature = "net",
    any(feature = "wifi-personal", feature = "upstream-supplicant-port")
))]
pub use composition::{
    CryptoReady, DataPathDiagnostics, DhcpDiagnostics, InitError, InitErrorKind,
    L2ProtocolDiagnostics, MissingCrypto, MissingPke, PkeNotRequired, PkeReady, Resources,
    ResourcesBuilder, RxQueueDiagnostics, WifiDevice, WifiParts, WifiRxToken, WifiTxToken,
};
#[cfg(all(
    feature = "net",
    feature = "incremental-backend-experiment",
    feature = "upstream-supplicant-port"
))]
#[allow(deprecated)]
pub use composition::{
    IncrementalRadioController, init_incremental, init_incremental_after_blocking_bootstrap,
};
#[cfg(all(
    feature = "net",
    feature = "incremental-embassy-wait",
    feature = "upstream-supplicant-port"
))]
pub use composition::{IncrementalRadioParts, IncrementalRadioRunner};
#[cfg(all(
    feature = "net",
    feature = "legacy-blocking-backend",
    any(feature = "wifi-personal", feature = "upstream-supplicant-port")
))]
pub use composition::{RadioController, init};
pub use hisi_rf_core::WifiL2Capabilities;
#[cfg(all(
    feature = "net",
    any(
        all(feature = "wpa2-personal", not(feature = "wpa3-personal")),
        all(feature = "wpa3-personal", not(feature = "wpa2-personal"))
    )
))]
#[allow(deprecated)]
pub use profile::SELECTED_TASK_STACK_ARENA_BYTES;
#[cfg(all(
    feature = "net",
    any(
        all(feature = "wpa2-personal", not(feature = "wpa3-personal")),
        all(feature = "wpa3-personal", not(feature = "wpa2-personal"))
    )
))]
pub use profile::SelectedProfile;
#[cfg(all(
    feature = "net",
    any(
        all(feature = "wpa2-personal", not(feature = "wpa3-personal")),
        all(feature = "wpa3-personal", not(feature = "wpa2-personal"))
    )
))]
pub use profile::{
    ArenaAdmissionError, InstalledRadioArena, InstalledRadioStorage, Profile, RadioArena,
    RadioArenaStorage, RadioStorage, ResourceReport, SELECTED_MINIMUM_TASK_STACK_BYTES,
    SELECTED_RF_ARENA_BYTES, SELECTED_RUNTIME_ARENA_BYTES, Storage, TaskGroupPlan,
    WifiResourcePlan, WifiWpa2Smoltcp, WifiWpa3Smoltcp, resource_report, wifi_resource_plan,
};

/// Declare all caller-owned storage for the selected named radio profile.
///
/// The application sees one composition object. Internally, bounded control
/// state stays in ordinary BSS and the large allocator arena is placed in the
/// runtime's dedicated post-stack `NOLOAD` range.
#[macro_export]
macro_rules! declare_radio_storage {
    ($(#[$meta:meta])* $vis:vis static $name:ident, events = $events:expr) => {
        $(#[$meta])*
        $vis static $name: $crate::RadioStorage<
            $crate::SelectedProfile,
            { $events },
            { $crate::SELECTED_RF_ARENA_BYTES },
        > = {
            static CONTROL: $crate::Storage<$crate::SelectedProfile, { $events }> =
                $crate::Storage::new();
            #[cfg_attr(
                target_arch = "riscv32",
                unsafe(link_section = ".hisi.shared-arena")
            )]
            static ARENA: $crate::RadioArenaStorage<
                { $crate::SELECTED_RF_ARENA_BYTES },
            > = $crate::RadioArenaStorage::new();
            $crate::RadioStorage::from_parts(&CONTROL, &ARENA)
        };
    };
}

/// Declare caller-owned storage for the selected named radio profile.
///
/// On WS63 firmware this places the arena in the runtime's dedicated
/// post-stack `NOLOAD` range. The runtime clears that range before `main`, and
/// changing the arena capacity therefore cannot move the trap or task stacks.
#[macro_export]
macro_rules! declare_radio_arena {
    ($(#[$meta:meta])* $vis:vis static $name:ident) => {
        $(#[$meta])*
        #[cfg_attr(
            target_arch = "riscv32",
            unsafe(link_section = ".hisi.shared-arena")
        )]
        $vis static $name: $crate::RadioArenaStorage<
            { $crate::SELECTED_RF_ARENA_BYTES },
        > = $crate::RadioArenaStorage::new();
    };
}

/// Terminal target for a mask-ROM callback not supplied by the current port.
///
/// This is part of the callback-table safety contract, not optional tracing:
/// every fixed-address veneer must point at executable code even in a minimal
/// full-init build.
#[cfg(target_arch = "riscv32")]
#[unsafe(no_mangle)]
pub extern "C" fn __ws63_missing_rom_callback() -> ! {
    let caller: u32;
    unsafe {
        core::arch::asm!("mv {caller}, ra", caller = out(reg) caller, options(nomem, nostack));
    }
    let mut hex = [0_u8; 8];
    for (index, byte) in hex.iter_mut().enumerate() {
        let nibble = ((caller >> ((7 - index) * 4)) & 0xf) as u8;
        *byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }
    log_emit(b"RFDBG_MISSING_ROM_CALLBACK ra=0x");
    log_emit(&hex);
    log_emit(b"\r\n");
    loop {
        core::hint::spin_loop();
    }
}

mod runtime;
mod selftest;
/// Internal netif→smoltcp bridge self-test (feature `net`). NOT a public API.
#[cfg(feature = "net")]
#[doc(hidden)]
pub use netif_smoltcp::netif_smoltcp_selftest;
/// Internal scheduler self-test hook (used by the `sched_selftest` example;
/// NOT a public API). Hidden from docs.
#[doc(hidden)]
pub use selftest::{frw_hcc_selftest, osal_queue_selftest, sched_selftest, timer_selftest};

// ── Return codes from the ws63-RF OSAL contract (port_osal.h) ──────────────
/// OSAL success (`OSAL_OK`).
pub const OSAL_OK: i32 = 0;
/// OSAL generic failure (`OSAL_NOK`).
pub const OSAL_NOK: i32 = 1;
/// `OSAL_SYS_WAIT_FOREVER`.
pub const OSAL_SYS_WAIT_FOREVER: u32 = 0xFFFF_FFFF;

// ── Log sink ───────────────────────────────────────────────────────────────
/// A log sink receives already-rendered bytes (a NUL-terminated C format
/// string; format specifiers are **not** expanded — see [`log`]).
pub type LogSink = fn(&[u8]);

static LOG_SINK: Mutex<Cell<Option<LogSink>>> = Mutex::new(Cell::new(None));

/// Install the sink that [`osal_printk`](log) / `log_event_wifi_print*` write to
/// (e.g. a UART writer). Without one, log calls are dropped.
pub fn set_log_sink(sink: LogSink) {
    critical_section::with(|cs| LOG_SINK.borrow(cs).set(Some(sink)));
}

/// Emit `bytes` to the installed log sink, if any. Used by [`log`].
pub(crate) fn log_emit(bytes: &[u8]) {
    let sink = critical_section::with(|cs| LOG_SINK.borrow(cs).get());
    if let Some(sink) = sink {
        sink(bytes);
    }
}

/// Force the C porting contract objects into the final link.
///
/// This is normally unnecessary with `rust-lld`, but it is useful for the RF
/// vendor-link lane: GNU ld scans static archives left-to-right, while rustc's
/// Rust rlibs can appear before the vendor Wi-Fi `.a` files that reference the
/// C ABI symbols. A binary that calls this function makes those symbols
/// live from Rust's side, so the linker does not depend on archive rescans.
#[doc(hidden)]
#[inline(never)]
pub fn force_link_contract() {
    macro_rules! keep {
        ($symbol:path as $ty:ty) => {
            let _ = core::hint::black_box($symbol as $ty);
        };
    }

    use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

    keep!(alloc::osal_kmalloc as extern "C" fn(usize) -> *mut c_void);
    keep!(alloc::osal_kfree as extern "C" fn(*mut c_void));

    keep!(log::log_event_wifi_print0 as extern "C" fn(c_uint) -> c_int);
    keep!(log::log_event_wifi_print1 as extern "C" fn(c_uint, c_uint) -> c_int);
    keep!(log::log_event_wifi_print2 as extern "C" fn(c_uint, c_uint, c_uint) -> c_int);
    keep!(log::log_event_wifi_print3 as extern "C" fn(c_uint, c_uint, c_uint, c_uint) -> c_int);
    keep!(
        log::log_event_wifi_print4
            as extern "C" fn(c_uint, c_uint, c_uint, c_uint, c_uint) -> c_int
    );
    keep!(log::log_event_print0 as extern "C" fn() -> c_int);
    keep!(log::log_event_print1 as extern "C" fn() -> c_int);
    keep!(log::log_event_print2 as extern "C" fn() -> c_int);
    keep!(log::log_event_print3 as extern "C" fn() -> c_int);
    keep!(log::log_event_print4 as extern "C" fn() -> c_int);
    keep!(log::osal_printk as unsafe extern "C" fn(*const c_char, ...) -> c_int);
    keep!(
        log::snprintf_s
            as unsafe extern "C" fn(*mut c_char, usize, usize, *const c_char, ...) -> c_int
    );
    keep!(log::memset_s as extern "C" fn(*mut c_void, usize, c_int, usize) -> c_int);
    keep!(log::memcpy_s as extern "C" fn(*mut c_void, usize, *const c_void, usize) -> c_int);

    #[cfg(all(feature = "rf-eloop-diag", target_arch = "riscv32"))]
    {
        keep!(
            eloop_diag::hmac_sta_wait_auth_seq2_rx_etc
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32
        );
        keep!(
            eloop_diag::hmac_sta_auth_timeout_etc
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32
        );
        keep!(
            eloop_diag::hmac_rx_mgmt_event_adapt
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32
        );
        keep!(
            eloop_diag::hmac_tx_mgmt_send_event_etc
                as unsafe extern "C" fn(*mut c_void, *mut c_void, u16) -> u32
        );
        keep!(
            eloop_diag::__ws63_diag_dmac_tx_complete_event_handler
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32
        );
        keep!(
            eloop_diag::dmac_rx_prepare_data_patch
                as unsafe extern "C" fn(
                    *mut c_void,
                    *mut c_void,
                    u32,
                    *mut c_void,
                    *mut c_void,
                ) -> u32
        );
    }

    #[cfg(all(
        feature = "data-path-diag",
        not(feature = "rf-eloop-diag"),
        target_arch = "riscv32"
    ))]
    {
        keep!(
            data_path_diag::dmac_tx_complete_event_handler
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32
        );
        keep!(
            data_path_diag::dmac_rx_prepare_data_patch
                as unsafe extern "C" fn(
                    *mut c_void,
                    *mut c_void,
                    u32,
                    *mut c_void,
                    *mut c_void,
                ) -> u32
        );
        keep!(
            data_path_diag::hmac_rx_data_event_adapt
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32
        );
        keep!(
            data_path_diag::hmac_rx_process_data_msg
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32
        );
        keep!(
            data_path_diag::hmac_rx_data as unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32
        );
        keep!(
            data_path_diag::hmac_tx_lan_to_wlan_no_tcp_opt_etc
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32
        );
        keep!(
            data_path_diag::hmac_tx_process_data
                as unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> u32
        );
        keep!(data_path_diag::hmac_tx_data_send as unsafe extern "C" fn(*mut c_void, *mut c_void));
        keep!(
            data_path_diag::frw_hmac_send_data as unsafe extern "C" fn(*mut c_void, u8, u8) -> u32
        );
        keep!(
            data_path_diag::dmac_tx_process_data_event
                as unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32
        );
    }

    keep!(libc::malloc as extern "C" fn(c_ulong) -> *mut c_void);
    keep!(libc::free as extern "C" fn(*mut c_void));
    keep!(libc::memalign as extern "C" fn(c_ulong, c_ulong) -> *mut c_void);
    keep!(libc::strcmp as extern "C" fn(*const c_char, *const c_char) -> c_int);
    keep!(libc::strtol as extern "C" fn(*const c_char, *mut *mut c_char, c_uint) -> c_long);
    keep!(libc::atoi as extern "C" fn(*const c_char) -> c_int);
    keep!(libc::strstr as extern "C" fn(*const c_char, *const c_char) -> *mut c_char);
    keep!(libc::tolower as extern "C" fn(c_int) -> c_int);
    keep!(libc::gettimeofday as extern "C" fn(*mut osal_ext::OsalTimeval, *mut c_void) -> c_int);
    keep!(libc::print_str as extern "C" fn(*const c_char));

    keep!(osal::osal_irq_lock as extern "C" fn() -> c_ulong);
    keep!(osal::osal_irq_restore as extern "C" fn(c_ulong));
    keep!(osal::osal_udelay as extern "C" fn(u32));
    keep!(osal::osal_flush_cache as extern "C" fn());
    keep!(
        osal::osal_irq_request
            as extern "C" fn(
                u32,
                Option<unsafe extern "C" fn(u32, *mut c_void)>,
                Option<unsafe extern "C" fn(u32, *mut c_void)>,
                *const c_char,
                *mut c_void,
            ) -> c_int
    );
    keep!(osal::osal_irq_enable as extern "C" fn(u32) -> c_int);
    keep!(osal::osal_irq_disable as extern "C" fn(u32) -> c_int);
    keep!(osal::osal_irq_clear as extern "C" fn(u32) -> c_int);
    keep!(osal::osal_msleep as extern "C" fn(u32));
    keep!(osal::osal_get_current_pid as extern "C" fn() -> c_int);
    keep!(osal::osal_get_current_tid as extern "C" fn() -> c_int);
    keep!(
        osal::osal_kthread_create
            as extern "C" fn(
                Option<extern "C" fn(*mut c_void) -> *mut c_void>,
                *mut c_void,
                *const c_char,
                usize,
            ) -> *mut c_void
    );

    keep!(osal_adapt::osal_adapt_atomic_set as extern "C" fn(*mut osal_sync::OsalAtomic, c_int));
    keep!(osal_adapt::osal_adapt_get_jiffies as extern "C" fn() -> u64);
    keep!(osal_adapt::osal_adapt_irq_lock as extern "C" fn() -> c_uint);
    keep!(osal_adapt::osal_adapt_irq_restore as extern "C" fn(c_uint));
    keep!(
        osal_adapt::osal_adapt_kthread_create
            as extern "C" fn(
                Option<extern "C" fn(*mut c_void) -> *mut c_void>,
                *mut c_void,
                *const c_char,
                c_uint,
            ) -> *mut c_void
    );

    keep!(osal_ext::osal_vmalloc as extern "C" fn(c_ulong) -> *mut c_void);
    keep!(osal_ext::osal_vfree as extern "C" fn(*mut c_void));
    keep!(osal_ext::osal_strlen as extern "C" fn(*const c_char) -> c_uint);
    keep!(osal_ext::osal_strcmp as extern "C" fn(*const c_char, *const c_char) -> c_int);
    keep!(
        osal_ext::osal_adapt_strncmp
            as extern "C" fn(*const c_char, *const c_char, c_uint) -> c_int
    );
    keep!(osal_ext::osal_memcmp as extern "C" fn(*const c_void, *const c_void, c_int) -> c_int);
    keep!(
        osal_ext::osal_strtol as extern "C" fn(*const c_char, *mut *mut c_char, c_uint) -> c_long
    );
    keep!(osal_ext::osal_get_jiffies as extern "C" fn() -> u64);
    keep!(osal_ext::osal_gettimeofday as extern "C" fn(*mut osal_ext::OsalTimeval));
    keep!(
        osal_ext::osal_copy_to_user
            as extern "C" fn(*mut c_void, *const c_void, c_ulong) -> c_ulong
    );

    keep!(netif::pbuf_alloc as extern "C" fn(c_int, u16, c_int) -> *mut c_void);
    keep!(netif::pbuf_free as extern "C" fn(*mut c_void) -> u8);
    keep!(netif::pbuf_ref as extern "C" fn(*mut c_void));
    keep!(netif::pbuf_header as extern "C" fn(*mut c_void, i16) -> u8);
    keep!(netif::driverif_input as extern "C" fn(*mut c_void, *mut c_void) -> i32);
    keep!(
        netif::netifapi_netif_add
            as extern "C" fn(*mut c_void, *const u32, *const u32, *const u32) -> c_int
    );
    keep!(netif::netifapi_netif_remove as extern "C" fn(*mut c_void) -> c_int);
    keep!(netif::netifapi_netif_find_by_name as extern "C" fn(*const u8) -> *mut c_void);
    keep!(
        netif::netifapi_netif_get_addr
            as extern "C" fn(*mut c_void, *mut u32, *mut u32, *mut u32) -> c_int
    );
    keep!(
        netif::netifapi_netif_add_ext_callback as extern "C" fn(*mut c_void, *mut c_void) -> c_int
    );
    keep!(netif::netifapi_set_ip6_autoconfig_disabled as extern "C" fn(*mut c_void) -> c_int);
    keep!(
        netif::netifapi_netif_add_ip6_linklocal_address as extern "C" fn(*mut c_void, u8) -> c_int
    );
    keep!(netif::netifapi_netif_set_up as extern "C" fn(*mut c_void) -> c_int);
    keep!(netif::netifapi_netif_set_down as extern "C" fn(*mut c_void) -> c_int);
    keep!(netif::netifapi_netif_set_link_up as extern "C" fn(*mut c_void) -> c_int);
    keep!(netif::netifapi_netif_set_default as extern "C" fn(*mut c_void) -> c_int);
    keep!(netif::netif_set_link_up_interface as extern "C" fn(*mut c_void));
    keep!(netif::netif_set_link_down_interface as extern "C" fn(*mut c_void));
    keep!(netif::tcpip_callback as extern "C" fn(*mut c_void, *mut c_void) -> c_int);

    keep!(uapi::uapi_tsensor_get_current_temp as extern "C" fn(*mut i8) -> u32);
    keep!(uapi::uapi_nv_read as extern "C" fn(u16, u16, *mut u16, *mut u8) -> u32);
    keep!(uapi::uapi_nv_write as extern "C" fn(u16, *const u8, u16) -> u32);
    keep!(uapi::uapi_efuse_read_bit as extern "C" fn(*mut u8, u32, u8) -> u32);
    keep!(uapi::uapi_efuse_read_buffer as extern "C" fn(*mut u8, u32, u16) -> u32);
    keep!(uapi::uapi_drv_cipher_trng_get_random as extern "C" fn(*mut u32) -> u32);
    keep!(uapi::uapi_drv_cipher_trng_get_random_bytes as extern "C" fn(*mut u8, u32) -> u32);
    keep!(uapi::get_dev_addr as extern "C" fn(*mut u8, u8, u8) -> u32);
    keep!(uapi::get_tcxo_freq as extern "C" fn() -> u32);
    #[cfg(not(feature = "wifi-personal"))]
    {
        keep!(uapi::uapi_wifi_softap_stop as extern "C" fn() -> i32);
        keep!(uapi::uapi_wifi_sta_stop as extern "C" fn() -> i32);
    }
}
