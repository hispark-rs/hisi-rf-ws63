//! `errcode_t` mapping for the public Wi-Fi API (future use).
//!
//! The vendor public API (`wifi_init`, `wifi_sta_scan`, `wifi_sta_connect`, …,
//! declared in `ws63-radio-sys/ws63-RF/include/api/wifi/`) returns `errcode_t` (0 = success).
//! NOTE: the current blob delivery exports the lower-level `uapi_wifi_init`
//! symbol from `libwifi_driver_hmac.a`, while the public header still declares
//! `wifi_init`. The guarded two-pass RF build can now produce the full init
//! image; a safe Rust API remains deferred until the on-silicon init contract
//! and its error classes are known. This module provides the error mapping that
//! binding will use.

/// Vendor `errcode_t` (0 = success).
pub type Errcode = u32;

/// `ERRCODE_SUCC`.
pub const ERRCODE_SUCC: Errcode = 0;

/// A non-zero vendor error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiError(pub Errcode);

/// Map an `errcode_t` to a `Result`.
pub fn check(code: Errcode) -> Result<(), WifiError> {
    if code == ERRCODE_SUCC {
        Ok(())
    } else {
        Err(WifiError(code))
    }
}

#[cfg(any(
    feature = "wifi-personal",
    feature = "upstream-supplicant-port",
    all(
        feature = "coexistence-wifi-sle",
        feature = "upstream-authenticator-wpa2"
    )
))]
pub(crate) const fn runtime_code(error: hisi_rf_rtos_driver::Error) -> u32 {
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

#[cfg(any(
    feature = "wifi-personal",
    feature = "upstream-supplicant-port",
    all(
        feature = "coexistence-wifi-sle",
        feature = "upstream-authenticator-wpa2"
    )
))]
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
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskStackMemory {
            required,
            available,
        } => {
            let required_kib = (required / 1024).min(u16::MAX as usize) as u32;
            let available_kib = (available / 1024).min(u16::MAX as usize) as u32;
            0x8000_0000 | (required_kib << 16) | available_kib
        }
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskGroupSlots {
            owner,
            required,
            available,
        } => {
            let owner = owner.into_raw().get().min(u8::MAX as u32);
            let required = required.min(u8::MAX as usize) as u32;
            let available = available.min(u8::MAX as usize) as u32;
            0x4000_0000 | (owner << 16) | (required << 8) | available
        }
        hisi_rf_rtos_driver::TaskAdmissionError::InsufficientTaskGroupStackMemory {
            owner,
            required,
            available,
            ..
        } => {
            let owner = owner.into_raw().get().min(u8::MAX as u32);
            let required_kib = (required / 1024).min(u8::MAX as usize) as u32;
            let available_kib = (available / 1024).min(u8::MAX as usize) as u32;
            0xc000_0000 | (owner << 16) | (required_kib << 8) | available_kib
        }
    }
}
