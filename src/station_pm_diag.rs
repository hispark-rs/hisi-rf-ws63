//! Diagnostic-only WS63 station power-save control.

#[cfg(target_arch = "riscv32")]
use core::ffi::c_void;

#[cfg(target_arch = "riscv32")]
const STATION_VAP_INDEX: u8 = 0;
#[cfg(target_arch = "riscv32")]
const PM_CONTROL_HOST: u32 = 0;
#[cfg(target_arch = "riscv32")]
const PM_SWITCH_OFF: u32 = 0;

/// Failure returned by the diagnostic station power-save override.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StationPowerSaveDiagnosticError {
    /// The vendor runtime did not expose the station VAP at the expected index.
    StationVapUnavailable,
    /// The vendor power-management operation rejected the request.
    Vendor(u32),
    /// The operation is only available in WS63 firmware builds.
    UnsupportedTarget,
}

/// Disable station power save after association for a bounded HIL A/B test.
///
/// This is not a production policy API. Normal profiles leave the vendor power
/// policy unchanged; callers must explicitly enable `station-pm-diag`.
#[cfg(target_arch = "riscv32")]
pub fn disable_station_power_save_for_diagnostics() -> Result<(), StationPowerSaveDiagnosticError> {
    unsafe extern "C" {
        fn mac_res_get_hmac_vap(index: u8) -> *mut c_void;
        fn hmac_config_set_pm_by_module_etc(
            vap: *mut c_void,
            control: u32,
            power_switch: u32,
        ) -> u32;
    }

    // SAFETY: the selected WS63 radio profile owns the vendor HMAC runtime.
    // Index zero is the sole STA VAP created by this profile. The returned
    // pointer is checked before it is passed back to the vendor function.
    let vap = unsafe { mac_res_get_hmac_vap(STATION_VAP_INDEX) };
    if vap.is_null() {
        return Err(StationPowerSaveDiagnosticError::StationVapUnavailable);
    }

    // SAFETY: `vap` was obtained from the vendor resource table above. Both
    // enum values match the SDK's `MAC_STA_PM_CTRL_TYPE_HOST` and
    // `MAC_STA_PM_SWITCH_OFF` ABI values. The call is made from task context,
    // outside interrupt-disabled and scheduler-lock regions.
    let status = unsafe { hmac_config_set_pm_by_module_etc(vap, PM_CONTROL_HOST, PM_SWITCH_OFF) };
    if status == 0 {
        Ok(())
    } else {
        Err(StationPowerSaveDiagnosticError::Vendor(status))
    }
}

/// Report that station power-save mutation is unavailable in host builds.
#[cfg(not(target_arch = "riscv32"))]
pub fn disable_station_power_save_for_diagnostics() -> Result<(), StationPowerSaveDiagnosticError> {
    Err(StationPowerSaveDiagnosticError::UnsupportedTarget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_build_rejects_target_only_operation() {
        assert_eq!(
            disable_station_power_save_for_diagnostics(),
            Err(StationPowerSaveDiagnosticError::UnsupportedTarget)
        );
    }
}
