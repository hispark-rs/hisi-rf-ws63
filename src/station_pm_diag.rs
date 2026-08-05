//! Diagnostic-only WS63 station power-save control.

#[cfg(target_arch = "riscv32")]
const PM_SWITCH_OFF: u8 = 0;

/// Failure returned by the diagnostic station power-save override.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StationPowerSaveDiagnosticError {
    /// The vendor power-management operation rejected the request.
    Vendor(i32),
    /// The operation is only available in WS63 firmware builds.
    UnsupportedTarget,
}

/// Disable station power save before association for a bounded HIL A/B test.
///
/// This is not a production policy API. Normal profiles leave the vendor power
/// policy unchanged; callers must explicitly enable `station-pm-diag`.
#[cfg(target_arch = "riscv32")]
pub fn disable_station_power_save_for_diagnostics() -> Result<(), StationPowerSaveDiagnosticError> {
    unsafe extern "C" {
        fn uapi_wifi_set_pm_switch(enable: u8, sleep_time: u32) -> i32;
    }

    // SAFETY: this is the public vendor station-PM UAPI used by
    // `wifi_sta_set_pm`. The radio is initialized, and the call runs from task
    // context outside interrupt-disabled and scheduler-lock regions.
    let status = unsafe { uapi_wifi_set_pm_switch(PM_SWITCH_OFF, 0) };
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
