//! Maintainer-only markers around the synchronous vendor BLE enable stages.

use core::ffi::c_void;

unsafe extern "C" {
    fn __real_bt_init();
    fn __real_hci_init();
    fn __real_btsdk_init();
    fn __real_app_ble_init();
    fn __real_sdk_bta_interface_init();
    fn __real_bt_mpc_ble_enable_comp_notify();
    fn __real_bt_sync_config_from_file_to_global() -> u32;
    fn __real_btsdk_power_on_bluetooth() -> u32;
    fn __real_btsdk_initialize_local_device() -> u32;
    fn __real_gap_reset_hardware() -> u32;
    fn __real_hci_controller_init(
        callback: *const c_void,
        context: *mut c_void,
        controller: u8,
    ) -> u32;
    fn __real_gaph_reset_hardware_cbk(handle: *mut c_void, event: *mut c_void, status: *mut c_void);
    fn __real_api_h2c_write(
        destination: u32,
        message: u32,
        length: u32,
        payload: *mut c_void,
    ) -> i32;
    fn __real_app_ble_service_init() -> u32;
    fn __real_bt_dev_start_bluetooh(product_type: u8) -> u32;
    fn __real_bt_acore_get_product_type(output: *mut u8) -> u32;
    fn __real_sapi_ble_recover_product_type(product_type: u8) -> u32;
    fn __real_bt_acore_get_system_config(output: *mut u32) -> u32;
    fn __real_sapi_ble_recover_sys_config(config: u32) -> u32;
    fn __real_bt_acore_get_bt_name(output: *mut u8, length: *mut u8) -> u32;
    fn __real_sapi_ble_set_local_name(name: *const c_void, length: u8) -> u32;
}

macro_rules! trace_stage {
    ($wrapper:ident, $real:ident, $name:literal) => {
        #[unsafe(no_mangle)]
        extern "C" fn $wrapper() {
            crate::log_emit(concat!("RFDBG_BLE_B1_STAGE_BEGIN name=", $name, "\r\n").as_bytes());
            // SAFETY: the linker `--wrap` contract preserves the vendor
            // function's no-argument C ABI and redirects `__real_*` to the
            // original archive definition.
            unsafe { $real() };
            crate::log_emit(concat!("RFDBG_BLE_B1_STAGE_END name=", $name, "\r\n").as_bytes());
        }
    };
}

trace_stage!(__wrap_bt_init, __real_bt_init, "bt_init");
trace_stage!(__wrap_hci_init, __real_hci_init, "hci_init");

trace_stage!(__wrap_btsdk_init, __real_btsdk_init, "btsdk_init");
trace_stage!(__wrap_app_ble_init, __real_app_ble_init, "app_ble_init");
trace_stage!(
    __wrap_sdk_bta_interface_init,
    __real_sdk_bta_interface_init,
    "sdk_bta_interface_init"
);
trace_stage!(
    __wrap_bt_mpc_ble_enable_comp_notify,
    __real_bt_mpc_ble_enable_comp_notify,
    "bt_mpc_ble_enable_comp_notify"
);

fn trace_begin(name: &[u8]) {
    crate::log_emit(b"RFDBG_BLE_B1_CONFIG_BEGIN name=");
    crate::log_emit(name);
    crate::log_emit(b"\r\n");
}

fn trace_end(name: &[u8], status: u32) {
    crate::log_emit(b"RFDBG_BLE_B1_CONFIG_END name=");
    crate::log_emit(name);
    crate::log_emit(b" status=0x");
    let mut output = [0_u8; 8];
    for (index, digit) in output.iter_mut().enumerate() {
        let nibble = ((status >> ((7 - index) * 4)) & 0xf) as u8;
        *digit = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }
    crate::log_emit(&output);
    crate::log_emit(b"\r\n");
}

fn trace_hex32(value: u32) {
    let mut output = [0_u8; 8];
    for (index, digit) in output.iter_mut().enumerate() {
        let nibble = ((value >> ((7 - index) * 4)) & 0xf) as u8;
        *digit = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }
    crate::log_emit(&output);
}

macro_rules! trace_config_no_args {
    ($wrapper:ident, $real:ident, $name:literal) => {
        #[unsafe(no_mangle)]
        extern "C" fn $wrapper() -> u32 {
            trace_begin($name);
            // SAFETY: `--wrap` preserves the vendor function's C ABI.
            let status = unsafe { $real() };
            trace_end($name, status);
            status
        }
    };
}

macro_rules! trace_config_one_arg {
    ($wrapper:ident, $real:ident, $arg:ident : $ty:ty, $name:literal) => {
        #[unsafe(no_mangle)]
        extern "C" fn $wrapper($arg: $ty) -> u32 {
            trace_begin($name);
            // SAFETY: `--wrap` preserves the vendor function's C ABI.
            let status = unsafe { $real($arg) };
            trace_end($name, status);
            status
        }
    };
}

trace_config_no_args!(
    __wrap_bt_sync_config_from_file_to_global,
    __real_bt_sync_config_from_file_to_global,
    b"bt_sync_config_from_file_to_global"
);
trace_config_no_args!(
    __wrap_btsdk_power_on_bluetooth,
    __real_btsdk_power_on_bluetooth,
    b"btsdk_power_on_bluetooth"
);
trace_config_no_args!(
    __wrap_btsdk_initialize_local_device,
    __real_btsdk_initialize_local_device,
    b"btsdk_initialize_local_device"
);
trace_config_no_args!(
    __wrap_gap_reset_hardware,
    __real_gap_reset_hardware,
    b"gap_reset_hardware"
);
trace_config_no_args!(
    __wrap_app_ble_service_init,
    __real_app_ble_service_init,
    b"app_ble_service_init"
);
trace_config_one_arg!(
    __wrap_bt_dev_start_bluetooh,
    __real_bt_dev_start_bluetooh,
    product_type: u8,
    b"bt_dev_start_bluetooh"
);
trace_config_one_arg!(
    __wrap_bt_acore_get_product_type,
    __real_bt_acore_get_product_type,
    output: *mut u8,
    b"bt_acore_get_product_type"
);
trace_config_one_arg!(
    __wrap_sapi_ble_recover_product_type,
    __real_sapi_ble_recover_product_type,
    product_type: u8,
    b"sapi_ble_recover_product_type"
);
trace_config_one_arg!(
    __wrap_bt_acore_get_system_config,
    __real_bt_acore_get_system_config,
    output: *mut u32,
    b"bt_acore_get_system_config"
);
trace_config_one_arg!(
    __wrap_sapi_ble_recover_sys_config,
    __real_sapi_ble_recover_sys_config,
    config: u32,
    b"sapi_ble_recover_sys_config"
);

#[unsafe(no_mangle)]
extern "C" fn __wrap_bt_acore_get_bt_name(output: *mut u8, length: *mut u8) -> u32 {
    trace_begin(b"bt_acore_get_bt_name");
    // SAFETY: `--wrap` preserves the vendor function's C ABI.
    let status = unsafe { __real_bt_acore_get_bt_name(output, length) };
    trace_end(b"bt_acore_get_bt_name", status);
    status
}

#[unsafe(no_mangle)]
extern "C" fn __wrap_sapi_ble_set_local_name(name: *const c_void, length: u8) -> u32 {
    trace_begin(b"sapi_ble_set_local_name");
    // SAFETY: `--wrap` preserves the vendor function's C ABI.
    let status = unsafe { __real_sapi_ble_set_local_name(name, length) };
    trace_end(b"sapi_ble_set_local_name", status);
    status
}

#[unsafe(no_mangle)]
extern "C" fn __wrap_hci_controller_init(
    callback: *const c_void,
    context: *mut c_void,
    controller: u8,
) -> u32 {
    trace_begin(b"hci_controller_init");
    // SAFETY: `--wrap` preserves the vendor function's C ABI.
    let status = unsafe { __real_hci_controller_init(callback, context, controller) };
    trace_end(b"hci_controller_init", status);
    status
}

#[unsafe(no_mangle)]
extern "C" fn __wrap_gaph_reset_hardware_cbk(
    handle: *mut c_void,
    event: *mut c_void,
    status: *mut c_void,
) {
    trace_begin(b"gaph_reset_hardware_cbk");
    // SAFETY: `--wrap` preserves the vendor callback's C ABI.
    unsafe { __real_gaph_reset_hardware_cbk(handle, event, status) };
    trace_end(b"gaph_reset_hardware_cbk", 0);
}

#[unsafe(no_mangle)]
extern "C" fn __wrap_api_h2c_write(
    destination: u32,
    message: u32,
    length: u32,
    payload: *mut c_void,
) -> i32 {
    trace_begin(b"api_h2c_write");
    let payload_word = if payload.is_null() || length < 4 {
        0
    } else {
        // SAFETY: the wrapped ABI promises `length` readable payload bytes.
        unsafe { payload.cast::<u32>().read_unaligned() }
    };
    crate::log_emit(b"RFDBG_BLE_B1_H2C destination=0x");
    trace_hex32(destination);
    crate::log_emit(b" message=0x");
    trace_hex32(message);
    crate::log_emit(b" length=0x");
    trace_hex32(length);
    crate::log_emit(b" payload_word=0x");
    trace_hex32(payload_word);
    crate::log_emit(b"\r\n");
    // SAFETY: `--wrap` preserves the vendor function's C ABI and ownership.
    let status = unsafe { __real_api_h2c_write(destination, message, length, payload) };
    trace_end(b"api_h2c_write", status as u32);
    status
}
