#![no_std]
#![no_main]

use hisi_panic_handler as _;
use hisi_rf_ws63 as _;
use hisi_riscv_rt::entry;

unsafe extern "C" {
    fn bt_thread_handle(argument: *mut core::ffi::c_void);
    fn bt_acore_task_main();
    fn sdk_msg_thread();
    fn btsrv_task_body(argument: *const core::ffi::c_void);
    fn btsdk_init();
    fn enable_ble() -> u32;
}

#[entry]
fn main() -> ! {
    hisi_rf_ws63::ensure_ble_init_link_contract();
    let roots = [
        bt_thread_handle as *const () as usize,
        bt_acore_task_main as *const () as usize,
        sdk_msg_thread as *const () as usize,
        btsrv_task_body as *const () as usize,
        btsdk_init as *const () as usize,
        enable_ble as *const () as usize,
    ];
    core::hint::black_box(roots);
    loop {
        core::hint::spin_loop();
    }
}
