//! Credential-free WS63 SLE S1 seek smoke.

#![no_std]
#![no_main]

use hisi_panic_handler as _;
use hisi_riscv_rt::entry;

#[path = "support/sle_firmware.rs"]
mod sle_firmware;

#[entry]
fn main() -> ! {
    sle_firmware::run(run_seek)
}

fn run_seek(controller: &mut hisi_rf_ws63::SleS1Controller) -> ! {
    let mut started = false;
    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::SleS1Event::Enabled { status: 0 } if !started => {
                    if controller.start_seek().is_err() {
                        fail(b"RFDBG_SLE_S1_SEEK_ERR\r\n");
                    }
                    started = true;
                }
                hisi_rf_ws63::SleS1Event::SeekEnabled { status: 0 } => {
                    sle_firmware::log(b"RFDBG_SLE_S1_SEEK_READY\r\n");
                }
                hisi_rf_ws63::SleS1Event::SeekResult { address, .. }
                    if address.bytes == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] =>
                {
                    sle_firmware::log(b"RFDBG_SLE_S1_SEEK_MATCH\r\n");
                }
                hisi_rf_ws63::SleS1Event::SeekResult { .. } => {
                    sle_firmware::log(b"RFDBG_SLE_S1_SEEK_RESULT\r\n");
                }
                _ => {}
            }
        }
        if controller.dropped_events() != 0 {
            fail(b"RFDBG_SLE_S1_EVENT_DROP\r\n");
        }
        sle_firmware::sleep();
    }
}

fn fail(marker: &[u8]) -> ! {
    sle_firmware::log(marker);
    sle_firmware::stop()
}
