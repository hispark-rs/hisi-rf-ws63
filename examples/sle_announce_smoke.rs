//! Credential-free WS63 SLE S1 announce smoke.

#![no_std]
#![no_main]

use hisi_panic_handler as _;
use hisi_riscv_rt::entry;

#[path = "support/sle_firmware.rs"]
mod sle_firmware;

#[entry]
fn main() -> ! {
    sle_firmware::run(run_announce)
}

fn run_announce(controller: &mut hisi_rf_ws63::SleS1Controller) -> ! {
    let mut started = false;
    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::SleS1Event::Enabled { status: 0 } if !started => {
                    static mut ANNOUNCE_DATA: [u8; 7] = [1, 1, 1, 3, 2, 0x0b, 0x06];
                    static mut SEEK_RESPONSE_DATA: [u8; 10] =
                        [5, 8, b'H', b'I', b'S', b'I', b'S', b'L', b'E', b'1'];
                    let announce = unsafe { &mut *core::ptr::addr_of_mut!(ANNOUNCE_DATA) };
                    let response = unsafe { &mut *core::ptr::addr_of_mut!(SEEK_RESPONSE_DATA) };
                    if controller.start_announce(announce, response).is_err() {
                        fail(b"RFDBG_SLE_S1_ANNOUNCE_ERR\r\n");
                    }
                    started = true;
                }
                hisi_rf_ws63::SleS1Event::AnnounceEnabled { status: 0, .. } => {
                    sle_firmware::log(b"RFDBG_SLE_S1_ANNOUNCE_OK\r\n");
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
