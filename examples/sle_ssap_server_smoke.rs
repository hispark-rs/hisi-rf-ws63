//! Credential-free WS63 SLE S3 SSAP notification server smoke.

#![no_std]
#![no_main]

use hisi_panic_handler as _;
use hisi_riscv_rt::entry;
use ws63_radio_sys::sle::{Address, CONNECTION_STATE_CONNECTED, CONNECTION_STATE_DISCONNECTED};

#[path = "support/sle_firmware.rs"]
mod sle_firmware;

const SERVER_ADDRESS: Address = Address {
    address_type: 0,
    bytes: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
};
const PAYLOAD: [u8; 8] = *b"HISISLE3";

#[entry]
fn main() -> ! {
    sle_firmware::run(run_server)
}

fn run_server(controller: &mut hisi_rf_ws63::SleS1Controller) -> ! {
    let mut handles = None;
    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::SleS1Event::Enabled { status: 0 } if handles.is_none() => {
                    static mut PROPERTY_VALUE: [u8; 8] = [0; 8];
                    static mut ANNOUNCE_DATA: [u8; 7] = [1, 1, 1, 3, 2, 0x0b, 0x06];
                    static mut SEEK_RESPONSE_DATA: [u8; 10] =
                        [5, 8, b'H', b'I', b'S', b'I', b'S', b'L', b'E', b'3'];
                    let property = unsafe { &mut *core::ptr::addr_of_mut!(PROPERTY_VALUE) };
                    if controller.set_local_address(SERVER_ADDRESS).is_err() {
                        fail(b"RFDBG_SLE_S3_SERVER_ADDR_ERR\r\n");
                    }
                    handles = controller.configure_ssap_server(property).ok();
                    if handles.is_none() {
                        fail(b"RFDBG_SLE_S3_SERVER_SERVICE_ERR\r\n");
                    }
                    let announce = unsafe { &mut *core::ptr::addr_of_mut!(ANNOUNCE_DATA) };
                    let response = unsafe { &mut *core::ptr::addr_of_mut!(SEEK_RESPONSE_DATA) };
                    if controller.start_announce(announce, response).is_err() {
                        fail(b"RFDBG_SLE_S3_SERVER_ANNOUNCE_ERR\r\n");
                    }
                }
                hisi_rf_ws63::SleS1Event::SsapServiceStarted { status: 0, .. } => {
                    sle_firmware::log(b"RFDBG_SLE_S3_SERVER_SERVICE_OK\r\n");
                }
                hisi_rf_ws63::SleS1Event::AnnounceEnabled { status: 0, .. } => {
                    sle_firmware::log(b"RFDBG_SLE_S3_SERVER_READY\r\n");
                }
                hisi_rf_ws63::SleS1Event::ConnectionStateChanged {
                    connection_state: CONNECTION_STATE_CONNECTED,
                    ..
                } => {
                    sle_firmware::log(b"RFDBG_SLE_S3_SERVER_CONNECTED\r\n");
                }
                hisi_rf_ws63::SleS1Event::SsapReadRequested {
                    connection_id,
                    status: 0,
                    ..
                } => {
                    static mut NOTIFICATION: [u8; 8] = PAYLOAD;
                    let data = unsafe { &mut *core::ptr::addr_of_mut!(NOTIFICATION) };
                    if controller
                        .notify_ssap(handles.unwrap(), connection_id, data)
                        .is_err()
                    {
                        fail(b"RFDBG_SLE_S3_SERVER_NOTIFY_ERR\r\n");
                    }
                    sle_firmware::log(b"RFDBG_SLE_S3_SERVER_NOTIFY_OK\r\n");
                }
                hisi_rf_ws63::SleS1Event::ConnectionStateChanged {
                    connection_state: CONNECTION_STATE_DISCONNECTED,
                    ..
                } => {
                    sle_firmware::log(b"RFDBG_SLE_S3_SERVER_DISCONNECTED\r\n");
                }
                _ => {}
            }
        }
        if controller.dropped_events() != 0 {
            fail(b"RFDBG_SLE_S3_SERVER_EVENT_DROP\r\n");
        }
        sle_firmware::sleep();
    }
}

fn fail(marker: &[u8]) -> ! {
    sle_firmware::log(marker);
    sle_firmware::stop()
}
