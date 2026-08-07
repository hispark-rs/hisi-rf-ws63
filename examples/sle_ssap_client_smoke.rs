//! Credential-free WS63 SLE S3 SSAP notification client smoke.

#![no_std]
#![no_main]

use hisi_panic_handler as _;
use hisi_riscv_rt::entry;
use ws63_radio_sys::sle::{Address, CONNECTION_STATE_CONNECTED, CONNECTION_STATE_DISCONNECTED};

#[path = "support/sle_firmware.rs"]
mod sle_firmware;

const CLIENT_ADDRESS: Address = Address {
    address_type: 0,
    bytes: [0x13, 0x67, 0x5c, 0x07, 0x00, 0x51],
};
const SERVER_ADDRESS: Address = Address {
    address_type: 0,
    bytes: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
};
const PAYLOAD: [u8; 8] = *b"HISISLE3";

#[entry]
fn main() -> ! {
    sle_firmware::run(run_client)
}

fn run_client(controller: &mut hisi_rf_ws63::SleS1Controller) -> ! {
    let mut seeking = false;
    let mut connect_after_stop = false;
    let mut service = None;
    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::SleS1Event::Enabled { status: 0 } if !seeking => {
                    if controller.set_local_address(CLIENT_ADDRESS).is_err()
                        || controller.configure_default_connection().is_err()
                        || controller.start_seek().is_err()
                    {
                        fail(b"RFDBG_SLE_S3_CLIENT_START_ERR\r\n");
                    }
                    seeking = true;
                }
                hisi_rf_ws63::SleS1Event::SeekResult { address, .. }
                    if address == SERVER_ADDRESS && !connect_after_stop =>
                {
                    if controller.stop_seek().is_err() {
                        fail(b"RFDBG_SLE_S3_CLIENT_STOP_SEEK_ERR\r\n");
                    }
                    connect_after_stop = true;
                }
                hisi_rf_ws63::SleS1Event::SeekDisabled { status: 0 } if connect_after_stop => {
                    if controller.connect(&SERVER_ADDRESS).is_err() {
                        fail(b"RFDBG_SLE_S3_CLIENT_CONNECT_ERR\r\n");
                    }
                    connect_after_stop = false;
                }
                hisi_rf_ws63::SleS1Event::ConnectionStateChanged {
                    connection_state: CONNECTION_STATE_CONNECTED,
                    ..
                } => {
                    sle_firmware::log(b"RFDBG_SLE_S3_CLIENT_CONNECTED\r\n");
                    if controller.pair(&SERVER_ADDRESS).is_err() {
                        fail(b"RFDBG_SLE_S3_CLIENT_PAIR_ERR\r\n");
                    }
                }
                hisi_rf_ws63::SleS1Event::PairComplete {
                    connection_id,
                    address,
                    status: 0,
                } if address == SERVER_ADDRESS => {
                    sle_firmware::log(b"RFDBG_SLE_S3_CLIENT_PAIR_OK\r\n");
                    if controller.exchange_ssap_info(connection_id).is_err() {
                        fail(b"RFDBG_SLE_S3_CLIENT_EXCHANGE_ERR\r\n");
                    }
                }
                hisi_rf_ws63::SleS1Event::SsapExchangeComplete {
                    connection_id,
                    status: 0,
                    ..
                } => {
                    sle_firmware::log(b"RFDBG_SLE_S3_CLIENT_EXCHANGE_OK\r\n");
                    if controller.discover_ssap_services(connection_id).is_err() {
                        fail(b"RFDBG_SLE_S3_CLIENT_DISCOVERY_ERR\r\n");
                    }
                }
                hisi_rf_ws63::SleS1Event::SsapServiceFound {
                    connection_id,
                    start_handle,
                    uuid,
                    status: 0,
                    ..
                } if uuid.len == 2 && uuid.bytes[14..] == [0x0b, 0x06] => {
                    service = Some((connection_id, start_handle));
                    sle_firmware::log(b"RFDBG_SLE_S3_CLIENT_SERVICE_OK\r\n");
                }
                hisi_rf_ws63::SleS1Event::SsapDiscoveryComplete {
                    connection_id,
                    status: 0,
                    ..
                } => {
                    let Some((service_connection, handle)) = service else {
                        fail(b"RFDBG_SLE_S3_CLIENT_SERVICE_MISSING\r\n");
                    };
                    static mut WRITE_VALUE: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
                    let data = unsafe { &mut *core::ptr::addr_of_mut!(WRITE_VALUE) };
                    if service_connection != connection_id
                        || controller.write_ssap(connection_id, handle, data).is_err()
                    {
                        fail(b"RFDBG_SLE_S3_CLIENT_WRITE_ERR\r\n");
                    }
                }
                hisi_rf_ws63::SleS1Event::SsapWriteComplete {
                    connection_id,
                    handle,
                    status: 0,
                    ..
                } => {
                    sle_firmware::log(b"RFDBG_SLE_S3_CLIENT_WRITE_OK\r\n");
                    if controller.read_ssap(connection_id, handle).is_err() {
                        fail(b"RFDBG_SLE_S3_CLIENT_READ_ERR\r\n");
                    }
                }
                hisi_rf_ws63::SleS1Event::SsapNotification {
                    status: 0,
                    data_len: 8,
                    data,
                    ..
                } if data[..8] == PAYLOAD => {
                    sle_firmware::log(b"RFDBG_SLE_S3_CLIENT_DATA_OK\r\n");
                    if controller.disconnect(&SERVER_ADDRESS).is_err() {
                        fail(b"RFDBG_SLE_S3_CLIENT_DISCONNECT_ERR\r\n");
                    }
                }
                hisi_rf_ws63::SleS1Event::SsapNotification { .. } => {
                    fail(b"RFDBG_SLE_S3_CLIENT_DATA_ERR\r\n");
                }
                hisi_rf_ws63::SleS1Event::ConnectionStateChanged {
                    connection_state: CONNECTION_STATE_DISCONNECTED,
                    ..
                } => {
                    sle_firmware::log(b"RFDBG_SLE_S3_DATA_DISCONNECT_OK\r\n");
                }
                _ => {}
            }
        }
        if controller.dropped_events() != 0 {
            fail(b"RFDBG_SLE_S3_CLIENT_EVENT_DROP\r\n");
        }
        sle_firmware::sleep();
    }
}

fn fail(marker: &[u8]) -> ! {
    sle_firmware::log(marker);
    sle_firmware::stop()
}
