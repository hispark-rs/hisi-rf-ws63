//! Credential-free WS63 BLE B3 GATT server smoke.

#![no_std]
#![no_main]

use hisi_panic_handler as _;
use hisi_riscv_rt::entry;

#[path = "support/ble_firmware.rs"]
mod ble_firmware;

static ADVERTISING_DATA: &[u8] = &[
    2, 0x01, 0x06, 8, 0x09, b'H', b'I', b'S', b'I', b'B', b'3', b'S',
];

#[entry]
fn main() -> ! {
    ble_firmware::run(run_server)
}

fn run_server(controller: &mut hisi_rf_ws63::BleB1Controller) -> ! {
    let mut server = None;
    let mut connected = false;

    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::BleB2Event::Enabled { status: 0 } if server.is_none() => {
                    match controller.register_gatt_server() {
                        Ok(registered) => {
                            server = Some(registered);
                            ble_firmware::log(b"RFDBG_BLE_B3_SERVER_REGISTERED\r\n");
                        }
                        Err(_) => fail(b"RFDBG_BLE_B3_SERVER_REGISTER_ERR\r\n"),
                    }
                }
                hisi_rf_ws63::BleB2Event::GattServiceStarted { status: 0, .. } => {
                    if controller.start_advertising(ADVERTISING_DATA).is_err() {
                        fail(b"RFDBG_BLE_B3_SERVER_ADV_ERR\r\n");
                    }
                    ble_firmware::log(b"RFDBG_BLE_B3_SERVICE_READY\r\n");
                }
                hisi_rf_ws63::BleB2Event::AdvertisingState { status: 1, .. } => {
                    ble_firmware::log(b"RFDBG_BLE_B3_SERVER_ADV_OK\r\n");
                }
                hisi_rf_ws63::BleB2Event::ConnectionState {
                    connected: true, ..
                } => {
                    connected = true;
                    ble_firmware::log(b"RFDBG_BLE_B3_SERVER_CONNECTED\r\n");
                }
                hisi_rf_ws63::BleB2Event::ConnectionState {
                    connected: false, ..
                } if connected => {
                    connected = false;
                    ble_firmware::log(b"RFDBG_BLE_B3_SERVER_DISCONNECTED\r\n");
                }
                hisi_rf_ws63::BleB2Event::GattServerWrite {
                    conn_id,
                    handle,
                    status: 0,
                    value_len,
                    value,
                    ..
                } => {
                    let Some(registered) = server else {
                        fail(b"RFDBG_BLE_B3_SERVER_STATE_ERR\r\n");
                    };
                    if handle != registered.value_handle || value_len == 0 {
                        continue;
                    }
                    if value[0] == b'N' {
                        static mut NOTIFICATION: [u8; 2] = *b"N3";
                        let payload = unsafe { &mut *core::ptr::addr_of_mut!(NOTIFICATION) };
                        if controller
                            .gatt_notify_or_indicate(registered, conn_id, payload)
                            .is_err()
                        {
                            fail(b"RFDBG_BLE_B3_NOTIFY_ERR\r\n");
                        }
                        ble_firmware::log(b"RFDBG_BLE_B3_NOTIFY_SENT\r\n");
                    } else if value[0] == b'I' {
                        static mut INDICATION: [u8; 2] = *b"I3";
                        let payload = unsafe { &mut *core::ptr::addr_of_mut!(INDICATION) };
                        if controller
                            .gatt_notify_or_indicate(registered, conn_id, payload)
                            .is_err()
                        {
                            fail(b"RFDBG_BLE_B3_INDICATE_ERR\r\n");
                        }
                        ble_firmware::log(b"RFDBG_BLE_B3_INDICATE_SENT\r\n");
                    }
                }
                hisi_rf_ws63::BleB2Event::GattIndicationConfirmed { status: 0, .. } => {
                    ble_firmware::log(b"RFDBG_BLE_B3_INDICATE_CONFIRMED\r\n");
                }
                _ => {}
            }
        }
        if controller.dropped_events() != 0 {
            fail(b"RFDBG_BLE_B3_EVENT_DROP\r\n");
        }
        ble_firmware::sleep();
    }
}

fn fail(marker: &[u8]) -> ! {
    ble_firmware::log(marker);
    ble_firmware::stop()
}
