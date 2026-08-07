//! Credential-free WS63 BLE B3 GATT client smoke.

#![no_std]
#![no_main]

use hisi_panic_handler as _;
use hisi_riscv_rt::entry;

#[path = "support/ble_firmware.rs"]
mod ble_firmware;

static SERVER_ADVERTISING_DATA: &[u8] = &[
    2, 0x01, 0x06, 8, 0x09, b'H', b'I', b'S', b'I', b'B', b'3', b'S',
];

#[derive(Clone, Copy, Eq, PartialEq)]
enum ClientStage {
    Boot,
    Scanning,
    Connecting,
    DiscoveringService,
    DiscoveringCharacteristic,
    DiscoveringDescriptor,
    EnablingNotification,
    WritingNotificationRequest,
    EnablingIndication,
    WritingIndicationRequest,
    Disconnecting,
    Complete,
}

#[entry]
fn main() -> ! {
    ble_firmware::run(run_client)
}

fn run_client(controller: &mut hisi_rf_ws63::BleB1Controller) -> ! {
    let mut client = None;
    let mut peer = None;
    let mut conn_id = 0;
    let mut value_handle = 0;
    let mut ccc_handle = 0;
    let mut stage = ClientStage::Boot;

    loop {
        while let Some(event) = controller.next_event() {
            match event {
                hisi_rf_ws63::BleB2Event::Enabled { status: 0 } if stage == ClientStage::Boot => {
                    client = Some(
                        controller
                            .register_gatt_client()
                            .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_CLIENT_REGISTER_ERR\r\n")),
                    );
                    controller
                        .start_scanning()
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_CLIENT_SCAN_ERR\r\n"));
                    stage = ClientStage::Scanning;
                    ble_firmware::log(b"RFDBG_BLE_B3_CLIENT_SCAN_READY\r\n");
                }
                hisi_rf_ws63::BleB2Event::ScanResult {
                    address,
                    address_type,
                    data_len,
                    data,
                    ..
                } if stage == ClientStage::Scanning => {
                    let length = usize::from(data_len).min(data.len());
                    if data[..length] == *SERVER_ADVERTISING_DATA {
                        peer = Some((address, address_type));
                        controller
                            .connect(address, address_type)
                            .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_CONNECT_ERR\r\n"));
                        stage = ClientStage::Connecting;
                        ble_firmware::log(b"RFDBG_BLE_B3_SCAN_MATCH\r\n");
                    }
                }
                hisi_rf_ws63::BleB2Event::ConnectionState {
                    conn_id: connected_id,
                    connected: true,
                    ..
                } if stage == ClientStage::Connecting => {
                    conn_id = connected_id;
                    controller
                        .discover_b3_service(client.unwrap(), conn_id)
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_SERVICE_DISCOVERY_ERR\r\n"));
                    stage = ClientStage::DiscoveringService;
                    ble_firmware::log(b"RFDBG_BLE_B3_CLIENT_CONNECTED\r\n");
                }
                hisi_rf_ws63::BleB2Event::GattServiceDiscovered {
                    start_handle,
                    uuid: hisi_rf_ws63::BLE_B3_SERVICE_UUID,
                    status: 0,
                    ..
                } if stage == ClientStage::DiscoveringService => {
                    controller
                        .discover_b3_characteristic(client.unwrap(), conn_id, start_handle)
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_CHAR_DISCOVERY_ERR\r\n"));
                    stage = ClientStage::DiscoveringCharacteristic;
                    ble_firmware::log(b"RFDBG_BLE_B3_SERVICE_FOUND\r\n");
                }
                hisi_rf_ws63::BleB2Event::GattCharacteristicDiscovered {
                    declaration_handle,
                    value_handle: discovered_value,
                    uuid: hisi_rf_ws63::BLE_B3_CHARACTERISTIC_UUID,
                    status: 0,
                    ..
                } if stage == ClientStage::DiscoveringCharacteristic => {
                    value_handle = discovered_value;
                    controller
                        .discover_descriptors(client.unwrap(), conn_id, declaration_handle)
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_DESC_DISCOVERY_ERR\r\n"));
                    stage = ClientStage::DiscoveringDescriptor;
                    ble_firmware::log(b"RFDBG_BLE_B3_CHARACTERISTIC_FOUND\r\n");
                }
                hisi_rf_ws63::BleB2Event::GattDescriptorDiscovered {
                    handle,
                    uuid: hisi_rf_ws63::BLE_B3_CCC_UUID,
                    status: 0,
                    ..
                } if stage == ClientStage::DiscoveringDescriptor => {
                    ccc_handle = handle;
                    static mut NOTIFY_CCC: [u8; 2] = [1, 0];
                    let payload = unsafe { &mut *core::ptr::addr_of_mut!(NOTIFY_CCC) };
                    controller
                        .gatt_write(client.unwrap(), conn_id, ccc_handle, payload)
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_CCC_NOTIFY_ERR\r\n"));
                    stage = ClientStage::EnablingNotification;
                    ble_firmware::log(b"RFDBG_BLE_B3_DESCRIPTOR_FOUND\r\n");
                }
                hisi_rf_ws63::BleB2Event::GattWriteCompleted {
                    handle, status: 0, ..
                } if stage == ClientStage::EnablingNotification && handle == ccc_handle => {
                    static mut REQUEST: [u8; 1] = *b"N";
                    let payload = unsafe { &mut *core::ptr::addr_of_mut!(REQUEST) };
                    controller
                        .gatt_write(client.unwrap(), conn_id, value_handle, payload)
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_WRITE_NOTIFY_ERR\r\n"));
                    stage = ClientStage::WritingNotificationRequest;
                }
                hisi_rf_ws63::BleB2Event::GattNotification {
                    handle,
                    status: 0,
                    value_len: 2,
                    value,
                    ..
                } if stage == ClientStage::WritingNotificationRequest
                    && handle == value_handle
                    && value[..2] == *b"N3" =>
                {
                    ble_firmware::log(b"RFDBG_BLE_B3_NOTIFICATION_OK\r\n");
                    static mut INDICATE_CCC: [u8; 2] = [2, 0];
                    let payload = unsafe { &mut *core::ptr::addr_of_mut!(INDICATE_CCC) };
                    controller
                        .gatt_write(client.unwrap(), conn_id, ccc_handle, payload)
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_CCC_INDICATE_ERR\r\n"));
                    stage = ClientStage::EnablingIndication;
                }
                hisi_rf_ws63::BleB2Event::GattWriteCompleted {
                    handle, status: 0, ..
                } if stage == ClientStage::EnablingIndication && handle == ccc_handle => {
                    static mut REQUEST: [u8; 1] = *b"I";
                    let payload = unsafe { &mut *core::ptr::addr_of_mut!(REQUEST) };
                    controller
                        .gatt_write(client.unwrap(), conn_id, value_handle, payload)
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_WRITE_INDICATE_ERR\r\n"));
                    stage = ClientStage::WritingIndicationRequest;
                }
                hisi_rf_ws63::BleB2Event::GattIndication {
                    handle,
                    status: 0,
                    value_len: 2,
                    value,
                    ..
                } if stage == ClientStage::WritingIndicationRequest
                    && handle == value_handle
                    && value[..2] == *b"I3" =>
                {
                    ble_firmware::log(b"RFDBG_BLE_B3_INDICATION_OK\r\n");
                    let (address, address_type) = peer.unwrap();
                    controller
                        .disconnect(address, address_type)
                        .unwrap_or_else(|_| fail(b"RFDBG_BLE_B3_DISCONNECT_ERR\r\n"));
                    stage = ClientStage::Disconnecting;
                }
                hisi_rf_ws63::BleB2Event::ConnectionState {
                    connected: false, ..
                } if stage == ClientStage::Disconnecting => {
                    stage = ClientStage::Complete;
                    ble_firmware::log(b"RFDBG_BLE_B3_CLIENT_DISCONNECTED\r\n");
                    ble_firmware::log(b"RFDBG_BLE_B3_GATT_OK\r\n");
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
