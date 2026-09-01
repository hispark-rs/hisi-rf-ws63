//! WS63 Wi-Fi plus BLE shared-resource initialization smoke.

#![no_std]
#![no_main]

const BLE_CONNECTED_CLIENT: bool = false;

include!("coexistence_init_smoke.rs");
