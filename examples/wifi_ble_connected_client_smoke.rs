//! WS63 connected BLE client plus Wi-Fi traffic coexistence smoke.

#![no_std]
#![no_main]

const BLE_CONNECTED_CLIENT: bool = true;

include!("coexistence_init_smoke.rs");
