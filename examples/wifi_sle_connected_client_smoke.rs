//! WS63 Wi-Fi traffic while an SLE link remains connected.

#![no_std]
#![no_main]

const SLE_CONNECTED_CLIENT: bool = true;

include!("coexistence_init_smoke.rs");
