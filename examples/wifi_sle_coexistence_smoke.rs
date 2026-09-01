//! WS63 Wi-Fi plus SLE shared-resource initialization smoke.

#![no_std]
#![no_main]

const SLE_CONNECTED_CLIENT: bool = false;

include!("coexistence_init_smoke.rs");
