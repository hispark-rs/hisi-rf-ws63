//! Compile-time migration contract for the internal BLE B3 and SLE S3 slices.
//!
//! These symbols deliberately remain `#[doc(hidden)]`. The contract keeps the
//! reviewed U0 migration inputs available until the `hisi-rf` facade owns their
//! behavior; it does not declare them stable application API.

#![cfg(any(feature = "ble-init", feature = "sle-init"))]

fn assert_type<T>() {}

#[cfg(feature = "ble-init")]
#[test]
fn ble_b3_migration_inputs_compile() {
    assert_type::<hisi_rf_ws63::BleB1Controller>();
    assert_type::<hisi_rf_ws63::BleB1Storage<{ hisi_rf_ws63::BLE_B1_ARENA_BYTES }>>();
    assert_type::<hisi_rf_ws63::BleB1Resources>();
    assert_type::<hisi_rf_ws63::BleB2Event>();
    assert_type::<hisi_rf_ws63::BleGattClient>();
    assert_type::<hisi_rf_ws63::BleGattServer>();
    let _ = hisi_rf_ws63::init_ble_b1;
    let _ = hisi_rf_ws63::BleB1Controller::next_event;
    let _ = hisi_rf_ws63::BleB1Controller::dropped_events;
    let _ = hisi_rf_ws63::BleB1Controller::stop_advertising;
    let _ = hisi_rf_ws63::BleB1Controller::stop_scanning;
}

#[cfg(feature = "sle-init")]
#[test]
fn sle_s3_migration_inputs_compile() {
    assert_type::<hisi_rf_ws63::SleS1Controller>();
    assert_type::<hisi_rf_ws63::SleS1Storage<{ hisi_rf_ws63::SLE_S1_ARENA_BYTES }>>();
    assert_type::<hisi_rf_ws63::SleS1Resources>();
    assert_type::<hisi_rf_ws63::SleS1Event>();
    assert_type::<hisi_rf_ws63::SsapServerHandles>();
    let _ = hisi_rf_ws63::init_sle_s1;
    let _ = hisi_rf_ws63::SleS1Controller::next_event;
    let _ = hisi_rf_ws63::SleS1Controller::dropped_events;
    let _ = hisi_rf_ws63::SleS1Controller::stop_announce;
    let _ = hisi_rf_ws63::SleS1Controller::stop_seek;
}
