use super::*;
use crate::netif_l2::{CallbackRoute, NativeLink};
use core::task::{Context, Waker};
use embassy_net_driver::{Driver, RxToken};
use hisi_rf_core::{WifiL2Capabilities, l2::L2Storage};

fn mac() -> WifiL2Capabilities {
    WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap()
}

fn pbuf(payload: &mut [u8]) -> Pbuf {
    Pbuf {
        next: core::ptr::null_mut(),
        payload: payload.as_mut_ptr().cast(),
        tot_len: payload.len() as u16,
        len: payload.len() as u16,
        list: core::ptr::null_mut(),
        malloc_len: 0,
        type_internal: PBUF_TYPE_RAM,
        _type_pad: 0,
        flags: 0,
        _flags_pad: 0,
        ref_count: 2,
        if_idx: NETIF_NO_INDEX,
        priority: 0,
        _tail_pad: [0; 2],
    }
}

#[test]
fn pbuf_padding_is_removed_and_vendor_memory_is_not_retained() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    let mut payload = [0xaa, 0xbb, 1, 2, 3];
    let p = pbuf(&mut payload);
    // SAFETY: p/payload remain live, immutable and exclusively owned here.
    assert!(unsafe { receive_standard_pbuf(route.enter(), &p) });
    payload.fill(0);
    let mut cx = Context::from_waker(Waker::noop());
    let (rx, tx) = parts.device.receive(&mut cx).unwrap();
    rx.consume(|frame| assert_eq!(frame, &[1, 2, 3]));
    drop(tx);
    assert_eq!(link.rx_diagnostics().delivered, 1);
}

#[test]
fn invalid_pbufs_and_full_queue_are_explicit_callback_drops() {
    let mut storage = L2Storage::<1, 1, 64>::new();
    let parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    // SAFETY: a null pbuf is expressly accepted by this helper.
    assert!(!unsafe { receive_standard_pbuf(route.enter(), core::ptr::null()) });
    for case in 0..6 {
        let mut payload = [0; 67];
        let mut p = pbuf(&mut payload[..5]);
        match case {
            0 => p.payload = core::ptr::null_mut(),
            1 => p.len = 2,
            2 => p.len = 0,
            3 => p.next = &raw mut p,
            4 => p.tot_len += 1,
            5 => {
                p.len = 67;
                p.tot_len = 67;
            }
            _ => unreachable!(),
        }
        // SAFETY: p and its non-null payload refer to live local storage.
        assert!(!unsafe { receive_standard_pbuf(route.enter(), &p) });
    }
    let mut payload = [0, 0, 1];
    let p = pbuf(&mut payload);
    // SAFETY: p/payload remain live and immutable across both copies.
    assert!(unsafe { receive_standard_pbuf(route.enter(), &p) });
    assert!(!unsafe { receive_standard_pbuf(route.enter(), &p) });
    let d = route.diagnostics();
    assert_eq!(d.entered, 9);
    assert_eq!(d.queued, 1);
    assert_eq!(d.dropped, 8);
    assert_eq!(d.in_flight, 0);
}

#[test]
fn close_during_pbuf_delivery_cannot_publish_into_the_next_epoch() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    let delayed = route.enter();
    link.close().unwrap();
    let mut payload = [0, 0, 9];
    let p = pbuf(&mut payload);
    // SAFETY: this local pbuf remains live while the old ticket is rejected.
    assert!(!unsafe { receive_standard_pbuf(delayed, &p) });
    link.begin_after_native_quiescence().unwrap();
    assert_eq!(link.rx_diagnostics().pending, 0);
    assert_eq!(route.diagnostics().dropped, 1);
}

#[test]
fn real_callback_uses_only_the_registered_route_and_releases_its_pbuf_reference() {
    // Only this test uses the process-global C callback route. Other tests use
    // local routes and cannot race its registration/netif identity.
    static STORAGE: static_cell::StaticCell<L2Storage<4, 2>> = static_cell::StaticCell::new();
    let storage = STORAGE.init(L2Storage::new());
    let parts = storage.split(mac());
    let mut link = crate::netif_l2::bind_native(parts.port).unwrap();
    let mut identity = 0_u8;
    let netif = (&raw mut identity).cast::<c_void>();
    netifapi_netif_add(
        netif,
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
    );
    let before = crate::netif_l2::NATIVE_RX_ROUTE.diagnostics();
    for case in 0..3 {
        if case == 1 {
            link.begin_after_native_quiescence().unwrap();
        }
        let mut payload = [0, 0, 1, 2, 3];
        let mut p = pbuf(&mut payload);
        let supplied_netif = if case == 1 {
            core::ptr::null_mut()
        } else {
            netif
        };
        assert_eq!(driverif_input(supplied_netif, (&raw mut p).cast()), 0);
        assert_eq!(
            p.ref_count, 1,
            "callback must release exactly its own reference"
        );
    }
    assert_eq!(link.rx_diagnostics().pending, 1);
    let after = crate::netif_l2::NATIVE_RX_ROUTE.diagnostics();
    assert_eq!(after.entered - before.entered, 3);
    assert_eq!(after.queued - before.queued, 1);
    assert_eq!(after.dropped - before.dropped, 2);
    assert_eq!(after.in_flight, 0);
    netifapi_netif_remove(netif);
    drop(link);
}
