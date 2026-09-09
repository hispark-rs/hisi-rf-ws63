use super::*;
use core::task::{Context, Poll, Waker};
use embassy_net_driver::{Driver, LinkState, TxToken};
use hisi_rf_core::{WifiL2Capabilities, l2::L2Storage};

fn mac() -> WifiL2Capabilities {
    WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap()
}

#[test]
fn native_close_is_level_observed_and_wakes_the_registered_worker() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::Wake;
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    link.begin_after_native_quiescence().unwrap();
    assert!(!link.poll_native_close(&mut cx).unwrap());
    parts
        .device
        .transmit(&mut cx)
        .unwrap()
        .consume(1, |b| b[0] = 1);
    route.close_admission();
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert!(link.poll_native_close(&mut cx).unwrap());
    assert!(parts.device.link_state(&mut cx) == LinkState::Down);
    assert_eq!(link.tx_diagnostics().dropped, 1);
    assert!(!link.poll_native_close(&mut cx).unwrap());

    // No waiter is needed for correctness: a close before the next subscribe
    // remains visible by revision, rather than relying only on an edge.
    link.begin_after_native_quiescence().unwrap();
    route.close_admission();
    route.close_admission();
    assert!(link.poll_native_close(&mut cx).unwrap());
    assert!(parts.device.link_state(&mut cx) == LinkState::Down);
    assert!(!link.poll_native_close(&mut cx).unwrap());
}

#[test]
fn close_before_first_worker_poll_is_not_lost() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    route.close_admission();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(link.poll_native_close(&mut cx).unwrap());
    assert!(parts.device.link_state(&mut cx) == LinkState::Down);
    assert!(parts.device.transmit(&mut cx).is_none());
}

fn assert_conserved(route: &CallbackRoute<'_, 2, 64>) {
    let d = route.diagnostics();
    assert_eq!(d.entered, d.queued + d.dropped + d.in_flight as u64);
}

#[test]
fn route_is_closed_until_claimed_and_opened() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    assert!(route.enter().is_none());
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    assert!(route.enter().is_none());
    assert!(matches!(
        route.claim(parts.port.ingress()),
        Err(RouteError::AlreadyRegistered)
    ));
    let generation = parts.port.begin_session().unwrap();
    owner.open_after_native_quiescence(generation).unwrap();
    assert_eq!(
        owner.open_after_native_quiescence(generation),
        Err(RouteError::AlreadyOpen)
    );
    route.enter().unwrap().receive(&[1, 2, 3]).unwrap();
    assert_eq!(parts.port.rx_diagnostics().pending, 1);
    assert_eq!(route.diagnostics().closed_drops, 2);
    assert_conserved(&route);
}

#[test]
fn delayed_callback_cannot_be_retagged_for_a_reconnection() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    let old = parts.port.begin_session().unwrap();
    owner.open_after_native_quiescence(old).unwrap();
    let delayed = route.enter().unwrap();
    owner.close();
    parts.port.link_down().unwrap();
    assert!(route.enter().is_none());
    let new = parts.port.begin_session().unwrap();
    assert_eq!(
        owner.open_after_native_quiescence(new),
        Err(RouteError::CallbacksInFlight)
    );
    assert_eq!(delayed.receive(&[9]), Err(QueueError::StaleGeneration));
    owner.open_after_native_quiescence(new).unwrap();
    route.enter().unwrap().receive(&[3]).unwrap();
    assert_eq!(parts.port.rx_diagnostics().pending, 1);
    assert_eq!(route.diagnostics().queued, 1);
    assert_conserved(&route);
}

#[test]
fn native_teardown_closes_admission_without_taking_the_worker_port() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    let generation = parts.port.begin_session().unwrap();
    owner.open_after_native_quiescence(generation).unwrap();
    let delayed = route.enter().unwrap();
    route.close_admission();
    assert!(route.enter().is_none());
    assert_eq!(delayed.receive(&[9]), Err(QueueError::StaleGeneration));
    assert_eq!(parts.port.rx_diagnostics().pending, 0);
    assert_conserved(&route);
    // The worker still owes port invalidation and native drainage; a route
    // close is deliberately not reported as an established native fence.
    parts.port.link_down().unwrap();
}

#[test]
fn drop_closes_registration_and_blocks_reclaim_until_tickets_drain() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    let generation = parts.port.begin_session().unwrap();
    owner.open_after_native_quiescence(generation).unwrap();
    let ticket = route.enter().unwrap();
    drop(owner);
    assert!(route.enter().is_none());
    assert!(matches!(
        route.claim(parts.port.ingress()),
        Err(RouteError::CallbacksInFlight)
    ));
    drop(ticket);
    let _new = route.claim(parts.port.ingress()).unwrap();
    assert!(route.enter().is_none());
    assert_eq!(route.diagnostics().abandoned, 1);
    assert_conserved(&route);
}

#[test]
fn full_oversized_and_abandoned_callbacks_are_accounted() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    let generation = parts.port.begin_session().unwrap();
    owner.open_after_native_quiescence(generation).unwrap();
    for _ in 0..2 {
        route.enter().unwrap().receive(&[1; 64]).unwrap();
    }
    assert_eq!(route.enter().unwrap().receive(&[2]), Err(QueueError::Full));
    assert_eq!(
        route.enter().unwrap().receive(&[3; 65]),
        Err(QueueError::FrameTooLarge)
    );
    drop(route.enter().unwrap());
    assert_eq!(route.diagnostics().queued, 2);
    assert_eq!(route.diagnostics().dropped, 3);
    assert_conserved(&route);
}

#[test]
fn concurrent_callbacks_do_not_share_mutable_payload_storage() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    let generation = parts.port.begin_session().unwrap();
    owner.open_after_native_quiescence(generation).unwrap();
    std::thread::scope(|scope| {
        for value in 0..4 {
            let route = &route;
            scope.spawn(move || {
                for _ in 0..8 {
                    let _ = route.enter().unwrap().receive(&[value; 64]);
                }
            });
        }
    });
    assert_eq!(route.diagnostics().entered, 32);
    assert_eq!(route.diagnostics().queued, 2);
    assert_eq!(route.diagnostics().dropped, 30);
    assert_conserved(&route);
}

#[test]
fn native_link_drop_invalidates_the_device_and_delayed_callbacks() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(parts.device.link_state(&mut cx) == LinkState::Down);
    link.begin_after_native_quiescence().unwrap();
    let ticket = route.enter().unwrap();
    assert!(parts.device.link_state(&mut cx) == LinkState::Up);
    drop(link);
    assert!(parts.device.link_state(&mut cx) == LinkState::Down);
    assert_eq!(ticket.receive(&[1]), Err(QueueError::StaleGeneration));
    assert!(parts.device.receive(&mut cx).is_none());
    assert_conserved(&route);
}

#[test]
fn native_close_during_link_up_wake_cannot_be_overwritten_by_open() {
    use std::sync::{Arc, Barrier};
    use std::task::Wake;

    struct Interleave {
        entered: Arc<Barrier>,
        closed: Arc<Barrier>,
    }
    impl Wake for Interleave {
        fn wake(self: Arc<Self>) {
            self.entered.wait();
            self.closed.wait();
        }
    }

    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    let entered = Arc::new(Barrier::new(2));
    let closed = Arc::new(Barrier::new(2));
    let waker = Waker::from(Arc::new(Interleave {
        entered: entered.clone(),
        closed: closed.clone(),
    }));
    assert!(parts.device.link_state(&mut Context::from_waker(&waker)) == LinkState::Down);

    let result = std::thread::scope(|scope| {
        let route = &route;
        let device = &mut parts.device;
        scope.spawn(move || {
            entered.wait();
            let mut cx = Context::from_waker(Waker::noop());
            assert!(device.link_state(&mut cx) == LinkState::Up);
            device.transmit(&mut cx).unwrap().consume(1, |b| b[0] = 7);
            route.close_admission();
            closed.wait();
        });
        link.begin_after_native_quiescence()
    });

    assert_eq!(result, Err(LinkError::Route(RouteError::OpenInterrupted)));
    assert!(route.enter().is_none());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(parts.device.link_state(&mut cx) == LinkState::Down);
    assert!(parts.device.transmit(&mut cx).is_none());
    assert_eq!(link.tx_diagnostics().pending, 0);
    assert_eq!(link.tx_diagnostics().dropped, 1);
    assert_eq!(
        link.poll_transmit(&mut cx, |_| Ok::<_, u8>(())),
        Poll::Pending
    );
    assert_conserved(&route);
}

#[test]
fn close_invalidates_prepared_open_even_when_already_closed() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    let generation = parts.port.begin_session().unwrap();
    let stale = owner.prepare_open().unwrap();
    route.close_admission();
    assert_eq!(
        owner.commit_open(stale, generation),
        Err(RouteError::OpenInterrupted)
    );
    assert!(route.enter().is_none());
    // Only a fresh caller-established native fence can justify a new attempt.
    let fresh = owner.prepare_open().unwrap();
    owner.commit_open(fresh, generation).unwrap();
    route.enter().unwrap().receive(&[1]).unwrap();
    assert_conserved(&route);
}

#[test]
fn close_revision_exhaustion_cannot_reopen_or_reclaim_the_route() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    let generation = parts.port.begin_session().unwrap();
    critical_section::with(|cs| route.state.borrow_ref_mut(cs).close_revision = Some(u64::MAX));
    let last = owner.prepare_open().unwrap();
    route.close_admission();
    assert_eq!(
        owner.commit_open(last, generation),
        Err(RouteError::LifecycleExhausted)
    );
    assert_eq!(
        owner.open_after_native_quiescence(generation),
        Err(RouteError::LifecycleExhausted)
    );
    assert!(route.enter().is_none());
    drop(owner);
    assert!(matches!(
        route.claim(parts.port.ingress()),
        Err(RouteError::LifecycleExhausted)
    ));
    assert_conserved(&route);
}

#[test]
fn native_admission_close_rejects_already_queued_tx() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    parts
        .device
        .transmit(&mut cx)
        .unwrap()
        .consume(1, |b| b[0] = 1);
    // The native teardown thread closes admission before the L2 worker next runs.
    route.close_admission();
    let mut submitted = false;
    assert_eq!(
        link.poll_transmit(&mut cx, |_| {
            submitted = true;
            Ok::<_, u8>(())
        }),
        Poll::Ready(Err(SubmitError::AdmissionClosed))
    );
    assert!(
        !submitted,
        "closed native admission must reject new TX submission"
    );
    assert_eq!(link.tx_diagnostics().delivered, 0);
    assert_eq!(link.tx_diagnostics().dropped, 1);
}

#[test]
fn admitted_tx_retains_its_permit_across_close_until_native_return() {
    for success in [false, true] {
        let mut storage = L2Storage::<2, 1, 64>::new();
        let mut parts = storage.split(mac());
        let route = CallbackRoute::new();
        let mut link = NativeLink::bind(parts.port, &route).unwrap();
        link.begin_after_native_quiescence().unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        parts
            .device
            .transmit(&mut cx)
            .unwrap()
            .consume(1, |b| b[0] = 1);
        let mut worker = Context::from_waker(Waker::noop());
        let result = link.poll_transmit(&mut worker, |_| {
            assert_eq!(route.diagnostics().transmits_in_flight, 1);
            route.close_admission();
            assert_eq!(route.diagnostics().transmits_in_flight, 1);
            assert!(parts.device.transmit(&mut cx).is_none());
            if success { Ok(()) } else { Err(42) }
        });
        assert_eq!(route.diagnostics().transmits_in_flight, 0);
        assert_eq!(
            result,
            Poll::Ready(if success {
                Ok(())
            } else {
                Err(SubmitError::Native(42))
            })
        );
        assert_eq!(link.tx_diagnostics().pending, 0);
        assert_eq!(link.tx_diagnostics().delivered, u64::from(success));
        assert_eq!(link.tx_diagnostics().dropped, u64::from(!success));
        assert!(route.enter().is_none());
    }
}

#[test]
fn tx_ticket_blocks_reopen_and_rejects_a_stale_epoch() {
    let mut storage = L2Storage::<2, 1, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut owner = route.claim(parts.port.ingress()).unwrap();
    let old = parts.port.begin_session().unwrap();
    owner.open_after_native_quiescence(old).unwrap();
    let ticket = owner.enter_transmit(old).unwrap();
    route.close_admission();
    assert!(matches!(
        owner.prepare_open(),
        Err(RouteError::CallbacksInFlight)
    ));
    assert!(owner.enter_transmit(old).is_none());
    drop(ticket);
    let current = parts.port.begin_session().unwrap();
    owner.open_after_native_quiescence(current).unwrap();
    assert!(owner.enter_transmit(old).is_none());
    drop(owner.enter_transmit(current).unwrap());
    assert_eq!(route.diagnostics().transmits_in_flight, 0);
}

#[test]
fn panicking_native_submit_releases_tx_payload_and_permit() {
    let mut storage = L2Storage::<2, 1, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    parts
        .device
        .transmit(&mut cx)
        .unwrap()
        .consume(1, |b| b[0] = 1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        link.poll_transmit(&mut cx, |_| -> Result<(), u8> {
            panic!("injected native panic")
        })
    }));
    assert!(result.is_err());
    assert_eq!(route.diagnostics().transmits_in_flight, 0);
    assert_eq!(link.tx_diagnostics().dropped, 1);
    assert_eq!(link.tx_diagnostics().pending, 0);
}

#[test]
fn tx_submission_is_bounded_and_distinguishes_native_failure() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    for value in [1, 2] {
        parts
            .device
            .transmit(&mut cx)
            .unwrap()
            .consume(64, |frame| frame.fill(value));
    }
    assert!(parts.device.transmit(&mut cx).is_none());
    assert_eq!(
        link.poll_transmit(&mut cx, |frame| {
            assert_eq!(frame, &[1; 64]);
            Ok::<_, u8>(())
        }),
        Poll::Ready(Ok(()))
    );
    assert_eq!(link.tx_diagnostics().pending, 1);
    assert_eq!(
        link.poll_transmit(&mut cx, |frame| {
            assert_eq!(frame, &[2; 64]);
            Err(42)
        }),
        Poll::Ready(Err(SubmitError::Native(42)))
    );
    assert_eq!(link.tx_diagnostics().delivered, 1);
    assert_eq!(link.tx_diagnostics().dropped, 1);
    assert_eq!(
        link.poll_transmit(&mut cx, |_| Ok::<_, u8>(())),
        Poll::Pending
    );
}

#[test]
fn close_discards_old_queues_and_does_not_reopen_with_live_callback() {
    let mut storage = L2Storage::<2, 2, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    parts
        .device
        .transmit(&mut cx)
        .unwrap()
        .consume(1, |frame| frame[0] = 1);
    route.enter().unwrap().receive(&[2]).unwrap();
    let ticket = route.enter().unwrap();
    link.close().unwrap();
    assert_eq!(link.rx_diagnostics().dropped, 1);
    assert_eq!(link.tx_diagnostics().dropped, 1);
    assert_eq!(
        link.begin_after_native_quiescence(),
        Err(LinkError::Route(RouteError::CallbacksInFlight))
    );
    drop(ticket);
    link.begin_after_native_quiescence().unwrap();
    assert!(parts.device.receive(&mut cx).is_none());
    assert_eq!(
        link.poll_transmit(&mut cx, |_| Ok::<_, u8>(())),
        Poll::Pending
    );
    assert_conserved(&route);
}

#[test]
fn tx_publication_wakes_worker_and_native_return_releases_real_capacity() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::Wake;
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let mut storage = L2Storage::<2, 1, 64>::new();
    let mut parts = storage.split(mac());
    let route = CallbackRoute::new();
    let mut link = NativeLink::bind(parts.port, &route).unwrap();
    link.begin_after_native_quiescence().unwrap();
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(counter.clone());
    let mut worker = Context::from_waker(&waker);
    let mut network = Context::from_waker(Waker::noop());
    assert_eq!(
        link.poll_transmit(&mut worker, |_| Ok::<_, u8>(())),
        Poll::Pending
    );
    parts
        .device
        .transmit(&mut network)
        .unwrap()
        .consume(1, |frame| frame[0] = 7);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert_eq!(
        link.poll_transmit(&mut worker, |_| {
            assert!(parts.device.transmit(&mut network).is_none());
            Ok::<_, u8>(())
        }),
        Poll::Ready(Ok(()))
    );
    assert!(parts.device.transmit(&mut network).is_some());
}
