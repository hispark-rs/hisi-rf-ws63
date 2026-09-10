//! NET0 selects direct native RX. Optional host message 595 is unsupported.
//!
//! This link-time interception applies from boot, before callback registration.
//! The pinned hmac_rx_data_event_adapt frees its netbuf when post returns 103;
//! this wrapper must not free it or borrow the payload. Other messages retain
//! their native behavior. Final-ELF checks bind the actual producer call site.

const RX_DATA_MESSAGE: u16 = 595;
const NATIVE_REJECT_AND_RELEASE: i32 = 103;
#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(crate) const UNSUPPORTED_QUEUED_RX: i32 = -0x1024;

fn post(message: u16, reject: impl FnOnce(), forward: impl FnOnce() -> i32) -> i32 {
    if message == RX_DATA_MESSAGE {
        reject();
        NATIVE_REJECT_AND_RELEASE
    } else {
        forward()
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
mod native {
    use super::*;
    use crate::frw::FrwMsg;
    use portable_atomic::{AtomicBool, Ordering};

    #[unsafe(export_name = "__hisi_net0_queued_rx_rejected")]
    static REJECTED: AtomicBool = AtomicBool::new(false);

    #[link(kind = "link-arg", name = "--wrap=frw_host_post_msg")]
    unsafe extern "C" {}

    unsafe extern "C" {
        #[link_name = "__real_frw_host_post_msg"]
        fn real_post(message: u16, priority: u8, vap: u8, msg: *mut FrwMsg) -> i32;
    }

    pub(crate) fn rejected() -> bool {
        REJECTED.load(Ordering::Acquire)
    }

    #[unsafe(export_name = "__wrap_frw_host_post_msg")]
    pub(crate) unsafe extern "C" fn post_message(
        message: u16,
        priority: u8,
        vap: u8,
        msg: *mut FrwMsg,
    ) -> i32 {
        post(
            message,
            || {
                REJECTED.store(true, Ordering::Release);
                super::super::NATIVE_RX_ROUTE.close_admission();
            },
            // SAFETY: unchanged native ABI and pointer lifetime, forwarded once
            // only for supported messages. The wrapper never reads the payload.
            || unsafe { real_post(message, priority, vap, msg) },
        )
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(crate) use native::{post_message, rejected};

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn queued_rx_fails_closed_without_transferring_or_freeing_the_input() {
        let rejected = Cell::new(false);
        assert_eq!(
            post(595, || rejected.set(true), || panic!("must not enqueue")),
            103
        );
        assert!(rejected.get());
    }

    #[test]
    fn unrelated_messages_forward_once_and_preserve_the_native_status() {
        for message in [0, 50, 52, 91, 594, 596, u16::MAX] {
            for status in [0, 100, 103, -1] {
                let calls = Cell::new(0);
                assert_eq!(
                    post(
                        message,
                        || panic!("must not reject"),
                        || {
                            calls.set(calls.get() + 1);
                            status
                        }
                    ),
                    status
                );
                assert_eq!(calls.get(), 1);
            }
        }
    }

    #[cfg(feature = "standard-l2-initial-session-experiment")]
    #[test]
    fn queued_rx_rejection_invalidates_both_pending_and_already_open_sessions() {
        use crate::netif_l2::{CallbackRoute, NativeLink};
        use hisi_rf_core::{OperationTracker, WifiL2Capabilities, l2::L2Storage};

        for open_first in [false, true] {
            let mut storage = L2Storage::<2, 2, 64>::new();
            let parts = storage.split(WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap());
            let route = CallbackRoute::new();
            let mut link = NativeLink::bind(parts.port, &route).unwrap();
            let id = OperationTracker::new().queue(0).unwrap();
            route.initial_bootstrap_complete();
            route.initial_connect_started(id);
            route.initial_association_started();
            route.initial_association_result(true);
            if open_first {
                link.begin_initial_session_experiment(id).unwrap();
            }
            assert_eq!(
                post(
                    595,
                    || route.close_admission(),
                    || panic!("must not enqueue")
                ),
                103
            );
            assert!(route.enter().is_none());
            assert!(link.begin_initial_session_experiment(id).is_err());
        }
    }
}
