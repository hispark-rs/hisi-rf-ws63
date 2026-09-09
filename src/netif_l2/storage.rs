use core::cell::UnsafeCell;
use core::mem::size_of;

use hisi_rf_core::{WifiL2Capabilities, l2::L2Parts, l2::L2Storage};
use portable_atomic::{AtomicBool, Ordering};

use super::{NATIVE_MTU, NATIVE_RX_SLOTS, NATIVE_TX_SLOTS};

/// Physical L2 allocation only, not a promise about RF throughput or headroom.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageReport {
    pub rx_slots: usize,
    pub tx_slots: usize,
    pub mtu: usize,
    pub payload_bytes: usize,
    /// Slot state, epochs, wakers, counters, claim flag and object padding.
    pub metadata_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    AlreadyClaimed,
}

/// In-place, caller-owned queues initialized by a static initializer, not by a
/// large temporary on the radio worker's stack. A failed bootstrap deliberately
/// leaves the storage claimed: native callbacks may retain ingress references.
pub struct NativeStorage {
    queues: UnsafeCell<L2Storage<NATIVE_RX_SLOTS, NATIVE_TX_SLOTS, NATIVE_MTU>>,
    claimed: AtomicBool,
}

// SAFETY: only the successful one-shot claim creates an exclusive queue borrow.
// Thereafter all access uses L2Storage's synchronized split capabilities; the
// claim is never reset, including after a failed initialization or dropped parts.
unsafe impl Sync for NativeStorage {}

impl NativeStorage {
    pub const fn new() -> Self {
        Self {
            queues: UnsafeCell::new(L2Storage::new()),
            claimed: AtomicBool::new(false),
        }
    }

    /// Borrow a single driver/worker pair. The address comes from the initialized
    /// native netif; no profile default or placeholder MAC is substituted.
    pub fn claim(
        &self,
        address: WifiL2Capabilities,
    ) -> Result<L2Parts<'_, NATIVE_RX_SLOTS, NATIVE_TX_SLOTS, NATIVE_MTU>, StorageError> {
        self.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| StorageError::AlreadyClaimed)?;
        // SAFETY: the successful one-shot claim is the only accessor to queues.
        // Returned lifetimes are bounded by self; they cannot outlive storage.
        Ok(unsafe { &mut *self.queues.get() }.split(address))
    }

    pub const fn report() -> StorageReport {
        let payload_bytes = (NATIVE_RX_SLOTS + NATIVE_TX_SLOTS) * NATIVE_MTU;
        StorageReport {
            rx_slots: NATIVE_RX_SLOTS,
            tx_slots: NATIVE_TX_SLOTS,
            mtu: NATIVE_MTU,
            payload_bytes,
            metadata_bytes: size_of::<Self>() - payload_bytes,
            total_bytes: size_of::<Self>(),
        }
    }
}

impl Default for NativeStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_net_driver::Driver;

    #[test]
    fn claim_is_one_shot_even_after_parts_are_dropped() {
        let storage = NativeStorage::new();
        let address = WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 1]).unwrap();
        {
            let parts = storage.claim(address).unwrap();
            assert_eq!(
                parts.device.hardware_address(),
                embassy_net_driver::HardwareAddress::Ethernet([2, 0, 0, 0, 0, 1])
            );
            assert!(matches!(
                storage.claim(address),
                Err(StorageError::AlreadyClaimed)
            ));
        }
        assert!(matches!(
            storage.claim(address),
            Err(StorageError::AlreadyClaimed)
        ));
    }

    #[test]
    fn physical_report_is_derived_from_the_actual_object() {
        let report = NativeStorage::report();
        assert_eq!(report.rx_slots, 4);
        assert_eq!(report.tx_slots, 4);
        assert_eq!(report.mtu, 1514);
        assert_eq!(report.payload_bytes, 12_112);
        assert!(report.metadata_bytes > 0);
        assert_eq!(report.total_bytes, size_of::<NativeStorage>());
        assert_eq!(
            report.payload_bytes + report.metadata_bytes,
            report.total_bytes
        );
    }

    #[test]
    fn competing_claims_cannot_create_two_device_owners() {
        let storage = NativeStorage::new();
        let address = WifiL2Capabilities::try_new([2, 0, 0, 0, 0, 3]).unwrap();
        let winners = std::thread::scope(|scope| {
            let first = scope.spawn(|| usize::from(storage.claim(address).is_ok()));
            let second = scope.spawn(|| usize::from(storage.claim(address).is_ok()));
            first.join().unwrap() + second.join().unwrap()
        });
        assert_eq!(winners, 1);
    }
}
