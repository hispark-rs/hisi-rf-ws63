//! Checked HMAC user teardown, not a host/DMAC queue-drain certificate.
//!
//! The pinned HMAC delete routine discards the final user-free status. Track
//! the nested call by user identity and a non-reusable ticket without retaining
//! or dereferencing vendor memory. An absent/duplicate/failed free cannot turn
//! into a successful delete. Native calls and route wakeups run outside the CS.

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
use core::cell::RefCell;
#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
use critical_section::Mutex;

const SLOTS: usize = 4;
const CONTRACT_ERROR: u32 = 0xffff_ff01;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ticket(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Free {
    NotSeen,
    Running,
    Returned(u32),
    Invalid,
}

#[derive(Clone, Copy)]
struct Active {
    ticket: Ticket,
    user: usize,
    free: Free,
}

/// Snapshot of checked HMAC calls only. Zero active calls is NOT a native fence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserCleanupDiagnostics {
    pub entered: u64,
    pub completed: u64,
    pub active: u32,
    pub free_completed: u64,
    pub unscoped_free: u64,
    pub fault: u32,
    pub last_outer_status: u32,
    pub last_free_status: Option<u32>,
    pub last_checked_status: u32,
}

struct Tracker {
    slots: [Option<Active>; SLOTS],
    issued: u64,
    diagnostic: UserCleanupDiagnostics,
}

impl Tracker {
    const fn new() -> Self {
        Self {
            slots: [None; SLOTS],
            issued: 0,
            diagnostic: UserCleanupDiagnostics {
                entered: 0,
                completed: 0,
                active: 0,
                free_completed: 0,
                unscoped_free: 0,
                fault: 0,
                last_outer_status: 0,
                last_free_status: None,
                last_checked_status: 0,
            },
        }
    }

    fn fail(&mut self, status: u32) -> u32 {
        if self.diagnostic.fault == 0 {
            self.diagnostic.fault = status;
        }
        status
    }

    fn checked_status(&self, status: u32) -> u32 {
        if status != 0 {
            status
        } else {
            self.diagnostic.fault
        }
    }

    fn begin(&mut self, user: usize) -> Option<Ticket> {
        let duplicate = self.slots.iter().flatten().any(|slot| slot.user == user);
        if user == 0 || duplicate {
            self.fail(CONTRACT_ERROR);
            return None;
        }
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            self.fail(CONTRACT_ERROR);
            return None;
        };
        let Some(sequence) = self.issued.checked_add(1) else {
            self.fail(CONTRACT_ERROR);
            return None;
        };
        self.issued = sequence;
        let ticket = Ticket(sequence);
        self.slots[index] = Some(Active {
            ticket,
            user,
            free: Free::NotSeen,
        });
        self.diagnostic.entered = sequence;
        self.diagnostic.active += 1;
        Some(ticket)
    }

    fn begin_free(&mut self, user: usize) -> Option<Ticket> {
        let Some(slot) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.user == user)
        else {
            // Allocation rollback and other native users may free outside a
            // delete scope. They cannot satisfy any active delete receipt.
            self.diagnostic.unscoped_free = self.diagnostic.unscoped_free.saturating_add(1);
            return None;
        };
        if slot.free != Free::NotSeen {
            slot.free = Free::Invalid;
            self.fail(CONTRACT_ERROR);
            return None;
        }
        slot.free = Free::Running;
        Some(slot.ticket)
    }

    fn finish_free(&mut self, ticket: Ticket, status: u32) {
        let Some(slot) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.ticket == ticket)
        else {
            self.fail(CONTRACT_ERROR);
            return;
        };
        if slot.free != Free::Running {
            slot.free = Free::Invalid;
            self.fail(CONTRACT_ERROR);
            return;
        }
        slot.free = Free::Returned(status);
        self.diagnostic.free_completed = self.diagnostic.free_completed.saturating_add(1);
        if status != 0 {
            self.fail(status);
        }
    }

    fn finish(&mut self, ticket: Option<Ticket>, outer: u32) -> u32 {
        let Some(index) = ticket.and_then(|ticket| {
            self.slots
                .iter()
                .position(|slot| slot.is_some_and(|slot| slot.ticket == ticket))
        }) else {
            return self.fail(CONTRACT_ERROR);
        };
        let slot = self.slots[index].take().expect("matched active ticket");
        self.diagnostic.active -= 1;
        self.diagnostic.completed += 1;
        self.diagnostic.last_outer_status = outer;
        self.diagnostic.last_free_status = match slot.free {
            Free::Returned(status) => Some(status),
            _ => None,
        };
        let checked = if outer != 0 {
            outer
        } else {
            match slot.free {
                Free::Returned(status) => status,
                _ => CONTRACT_ERROR,
            }
        };
        if checked != 0 {
            self.fail(checked);
        }
        // A previous missing/failed completion poisons this boot's lifecycle.
        // Later successful calls cannot silently reopen it.
        self.diagnostic.last_checked_status = self.diagnostic.fault;
        self.diagnostic.fault
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
static TRACKER: Mutex<RefCell<Tracker>> = Mutex::new(RefCell::new(Tracker::new()));

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(super) fn diagnostics() -> UserCleanupDiagnostics {
    critical_section::with(|cs| TRACKER.borrow_ref(cs).diagnostic)
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(crate) fn checked_status(status: i32) -> i32 {
    critical_section::with(|cs| TRACKER.borrow_ref(cs).checked_status(status as u32) as i32)
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
mod native {
    use super::*;
    use core::ffi::c_void;

    unsafe extern "C" {
        // hmac_user.h and mac_resource_ext.h declare these signatures. The
        // pinned object's local hmac_user_free_etc forwards the resource-free
        // result after calling _mac_res_free_hmac_user. Observe the exported
        // resource operation, not an unwrappable local ELF symbol.
        #[link_name = "__real_hmac_user_del_etc"]
        fn real_delete(vap: *mut c_void, user: *mut c_void) -> u32;
        #[link_name = "__real_hmac_res_free_mac_user_etc"]
        fn real_free(index: u16) -> u32;
        fn _mac_res_get_hmac_user(index: u16) -> *mut c_void;
    }

    #[unsafe(export_name = "__wrap_hmac_user_del_etc")]
    pub(crate) unsafe extern "C" fn delete(vap: *mut c_void, user: *mut c_void) -> u32 {
        super::super::NATIVE_RX_ROUTE.close_admission();
        let ticket = critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).begin(user.addr()));
        // SAFETY: this linker wrapper forwards the vendor's unchanged argument
        // pair exactly once. It neither dereferences nor retains either pointer.
        let status = unsafe { real_delete(vap, user) };
        critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).finish(ticket, status))
    }

    #[unsafe(export_name = "__wrap_hmac_res_free_mac_user_etc")]
    pub(crate) unsafe extern "C" fn free(index: u16) -> u32 {
        // SAFETY: the pinned lookup checks the index against the native user
        // capacity, returning null out of range. This is before resource free;
        // only the opaque identity is used, with no Rust dereference or borrow.
        let user = unsafe { _mac_res_get_hmac_user(index) };
        let ticket =
            critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).begin_free(user.addr()));
        // SAFETY: same native index and ABI, exactly one native free call.
        let status = unsafe { real_free(index) };
        if let Some(ticket) = ticket {
            critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).finish_free(ticket, status));
        }
        status
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(crate) use native::{delete, free};

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tracker: &mut Tracker, user: usize, status: u32) {
        let ticket = tracker.begin_free(user).unwrap();
        tracker.finish_free(ticket, status);
    }

    #[test]
    fn checked_free_and_outer_return_are_both_required() {
        let mut tracker = Tracker::new();
        let ticket = tracker.begin(1);
        assert_eq!(tracker.diagnostic.active, 1);
        release(&mut tracker, 1, 0);
        assert_eq!(tracker.finish(ticket, 0), 0);
        assert_eq!(tracker.diagnostic.active, 0);
        assert_eq!(tracker.diagnostic.entered, tracker.diagnostic.completed);
        assert_eq!(tracker.diagnostic.last_free_status, Some(0));
    }

    #[test]
    fn native_free_failure_is_not_hidden_by_outer_success() {
        let mut tracker = Tracker::new();
        let ticket = tracker.begin(1);
        release(&mut tracker, 1, 100);
        assert_eq!(tracker.finish(ticket, 0), 100);
        // hmac_config_kick_user itself also discards the delete status. The
        // WAL/worker boundary must consult the sticky native failure again.
        assert_eq!(tracker.checked_status(0), 100);
        assert_eq!(tracker.checked_status(19), 19);
        let next = tracker.begin(2);
        release(&mut tracker, 2, 0);
        assert_eq!(tracker.finish(next, 0), 100);
    }

    #[test]
    fn missing_free_or_early_outer_return_fails_closed() {
        for start_free in [false, true] {
            let mut tracker = Tracker::new();
            let ticket = tracker.begin(1);
            if start_free {
                tracker.begin_free(1).unwrap();
            }
            assert_eq!(tracker.finish(ticket, 0), CONTRACT_ERROR);
        }
    }

    #[test]
    fn native_outer_failure_is_preserved() {
        let mut tracker = Tracker::new();
        let ticket = tracker.begin(1);
        assert_eq!(tracker.finish(ticket, 17), 17);
    }

    #[test]
    fn interleaved_users_do_not_share_receipts() {
        let mut tracker = Tracker::new();
        let a = tracker.begin(1);
        let b = tracker.begin(2);
        release(&mut tracker, 2, 0);
        assert_eq!(tracker.finish(b, 0), 0);
        assert_eq!(tracker.finish(a, 0), CONTRACT_ERROR);
    }

    #[test]
    fn stale_completion_cannot_satisfy_reused_user_address() {
        let mut tracker = Tracker::new();
        let old = tracker.begin(1);
        let free = tracker.begin_free(1).unwrap();
        tracker.finish_free(free, 0);
        assert_eq!(tracker.finish(old, 0), 0);
        let new = tracker.begin(1);
        assert_ne!(new, old);
        tracker.finish_free(free, 0);
        assert_eq!(tracker.finish(new, 0), CONTRACT_ERROR);
    }

    #[test]
    fn duplicate_free_and_delete_cannot_pass() {
        let mut tracker = Tracker::new();
        let ticket = tracker.begin(1);
        release(&mut tracker, 1, 0);
        assert!(tracker.begin_free(1).is_none());
        assert_eq!(tracker.finish(ticket, 0), CONTRACT_ERROR);
        let mut tracker = Tracker::new();
        let ticket = tracker.begin(1);
        assert!(tracker.begin(1).is_none());
        release(&mut tracker, 1, 0);
        assert_eq!(tracker.finish(ticket, 0), CONTRACT_ERROR);
    }

    #[test]
    fn unrelated_free_is_not_a_delete_receipt() {
        let mut tracker = Tracker::new();
        let ticket = tracker.begin(1);
        assert!(tracker.begin_free(2).is_none());
        assert_eq!(tracker.diagnostic.unscoped_free, 1);
        assert_eq!(tracker.finish(ticket, 0), CONTRACT_ERROR);
    }

    #[test]
    fn capacity_and_generation_exhaustion_fail_closed() {
        let mut tracker = Tracker::new();
        for user in 1..=SLOTS {
            assert!(tracker.begin(user).is_some());
        }
        assert!(tracker.begin(SLOTS + 1).is_none());
        assert_eq!(tracker.diagnostic.active, SLOTS as u32);
        let mut tracker = Tracker::new();
        tracker.issued = u64::MAX;
        assert!(tracker.begin(1).is_none());
        assert_eq!(tracker.diagnostic.fault, CONTRACT_ERROR);
    }
}
