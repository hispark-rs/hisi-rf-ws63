//! Host queue-4 ownership, separate from DMAC TX completion and RX drainage.
//!
//! `frw_host_post_data` masks enqueue/free failures. Observe both the actual
//! dispatch and pre-dispatch free, never infer completion from its zero return.
//! Slots contain opaque identities, not packets. No native call runs in a CS.

const CAPACITY: usize = 32;
const CONTRACT_ERROR: i32 = -0x1002;
const DRAIN_TIMEOUT: i32 = -0x1003;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ticket(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Queued,
    Executing,
    Executed,
    Freeing,
    Freed,
}

#[derive(Clone, Copy)]
struct Active {
    ticket: Ticket,
    pointer: usize,
    stage: Stage,
    post_returned: bool,
}

/// `accepted = processed + dropped + pending`; not an over-the-air receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostTxDiagnostics {
    pub accepted: u64,
    pub processed: u64,
    pub dropped: u64,
    pub pending: u32,
    pub peak: u32,
    pub rejected: u64,
    pub callback_errors: u64,
    pub closed: bool,
    pub fault: i32,
}

struct Tracker {
    slots: [Option<Active>; CAPACITY],
    diagnostic: HostTxDiagnostics,
    terminal: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum Rejection {
    Release,
    // The original queue still owns this address: never free it a second time.
    Duplicate,
}

impl Tracker {
    const fn new() -> Self {
        Self {
            slots: [None; CAPACITY],
            terminal: false,
            diagnostic: HostTxDiagnostics {
                accepted: 0,
                processed: 0,
                dropped: 0,
                pending: 0,
                peak: 0,
                rejected: 0,
                callback_errors: 0,
                closed: false,
                fault: 0,
            },
        }
    }

    fn fail(&mut self, status: i32) {
        if self.diagnostic.fault == 0 {
            self.diagnostic.fault = status;
        }
        self.diagnostic.closed = true;
    }

    fn begin(&mut self, pointer: usize) -> Result<Ticket, Rejection> {
        if self
            .slots
            .iter()
            .flatten()
            .any(|a| a.pointer == pointer && a.stage == Stage::Queued)
        {
            self.fail(CONTRACT_ERROR);
            self.diagnostic.rejected = self.diagnostic.rejected.saturating_add(1);
            return Err(Rejection::Duplicate);
        }
        let slot = self.slots.iter().position(Option::is_none);
        let sequence = self.diagnostic.accepted.checked_add(1);
        if pointer == 0 || slot.is_none() || sequence.is_none() {
            self.fail(CONTRACT_ERROR);
        }
        if self.diagnostic.closed {
            self.diagnostic.rejected = self.diagnostic.rejected.saturating_add(1);
            return Err(Rejection::Release);
        }
        let ticket = Ticket(sequence.expect("checked sequence"));
        self.slots[slot.expect("checked capacity")] = Some(Active {
            ticket,
            pointer,
            stage: Stage::Queued,
            post_returned: false,
        });
        self.diagnostic.accepted = ticket.0;
        self.diagnostic.pending += 1;
        self.diagnostic.peak = self.diagnostic.peak.max(self.diagnostic.pending);
        Ok(ticket)
    }

    fn post_returned(&mut self, ticket: Ticket, status: i32) {
        let Some(a) = self.slots.iter_mut().flatten().find(|a| a.ticket == ticket) else {
            self.fail(CONTRACT_ERROR);
            return;
        };
        if a.post_returned {
            self.fail(CONTRACT_ERROR);
            return;
        }
        a.post_returned = true;
        // A failure alone does not retire an opaque owner without a free.
        if status != 0 {
            self.fail(status);
        }
        self.retire(ticket);
    }

    fn dispatch(&mut self, pointer: usize) -> Option<Ticket> {
        let Some(a) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|a| a.pointer == pointer && a.stage == Stage::Queued)
        else {
            self.fail(CONTRACT_ERROR);
            return None;
        };
        a.stage = Stage::Executing;
        Some(a.ticket)
    }

    fn before_free(&mut self, pointer: usize) -> Option<Ticket> {
        let a = self
            .slots
            .iter_mut()
            .flatten()
            .find(|a| a.pointer == pointer && a.stage == Stage::Queued)?;
        a.stage = Stage::Freeing;
        Some(a.ticket)
    }

    fn complete(&mut self, ticket: Ticket, freeing: bool, status: i32) {
        let Some(a) = self.slots.iter_mut().flatten().find(|a| a.ticket == ticket) else {
            self.fail(CONTRACT_ERROR);
            return;
        };
        let expected = if freeing {
            Stage::Freeing
        } else {
            Stage::Executing
        };
        if a.stage != expected {
            self.fail(CONTRACT_ERROR);
            return;
        }
        if freeing && status != 0 {
            self.fail(status);
            return;
        }
        a.stage = if freeing {
            Stage::Freed
        } else {
            Stage::Executed
        };
        if !freeing && status != 0 {
            self.diagnostic.callback_errors = self.diagnostic.callback_errors.saturating_add(1);
            self.fail(status);
        }
        self.retire(ticket);
    }

    fn retire(&mut self, ticket: Ticket) {
        let Some(index) = self
            .slots
            .iter()
            .position(|a| a.is_some_and(|a| a.ticket == ticket))
        else {
            return;
        };
        let a = self.slots[index].expect("matched ticket");
        if !a.post_returned || !matches!(a.stage, Stage::Executed | Stage::Freed) {
            return;
        }
        self.slots[index] = None;
        self.diagnostic.pending -= 1;
        if a.stage == Stage::Executed {
            self.diagnostic.processed += 1;
        } else {
            self.diagnostic.dropped += 1;
        }
    }

    fn close(&mut self) {
        self.diagnostic.closed = true;
    }

    #[cfg(any(test, feature = "standard-l2-rx-stop-experiment"))]
    fn seal(&mut self) {
        self.terminal = true;
        self.close();
    }

    fn resume_handshake(&mut self, native_status: i32) -> Result<(), i32> {
        // The caller samples disconnect/user ownership under the same CS as
        // this transition. This is only queue-4 admission, never L2 reopening.
        if native_status != 0 {
            return Err(native_status);
        }
        if self.diagnostic.fault != 0 {
            return Err(self.diagnostic.fault);
        }
        if self.terminal || self.diagnostic.pending != 0 {
            return Err(CONTRACT_ERROR);
        }
        self.diagnostic.closed = false;
        Ok(())
    }

    fn drained(&self) -> Result<bool, i32> {
        if self.diagnostic.fault != 0 {
            return Err(self.diagnostic.fault);
        }
        Ok(self.diagnostic.closed && self.diagnostic.pending == 0)
    }
}

#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
mod native {
    use super::*;
    use crate::frw::FrwMsg;
    use core::{cell::RefCell, ffi::c_void, num::NonZeroU32};
    use critical_section::Mutex;

    // A named physical object lets final-ELF CI report the native metadata cost.
    #[unsafe(export_name = "__hisi_net0_host_tx_tracker")]
    static TRACKER: Mutex<RefCell<Tracker>> = Mutex::new(RefCell::new(Tracker::new()));
    const _: () = assert!(core::mem::size_of::<Mutex<RefCell<Tracker>>>() == 584);

    #[link(kind = "link-arg", name = "--wrap=frw_host_post_data")]
    unsafe extern "C" {}
    #[link(kind = "link-arg", name = "--wrap=frw_netbuf_exec_callback")]
    unsafe extern "C" {}
    #[link(kind = "link-arg", name = "--wrap=oal_netbuf_free")]
    unsafe extern "C" {
        #[link_name = "__real_frw_host_post_data"]
        fn real_post(kind: u16, vap: u8, netbuf: *mut c_void) -> i32;
        #[link_name = "__real_frw_netbuf_exec_callback"]
        fn real_dispatch(kind: u16, vap: u8, msg: *mut FrwMsg) -> i32;
        #[link_name = "__real_oal_netbuf_free"]
        fn real_free(netbuf: *mut c_void) -> u32;
    }

    pub(crate) fn close() {
        critical_section::with(close_locked);
    }

    pub(crate) fn close_locked(cs: critical_section::CriticalSection<'_>) {
        TRACKER.borrow_ref_mut(cs).close();
    }

    pub(crate) fn diagnostics() -> HostTxDiagnostics {
        critical_section::with(|cs| TRACKER.borrow_ref(cs).diagnostic)
    }

    pub(crate) fn resume_handshake(
        cs: critical_section::CriticalSection<'_>,
        native_status: i32,
    ) -> Result<(), i32> {
        TRACKER.borrow_ref_mut(cs).resume_handshake(native_status)
    }

    #[cfg(feature = "standard-l2-rx-stop-experiment")]
    pub(crate) fn seal_and_drain() -> Result<(), i32> {
        critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).seal());
        close_and_drain()
    }

    pub(crate) fn close_and_drain() -> Result<(), i32> {
        close();
        let result = wait_for_drain();
        if let Err(status) = result {
            critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).fail(status));
        }
        result
    }

    fn wait_for_drain() -> Result<(), i32> {
        let started = crate::uapi::try_monotonic_ms().ok_or(CONTRACT_ERROR)?;
        loop {
            if critical_section::with(|cs| TRACKER.borrow_ref(cs).drained())? {
                return Ok(());
            }
            let now = crate::uapi::try_monotonic_ms().ok_or(CONTRACT_ERROR)?;
            if now < started || now - started >= 1_000 {
                return Err(DRAIN_TIMEOUT);
            }
            hisi_rf_rtos_driver::sleep_ms(NonZeroU32::new(1).unwrap())
                .map_err(|_| CONTRACT_ERROR)?;
        }
    }

    #[unsafe(export_name = "__wrap_frw_host_post_data")]
    unsafe extern "C" fn post(kind: u16, vap: u8, netbuf: *mut c_void) -> i32 {
        if kind != 4 {
            // SAFETY: unchanged native call ABI and ownership for other types.
            return unsafe { real_post(kind, vap, netbuf) };
        }
        let ticket = critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).begin(netbuf.addr()));
        let Ok(ticket) = ticket else {
            if ticket == Err(Rejection::Release) {
                // SAFETY: post transfers this unique native netbuf, including
                // rejection paths. A duplicate is deliberately NOT freed.
                unsafe { real_free(netbuf) };
            }
            return CONTRACT_ERROR;
        };
        // SAFETY: exactly one unchanged native post. It may synchronously free
        // or concurrently dispatch the input; no Rust pointer dereference.
        let status = unsafe { real_post(kind, vap, netbuf) };
        critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).post_returned(ticket, status));
        status
    }

    #[unsafe(export_name = "__wrap_frw_netbuf_exec_callback")]
    unsafe extern "C" fn dispatch(kind: u16, vap: u8, msg: *mut FrwMsg) -> i32 {
        let ticket = if kind == 4 {
            // SAFETY: the vendor queue passes a live frw_msg. Its data is a
            // copied pointer-sized payload (not a netbuf itself), as shown by
            // frw_host_post_data and the callback's invalid-VAP free path.
            let pointer = unsafe {
                if msg.is_null() || (*msg).data_len != 4 || (*msg).data.is_null() {
                    0
                } else {
                    (*msg).data.cast::<*mut c_void>().read_unaligned().addr()
                }
            };
            critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).dispatch(pointer))
        } else {
            None
        };
        // SAFETY: forward every dispatch exactly once; the real callback owns
        // the native netbuf/free/TX handoff. Never access msg after return.
        let status = unsafe { real_dispatch(kind, vap, msg) };
        if let Some(ticket) = ticket {
            critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).complete(ticket, false, status));
        }
        status
    }

    #[unsafe(export_name = "__wrap_oal_netbuf_free")]
    unsafe extern "C" fn free(netbuf: *mut c_void) -> u32 {
        let ticket =
            critical_section::with(|cs| TRACKER.borrow_ref_mut(cs).before_free(netbuf.addr()));
        // SAFETY: unchanged native ownership and exactly one free; only an
        // opaque identity was inspected before this call.
        let status = unsafe { real_free(netbuf) };
        if let Some(ticket) = ticket {
            critical_section::with(|cs| {
                TRACKER
                    .borrow_ref_mut(cs)
                    .complete(ticket, true, status as i32)
            });
        }
        status
    }
}

#[cfg(all(
    target_arch = "riscv32",
    feature = "wifi",
    feature = "standard-l2-rx-stop-experiment"
))]
pub(crate) use native::seal_and_drain;
#[cfg(all(target_arch = "riscv32", feature = "wifi"))]
pub(crate) use native::{close, close_and_drain, close_locked, diagnostics, resume_handshake};

#[cfg(test)]
mod tests {
    use super::*;

    fn conserved(t: &Tracker) {
        let d = t.diagnostic;
        assert_eq!(d.accepted, d.processed + d.dropped + u64::from(d.pending));
        assert_eq!(d.pending as usize, t.slots.iter().flatten().count());
    }

    #[test]
    fn post_return_is_not_dispatch_completion() {
        let mut t = Tracker::new();
        let ticket = t.begin(1).unwrap();
        t.post_returned(ticket, 0);
        t.close();
        assert_eq!(t.drained(), Ok(false));
        assert_eq!(t.dispatch(1), Some(ticket));
        assert_eq!(t.drained(), Ok(false));
        t.complete(ticket, false, 0);
        assert_eq!(t.drained(), Ok(true));
        conserved(&t);
    }

    #[test]
    fn dispatch_can_finish_before_the_posting_thread_resumes() {
        let mut t = Tracker::new();
        let ticket = t.begin(7).unwrap();
        t.dispatch(7).unwrap();
        assert_eq!(t.before_free(7), None);
        t.complete(ticket, false, 0);
        t.close();
        assert_eq!(t.drained(), Ok(false));
        t.post_returned(ticket, 0);
        assert_eq!(t.drained(), Ok(true));
        conserved(&t);
    }

    #[test]
    fn hidden_post_rejection_requires_completed_free() {
        for outer_first in [false, true] {
            let mut t = Tracker::new();
            let ticket = t.begin(9).unwrap();
            if outer_first {
                t.post_returned(ticket, 0);
            }
            assert_eq!(t.before_free(9), Some(ticket));
            t.close();
            assert_eq!(t.drained(), Ok(false));
            t.complete(ticket, true, 0);
            if !outer_first {
                t.post_returned(ticket, 0);
            }
            assert_eq!(t.diagnostic.dropped, 1);
            assert_eq!(t.drained(), Ok(true));
            conserved(&t);
        }
    }

    #[test]
    fn duplicate_owner_is_not_released_and_capacity_is_bounded() {
        let mut t = Tracker::new();
        t.begin(1).unwrap();
        assert_eq!(t.begin(1), Err(Rejection::Duplicate));
        assert!(t.drained().is_err());
        conserved(&t);
        let mut t = Tracker::new();
        for pointer in 1..=CAPACITY {
            t.begin(pointer).unwrap();
        }
        assert_eq!(t.begin(CAPACITY + 1), Err(Rejection::Release));
        assert_eq!(t.diagnostic.pending as usize, CAPACITY);
        conserved(&t);
    }

    #[test]
    fn failed_or_missing_callback_never_becomes_a_drain_receipt() {
        let mut t = Tracker::new();
        let ticket = t.begin(1).unwrap();
        t.post_returned(ticket, 0);
        t.close();
        assert_eq!(t.drained(), Ok(false));
        t.fail(DRAIN_TIMEOUT);
        t.dispatch(1).unwrap();
        t.complete(ticket, false, 0);
        assert_eq!(t.drained(), Err(DRAIN_TIMEOUT));
        conserved(&t);
    }

    #[test]
    fn stale_completions_cannot_retire_reused_addresses() {
        let mut t = Tracker::new();
        let old = t.begin(1).unwrap();
        t.post_returned(old, 0);
        t.dispatch(1).unwrap();
        t.complete(old, false, 0);
        let new = t.begin(1).unwrap();
        assert_ne!(old, new);
        t.complete(old, false, 0);
        assert_eq!(t.diagnostic.pending, 1);
        assert!(t.drained().is_err());
        conserved(&t);
    }

    #[test]
    fn freed_address_can_be_reused_before_old_dispatch_or_post_returns() {
        let mut t = Tracker::new();
        let old = t.begin(1).unwrap();
        t.dispatch(1).unwrap();
        assert_eq!(t.before_free(1), None);
        // Native free releases the address before returning through the old
        // callback/post stack. The next allocation has a distinct ticket.
        let new = t.begin(1).unwrap();
        assert_eq!(t.before_free(1), Some(new));
        t.complete(old, false, 0);
        t.post_returned(old, 0);
        assert_eq!(t.diagnostic.pending, 1);
        t.complete(new, true, 0);
        t.post_returned(new, 0);
        t.close();
        assert_eq!(t.drained(), Ok(true));
        conserved(&t);
    }

    #[test]
    fn free_errors_and_late_posts_fail_closed() {
        let mut t = Tracker::new();
        let ticket = t.begin(1).unwrap();
        t.before_free(1).unwrap();
        t.complete(ticket, true, 100);
        t.post_returned(ticket, 0);
        assert_eq!(t.drained(), Err(100));
        assert_eq!(t.begin(2), Err(Rejection::Release));
        conserved(&t);
    }

    #[test]
    fn protocol_cleanup_can_resume_handshake_only_after_all_old_owners_retire() {
        for post_first in [false, true] {
            let mut t = Tracker::new();
            let old = t.begin(1).unwrap();
            t.close();
            assert_eq!(t.begin(2), Err(Rejection::Release));
            assert_eq!(t.resume_handshake(0), Err(CONTRACT_ERROR));
            t.dispatch(1).unwrap();
            if post_first {
                t.post_returned(old, 0);
            }
            t.complete(old, false, 0);
            if !post_first {
                assert_eq!(t.resume_handshake(0), Err(CONTRACT_ERROR));
                t.post_returned(old, 0);
            }
            assert_eq!(t.resume_handshake(-0x6309), Err(-0x6309));
            assert!(t.diagnostic.closed);
            t.resume_handshake(0).unwrap();
            let new = t.begin(1).unwrap();
            assert_ne!(new, old);
            assert_eq!(t.dispatch(1), Some(new));
            t.complete(new, false, 0);
            t.post_returned(new, 0);
            assert_eq!(t.diagnostic.processed, 2);
            conserved(&t);
        }
    }

    #[test]
    fn terminal_stop_fault_and_new_close_cannot_be_overridden_by_handshake_resume() {
        let mut t = Tracker::new();
        t.close();
        t.resume_handshake(0).unwrap();
        // An IRQ/native user deletion after the atomic resume still closes
        // admission before the next native post; no stale reopen is pending.
        t.close();
        assert_eq!(t.begin(1), Err(Rejection::Release));
        t.seal();
        assert_eq!(t.resume_handshake(0), Err(CONTRACT_ERROR));
        assert_eq!(t.begin(1), Err(Rejection::Release));
        let mut t = Tracker::new();
        t.fail(DRAIN_TIMEOUT);
        assert_eq!(t.resume_handshake(0), Err(DRAIN_TIMEOUT));
        assert_eq!(t.begin(1), Err(Rejection::Release));
        conserved(&t);
    }

    #[test]
    fn a_completed_old_ticket_cannot_retire_work_after_protocol_resume() {
        let mut t = Tracker::new();
        let old = t.begin(1).unwrap();
        t.dispatch(1).unwrap();
        t.complete(old, false, 0);
        t.post_returned(old, 0);
        t.close();
        t.resume_handshake(0).unwrap();
        let new = t.begin(1).unwrap();
        assert_ne!(new, old);
        t.complete(old, false, 0);
        assert_eq!(t.diagnostic.pending, 1);
        assert_eq!(t.resume_handshake(0), Err(CONTRACT_ERROR));
        conserved(&t);
    }
}
