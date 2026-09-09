//! Bounded receipts for the serialized WAL disconnect worker.
//!
//! A receipt proves only that the exact accepted ioctl calls returned. It is
//! not a fence for native RX queues, DMA, user deletion, or over-the-air TX.

use core::{cell::RefCell, task::Poll};
use critical_section::Mutex;

pub(super) const CAPACITY: usize = 4;
const HISTORY: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Ticket(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Request {
    pub ticket: Ticket,
    pub reason: u16,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Checkpoint {
    issued: u64,
    rejected: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Receipt {
    before: u64,
    through: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Returned {
    /// Hostap changed local state without submitting any native ioctl.
    NoRequest,
    Ioctls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Full,
    Exhausted,
    Rejected,
    EvidenceLost,
    InvalidCompletion,
    WakeFailed,
    WorkerUnavailable,
    Busy,
    Native(i32),
}

impl Error {
    pub(super) const fn status(self) -> i32 {
        match self {
            Self::Full => -0x6301,
            Self::Exhausted => -0x6302,
            Self::Rejected => -0x6303,
            Self::EvidenceLost => -0x6304,
            Self::InvalidCompletion => -0x6305,
            Self::WakeFailed => -0x6306,
            Self::WorkerUnavailable => -0x6308,
            Self::Busy => -0x6309,
            Self::Native(status) => status,
        }
    }
}

pub(super) struct Queue {
    requests: [Option<Request>; CAPACITY],
    head: usize,
    len: usize,
    running: Option<Ticket>,
    issued: u64,
    rejected: u64,
    history: [Option<(Ticket, i32)>; HISTORY],
    history_next: usize,
    fault: Option<Error>,
    native_failure: Option<i32>,
}

/// Claim and retire the same slot used by the worker, without calling native
/// code or waking another task under the metadata lock. A callback can enqueue
/// during `native`; its first wake may run too early to acquire this slot.
pub(super) fn run_inline(
    queue: &Mutex<RefCell<Queue>>,
    reason: &mut u16,
    native: impl FnOnce(&mut u16) -> i32,
    wake: impl FnOnce() -> bool,
) -> Result<i32, Error> {
    let request = critical_section::with(|cs| queue.borrow_ref_mut(cs).begin_inline(*reason))?;
    let status = native(reason);
    let completed =
        critical_section::with(|cs| queue.borrow_ref_mut(cs).complete(request.ticket, status));
    if !wake() {
        critical_section::with(|cs| queue.borrow_ref_mut(cs).wake_failed());
    }
    completed?;
    critical_section::with(|cs| queue.borrow_ref(cs).health())?;
    Ok(status)
}

impl Queue {
    pub(super) const fn new() -> Self {
        Self {
            requests: [None; CAPACITY],
            head: 0,
            len: 0,
            running: None,
            issued: 0,
            rejected: 0,
            history: [None; HISTORY],
            history_next: 0,
            fault: None,
            native_failure: None,
        }
    }

    pub(super) fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            issued: self.issued,
            rejected: self.rejected,
        }
    }

    pub(super) fn health(&self) -> Result<(), Error> {
        self.fault.map_or(Ok(()), Err)
    }

    /// Session-wide progress also covers autonomous hostap requests, which
    /// have no explicit caller receipt. Failures cannot disappear when bounded
    /// terminal history is reused. This is still only an ioctl-return boundary.
    pub(super) fn poll_idle(&self) -> Result<Poll<()>, Error> {
        self.health()?;
        if let Some(status) = self.native_failure {
            return Err(Error::Native(status));
        }
        if self.rejected != 0 {
            return Err(Error::Rejected);
        }
        Ok(if self.running.is_some() || self.len != 0 {
            Poll::Pending
        } else {
            Poll::Ready(())
        })
    }

    fn reject(&mut self, error: Error) -> Error {
        if let Some(rejected) = self.rejected.checked_add(1) {
            self.rejected = rejected;
            error
        } else {
            self.fault = Some(Error::Exhausted);
            Error::Exhausted
        }
    }

    /// A synchronous recovery call must not overtake queued deauthentication
    /// or overlap the worker. Call under the queue's metadata lock, then release
    /// it before entering WAL. The returned ticket owns the single native slot.
    pub(super) fn begin_inline(&mut self, reason: u16) -> Result<Request, Error> {
        if self.poll_idle()?.is_pending() {
            return Err(self.reject(Error::Busy));
        }
        let ticket = self.push(reason)?;
        self.pop()
            .filter(|request| request.ticket == ticket)
            .ok_or_else(|| {
                self.fault = Some(Error::InvalidCompletion);
                Error::InvalidCompletion
            })
    }

    pub(super) fn push(&mut self, reason: u16) -> Result<Ticket, Error> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if self.len == CAPACITY {
            return Err(self.reject(Error::Full));
        }
        let Some(sequence) = self.issued.checked_add(1) else {
            self.fault = Some(Error::Exhausted);
            return Err(Error::Exhausted);
        };
        let ticket = Ticket(sequence);
        let tail = (self.head + self.len) % CAPACITY;
        self.requests[tail] = Some(Request { ticket, reason });
        self.len += 1;
        self.issued = sequence;
        Ok(ticket)
    }

    /// The single worker retains ownership until `complete`, including while
    /// the native ioctl blocks. A second pop cannot hide a stuck native call.
    pub(super) fn pop(&mut self) -> Option<Request> {
        if self.running.is_some() || self.len == 0 || self.fault.is_some() {
            return None;
        }
        let request = self.requests[self.head].take()?;
        self.head = (self.head + 1) % CAPACITY;
        self.len -= 1;
        self.running = Some(request.ticket);
        Some(request)
    }

    pub(super) fn complete(&mut self, ticket: Ticket, status: i32) -> Result<(), Error> {
        if self.running != Some(ticket) {
            self.fault = Some(Error::InvalidCompletion);
            return Err(Error::InvalidCompletion);
        }
        self.history[self.history_next] = Some((ticket, status));
        self.history_next = (self.history_next + 1) % HISTORY;
        self.running = None;
        if status != 0 && self.native_failure.is_none() {
            self.native_failure = Some(status);
        }
        Ok(())
    }

    pub(super) fn wake_failed(&mut self) {
        // Admission already happened. Do not pretend to roll it back: the
        // worker might have consumed the request before the wake failed.
        self.fault = Some(Error::WakeFailed);
    }

    pub(super) fn worker_unavailable(&mut self) {
        self.fault = Some(Error::WorkerUnavailable);
    }

    pub(super) fn receipt_since(&self, before: Checkpoint) -> Result<Receipt, Error> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if before.rejected != self.rejected {
            return Err(Error::Rejected);
        }
        if before.issued > self.issued || self.issued - before.issued > HISTORY as u64 {
            return Err(Error::EvidenceLost);
        }
        Ok(Receipt {
            before: before.issued,
            through: self.issued,
        })
    }

    /// Bounded, read-only progress query. No waiting, callbacks, or native code.
    pub(super) fn poll(&self, receipt: Receipt) -> Result<Poll<Returned>, Error> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if receipt.through > self.issued
            || receipt.before > receipt.through
            || receipt.through - receipt.before > HISTORY as u64
        {
            return Err(Error::EvidenceLost);
        }
        if receipt.before == receipt.through {
            return Ok(Poll::Ready(Returned::NoRequest));
        }
        let mut pending = false;
        for sequence in (receipt.before + 1)..=receipt.through {
            let ticket = Ticket(sequence);
            if let Some((_, status)) = self.history.iter().flatten().find(|(id, _)| *id == ticket) {
                if *status != 0 {
                    return Err(Error::Native(*status));
                }
            } else if self.running == Some(ticket)
                || self
                    .requests
                    .iter()
                    .flatten()
                    .any(|request| request.ticket == ticket)
            {
                pending = true;
            } else {
                // A delayed owner cannot mistake an overwritten result for
                // success. It must abandon this lifecycle instead of guessing.
                return Err(Error::EvidenceLost);
            }
        }
        Ok(if pending {
            Poll::Pending
        } else {
            Poll::Ready(Returned::Ioctls)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish(queue: &mut Queue, status: i32) -> Request {
        let request = queue.pop().unwrap();
        queue.complete(request.ticket, status).unwrap();
        request
    }

    #[test]
    fn production_inline_handoff_rewakes_work_enqueued_during_native_call() {
        let queue = Mutex::new(RefCell::new(Queue::new()));
        let calls = core::cell::Cell::new(0);
        let result = run_inline(
            &queue,
            &mut 2,
            |reason| {
                assert_eq!(*reason, 2);
                calls.set(1);
                critical_section::with(|cs| {
                    let mut queue = queue.borrow_ref_mut(cs);
                    assert!(queue.running.is_some());
                    queue.push(3).unwrap();
                    // Simulate an early worker wake while native still owns
                    // the slot. It must not consume the queued request.
                    assert!(queue.pop().is_none());
                });
                0
            },
            || {
                assert_eq!(calls.get(), 1);
                calls.set(2);
                critical_section::with(|cs| {
                    let mut queue = queue.borrow_ref_mut(cs);
                    assert!(queue.running.is_none());
                    let request = queue.pop().unwrap();
                    assert_eq!(request.reason, 3);
                    queue.complete(request.ticket, 0).unwrap();
                });
                true
            },
        );
        assert_eq!(result, Ok(0));
        assert_eq!(calls.get(), 2);
        critical_section::with(|cs| {
            assert_eq!(queue.borrow_ref(cs).poll_idle(), Ok(Poll::Ready(())));
        });
    }

    #[test]
    fn production_inline_rejection_never_calls_native_or_wake() {
        for running in [false, true] {
            let mut state = Queue::new();
            state.push(1).unwrap();
            if running {
                state.pop().unwrap();
            }
            let queue = Mutex::new(RefCell::new(state));
            assert_eq!(
                run_inline(
                    &queue,
                    &mut 2,
                    |_| panic!("rejected call reached native"),
                    || panic!("rejected call emitted a completion wake"),
                ),
                Err(Error::Busy)
            );
        }
    }

    #[test]
    fn production_inline_retains_native_error_after_completion_wake() {
        let queue = Mutex::new(RefCell::new(Queue::new()));
        assert_eq!(run_inline(&queue, &mut 2, |_| -17, || true), Ok(-17));
        critical_section::with(|cs| {
            assert_eq!(queue.borrow_ref(cs).poll_idle(), Err(Error::Native(-17)));
        });
    }

    #[test]
    fn production_inline_wake_error_cannot_report_native_success() {
        let queue = Mutex::new(RefCell::new(Queue::new()));
        assert_eq!(
            run_inline(&queue, &mut 2, |_| 0, || false),
            Err(Error::WakeFailed)
        );
        critical_section::with(|cs| {
            assert_eq!(queue.borrow_ref(cs).poll_idle(), Err(Error::WakeFailed));
        });
    }

    #[test]
    fn production_inline_duplicate_completion_fails_closed() {
        let queue = Mutex::new(RefCell::new(Queue::new()));
        assert_eq!(
            run_inline(
                &queue,
                &mut 2,
                |_| {
                    critical_section::with(|cs| {
                        let mut queue = queue.borrow_ref_mut(cs);
                        let ticket = queue.running.unwrap();
                        queue.complete(ticket, 0).unwrap();
                    });
                    0
                },
                || true,
            ),
            Err(Error::InvalidCompletion)
        );
    }

    #[test]
    fn fifo_wraps_and_keeps_running_request_owned() {
        let mut queue = Queue::new();
        for reason in 1..=CAPACITY as u16 {
            queue.push(reason).unwrap();
        }
        assert_eq!(queue.push(99), Err(Error::Full));
        let first = queue.pop().unwrap();
        assert_eq!(first.reason, 1);
        assert!(queue.pop().is_none());
        queue.push(5).unwrap();
        queue.complete(first.ticket, 0).unwrap();
        for reason in 2..=5 {
            assert_eq!(finish(&mut queue, 0).reason, reason);
        }
        assert!(queue.pop().is_none());
    }

    #[test]
    fn enqueue_and_unrelated_completion_do_not_finish_receipt() {
        let mut queue = Queue::new();
        queue.push(1).unwrap();
        let before = queue.checkpoint();
        queue.push(2).unwrap();
        let receipt = queue.receipt_since(before).unwrap();
        assert_eq!(queue.poll(receipt), Ok(Poll::Pending));
        finish(&mut queue, -7); // Earlier request is not this operation.
        assert_eq!(queue.poll(receipt), Ok(Poll::Pending));
        let request = queue.pop().unwrap();
        assert_eq!(queue.poll(receipt), Ok(Poll::Pending));
        queue.complete(request.ticket, 0).unwrap();
        assert_eq!(queue.poll(receipt), Ok(Poll::Ready(Returned::Ioctls)));
    }

    #[test]
    fn every_request_in_a_receipt_must_return_successfully() {
        let mut queue = Queue::new();
        let before = queue.checkpoint();
        queue.push(1).unwrap();
        queue.push(2).unwrap();
        let receipt = queue.receipt_since(before).unwrap();
        finish(&mut queue, 0);
        assert_eq!(queue.poll(receipt), Ok(Poll::Pending));
        finish(&mut queue, -19);
        assert_eq!(queue.poll(receipt), Err(Error::Native(-19)));
    }

    #[test]
    fn no_request_is_distinct_from_native_completion() {
        let queue = Queue::new();
        let receipt = queue.receipt_since(queue.checkpoint()).unwrap();
        assert_eq!(queue.poll(receipt), Ok(Poll::Ready(Returned::NoRequest)));
    }

    #[test]
    fn rejected_request_cannot_disappear_from_a_receipt() {
        let mut queue = Queue::new();
        let before = queue.checkpoint();
        for reason in 0..CAPACITY as u16 {
            queue.push(reason).unwrap();
        }
        assert_eq!(queue.push(99), Err(Error::Full));
        assert!(matches!(queue.receipt_since(before), Err(Error::Rejected)));
    }

    #[test]
    fn stale_or_duplicate_completion_poison_instead_of_completing_new_work() {
        for duplicate in [false, true] {
            let mut queue = Queue::new();
            let before = queue.checkpoint();
            queue.push(1).unwrap();
            let receipt = queue.receipt_since(before).unwrap();
            let first = finish(&mut queue, 0);
            if !duplicate {
                queue.push(2).unwrap();
                queue.pop().unwrap();
            }
            assert_eq!(
                queue.complete(first.ticket, 0),
                Err(Error::InvalidCompletion)
            );
            assert_eq!(queue.poll(receipt), Err(Error::InvalidCompletion));
        }
    }

    #[test]
    fn history_eviction_is_an_error_not_a_false_success() {
        let mut queue = Queue::new();
        let before = queue.checkpoint();
        queue.push(1).unwrap();
        let receipt = queue.receipt_since(before).unwrap();
        finish(&mut queue, -9);
        for _ in 0..HISTORY {
            queue.push(2).unwrap();
            finish(&mut queue, 0);
        }
        assert_eq!(queue.poll(receipt), Err(Error::EvidenceLost));
    }

    #[test]
    fn failed_wake_remains_visible_even_if_worker_already_started() {
        for started in [false, true] {
            let mut queue = Queue::new();
            let before = queue.checkpoint();
            queue.push(1).unwrap();
            let receipt = queue.receipt_since(before).unwrap();
            let running = started.then(|| queue.pop().unwrap());
            queue.wake_failed();
            if let Some(request) = running {
                queue.complete(request.ticket, 0).unwrap();
            }
            assert_eq!(queue.poll(receipt), Err(Error::WakeFailed));
            assert_eq!(queue.push(2), Err(Error::WakeFailed));
        }
    }

    #[test]
    fn sequence_exhaustion_cannot_reuse_a_ticket() {
        let mut queue = Queue::new();
        queue.issued = u64::MAX - 1;
        let before = queue.checkpoint();
        assert_eq!(queue.push(1), Ok(Ticket(u64::MAX)));
        let receipt = queue.receipt_since(before).unwrap();
        finish(&mut queue, 0);
        assert_eq!(queue.poll(receipt), Ok(Poll::Ready(Returned::Ioctls)));
        assert_eq!(queue.push(2), Err(Error::Exhausted));
        assert_eq!(queue.poll(receipt), Err(Error::Exhausted));
    }

    #[test]
    fn receipt_survives_completion_during_the_c_call() {
        // IRQ scheduling may run the native worker after any enqueue, before
        // the C call returns and the owner seals its receipt.
        for completion_mask in 0..(1 << CAPACITY) {
            let mut queue = Queue::new();
            let before = queue.checkpoint();
            for index in 0..CAPACITY {
                queue.push(index as u16).unwrap();
                if completion_mask & (1 << index) != 0 {
                    while let Some(request) = queue.pop() {
                        queue.complete(request.ticket, 0).unwrap();
                    }
                }
            }
            let receipt = queue.receipt_since(before).unwrap();
            while let Some(request) = queue.pop() {
                assert_eq!(queue.poll(receipt), Ok(Poll::Pending));
                queue.complete(request.ticket, 0).unwrap();
            }
            assert_eq!(queue.poll(receipt), Ok(Poll::Ready(Returned::Ioctls)));
        }
    }

    #[test]
    fn an_old_rejection_does_not_reject_a_new_batch() {
        let mut queue = Queue::new();
        for _ in 0..CAPACITY {
            queue.push(1).unwrap();
        }
        assert_eq!(queue.push(99), Err(Error::Full));
        for _ in 0..CAPACITY {
            finish(&mut queue, 0);
        }
        let before = queue.checkpoint();
        queue.push(2).unwrap();
        let receipt = queue.receipt_since(before).unwrap();
        finish(&mut queue, 0);
        assert_eq!(queue.poll(receipt), Ok(Poll::Ready(Returned::Ioctls)));
    }

    #[test]
    fn a_missing_worker_poison_is_visible_without_a_receipt() {
        let mut queue = Queue::new();
        let before = queue.checkpoint();
        queue.worker_unavailable();
        assert_eq!(queue.health(), Err(Error::WorkerUnavailable));
        assert!(matches!(
            queue.receipt_since(before),
            Err(Error::WorkerUnavailable)
        ));
        assert_eq!(queue.push(1), Err(Error::WorkerUnavailable));
    }

    #[test]
    fn inline_and_worker_share_exactly_one_native_owner() {
        let mut queue = Queue::new();
        let before = queue.checkpoint();
        let inline = queue.begin_inline(2).unwrap();
        assert_eq!(queue.poll_idle(), Ok(Poll::Pending));
        queue.push(3).unwrap();
        // The queued request's first wake may run the worker before inline
        // completion. A later completion wake must retry this same request.
        assert!(queue.pop().is_none());
        let receipt = queue.receipt_since(before).unwrap();
        queue.complete(inline.ticket, 0).unwrap();
        assert_eq!(queue.poll_idle(), Ok(Poll::Pending));
        let worker = queue.pop().unwrap();
        assert_eq!(worker.reason, 3);
        assert_ne!(worker.ticket, inline.ticket);
        queue.complete(worker.ticket, 0).unwrap();
        assert_eq!(queue.poll_idle(), Ok(Poll::Ready(())));
        assert_eq!(queue.poll(receipt), Ok(Poll::Ready(Returned::Ioctls)));
    }

    #[test]
    fn inline_cannot_overtake_queued_or_running_teardown() {
        for running in [false, true] {
            let mut queue = Queue::new();
            let ticket = queue.push(1).unwrap();
            let owned = running.then(|| queue.pop().unwrap());
            let before = queue.checkpoint();
            assert_eq!(queue.begin_inline(2), Err(Error::Busy));
            assert_eq!(queue.issued, before.issued);
            assert_eq!(queue.poll_idle(), Err(Error::Rejected));
            let request = owned.unwrap_or_else(|| queue.pop().unwrap());
            assert_eq!(request.ticket, ticket);
            queue.complete(ticket, 0).unwrap();
            assert_eq!(queue.poll_idle(), Err(Error::Rejected));
        }
    }

    #[test]
    fn completed_explicit_receipt_does_not_hide_autonomous_work() {
        let mut queue = Queue::new();
        let before = queue.checkpoint();
        queue.push(1).unwrap();
        let receipt = queue.receipt_since(before).unwrap();
        finish(&mut queue, 0);
        queue.push(2).unwrap();
        assert_eq!(queue.poll(receipt), Ok(Poll::Ready(Returned::Ioctls)));
        assert_eq!(queue.poll_idle(), Ok(Poll::Pending));
        finish(&mut queue, 0);
        assert_eq!(queue.poll_idle(), Ok(Poll::Ready(())));
    }

    #[test]
    fn autonomous_native_failure_survives_history_eviction() {
        let mut queue = Queue::new();
        queue.push(1).unwrap();
        finish(&mut queue, -17);
        for _ in 0..HISTORY {
            queue.push(2).unwrap();
            finish(&mut queue, 0);
        }
        assert_eq!(queue.poll_idle(), Err(Error::Native(-17)));
        assert_eq!(queue.begin_inline(3), Err(Error::Native(-17)));
    }

    #[test]
    fn inline_failure_is_visible_without_an_explicit_receipt() {
        let mut queue = Queue::new();
        let request = queue.begin_inline(2).unwrap();
        queue.complete(request.ticket, -23).unwrap();
        assert_eq!(queue.poll_idle(), Err(Error::Native(-23)));
    }

    #[test]
    fn inline_and_queued_tickets_never_reuse_exhausted_identity() {
        let mut queue = Queue::new();
        queue.issued = u64::MAX - 1;
        let request = queue.begin_inline(1).unwrap();
        assert_eq!(request.ticket, Ticket(u64::MAX));
        queue.complete(request.ticket, 0).unwrap();
        assert_eq!(queue.begin_inline(2), Err(Error::Exhausted));
        assert_eq!(queue.push(3), Err(Error::Exhausted));
    }

    #[test]
    fn completion_wake_failure_cannot_report_idle_success() {
        let mut queue = Queue::new();
        let request = queue.begin_inline(1).unwrap();
        queue.push(2).unwrap();
        assert!(queue.pop().is_none());
        queue.complete(request.ticket, 0).unwrap();
        queue.wake_failed();
        assert_eq!(queue.poll_idle(), Err(Error::WakeFailed));
    }
}
