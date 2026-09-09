//! Bounded receipts for the serialized WAL disconnect worker.
//!
//! A receipt proves only that the exact accepted ioctl calls returned. It is
//! not a fence for native RX queues, DMA, user deletion, or over-the-air TX.

use core::task::Poll;

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

    pub(super) fn push(&mut self, reason: u16) -> Result<Ticket, Error> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if self.len == CAPACITY {
            let Some(rejected) = self.rejected.checked_add(1) else {
                self.fault = Some(Error::Exhausted);
                return Err(Error::Exhausted);
            };
            self.rejected = rejected;
            return Err(Error::Full);
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
}
