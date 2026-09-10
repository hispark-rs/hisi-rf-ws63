# Experimental NET0 Host TX Drain

This contract applies only to `standard-l2` on WS63. Existing Wi-Fi profiles
without that feature retain their native path. It is one component of a native
fence, not a reconnect authorization.

## Observed ABI

The pinned `ws63-radio-sys` native archives and WS63 SDK disassembly establish:

- `frw_host_post_data(u16, u8, netbuf*) -> i32` puts type 4 TX/EAPOL work on
  host thread 1, queue 4. Its message contains a copied pointer-sized payload.
- The function can return zero after an enqueue rejection and native free.
- `frw_netbuf_que_handle` calls `frw_netbuf_exec_callback` with the message;
  the callback may transfer the netbuf to DMAC or free it on rejection.
- `oal_netbuf_free(netbuf*) -> u32` returns zero on successful release.

Ordinary `uapi_lwip_send` can select a direct HMAC fast path instead of queue 4;
EAPOL uses queue 4. Therefore queue-4 counts must not be compared to the number
of application UDP frames. The final-ELF check covers the queued branch only;
the direct branch needs its separate existing call-lifetime/native TX contract.

The final-ELF check verifies the actual resolved calls, including both free
branches and EAPOL/ordinary TX entry points. Symbol presence alone is not proof.
This assumes the native code obeys its own ownership/callback ABI. A malicious
native callback carrying an already reused address is outside that assumption.

## Ownership

Each accepted post receives a non-reused ticket. Thirty-two fixed slots track
opaque pointers and post/callback state, not packet payload. The physical RV32
metadata object is 584 bytes, reported separately from caller-owned L2 storage.
This includes terminal-shutdown state; packet capacity and RF stacks are unchanged.

An entry retires only after post returns and either dispatch returns or a
pre-dispatch free succeeds. Freed addresses can be reused before old stack
frames return; ticketed completion cannot retire the new allocation. A free
inside dispatch belongs to dispatch and is not counted twice.

`accepted = processed + dropped + pending`. `processed` means host dispatch
returned, not successful DMAC completion or over-the-air delivery. Native
callback errors, sequence exhaustion, duplicate queued pointers, capacity and
free errors close admission and remain sticky. Rejected unique inputs are
freed; duplicate queue-owned inputs are not freed a second time.

## Closure And Limits

Requested disconnect closes host TX admission before enqueueing the disconnect
work. The worker waits at most 1000 ms for the tracked host work, outside critical
sections, before calling WAL. Missing clock, runtime sleep failure, timeout or
tracker fault fails closed without submitting that WAL disconnect.

Hostap also requests deauthentication during association cleanup and recovery.
Those protocol transitions are not permanent device shutdown. Immediately before
each native association (including the bounded inline retry), the adapter checks
the disconnect queue is idle, every user cleanup has returned successfully, and
all old host TX owners have retired. It restores **queue-4 handshake admission**
in the same short metadata critical section. Native I/O and waits remain outside.
This does not reopen the Ethernet route or clear any RX generation/fence guard.

Queueing a disconnect and starting user deletion atomically close TX with
publication of their respective ownership. A later close still rejects new posts;
there is no deferred resume ticket that can overwrite that close. Native failure,
unreturned ownership, timeout or stale completion prevents admission. Completed
old tickets cannot complete a newly allocated packet at the same address.

The explicit terminal RX-stop operation first **seals** host TX. A seal is
irreversible for this boot, even when a later caller requests association. This
separates ordinary protocol closure from destructive shutdown without weakening
the existing one-shot L2 experiment.

Autonomous native user deletion closes admission too, but does not synchronously
wait in the native callback. There is no claim that this fences already-running
DMAC, RX descriptors, native RX messages, or autonomous teardown. Those remain
NET0 integration gates. The outer controller timeout cannot cancel an arbitrary
C call after the host drain succeeds.

## Verification

- Host tests/Miri cover post/dispatch order, native masked rejection, queue
  capacity, stale completion, pointer reuse, failed free, checked handshake
  admission, active user cleanup and irreversible terminal shutdown.
- `check-net0-host-tx.py` checks eleven native call sites and the physical
  metadata object. Removing each call independently must fail verification.
- Three host OS CI lanes and the packaged external-consumer fixture run the
  same check. This is a maintainer check, not a dependency on Python for users.
- HIL must separately report host TX conservation and zero pending at completed
  disconnect, plus the existing sequence/content-checked local traffic gate.
  Successful samples do not establish the remaining native producer fence.
