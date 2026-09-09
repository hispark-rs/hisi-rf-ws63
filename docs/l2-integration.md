# NET0 Native L2 Integration

Status: experimental callback path under `standard-l2`. When selected,
`driverif_input` uses its exclusive route, initially closed. Existing named
profiles do not select this feature and retain their verified smoltcp bridge.
A passing host contract is not evidence that WS63 implements Embassy Net yet.

## Ownership

The caller owns `hisi_rf_core::l2::L2Storage`. Its exclusive split gives one
`L2Device` to one IP stack, and one `L2Port` to the native worker. `NativeLink`
owns that port and the non-cloneable `Registration` of a `CallbackRoute`.
The route holds only an ingress capability and small metadata; no packet bytes,
allocator, socket, or IP state belongs to a global callback object.

`bind_native` registers caller-owned static storage against the sole C callback
route (initially four RX slots of 1514 bytes). No packet array is global. An
incoming pbuf must belong to the registered netif and contain one complete
frame after the two-byte Ethernet padding. Null, chained, truncated, oversized,
closed and full cases are explicit drops; the callback releases its pbuf
reference on every exit. Selecting `standard-l2` together with `net` does not
duplicate delivery or enable fallback to the old smoltcp queue.

At callback entry, `enter` captures the active ingress and generation. The
resulting ticket cannot be cloned or retagged. `receive` copies outside critical
sections and publishes into the core queue. All exits, including abandoned
tickets, participate in `entered = queued + dropped + in_flight`. Core counters
separately prove accepted queue frames equal delivered, dropped and pending.
These are lifetime counters with the same no-u64-exhaustion measurement bound
as the core contract; they do not prove over-the-air delivery.

`poll_transmit` submits at most one frame per worker turn. Real queue capacity is
held until the native call has copied/finished reading the frame. Native errors
count as drops, not delivery. The worker waker is registered before checking the
TX queue. No timer polling is needed to notice a newly queued TX frame.

## Connection Fence

The required ordering is:

1. Close callback admission and invalidate the L2 epoch using `NativeLink::close`.
2. Stop/drain old native RX/TX work and wait for existing Rust callback tickets.
3. Establish an authorized native link and its immutable real MAC identity.
4. Open the new epoch with `begin_after_native_quiescence`.

The last method checks Rust callback drainage and refuses an already open route.
It cannot inspect native DMA/FRW queues. **Native quiescence remains an unproven
production prerequisite**; successful disconnect submission or a zero return
code from a no-response WAL command must not be treated as that proof. Do not
wire reconnect by looking up the current generation for a delayed old callback.

Already issued queue tokens retain their storage until consumed/dropped. A new
epoch cannot retract a frame already submitted to hardware. Network connection
objects must also be invalidated at a link transition.

## Current Verification

Host and Miri tests cover exclusive registration, down-route rejection, delayed
callback/reconnect, abandon/drop, queue overflow and oversize, concurrent
producers, close/reset conservation, one-frame worker budget, native TX failure,
TX wake, and capacity held through native return. CI runs the host contract on
Linux, macOS ARM64 and Windows, plus RV32 checks and Linux Miri.
The same suites now exercise the real `driverif_input` entry, pbuf reference
release, padding removal, native-buffer independence, and wrong-netif rejection.

Remaining integration gates are profile-owned registration, native quiescence/
authorization events, worker wake wiring, caller-owned storage and ELF resource
reports, followed by exact-artifact WS63 HIL. No new user-facing network profile
is advertised before those gates pass.
