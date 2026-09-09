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

With `standard-l2`, the profile's `Storage` now embeds `NativeStorage` (four RX
and four TX slots) initialized in place by its static initializer. A one-shot
claim splits it using the actual native MAC; failed bootstrap or dropped parts
do not release that claim. The experimental v14 resource report separately
lists payload, metadata, object size and offset, all derived from the actual
Rust types. L2 bytes are already part of control storage and are not added to
the total again. Existing v13 named-profile reports are unchanged without this
feature; no new profile is claimed to be HIL calibrated.

The NET0 bootstrap fixture embeds its RV32 report in the ELF. CI compares it
against the actual control symbol, shared-arena section, packet RAM and main
stack linker symbols. This also fixes the older bootstrap fixture's missing
independent RTOS arena: it now uses the existing `SchedulerStorage`/
`SchedulerArena` composition, rather than incorrectly allocating RTOS state
from the smaller RF heap. No RF/vendor/main stack size is reduced to fit L2.
Standalone firmware fixtures explicitly use the same release profile as the
parent and application template (`opt-level = "s"`, LTO, one codegen unit,
debug information). Cargo's implicit default release profile was not equivalent:
it overflowed SRAM after the missing arena was restored. The linker guard is
retained; downstream applications own their release profile and must pass the
same final-layout gate rather than assume all compiler profiles fit.

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

With `standard-l2`, the existing deauthentication worker now carries monotonic
request tickets. An explicit hostap disconnect captures the exact submitted
ticket range, including native calls that return before the C call itself
returns. The queue retains at most four waiting requests, one running request,
and eight terminal results. No allocation or native work runs under its lock.

Hostap output is not delivered as operation completion while that receipt is
pending. Native completion wakes the runner; native errors propagate even with
no hostap output. Configure/connect/scan and another explicit disconnect cannot
replace a pending or failed receipt, including after an outer cancellation or
deadline. Queue rejection, failed wake, mismatched completion, counter exhaustion
and overwritten result history fail closed. The existing named smoltcp profiles
retain their previous path until this opt-in lifecycle is validated on silicon.

`NoRequest` (hostap submitted no ioctl) is distinct from `Ioctls` (all captured
calls returned zero). **Neither outcome is native quiescence**. A returned ioctl
may take the no-user branch or have posted an earlier disconnect event. The
receipt does not cancel a blocked native C call, drain hardware, acknowledge
user deletion, or cover autonomous hostap requests outside its captured range.
The outer operation deadline remains bounded, but reuse after native cleanup
failure is deliberately refused, not silently retried.

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
Disconnect receipt tests call the production queue helpers, including all 16
enqueue/worker-completion interleavings for a four-request batch, unrelated/old
completions, queue rejection, failure retention, history eviction and u64
exhaustion. These are command sequencing tests, not native-fence or HIL proof.

Remaining integration gates are profile-owned registration, native quiescence/
authorization events and worker wake wiring, followed by exact-artifact WS63
HIL. Storage/layout CI is not a peak-usage or working-profile HIL result. No new user-facing network profile
is advertised before those gates pass.
