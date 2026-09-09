# NET0 Native L2 Integration

## Checked HMAC User Cleanup

The NET0 final link wraps `hmac_user_del_etc` and the exported
`hmac_res_free_mac_user_etc`. The local `hmac_user_free_etc` cannot itself be
wrapped: it is an ELF-local symbol in the pinned archive. Its resource-free
result is the status it returns after the subsequent void HMAC-resource free.
Both the enclosing delete and its kick-user caller can discard that status.
The Rust boundary therefore checks a sticky failure again when WAL returns.

`netif_l2::user_cleanup` associates at most four in-flight deletions with opaque
user addresses and non-reusable sequence tickets. The bounded native
`_mac_res_get_hmac_user(u16)` lookup resolves the resource index before release;
Rust does not read a private user layout or retain a pointer after the call.
Missing, duplicate, foreign and stale completions cannot satisfy another
deletion. Every native call runs outside the tracker critical section, and
delete entry closes L2 admission before native progress. A cleanup error
poisons this boot's cleanup status instead of being cleared by a later success.

The explicit `standard-l2-cleanup-fault-injection` maintainer feature is a
negative fixture only: after one real scoped resource-free returns success,
its return is changed to 100. It must reach the controller as an error while
the device stays Down with no TX token. It does not deliberately corrupt the
native allocator or claim that an actual hardware free failure was induced.
No public profile selects this feature; its ELF/evidence must never be mixed
with the healthy image or described as a normal connectivity success.

ABI oracle: the pinned SDK `hmac_user.h` and `mac_resource_ext.h`, plus the
normalized `hmac_user.c.obj`. The maintained final-ELF check decodes resolved
AUIPC/JALR calls on all three host platforms; symbol presence alone is not
sufficient. Six equal-size removed-call mutations must fail. The current
non-default fixtures receive the wrapper arguments from this package's
`build.rs`; these arguments are **not** a transitive Cargo consumer contract.
Do not graduate this integration to a public profile before that delivery
boundary and the full native fence are implemented and tested.

`RFDBG_NET0_USER_CLEANUP` reports entered/completed/active deletes, scoped free
completions, unscoped frees, sticky failure, last outer result, presence/value
of the last free result and checked result. These counters show host-user
cleanup only. They do not certify DMAC free success, queued message 595,
TX/EAPOL drainage, work before pbuf allocation or bounded native execution.
An unbounded native delete remains visible as active; application timeout must
not reuse its resources. No reconnect transition is enabled by this change.

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

The opt-in incremental composition claims this storage after native bootstrap
provides the station MAC. It returns an opaque `WifiDevice` implementing
`embassy_net_driver::Driver` (and the optional smoltcp adapter over that same
device), and moves the only `NativeLink` into the existing native worker.
Neither handle contains another packet array. Missing identity or a repeated
claim fails explicitly. The station composition requires
`incremental-embassy-wait`; existing named profiles are unchanged. This wiring
does not call `begin_after_native_quiescence`: the device remains Down and
offers no TX token, even when the control-plane connect operation succeeds.

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

Native `pbuf_alloc` captures the current non-reused close revision before
allocation can be preempted. A private 16-byte, 16-byte-aligned prefix holds
that stamp; native pbuf size/offsets, 80-byte headroom, payload and `malloc_len`
remain unchanged. `pbuf_header` cannot expose the prefix. `pbuf_free` releases
the complete allocation at the last reference. This follows the pinned native
ownership contract: `oal_pbuf_netbuf_alloc` stores the pbuf pointer in its netbuf
and `oal_netbuf_free` calls `pbuf_free` (SDK final-ELF oracle at 0x268922 and
0x2688e4), rather than freeing the pbuf as an `osal_kmalloc` base pointer.

`driverif_input` checks this immutable stamp against the current registration
before admitting a callback ticket. Old and closed allocations increment
`allocation_drops`; they cannot become new-session frames merely by arriving
late. The ticket then retains the active ingress and generation and cannot be
cloned or retagged. `receive` copies outside critical
sections and publishes into the core queue. All exits, including abandoned
tickets, participate in `entered = queued + dropped + in_flight`. Core counters
separately prove accepted queue frames equal delivered, dropped and pending.
These are lifetime counters with the same no-u64-exhaustion measurement bound
as the core contract; they do not prove over-the-air delivery.

The per-live-pbuf prefix cost is `native_pbuf_prefix_bytes` in the resource
report and v3 ELF descriptor. It consumes the existing RF heap, not a second
static queue and not extra arena capacity; native payload and allocator headers
remain additional costs. No stack or arena is reduced/increased by this change.
The provenance regression includes real allocation/delivery/free, header moves,
allocator preemption, re-registration and revision exhaustion. It closes only
the interval **after this allocation**: native work before allocation and a
native copy into a freshly allocated pbuf still require the separate producer
fence. The one-association experiment and closed default remain unchanged.

`poll_transmit` submits at most one frame per worker turn. Real queue capacity is
held until the native call has copied/finished reading the frame. Native errors
count as drops, not delivery. The worker waker is registered before checking the
TX queue. No timer polling is needed to notice a newly queued TX frame.
The static worker waker only signals its existing semaphore; no allocation,
native call or payload access runs from the wake callback. A native close takes
and wakes its subscriber outside the metadata lock. The worker subscribes
before reading the close revision, so closure before the first poll or several
coalesced closures still invalidate the port on its next turn. This notification
does not certify native drainage or reopen the link.
Before entering native code, the worker claims a non-cloneable submission
ticket for the packet's original generation, linearized against admission close.
A packet queued before close is explicitly dropped if it has not yet gained
that ticket. An already admitted call may finish after close; its ticket and
payload remain owned through native return/error. `transmits_in_flight` counts
these Rust borrows, and reopening refuses them. It does not count native-owned
frames still queued or in DMA after return, nor prove over-the-air delivery.

## Connection Fence

The required ordering is:

1. Close callback admission and invalidate the L2 epoch using `NativeLink::close`.
2. Stop/drain old native RX/TX work and wait for existing Rust callback tickets.
3. Establish an authorized native link and its immutable real MAC identity.
4. Open the new epoch with `begin_after_native_quiescence`.

The last method checks Rust callback drainage and refuses an already open route.
It captures a close revision before publishing link-up/waking the network. A
native admission close during those wakeups invalidates that attempt: the route
stays closed, the port returns Down, and TX queued in the window is discarded.
Close revisions never wrap; exhaustion permanently refuses open/registration.
This guards Rust publication, not native producer quiescence.
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
pending. A session-wide idle check also includes autonomous hostap requests
outside the explicit receipt. While any accepted teardown is queued/running,
polling leaves C input/output untouched; native completion wakes the runner.
Native errors propagate even with no hostap output and remain visible after
terminal-history eviction. Configure/connect/scan and another explicit
disconnect cannot replace pending or failed work, including after an outer
cancellation or deadline. Queue rejection, failed wake, mismatched completion,
counter exhaustion and overwritten receipt history fail closed. The existing
named smoltcp profiles retain their previous path until this opt-in lifecycle
is validated on silicon.

The two inline recovery disconnects claim the same ticketed native slot as the
worker. They reject overlapping/queued teardown without entering WAL, then
complete and wake outside the metadata lock. The completion wake is necessary:
a request enqueued during native execution may have consumed its first wake
before the slot became available. Association and its retry refuse known
pending teardown. Every disconnect entry closes new Rust callback admission
before native submission. This early close rejects new TX submission tickets
but does not revoke a copy/native call already in progress or a network TX
token; the worker still owes `NativeLink::close`, native
quiescence, and Rust-ticket drainage before opening another epoch.

`NoRequest` (hostap submitted no ioctl) is distinct from `Ioctls` (all captured
calls returned zero). **Neither outcome is native quiescence**. A returned ioctl
may take the no-user branch or have posted an earlier disconnect event. The
receipt does not cancel a blocked native C call, drain hardware, or acknowledge
user deletion. The separate session-wide check covers autonomous ioctl returns,
not native RX/TX producer ownership or all other WAL commands.
The outer operation deadline remains bounded, but reuse after native cleanup
failure is deliberately refused, not silently retried.

Native association/disconnect callbacks also close admission independently of
the control runner. Disconnect and rejected-association events close before
being published; unavailable ports, oversized/malformed event payloads and a
full link-event queue fail closed even when the event cannot be delivered.
The close revision wakes the L2 worker to invalidate its port and queued TX.
A successful association event neither authorizes nor opens the route: WPA
authorization and the native producer fence remain separate prerequisites.
Host tests exercise the production event-queue helper against the real route
and L2 storage, including undeliverable events and queued TX. A mutation that
restores enqueue-only behavior fails this regression. This closes a Rust
notification gap, not native FRW/DMA drainage or reconnect HIL.

Already issued queue tokens retain their storage until consumed/dropped. A new
epoch cannot retract a frame already submitted to hardware. Network connection
objects must also be invalidated at a link transition.

## Current Verification

Host and Miri tests cover exclusive registration, down-route rejection, delayed
callback/reconnect, abandon/drop, queue overflow and oversize, concurrent
producers, close/reset conservation, one-frame worker budget, native TX failure,
TX wake, and capacity held through native return. CI runs the host contract on
Linux, macOS ARM64 and Windows, plus RV32 checks and Linux Miri.
An interleaving regression uses the actual link-up waker to accept one TX and
close admission before open commits; it checks rollback, closed RX, Down state
and explicit TX drop. It fails against the pre-revision implementation. Separate
tests cover a close on an already closed route and revision exhaustion.
The same suites now exercise the real `driverif_input` entry, pbuf reference
release, padding removal, native-buffer independence, and wrong-netif rejection.
TX tests reject prequeued frames after native admission closes, preserve the
ticket/capacity through a close reentered from native code, refuse reopening
with a live submit ticket, reject old epochs, and release on native error or
host unwind. The closed-admission regression fails on the older implementation.
Disconnect receipt tests call the production queue helpers, including all 16
enqueue/worker-completion interleavings for a four-request batch, unrelated/old
completions, queue rejection, failure retention, history eviction and u64
exhaustion. They also call the production inline handoff with reentrant queue
access, an early consumed wake, queued work, native failure and completion-wake
failure. These are command sequencing tests, not native-fence or HIL proof.

The opt-in composition also final-links `incremental_scan_profile` on all
three host OSes. It checks the actual MAC, Down state and absent TX token and
emits `RFDBG_NET0_BOUND_CLOSED`. This marker means bound/closed storage only,
not a functioning network. Host tests cover the opaque Driver's real capacity,
its shared smoltcp queue, rejected identity/duplicate claims, and close wakeups
before subscription or coalesced across polls.

Remaining integration gates are native quiescence/authorization events and
exact-artifact WS63 traffic/reconnect HIL. Storage/layout CI and bound/closed
control HIL are not peak-usage or working-network evidence. No new user-facing
network profile is advertised before those gates pass.
