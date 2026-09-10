# One-Shot Native RX Stop Experiment

`standard-l2-rx-stop-experiment` is a maintainer-only, terminal operation after
checked station disconnect. It is not a production profile, DMA fence, or
permission to reconnect. BLE/SLE/SoftAP compositions are rejected at compile
time because this operation stops the shared Wi-Fi MAC.

The owner is the incremental controller's explicit **Disconnect** operation.
After its native ioctl receipt and DISCONNECTED event, a separate worker turn
rechecks ioctl completion, drains host TX, checks user cleanup and submits the
terminal stop. That turn has its own work charge and checks the operation's
deadline before starting. Error, cancellation or deadline expiry cannot report
successful disconnect/stop. This step never runs in the async network executor.

Hostap deauthentication is a protocol request, not this terminal operation:
the same callback is used for initial association cleanup and recovery. Those
requests must not destroy RX descriptors. The first stop prototype put the
experiment in that shared helper and a long matrix reached stop before initial
authorization. Moving ownership to explicit operation completion removes that
destructive coupling; it does not relax the one-shot L2 policy or prove that the
preceding association failure is fixed. Protocol recovery can separately restore
checked queue-4 handshake admission, as specified in [host TX](net0-host-tx.md).
The terminal operation seals that admission before executing the stop.

## Native Contract

The SDK `frw_dmac_rom.h` defines an eight-byte control prefix (min/max message
IDs and callback-table pointer), with a two-argument device handler. Message 91
is `WLAN_MSG_H2D_C_CFG_DESTROY_RX_DSCR`. The initialized table must contain
`hal_dev_fsm_destroy_rx_dscr`; unexpected owners fail bootstrap. Registration
replaces exactly this handler in one short critical section, using the ROM
unregister/register functions and readback. Unrelated invocations forward to
the original unchanged. No queue is replaced or assigned a fabricated message.

The native operation worker sends an eight-byte `NRX0`/ticket-1 payload using
the asynchronous device path. ROM `frw_alloc_msg_node` copies payload bytes
before enqueue returns; the native node owns that copy. Rust receipt state is
static and one-shot, never reused after timeout. Enqueue return alone is not
success. Only the matching, single device-worker callback can complete it.

The callback compares the full generation-tagged `OsalTask.task` returned by
FRW with `hisi-rf-rtos-driver::current_task`, not the slot-only OSAL pid/tid.
Both values are included in the receipt; stale generations fail closed.
It rejects active throughput mode
18 (queued host RX). It disables the MAC through the existing native helper,
reads `hal_is_machw_enabled`, invokes the original descriptor teardown only if
disabled, then reads MAC enable and `hal_is_hw_rx_queue_empty`. The latter reads
three **software descriptor-list counts**, not DMA status. Zero return from
teardown alone is insufficient: the ROM function is a no-op if MAC is enabled.

### Checked Descriptor Rebuild

After that immediate stop, the same correlated callback tests reconstruction
while application admission remains sealed. It invokes the original
`hal_dev_fsm_init_rx_dscr`, checks all three configured/actual counts and then
destroys the reconstructed lists again. It never enables the MAC or reopens
RX/TX. No new profile or public restart API is introduced.

The inner `hal_rx_init_dscr_queue` is **void**. The ROM logs partial allocation
and may program a nonempty hardware head even when a queue is undersized; the
outer handler returns zero. Therefore zero status, nonempty lists or an
unchanged total count cannot prove successful reconstruction. Counts must
match individually in native queue order (normal, high, small), with an
unchanged, non-all-zero configuration. A disabled configured queue may be zero.

The read-only RAM prefix is bound to this mask-ROM ABI: RX headers are 12 bytes,
starting at device+4; actual counts are at +12/+24/+36. Six 12-byte TX headers
and three hardware-head words precede configured normal/small/high at
+124/+126/+128. The SDK `hal_ops_common_rom.h` and `wlan_spec_hh503_rom.h` agree
with ROM comparisons at 0x12c75e/0x12c784/0x12c7aa. The optional DFR-stat TX
header variant is **not** this ROM's layout. Rust compile-time assertions fix
the prefix; only six volatile u16 values are read, never queue links or MMIO.

Every attempted initialization is followed by cleanup, including partial/error
returns. Cleanup first disables/rechecks MAC; it refuses to free while enabled.
First failure and separate cleanup status are both retained. Final MAC must
remain disabled and all three actual counts must be zero. A timeout observed
before the rebuild prevents starting it; one occurring after the check cannot
cancel an in-flight native routine, but is sticky and cannot become success.
`RFDBG_NET0_RX_REBUILD` records attempted/cleanup, expected/actual/final counts,
MAC states and statuses. Host fake counts exercise the production decision
function; they do not replace real partial-allocation HIL.

The requester waits at most 1000 ms outside Rust critical sections. Failed
enqueue, missing receipt, duplicate callback, wrong thread, timeout, or failed
postcondition is sticky. A timed-out queued request cannot later start teardown;
an already-running native call may finish, but cannot turn timeout into success.
The ROM routine itself masks IRQs while freeing descriptors; this experiment
does not claim a bound for arbitrary native C/ROM execution.

The transaction owns the monotonic start timestamp. Callback entry, the last
check before native teardown, rebuild admission, callback completion and waiter
result consumption all check the same deadline. A native call can delay both
timer delivery and the waiter; completion must not be inspected before time.
An exactly-expired, backward or missing clock sample fails closed. Late native
observations remain recorded, but cannot become a successful receipt. The clock
must itself advance while the waiter is not scheduled; these checks do not make
an uninterruptible native call cancellable or prove a wall-clock execution bound.

## Standard ROM Calls

New direct `R_RISCV_CALL` references to the ROM linker script's `SHN_ABS`
symbols were experimentally rejected: the final instruction encoded the ROM
address as a PC-relative displacement. Seven private, 12-byte standard RV32
LUI/ADDI/JR veneers instead use HI20/LO12 relocation against the same symbols.
No numeric ROM addresses enter production Rust or assembly. Existing native
callback veneers (MAC disable/device lookup) retain their original behavior.

`check-net0-rx-stop.py` verifies eighteen resolved call sites, seven exact veneer
targets, and the 112-byte transaction metadata object; twenty-five call/address
mutations must fail. Runtime callback-table ownership still needs HIL. The
consumer needs no external compiler, post-link script, or custom linker.

The object includes eight 32-bit wall-time checkpoints. The
[`RFDBG_NET0_RX_STOP_MS` contract](../README.md#experimental-net0-link-contract)
distinguishes handler work from message/waiter scheduling without UART output
inside the measured handler. The deadline stays 1,000 ms; a fast native return
followed by late waiter observation remains a failed transaction.

## Remaining Gates

This establishes only a correlated **immediate stop observation**. Native RX
callbacks already running, DMA/descriptor visibility, DMAC user
free status, autonomous native re-enable, and a bounded, reusable native
lifecycle remain separate gates. This allocation round-trip does not prove
hardware quiescence or authorize reconnect. Reading throughput flag 18 twice is not proof it was
never previously enabled. No `NativeFence` or reopen capability is produced.
After terminal stop, the one-shot L2 route and host TX stay closed for this boot.

### Direct RX Profile

`standard-l2` rejects the optional host-queued RX path from boot with a native
link wrapper on `frw_host_post_msg`. Message 595 closes Rust L2 admission and
sets a sticky, one-byte fault before returning native status 103. The pinned
`hmac_rx_data_event_adapt` owns and frees the rejected netbuf; the wrapper never
reads, retains or frees its payload. Other messages forward unchanged, including
the message-597 TID notifications. The sticky fault blocks later handshake TX
admission and terminal stop even if throughput flag 18 is subsequently cleared.
No additional packet storage or second RX queue is introduced.

The source oracle is the `frw_thread.h` post ABI and the SDK disassembly of
`hmac_rx_data_event_adapt`, bound to the published radio artifact dependency.
`check-net0-rx-mode.py` verifies all three non-relaxed native direct call sites,
the unchanged direct-RX call, the free-on-103 branch, wrapper forwarding and
physical fault storage. Removing a call or changing message/ownership bytes
must fail. Three-host external-consumer CI also removes the RX wrapper's native
link metadata and requires an undefined-real-symbol failure, then restores it.
This bounds the selected native direct-call path, not arbitrary indirect calls
or DMA lifetime. Unsupported throughput modes are not a production feature;
the actual target rejection and normal traffic still require separate HIL.

Host tests cover both return orders, timeout before/during dispatch, duplicate
receipts, zero-return/no-op, enqueue errors, and nonreuse. The production
incremental state machine also verifies the separate terminal work turn,
recovery/Connect versus explicit Disconnect, cancel-before-stop, expired
deadline and stop failure propagation. Three-host-OS CI also
links/checks the experiment and a packaged external consumer. HIL must preserve
the original failed direct-call image/result and separately report traffic,
checked cleanup, and immediate RX-stop receipts; none implies NET0 completion.
