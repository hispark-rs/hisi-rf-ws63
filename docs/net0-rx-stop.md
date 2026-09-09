# One-Shot Native RX Stop Experiment

`standard-l2-rx-stop-experiment` is a maintainer-only, terminal operation after
checked station disconnect. It is not a production profile, DMA fence, or
permission to reconnect. BLE/SLE/SoftAP compositions are rejected at compile
time because this operation stops the shared Wi-Fi MAC.

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

The requester waits at most 1000 ms outside Rust critical sections. Failed
enqueue, missing receipt, duplicate callback, wrong thread, timeout, or failed
postcondition is sticky. A timed-out queued request cannot later start teardown;
an already-running native call may finish, but cannot turn timeout into success.
The ROM routine itself masks IRQs while freeing descriptors; this experiment
does not claim a bound for arbitrary native C/ROM execution.

## Standard ROM Calls

New direct `R_RISCV_CALL` references to the ROM linker script's `SHN_ABS`
symbols were experimentally rejected: the final instruction encoded the ROM
address as a PC-relative displacement. Six private, 12-byte standard RV32
LUI/ADDI/JR veneers instead use HI20/LO12 relocation against the same symbols.
No numeric ROM addresses enter production Rust or assembly. Existing native
callback veneers (MAC disable/device lookup) retain their original behavior.

`check-net0-rx-stop.py` verifies ten resolved call sites, six exact veneer
targets, and the 32-byte transaction metadata object; sixteen call/address
mutations must fail. Runtime callback-table ownership still needs HIL. The
consumer needs no external compiler, post-link script, or custom linker.

## Remaining Gates

This establishes only a correlated **immediate stop observation**. Native RX
message 595, callbacks already running, DMA/descriptor visibility, DMAC user
free status, autonomous native re-enable, and bounded descriptor reinitialization
remain separate gates. Reading throughput flag 18 twice is not proof it was
never previously enabled. No `NativeFence` or reopen capability is produced.
The existing one-shot L2 route and host TX admission stay closed for this boot.

Host tests cover both return orders, timeout before/during dispatch, duplicate
receipts, zero-return/no-op, enqueue errors, and nonreuse. Three-host-OS CI also
links/checks the experiment and a packaged external consumer. HIL must preserve
the original failed direct-call image/result and separately report traffic,
checked cleanup, and immediate RX-stop receipts; none implies NET0 completion.
