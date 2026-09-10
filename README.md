# hisi-rf-ws63

`hisi-rf-ws63` is the WS63 backend and composition root for the chip-neutral
[`hisi-rf-core`](https://crates.io/crates/hisi-rf-core) contracts. It owns the
WS63 radio ABI adapter, L2 bridge, hardware-crypto resource wiring, and the
safe assembly of HAL peripheral tokens into one radio controller.

Applications normally select this backend through the `hisi-rf` facade. This
crate remains independently versioned so WS63 blob/ABI changes do not change
the portable controller API.

## Boundaries

- `hisi-rf-core` owns portable controller, runner, configuration, event, and
  L2-device contracts.
- `hisi-rf-ws63` owns WS63 resources and the implementation of those contracts.
- `ws63-radio-sys` owns raw ABI declarations, normalized target archives, ROM
  patch objects, and native link metadata.
- `hisi-rf-rtos-driver` owns the runtime-neutral scheduler/IPC contract.
- `hisi-rtos` is the maintained target runtime backend and is started by the
  application, not hidden inside this crate.

The ordinary consumer build uses Cargo-delivered normalized archives and stock
`rust-lld`; it does not require a vendor SDK checkout, Python, Bash, RISC-V GCC,
or post-link relocation scripts.

## Profiles

- `wpa2-personal,smoltcp`: pinned upstream hostap WPA2-Personal backend plus the
  WS63 smoltcp L2 device.
- `wpa3-personal,smoltcp`: adds SAE/PMF support. Transition-mode HIL is proven;
  the pure WPA3-only 20-reset gate remains externally blocked until a suitable
  controlled AP is available.

The old vendor-supplicant path remains a migration oracle and is not selected
by either public Personal profile.

Each profile also has a type-level marker and caller-owned storage. The selected
Cargo feature exposes `SelectedProfile`, so firmware can make the RAM cost and
one-time ownership explicit without repeating the security mode in source:

```rust,ignore
hisi_rf_ws63::declare_radio_storage!(
    static RADIO_STORAGE,
    events = 4
);
```

`RADIO_STORAGE.install()` is the single pre-RTOS admission point. The macro
keeps bounded state in ordinary BSS and places the large shared allocator arena
in the runtime's dedicated `NOLOAD` section, so applications do not maintain
two public statics or reproduce linker attributes. The installed capability
supplies the RTOS allocation hooks and is split only at the later radio-init
boundary.

The selected profile atomically reserves its dynamic RTOS task slots before
claiming control storage or touching radio hardware. The opaque generation-bearing
reservation remains inside `Storage`; vendor worker creation consumes those
slots through contract v1.3, while unrelated task creation cannot steal them.
The reservation covers the one public `RadioRunner` task plus the six workers
observed in the pinned payload. Applications consume the controller with
`start_runner()` and receive only the Wi-Fi control/L2 handles; they do not call
the runtime-driver spawn API themselves.

`RadioStorage::report()` exposes deterministic
`hisi-rf-resource-report/v10` metadata. The report separates ordinary control
BSS, the composition handle, the RF/supplicant arena, bounded event capacity,
the 4,384-byte caller-owned crypto DMA scratch, task-stack payload, explicit
RTOS-object headroom and scheduler arena bytes, and the 48 KiB linker-owned
packet RAM. Final-image bytes remain a packaging concern.

Backend failures use the chip-neutral `hisi-rf-error/v3` schema. The WS63
adapter supplies the selected profile revision, protocol stage, raw IEEE or
hostap status, and at most four numeric context snapshots; it never inserts
SSID, passphrase, key material, or arbitrary log text into the public error.

## Validation

```console
cargo check --features wpa2-personal,smoltcp
cargo check --features wpa3-personal,smoltcp
cargo package --locked
```

This crate is an early alpha. Resource profiles and the final application
facade are still being tightened before a stable release.

### Experimental NET0 Link Contract

`standard-l2` remains a closed-admission experiment until native drainage and
reconnect are verified. The separate one-shot experiment does not relax that
gate. Its checked HMAC cleanup wrappers use the pinned nightly's
[`link_arg_attribute`](https://doc.rust-lang.org/unstable-book/language-features/link-arg-attribute.html)
to carry linker metadata through an rlib into the final application. Applications
must not repeat the cleanup `--wrap` flags themselves.

The maintainer-only `uv run --script .github/scripts/check-net0-consumer.py
--output <new-directory>` packages this repository, builds an isolated dependency
consumer with plain offline Cargo in a space/Unicode path, validates actual
cleanup calls and physical storage, and rejects removal of the metadata. The
consumer has no build script. This gate is not a crates.io-only facade release
test, byte-identical firmware guarantee, or native-fence/HIL acceptance.

`standard-l2-rx-origin-experiment` is an observation-only maintainer lane. It
correlates the existing patched RX descriptor allocator with the earlier native
host callback using 384 bytes of fixed census metadata and a 4-byte original
free-callback pointer. The native free function is local to its archive member;
the experiment captures callback 249 at the public registration boundary and
forwards it once, outside Rust critical sections. A retired observation means
only a free **attempt**, not successful release or DMA quiescence. Unknown/replaced identities,
closed/stale origins and capacity exhaustion remain visible; no observation
authorizes packet admission or reconnect. The final-ELF checker verifies the
existing ROM patch destinations, the real forwarded descriptor call and the
initializer's original free pointer/registration calls, not merely the presence
of a wrapper symbol. Runtime validation rejects a missing original callback or
a callback 250 that could bypass the observer. Native buffer ownership is unchanged.
The [native-free observation contract](docs/net0-native-free-observation.md)
records the ABI/oracle sources and the boundary of this census.

The default-off `standard-l2-rx-stop-experiment` records eight bounded
wall-time checkpoints in `RFDBG_NET0_RX_STOP_MS`: device-handler entry, MAC
disable return, first descriptor destroy return, reconstruction return,
reconstruction cleanup return, handler finish, message-post return, and the
waiter's terminal result. Each word is milliseconds since the request;
`0xffffffff` means absent or unrepresentable, not zero. Post and worker
checkpoints need not be ordered with respect to one another. Measurements
include preemption; they do not claim exclusive native-call CPU time.

This adds 32 bytes to the checked 112-byte stop-transaction object. No UART is
written by the measured handler, and the existing 1,000 ms deadline is unchanged.
A late waiter still fails even if the native handler returned zero earlier.
The marker is diagnostic evidence, not a successful DMA/host-queue fence.

The incremental fixture also emits `RFDBG_NET0_STOP_RUNTIME_PHASE before/after`
around disconnect (outside the measured native handler). Its adjacent
`RFDBG_NET0_STOP_RUNTIME` words are systick milliseconds, timer IRQs, SWIs,
context switches, sleeps, sleeper wakes, current task, current lock depth,
ready-ownership violations, budget exhaustions, created/completed switch
intents, and read-only `mstatus`. `RFDBG_NET0_STOP_TASK` selects main, priority-0
tasks, and the 8-KiB worker; its words are slot, priority, policy (0 cooperative,
1 budgeted, 2 preemptive), CPU/IRQ milliseconds, dispatches, budget exhaustions,
maximum run/ready/lock milliseconds, IRQ entries, ready-queued, pending-target.
Snapshots use stack storage and existing runtime APIs; task and scheduler
snapshots are individually synchronized, not one combined atomic snapshot.
Historical maxima are not transaction-local. These UART observations precede
any postmortem probe attach; they do not certify timing or queue liveness.
