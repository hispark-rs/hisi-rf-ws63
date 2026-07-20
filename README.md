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

## Validation

```console
cargo check --features wpa2-personal,smoltcp
cargo check --features wpa3-personal,smoltcp
cargo package --locked
```

This crate is an early alpha. Resource profiles and the final application
facade are still being tightened before a stable release.
