# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.4] - 2026-07-20

### Added

- Added typed WPA2/WPA3 smoltcp profiles, caller-owned `Storage<Profile, EVENTS>`,
  and a deterministic no-allocation resource report.

### Changed

- Moved the 4,384-byte WS63 crypto DMA scratch out of an internal static into
  application-owned profile storage.
- Made radio initialization reject reused storage before the backend or blob
  starts executing.

## [0.1.0-alpha.3] - 2026-07-20

### Added

- Moved the complete WS63 native radio link contract into the chip backend:
  normalized Wi-Fi and upstream-hostap archives, ROM/NVS fallbacks, runtime
  compatibility roots, and the relocatable 37-entry ROM patch table now reach
  the final firmware transitively through `hisi-rf-ws63`.
- Added a deterministic pure-Rust archive composition step so downstream
  firmware can use stock `rust-lld` without a consumer `build.rs`, shell,
  Python, vendor SDK, or external RISC-V binutils.
- Added a complete minimal firmware link fixture on Linux, macOS, and Windows;
  CI now exercises the transitive archive and ROM-patch contract at final-link
  time rather than stopping at a library-only `cargo check`.

### Changed

- Updated `ws63-radio-sys` to `0.1.0-alpha.6`, which exports the versioned
  runtime-compatibility and native-supplicant root-symbol manifests consumed by
  the chip composition root.

## [0.1.0-alpha.2] - 2026-07-20

### Fixed

- Included the target-side WAL adapter in the feature-minimal RV32 build so a
  facade selecting only `chip-ws63` compiles without enabling a security
  profile.

### CI

- Added a feature-minimal `riscv32imfc-unknown-none-elf` build gate.

## [0.1.0-alpha.1] - 2026-07-20

### Added

- Initial independent WS63 radio backend release, mechanically migrated from
  the hardware-verified `ws63-rf-rs` integration crate.
- Safe `Resources::new` composition from uniquely owned WS63 HAL peripheral
  tokens and a typed `init` entry into `hisi-rf-core`.
- Upstream hostap WPA2/WPA3 Personal profiles, WS63 L2/smoltcp bridge, hardware
  crypto integration, radio ABI adapter, and runtime-neutral OS services.
- Cargo-only link path through `ws63-radio-sys 0.1.0-alpha.5` normalized
  archives and relocatable ROM patch table.

[Unreleased]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.1
