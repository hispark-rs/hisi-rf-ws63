# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.14] - 2026-07-23

### Added

- Added allocation-free WS63 RF heap metrics for current/peak usage, live
  allocations, and rejected allocation/deallocation diagnostics.
- Documented that the linker-owned RF heap is shared by the native supplicant,
  vendor queues, and OSAL objects, so observations do not constitute static
  profile admission or a supplicant-only arena size.

### Fixed

- Use `critical-section`'s reentrant `std` implementation for host tests instead
  of an empty test implementation that allowed parallel tests to mutate shared
  RF state concurrently.

## [0.1.0-alpha.13] - 2026-07-23

### Fixed

- Route the C `memalign` ABI through the checked RF heap aligned-allocation
  path, preserving requested power-of-two alignment and rejecting invalid
  alignment instead of silently returning a default-aligned block.

## [0.1.0-alpha.12] - 2026-07-23

### Added

- Source-aware WS63 diagnostic fixtures that distinguish vendor, IEEE 802.11,
  and upstream hostap status values while preserving unknown numeric codes.
- Connection timeout classification for first-EAPOL stalls and temporary PMF
  association rejection, derived from bounded association/EAPOL snapshots.

## [0.1.0-alpha.11] - 2026-07-23

### Added

- Added `station_mac_address()` to the safe WS63 composition root so a
  standard L2/IP stack can use the initialized station identity without
  importing vendor netif internals.

## [0.1.0-alpha.10] - 2026-07-23

### Added

- Added `RadioController::start_runner`, which stores the mandatory bounded-work
  runner in caller-owned profile storage and starts it without exposing
  `hisi-rf-rtos-driver` to applications.

### Changed

- Bound each initialized controller to the `Storage` instance that owns its
  runner, preventing the public happy path from pairing a runner with unrelated
  storage.
- The profile task reservation now covers one public radio runner plus the five
  workers observed in the pinned WS63 payload.

## [0.1.0-alpha.9] - 2026-07-23

### Added

- Unified, allocation-free diagnostics for WS63 initialization failures.
- Task-admission errors preserve required and available dynamic slots in the
  public `hisi-rf-error/v2` trace and recommend an actionable resource fix.
- Runtime and already-claimed storage failures use the same diagnostic schema
  as control-plane operation failures.

### Changed

- Updated `hisi-rf-core` to `0.1.0-alpha.4` for explicit cancellation and
  resource-exhaustion classes.

## [0.1.0-alpha.8] - 2026-07-22

### Added

- Owner-bound dynamic-task reservations that are acquired before storage or
  hardware is touched and consumed only by the WS63 radio task spawner.
- Resource-report schema v2 with the runtime contract, admission mechanism,
  and profile revision used by the pinned Wi-Fi payload.

## [0.1.0-alpha.7] - 2026-07-22

### Added

- WS63 errors now report explicit scan/authenticate/associate/SAE/EAPOL/PMF/
  disconnect/runtime stages and the selected profile revision.
- Terminal connection failures retain raw IEEE/backend status plus bounded
  supplicant and driver snapshots instead of depending on best-effort UART.
- Differential tests cover IEEE status 30 PMF classification and lossless
  negative hostap status preservation.

### Changed

- Updated `hisi-rf-core` to `0.1.0-alpha.3` and its versioned v2 diagnostic
  schema.

## [0.1.0-alpha.6] - 2026-07-22

### Fixed

- Limited the shared Wi-Fi dynamic-task requirement constant to target and
  complete-profile graphs, keeping the feature-minimal host composition free
  of dead-code warnings under `clippy -D warnings`.

### Changed

- Updated `hisi-rf-core` to `0.1.0-alpha.2`.

## [0.1.0-alpha.5] - 2026-07-22

### Added

- Added the `hisi-rf-rtos-driver/v1.2` advisory dynamic-task capacity preflight
  before caller storage is claimed or radio hardware is touched.
- Added typed task-admission errors that preserve required and available slot
  counts through the WS63 backend boundary.

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

[Unreleased]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.12...HEAD
[0.1.0-alpha.12]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.12
[0.1.0-alpha.11]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.11
[0.1.0-alpha.10]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.10
[0.1.0-alpha.9]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.9
[0.1.0-alpha.8]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.8
[0.1.0-alpha.7]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.7
[0.1.0-alpha.6]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.5...v0.1.0-alpha.6
[0.1.0-alpha.5]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.4...v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.1
