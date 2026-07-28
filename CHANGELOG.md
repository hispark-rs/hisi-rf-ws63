# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.30] - 2026-07-28

### Added

- Added credential-free RV32 fixtures for the production association-rejection
  and first-EAPOL-timeout diagnostic builders. The same image now verifies
  stable code, stage, recovery action, profile revision, and bounded trace
  serialization on QEMU and real WS63 silicon.

## [0.1.0-alpha.29] - 2026-07-28

### Added

- Added a credential-free target fixture for `operation.cancelled` and
  `backend.timeout` JSON/UART parity on QEMU and real WS63 silicon.

## [0.1.0-alpha.28] - 2026-07-28

### Added

- Added stable `hisi-rf-error/v2` diagnostics for caller-owned RF arena
  admission failures, including exact required/available byte traces.
- Added a credential-free target fixture that proves arena shortage
  classification before RF power or blob startup.

## [0.1.0-alpha.27] - 2026-07-28

### Added

- Added profile-typed, caller-owned `RadioArenaStorage<N>` and a one-shot
  `RadioArena<P>` claim. Capacity is checked before the claim is consumed, and
  target initialization now fails closed instead of deriving a heap from
  linker remainder.
- Added resource-report schema v5 with the selected profile's explicit 296 KiB
  shared RF/supplicant/OSAL arena envelope, sized to coexist with the 32 KiB
  radio main stack in the WS63 544 KiB BGLE memory profile.

### Changed

- Made the selected profile part of `Resources<P>` so an arena admitted for one
  profile cannot initialize another profile.
- Updated all backend firmware fixtures to provide the named profile arena
  explicitly.

### Fixed

- Kept caller-owned RF storage out of ordinary `.bss` through the runtime's
  fixed-stack shared-arena contract. A 296 KiB arena now boots the ported RTOS
  and completes the incremental initialize/scan profile on WS63 silicon.
- Restored the normalized-archive `rf-eloop-diag` link path by wrapping the
  five vendor MAC diagnostic entry points with stock linker `--wrap` semantics
  instead of relying on guarded-link archive symbol rewriting.

## [0.1.0-alpha.26] - 2026-07-28

### Added

- Added owner-bound admission for six dynamic WS63 radio task slots and six
  24-KiB task stacks before radio hardware initialization.
- Added task-slot and task-stack requirements to resource-report schema v4.

## [0.1.0-alpha.25] - 2026-07-28

### Added

- Added a credential-free `incremental_scan_profile` HIL fixture that exercises
  the production composition root, RTOS/Embassy wait bridge, bounded
  incremental initialize/scan runner, work-budget continuation, and
  secret-free diagnostics on real WS63 silicon.
- Extended the incremental fixture with an opt-in, credential-redacted
  association/disconnect profile for WPA2 and WPA3 transition-mode reliability
  experiments. The fixture reports the observed AP security mode and bounded
  authentication, association, EAPOL, and recovery counters without emitting
  credentials or frame contents.
- Added host coverage for scan completion racing its deadline, bounded result
  draining after the hardware deadline, first-EAPOL recovery, external-auth
  retry ownership, and disconnect-before-reconnect ordering.

### Changed

- Updated the exact `ws63-radio-sys` dependency to `0.1.0-alpha.8`, which
  carries the association status-30 recovery diagnostics used by this release.
- Tightened the opt-in incremental connect fixture's per-step work budget from
  5 seconds to 100 milliseconds after a 20-reset transition-mode HIL matrix
  completed 20/20 with a 38 ms maximum runner step. Added secret-free
  association/deauthentication ioctl latency counters to distinguish WAL
  latency from hostap event-loop work. This is transition-mode evidence only;
  pure WPA3 remains an external validation gate.
- Split firmware-example and Embassy wait support into explicit features so
  enabling the incremental backend contract alone does not install a
  process-wide executor or time driver.
- Treat locally owned scan/output work as immediately runnable instead of
  waiting for a callback edge that may never recur after a bounded batch.
- Keep the transition-mode recovery path experimental. Current repeated-reset
  HIL still shows non-deterministic association-to-EAPOL and SAE-retry failures,
  so this evidence does not establish pure-WPA3 support or release readiness.

### Fixed

- Wake both the legacy runtime semaphore and the incremental wait bridge from
  scan, management, association, disconnect, and EAPOL callbacks.
- Abort an expired vendor scan before admitting a replacement transaction, and
  take one final completion snapshot at the timeout linearization point so a
  scan-done callback already published by the IRQ cannot be discarded.
- Restore WS63 mask-ROM fallbacks to linker-script `PROVIDE` definitions.
  Strong assembler aliases can be misinterpreted as PC-relative
  `R_RISCV_CALL_PLT` displacements when LTO preserves call relocations.

## [0.1.0-alpha.24] - 2026-07-26

### Added

- Added allocation-free diagnostics for the experimental incremental runner
  and WS63 wait bridge. The snapshots distinguish bounded runner transitions,
  selected wake-source batches, raw backend/L2 signal calls, executor
  notifications, pending/ready wait polls, timer readiness, terminal outcomes,
  and fail-closed errors without recording network configuration or secrets.

## [0.1.0-alpha.23] - 2026-07-26

### Fixed

- Embedded mask-ROM fallback addresses as strong absolute ELF symbols in the
  backend rlib. The complete link contract now remains transitive when a
  firmware depends only on the `hisi-rf` facade; it no longer relies on a
  non-transitive Cargo linker-script argument.

## [0.1.0-alpha.22] - 2026-07-26

### Fixed

- Exported the generated WS63 mask-ROM fallback linker script through Cargo
  dependency metadata so the user-facing `hisi-rf` facade can preserve the
  complete native link contract across the crate boundary.

## [0.1.0-alpha.21] - 2026-07-26

### Added

- Added the target-owned incremental wait platform that combines backend
  callback wakes, level-triggered L2 RX readiness, and monotonic operation
  deadlines. The WS63 runner now exposes `wait_ready()` without requiring an
  application-defined platform adapter.
- Added allocation-free wake registration and source-filtering tests. Callback
  and RX paths only publish bounded readiness and wake the executor; vendor and
  network work still runs in normal runner context.

### Changed

- Retained `wait_ready_with` as a hidden conformance hook while making the
  composition-owned wait platform the normal experimental API.
- Enabled the `hisi-rtos` Embassy time driver in target fixtures so deadline
  wakes share the RTOS timer instead of introducing a second target timer.

## [0.1.0-alpha.20] - 2026-07-26

### Added

- Added the credential-free `bootstrap_profile` firmware fixture. It executes
  the real WS63 composition root only through native supplicant construction,
  then emits all stage counters and worst observed durations without starting
  scan or association.
- Added the HIL-verified 32 KiB radio main-stack requirement to resource-report
  schema v3 and made the internal firmware fixture select the corresponding
  `hisi-riscv-rt` memory profile.

### Fixed

- Emit mask-ROM fallback addresses as linker-script symbols so stock rust-lld
  resolves RISC-V call relocations to their true absolute ROM destinations.
- Initialize and trace the ROM systick/TCXO timebase before timed radio stages,
  while keeping hardware crypto usable when timing is not yet available.
- Prevent synchronous vendor Wi-Fi bootstrap from overflowing the runtime's
  non-radio 8 KiB main stack and corrupting adjacent vendor BSS. The explicit
  32 KiB profile completed 20/20 hardware-reset bootstrap trials.

## [0.1.0-alpha.19] - 2026-07-23

### Added

- Added secret-free, stage-level bootstrap diagnostics for resource claim,
  hardware crypto installation and self-tests, vendor memory/timebase/Wi-Fi
  initialization, station/event setup, and native supplicant construction.
  Each stable stage identifier records entered, completed, failed and timed
  counters plus maximum duration, without claiming that the enclosed vendor
  call is preemptible.

## [0.1.0-alpha.18] - 2026-07-23

### Added

- Added an opt-in owned incremental composition path. Its explicit
  `init_incremental_after_blocking_bootstrap` entry completes the existing
  non-sliceable vendor bootstrap before transferring Wi-Fi and supplicant
  ownership to a bounded runner.
- Added an opaque WS63 incremental controller/runner facade, including typed
  wait intent, deadline, platform wait, and one-budgeted-step operations.

### Changed

- The incremental `Initialize` command now acknowledges the already completed
  bootstrap in one bounded step, including deterministic cancellation, rather
  than pretending to execute vendor initialization incrementally.
- The default blocking `init` and `RadioRunner` path remain unchanged.

## [0.1.0-alpha.17] - 2026-07-23

### Added

- Extended the non-default incremental backend with a genuine WS63 scan state
  machine: the vendor ioctl only starts work, scan/cache progress is polled,
  retained results are copied under the caller's event budget, and truncation
  is explicit.
- Scan cancellation now waits for the old vendor transaction and hostap cache
  feed to quiesce before completing, preventing untagged late scan callbacks
  from leaking into a subsequent operation generation.

### Changed

- Split the existing blocking `Wifi::scan` implementation over crate-private
  begin/poll/result/cancel primitives. The public blocking behavior and default
  backend remain unchanged.

## [0.1.0-alpha.16] - 2026-07-23

### Added

- Added the non-default `incremental-backend-experiment` connect/disconnect
  slice over the pinned upstream supplicant. It enforces generation-tagged
  operation identity, exact event accounting, elapsed-time budgets, bounded
  event draining, explicit cancellation, and deterministic host tests.
- Initialization deliberately remains fail closed in the experimental adapter
  because its vendor ABI is not cancellable or pollable; the current validated
  blocking backend remains the default.

### Changed

- Updated to `ws63-radio-sys 0.1.0-alpha.7` and its v9 poll ABI, separating
  completed work from output-event readiness.

## [0.1.0-alpha.15] - 2026-07-23

### Added

- Added secret-free blocking backend metrics for per-operation call counts,
  available monotonic timing, internal sleeps, and native supplicant polls.
  Calls made before the ROM timebase is initialized remain explicitly untimed.

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

[Unreleased]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.23...HEAD
[0.1.0-alpha.23]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.22...v0.1.0-alpha.23
[0.1.0-alpha.22]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.21...v0.1.0-alpha.22
[0.1.0-alpha.21]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.20...v0.1.0-alpha.21
[0.1.0-alpha.20]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.19...v0.1.0-alpha.20
[0.1.0-alpha.19]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.18...v0.1.0-alpha.19
[0.1.0-alpha.18]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.17...v0.1.0-alpha.18
[0.1.0-alpha.17]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.16...v0.1.0-alpha.17
[0.1.0-alpha.16]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.15...v0.1.0-alpha.16
[0.1.0-alpha.15]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.14...v0.1.0-alpha.15
[0.1.0-alpha.14]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.13...v0.1.0-alpha.14
[0.1.0-alpha.13]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.12...v0.1.0-alpha.13
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
