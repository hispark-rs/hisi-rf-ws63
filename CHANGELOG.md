# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.91] - 2026-09-01

### Added

- Add a maintainer-only WPA2 SoftAP plus SLE composition that admits Wi-Fi and
  BGLE task groups atomically, shares one allocator and crypto service, and
  keeps the station-only incremental worker out of the access-point profile.
- Add an SLE-connected station fixture for measuring local Wi-Fi traffic while
  the SLE link remains established on a two-board rig.

### Changed

- Separate the shared Wi-Fi/SLE feature shape from the station incremental
  runner so AP authenticator and STA supplicant target archives remain
  mutually exclusive and fail closed under Cargo feature unification.

## [0.1.0-alpha.90] - 2026-08-31

### Added

- Report RF heap arena, usage, peak, live allocation, and failure counters
  after each coexistence scan and on scan failure, so repeated-scan HIL can
  distinguish retained ownership from an opaque native feed error.

### Fixed

- Update the exact `ws63-radio-sys` dependency to `0.1.0-alpha.25`, whose
  native hostap driver retains only the SSID and WPA/RSN/RSNXE protocol IEs in
  its deep-copied scan results. Unrelated broadcast telemetry no longer consumes
  the fixed Wi-Fi plus BLE coexistence arena twice.

## [0.1.0-alpha.89] - 2026-08-31

### Fixed

- Update the exact `ws63-radio-sys` dependency to `0.1.0-alpha.24`, whose
  native supplicant releases unused BSS entries before allocating the next
  externally captured scan batch. This reduces the retained-cache plus fresh
  scan-results peak in the fixed caller-owned RF arena.

## [0.1.0-alpha.88] - 2026-08-31

### Fixed

- Update the exact `ws63-radio-sys` dependency to `0.1.0-alpha.23`, whose
  native supplicant bounds the retained BSS cache and reports distinct scan
  feed capacity, allocation, and invalid-input failures. This prevents repeated
  coexistence scans from exhausting the fixed caller-owned RF arena.

## [0.1.0-alpha.87] - 2026-08-29

### Added

- Add a credential-free Wi-Fi plus BLE activity fixture that keeps BLE
  advertising active while the incremental Wi-Fi runner completes three scan
  transactions.

### Fixed

- Begin every externally driven vendor scan with the versioned native
  supplicant capture boundary from `ws63-radio-sys 0.1.0-alpha.22`, clearing
  the prior deep-copied hostap result cache before new results are queued.
- Report capture-boundary rejection separately from scan-result feed failures
  and release the active transaction claim when native setup fails.

## [0.1.0-alpha.86] - 2026-08-29

### Added

- Add named Wi-Fi plus BLE and Wi-Fi plus SLE coexistence profiles whose task,
  stack, queue, control-storage and RF-arena requirements are derived from one
  checked resource tree.
- Add credential-free final-link and real-silicon smoke examples for the two
  shared-platform compositions.

### Fixed

- Avoid counting the seven already-reserved Wi-Fi vendor tasks a second time
  when the composition root enters the vendor bootstrap.
- Map SLE task reservations independently from the SLE-local stack inventory,
  so a non-zero coexistence reservation offset cannot select the wrong stack
  size or priority.
- Exercise the admission regression in every host profile without requiring a
  station-only feature or leaking it into SoftAP builds.

### Changed

- Update the runtime contract to `hisi-rf-rtos-driver 0.1.0-alpha.20` and use
  owner-bound task-slot and stack reservations for the complete composition.

### Verified

- Pass credential-free Wi-Fi plus BLE and Wi-Fi plus SLE shared-platform
  initialization for 3/3 and then 20/20 hardware-reset runs on two WS63 boards.
  This evidence proves resource admission, Wi-Fi bootstrap and BLE/SLE platform
  initialization; concurrent Wi-Fi traffic and BLE/SLE over-air operation remain
  separate gates.

## [0.1.0-alpha.85] - 2026-08-29

### Fixed

- Restrict the non-radio IRQ fallback to the RV32 runtime that owns its
  assembly dispatcher, allowing host-only resource-report consumers to link on
  Windows without changing silicon interrupt routing.

## [0.1.0-alpha.84] - 2026-08-29

### Added

- Export the pinned BLE and SLE task-count, total-stack, minimum-stack, and
  backend event-capacity facts so the public facade can produce one truthful,
  allocation-free resource report without copying private admission constants.

## [0.1.0-alpha.83] - 2026-08-24

### Fixed

- Route the WS63 BLE Secure Connections public-key generation and ECDH
  compatibility calls through the uniquely installed hardware P-256 backend,
  while retaining the vendor ROM scratch lifecycle and failing closed without
  a software fallback.
- Convert the vendor scalar, coordinate and shared-secret byte order at the
  archive boundary so the generated MacKey and DHKey match the WS63 host.

### Changed

- Update `ws63-radio-sys` to `0.1.0-alpha.21` for the published passkey pairing
  context contract used by standalone builds.

### Verified

- Pass a 3/3 two-board fresh/restored pairing smoke and a 20/20 restored-bond
  reset matrix with authenticated Secure Connections on real WS63 silicon.

## [0.1.0-alpha.82] - 2026-08-20

### Added

- Bridge the WS63 BLE passkey request/display callbacks into bounded events
  and expose the narrow passkey reply adapter used by the generation-bound
  pairing responder.

### Changed

- Update `hisi-rf-core` to `0.1.0-alpha.23` and `ws63-radio-sys` to
  `0.1.0-alpha.20` so standalone builds consume the authenticated-pairing
  contracts from published release units.

## [0.1.0-alpha.81] - 2026-08-20

### Fixed

- Keep the 4 KiB NV erase-alignment check warning-free on the pinned nightly
  without requiring an integer API newer than the crate's Rust 2024 baseline.

## [0.1.0-alpha.80] - 2026-08-20

### Added

- Add linker-bounded 4 KiB erase support to the WS63 runtime NV backend and
  route full-page updates through `hisi-nvs` transactional compaction.

### Fixed

- Read NV writer transactions through the SRAM SFC command path so erase and
  program verification cannot observe stale XIP-prefetch data in the same
  boot.
- Preserve the ordinary read-only NV path on the memory-mapped XIP backend;
  command reads are confined to the serialized writer transaction.
- Align the WS63 crypto backend with `hisi-hal 0.7.0-alpha.9` through
  `hisi-crypto-ws63 0.1.0-alpha.5` so the standalone release has one HAL
  peripheral-token version.

### Verified

- Exercise a real full-page bond removal through erase, compaction, header
  commit, replacement and next-reset persistence, followed by a 20/20
  two-board fresh/restored-remove lifecycle matrix with no NV failure marker.

## [0.1.0-alpha.79] - 2026-08-20

### Fixed

- Scope legacy Wi-Fi imports to the backend profiles that actually expose them,
  restoring the `wpa2-personal,smoltcp,legacy-blocking-backend` CI contract.

## [0.1.0-alpha.78] - 2026-08-13

### Fixed

- Scope BLE/SLE-only P-256 key generation and typed SM3/CMAC imports to the
  profiles that consume them, keeping Wi-Fi-only workspace and plain-Cargo
  builds warning-free under Clippy's `-D warnings` gate.

## [0.1.0-alpha.77] - 2026-08-13

### Fixed

- Validate the actual BLE callback-provider metadata exported by
  `ws63-radio-sys 0.1.0-alpha.19` instead of a fabricated build-script fixture.
  BLE final links now fail closed unless all indirect SMP allocation, AES, CMAC,
  byte-order, XOR, and channel-map callbacks resolve to real providers.

## [0.1.0-alpha.76] - 2026-08-13

- Copy complete WS63 BLE SMP records from internal GAP event 19 into a
  dedicated bounded, zeroizing observer queue with conservation diagnostics.
  Vendor automatic persistence remains the sole owner until manual-mode
  behavior is proven on silicon.

### Added

- Route the BLE archive's caller-provided NIST P-256 private-key, random-key
  generation, and ECDH compatibility calls through the uniquely installed
  `hisi-crypto-ws63` PKE capability. Random private keys come from an explicit
  HMAC-SHA256 DRBG seeded and periodically reseeded by a private, startup- and
  continuously-health-checked WS63 TRNG adapter; raw TRNG output is never used
  directly as a CSPRNG.
- Add generation-tagged, bounded compatibility handles for the BLE archive's
  reviewed KM/keyslot/KLAD lifecycle and its one-update HMAC-SM3 and
  AES-128-CMAC sequences. Unsupported algorithms and stale handles fail closed;
  SPACC execution remains outside critical sections.
- Add an opt-in BLE initialization diagnostic that exercises the exact
  archive-facing HMAC-SM3, AES-128-CMAC, P-256 public-key and ECDH UAPI hooks
  with independent known-answer vectors on real WS63 silicon.

### Changed

- Require the BLE profile to own the WS63 PKE peripheral instead of leaving
  pairing key agreement backed by an unresolved or implicit resource.
- Name the authentication callback's secret-free observation `ltk_present` to
  match the reviewed WS63 ABI. The callback carries one 16-byte LTK field, not
  complete restorable IRK/CSRK bond material.
- Keep BLE startup on flashboot's live XIP configuration and initialize the
  mask-ROM SFC software control block only when a vendor NV write begins.
- Route runtime NV programming and readback through bounded SRAM-resident HAL
  command transactions while interrupts are masked, then restore the APP
  protection registers without resetting the NOR's active XIP bus mode.

## [0.1.0-alpha.75] - 2026-08-09

- Add internal BLE advertising/scan and SLE announce/seek stop operations for
  generation-tagged facade lifecycle cancellation. BLE advertising and SLE
  stop callbacks remain copied into the existing bounded backend event queues.
- Freeze the internal BLE B3 and SLE S3 migration inputs with host compile
  contracts and documented public-API snapshots. The stage types remain
  `#[doc(hidden)]`; this evidence supports the future `hisi-rf` composition
  root without declaring the backend API stable.
- Keep the SLE UUID type available to host rustdoc/API builds, and keep the
  target-only BLE callback queue warning-free under host clippy.
- Add typed BLE advertising/scanning and SLE announce/seek adapters for the U2
  facade runner. Vendor-visible payloads and raw parameter blocks now live in
  caller-owned process-lifetime storage instead of borrowing a queued command
  or a temporary stack frame.

## [0.1.0-alpha.74] - 2026-08-07

### Added

- Add an internal, credential-free BLE B1 init smoke that installs a
  caller-owned shared arena, hardware crypto/TRNG, the exact four-task vendor
  runtime plan, BLE IRQ routing, and the controller/host `enable_ble` closure.
- Add typed fail-closed B1 storage, resource, admission, spawn, scheduler, and
  vendor-init errors without exposing advertising, scanning, GATT, or pairing
  as public BLE APIs.

### Fixed

- Select the BLE profile's 512-byte minimum task stack at RTOS startup so its
  four heterogeneous preallocated reservations are not rejected by the
  Wi-Fi-oriented 24 KiB default floor.
- Give the opt-in BLE task snapshot worker a dedicated 4 KiB stack. Its 17-entry
  diagnostic array exceeded the former 2 KiB stack and underflowed into the
  adjacent calibration state on real WS63 silicon.

### Changed

- Update the BLE link dependency to `ws63-radio-sys 0.1.0-alpha.16`, whose
  profile-derived controller closure includes the original ROM timebase data
  and exports the guarded ROM callback symbol contract to standalone builds.

## [0.1.0-alpha.73] - 2026-08-06

### Added

- Link the hash-bound WS63 BLE B1 controller closure through the published
  `ws63-radio-sys 0.1.0-alpha.13` Cargo metadata, including the rooted init
  entries and the exact four-task runtime compatibility profile.
- Add a credential-free BLE final-link fixture and cross-platform CI gate that
  proves stock rust-lld consumes the normalized controller archive without
  vendor relocations or Wi-Fi ROM patch-table coupling.
- Add the bounded BLE controller compatibility ABI required by B1, including
  queue, synchronization, timer, allocator, NVS/eFuse and explicit unsupported
  PKE behavior. Advertising, scanning, GATT and pairing remain later gates.

### Changed

- Record the queue-depth compatibility symbol in the intentional WPA2 public C
  ABI snapshot; it is shared infrastructure for the BLE controller closure.

## [0.1.0-alpha.72] - 2026-08-06

### Changed

- Update the exact radio artifact dependency to `ws63-radio-sys
  0.1.0-alpha.12`, preserving the existing Wi-Fi behavior while sharing the
  newly published BLE B0 archive/ABI release contract.

## [0.1.0-alpha.71] - 2026-08-06

### Changed

- Move the one-shot vendor bootstrap behind an inherent backend operation so
  the bounded runner no longer initializes through the synchronous
  `WifiBackend` trait.
- Compile the old synchronous runner, adapter, and storage only with the
  explicit `legacy-blocking-backend` migration feature. Normal bounded builds
  remove 3,744 bytes from the 32-bit caller-owned control storage.

## [0.1.0-alpha.70] - 2026-08-04

### Fixed

- Make missing and conflicting station security profiles fail with one
  actionable compile-time diagnostic instead of leaking undefined or duplicate
  `SelectedProfile` errors from the internal resource model.

## [0.1.0-alpha.69] - 2026-08-03

### Added

- Add a pure WPA3-SAE SoftAP profile backed by the pinned upstream
  authenticator artifact. Its typed resource constructor requires the WS63
  PKE token, and initialization runs the bounded P-256 hardware self-test.
- Add independent WPA2/WPA3 SoftAP host, clippy, and RV32 CI lanes.

### Fixed

- Update the exact radio artifact dependency to `ws63-radio-sys
  0.1.0-alpha.11` and share the SAE crypto ABI between STA and AP roles
  without selecting both target archives.

## [0.1.0-alpha.68] - 2026-08-03

### Added

- Expose one-shot ownership of the WS63 SoftAP L2 device and hardware address
  so an application-owned network stack can serve DHCP and local traffic.

### Fixed

- Drain queued AP EAPOL frames only after a level-triggered callback wake and
  bridge SoftAP Ethernet TX through the same vendor data path used by the
  station facade.
- Update the exact radio artifact dependency to `ws63-radio-sys
  0.1.0-alpha.10`, which packages the native WPA2 authenticator archive and
  station-event ABI used by the two-board fixture.

## [0.1.0-alpha.67] - 2026-08-03

### Fixed

- Preserve multiple backend and L2 wake observations that arrive before the
  incremental runner polls, preventing worker-response readiness from hiding a
  queued EAPOL input event.
- Keep queued supplicant input level-triggered until consumed and retain scan
  storage without manufacturing a mutable reference from shared state.
- Update the exact WS63 radio ABI dependency to `ws63-radio-sys
  0.1.0-alpha.9` for the association diagnostic contract.

## [0.1.0-alpha.66] - 2026-08-03

### Added

- Derive WS63 task slots, heterogeneous stack bytes, and runtime arena size
  from one checked resource tree covering vendor tasks and the incremental
  worker.
- Reserve the complete task resource plan atomically before claiming storage
  or touching RF hardware, with owner-aware failure diagnostics.

### Fixed

- Remove composition-level double counting of the incremental worker and make
  the generated resource report match the final linked shared arena exactly.

### Added

- Add an opt-in, credential-free late-completion fixture that injects one
  old-generation success after a replacement operation starts and requires the
  worker proxy to drop it without disturbing the replacement scan.
- Make the credential-free incremental scan and cancellation fixture identify
  the real 8 KiB RTOS worker and fail closed when its measured uninterrupted
  run exceeds the configured 100 ms CPU quota or a budget expires while the
  scheduler lock is held. The emitted counters remain HIL observations rather
  than a wall-clock return guarantee for individual vendor calls.

### Fixed

- Keep the replacement operation active when the RTOS worker proxy receives a
  response for an older `OperationId`. Stale responses are discarded before
  they can copy scan output or clear the current operation identity.

## [0.1.0-alpha.65] - 2026-08-03

### Fixed

- Configure firmware examples from the selected profile's minimum task stack
  instead of the RTOS vendor default. The incremental worker keeps its explicit
  8 KiB reservation while all seven vendor tasks retain their measured 24 KiB
  reservations.

### Changed

- Advance the resource report to `hisi-rf-resource-report/v9` and publish the
  heterogeneous profile's minimum task-stack setting beside its total stack
  budget.

## [0.1.0-alpha.64] - 2026-08-03

### Fixed

- Keep the seven-slot vendor bootstrap admission separate from the eighth
  Rust incremental worker slot. The vendor runtime now validates only its own
  reserved capacity instead of rejecting the correctly split `7 + 1` profile
  with an `8 required, 7 available` initialization error.

## [0.1.0-alpha.63] - 2026-08-03

### Fixed

- Account for the worker's bounded control state in the complete WS63 SRAM
  envelope so the facade-selected `wifi_connectivity` firmware links without
  overlapping the fixed stack region.
- Reserve the seven 24 KiB vendor task stacks and the 8 KiB Rust worker stack
  as two exact owner-bound requests. This preserves eight admitted dynamic
  tasks without charging the worker as another 24 KiB vendor task.

## [0.1.0-alpha.62] - 2026-08-03

### Added

- Run the opt-in Embassy incremental backend through a caller-owned RTOS worker
  and fixed mailbox. The worker receives its `Budgeted` 100/200 ms periodic CPU
  quota atomically at task creation, so a synchronous vendor turn can no longer
  monopolize the hart indefinitely while the runner remains responsive to
  deferred completion and cancellation.

### Changed

- Require runtime contract v1.5 for the worker-backed path, reserve an eighth
  dynamic task slot, and advance the resource profile to
  `ws63-wifi-2026-08-03-r7`. The profile is uncalibrated until repeated WS63 HIL
  establishes its actual scheduling and memory envelope.
- Keep `WorkReport` elapsed-time accounting distinct from the RTOS CPU quota:
  the quota bounds CPU ownership, but does not claim that one uninterruptible C
  call returns within the 100 ms wall-clock grant.

## [0.1.0-alpha.61] - 2026-08-02

### Fixed

- Keep the incremental operation active when a synchronous WS63 supplicant
  submission or eloop poll returns after the configured time grant. The runner
  now observes a budget-exhaustion turn and can receive the later authorization
  event instead of failing with internal status `0x5732b003` after external
  protocol state has already advanced.

## [0.1.0-alpha.60] - 2026-07-30

### Changed

- Mark the WPA2-smoltcp runtime resource profile calibrated after a same-image
  20-reset WS63 matrix observed zero RTOS/RF allocation failures, while keeping
  the WPA3 profile uncalibrated until its separate silicon gate is available.
- Advance the profile revision to `ws63-wifi-2026-07-30-r6`.

## [0.1.0-alpha.59] - 2026-07-30

### Fixed

- Reserve an explicit 16 KiB scheduler-object headroom in the caller-owned
  runtime arena. The first split-arena HIL exhausted the stack-only arena while
  creating runtime semaphore and mutex objects, even though the RF arena still
  had ample capacity.

### Changed

- Advance the resource report to `hisi-rf-resource-report/v8`, naming the
  scheduler arena and its object headroom separately. The total 296 KiB NOLOAD
  envelope remains unchanged.

## [0.1.0-alpha.58] - 2026-07-30

### Changed

- Split the selected profile's caller-owned memory envelope into a dedicated
  RTOS task-stack arena and an RF/supplicant arena without increasing the total
  296 KiB NOLOAD budget.
- Advance the machine-readable resource report to
  `hisi-rf-resource-report/v7`, distinguishing stack payload bytes, allocator
  arena bytes, and the remaining RF arena.

## [0.1.0-alpha.57] - 2026-07-30

### Added

- Add bounded Ethernet protocol diagnostics for ARP request/reply, IPv4, and
  other frames in both RX and TX directions. Frame classification happens
  before the short counter update critical section; the TX sink remains
  outside that section.

## [0.1.0-alpha.56] - 2026-07-30

### Added

- Add a typed, secret-free scan diagnostic snapshot covering native request,
  result, completion, bounded-event-queue, and vendor-driver state. The raw
  compatibility array remains available for the existing integration path.

## [0.1.0-alpha.55] - 2026-07-30

### Fixed

- Keep the minimal `chip-ws63` composition warning-free when no Wi-Fi
  profile consumes the internal station-address helper. Full Wi-Fi profiles
  retain the same hardware-address behavior.

## [0.1.0-alpha.54] - 2026-07-30

### Changed

- Rename the aggregate diagnostic field from `mac_rx_filter_command` to
  `mac_rx_filter_control`, matching the packed WLMAC register semantics.
- Require `hisi-hal 0.7.0-alpha.6` for network-order VAP0 address decoding.

### Fixed

- Compare the L2 station identity against the corrected HAL snapshot. The
  secret-free `station-address-matches-device` result was verified true on
  WS63 silicon.

## [0.1.0-alpha.53] - 2026-07-30

### Added

- Extend the opt-in data-path diagnostic snapshot with the active WLMAC receive
  filter command, a station-address identity match flag, and a BSSID-programmed
  flag. The snapshot remains read-only and does not expose either address.

### Changed

- Require `hisi-hal 0.7.0-alpha.5` for typed WLMAC filter-state snapshots.

## [0.1.0-alpha.52] - 2026-07-29

### Added

- Added the opt-in `station-pm-diag` A/B helper. It disables station power save
  only after the caller has established the sole STA VAP, reports typed vendor
  failures, and remains hidden from normal radio profiles.

## [0.1.0-alpha.51] - 2026-07-29

### Fixed

- Replace the blocking mask-ROM MAC statistics helper with the generated
  `hisi-hal` WLMAC read-only snapshot. This avoids the ROM helper's fixed
  LiteOS IRQ callback trampoline while preserving the six audited counters.
- Advertise the MAC RX counter boundary in the bounded `data-path-diag`
  capability mask.

## [0.1.0-alpha.50] - 2026-07-29

### Added

- Extended the opt-in `data-path-diag` snapshot with bounded wrappers around
  the DMAC TX-completion callback and RX-preparation path. The wrappers only
  update atomic call counters before forwarding to the original implementation;
  they do not parse frames, call ROM statistics helpers, allocate, or invoke
  user code.

### Fixed

- Corrected the full `rf-eloop-diag` capability mask to declare its existing
  DMAC RX-preparation counter.

## [0.1.0-alpha.49] - 2026-07-29

### Fixed

- Split packet-path progress counters from the full authentication event-loop
  diagnostic profile. The new `data-path-diag` feature counts the existing
  Rust TX/RX seams without linker wrapping, ROM calls, or large trace storage;
  its capability mask leaves MAC statistics and DMAC completion explicitly
  unavailable.

## [0.1.0-alpha.48] - 2026-07-29

### Added

- Extended the secret-free data-path snapshot with vendor bridge TX, DMAC TX
  completion, final vendor RX, and MAC receive-engine counters. These counters
  distinguish Rust queue progress from vendor, hardware, and IRQ stalls without
  changing packet handling.

### Fixed

- Moved upstream-hostap deauthentication requests from the bounded
  `RadioRunner` turn into a lower-priority, bounded WS63 control worker. The
  vendor disconnect ioctl uses a synchronous HMAC post with a 4000 ms window;
  it can therefore no longer consume the runner's 100 ms response budget.
- Increased named-profile task admission from six to seven dynamic tasks and
  updated the machine-readable stack report for the added control worker.

## [0.1.0-alpha.47] - 2026-07-29

### Added

- Added a secret-free, non-consuming snapshot of the singleton incremental
  wait bridge for facade-owned aggregate diagnostics.

### Changed

- Updated to `hisi-rf-core 0.1.0-alpha.19`, whose runner diagnostics are
  readable through the owning radio instance without borrowing the runner.
- Updated the WS63 profile revision and caller-owned RAM report to include the
  72-byte instance-owned incremental diagnostic snapshot. The JSON shape
  remains `hisi-rf-resource-report/v6`; only the reported layout changed.

## [0.1.0-alpha.46] - 2026-07-29

### Added

- Added `resource_report::<Profile, EVENTS>()` as the storage-independent
  compile-time resource metadata entry used by the public facade's unified
  diagnostic snapshot. It does not construct, claim, or borrow radio storage.

## [0.1.0-alpha.45] - 2026-07-29

### Changed

- Adopted `hisi-rf-core 0.1.0-alpha.18` and publish the validated WS63 station
  MAC into the owning radio instance after successful initialization.
- Moved ordinary station MAC access to `WifiDevice`; the composition root no
  longer exports a process-global accessor, and the raw netif accessor is now
  crate-private.
- Updated the RV32 resource report and compile-time layout assertions for the
  instance-owned L2 capability snapshot, including 32-byte storage alignment.

## [0.1.0-alpha.44] - 2026-07-29

### Changed

- Adopted `hisi-rf-core 0.1.0-alpha.17` typed operation and backend
  timeouts. Protocol deadlines now report `operation.timeout`, while bounded
  WS63 lifecycle waits retain `backend.timeout`.
- Updated the caller-owned resource model for the cancellation channel added
  to the radio control state. RV32 assertions now lock both four-event and
  eight-event storage layouts.

### Fixed

- Routed dropped incremental controller futures into the backend cancellation
  path and unified wait source, so abandoned operations receive bounded cleanup
  without running vendor work from `Drop`.

## [0.1.0-alpha.43] - 2026-07-29

### Fixed

- Made host-generated resource reports describe the WS63 RV32 layout rather
  than the build host's pointer-width-dependent Rust layout. RV32 compile-time
  assertions now lock the calibrated 4/8-event control and radio-state sizes.
- Accounted for the aligned arena backing object's claim metadata in
  `arena_storage_bytes` and the total caller-owned RAM budget.

## [0.1.0-alpha.42] - 2026-07-29

### Added

- Added `RadioStorage` and `declare_radio_storage!` as the single
  caller-owned composition and pre-RTOS admission entry. The macro preserves
  the separate ordinary-BSS control store and dedicated `NOLOAD` shared arena
  without exposing two application statics.
- Added `InstalledRadioStorage` allocation hooks and an explicit
  post-RTOS `into_init_parts` boundary.

### Changed

- Upgraded the deterministic resource report to
  `hisi-rf-resource-report/v6`, accounting separately for control storage,
  composition-handle bytes, shared arena bytes, and their caller-owned total.

## [0.1.0-alpha.41] - 2026-07-29

### Added

- Added `init_incremental` as the backend-specific bounded-runner composition
  entry without encoding its synchronous vendor-bootstrap prerequisite in the
  function name.

### Deprecated

- Deprecated `init_incremental_after_blocking_bootstrap` for one alpha
  migration cycle. Applications should use the chip-selecting facade's
  `hisi_rf::ws63::init` entry.

## [0.1.0-alpha.40] - 2026-07-29

### Changed

- Kept both concrete Personal-profile builder definitions visible across
  feature selections so changing the selected security profile does not alter
  the facade's public name set. `SelectedProfile` still determines which
  typestate chain application code can complete.

## [0.1.0-alpha.39] - 2026-07-29

### Added

- Added a profile-aware typestate resource builder. WPA2 consumes only
  eFuse/KM/SPACC/TRNG and leaves PKE available to the application; WPA3 cannot
  be built until its PKE capability is supplied.
- Added pinned WPA2 and WPA3 `cargo-public-api` snapshots for the complete
  incremental WS63 composition surface. CI now reports an exact API diff in
  addition to rejecting hidden sys/backend/runtime types.

### Deprecated

- Deprecated the six-argument `Resources::new` compatibility constructor for
  one alpha migration cycle.

## [0.1.0-alpha.38] - 2026-07-28

### Added

- Added structured, counter-only association ioctl timing diagnostics so A5B
  response budgets no longer depend on a private positional word array.

## [0.1.0-alpha.37] - 2026-07-28

### Added

- Added a credential-free target fixture for the shared connectivity marker
  contract. Its explicit contract-only marker prevents QEMU parser parity from
  being misreported as real RF evidence.
- Added the fixture to the cross-platform final-link CI matrix.
- Added counter-only DHCP and receive-queue diagnostic snapshots to the safe
  `WifiDevice`. Applications can now attribute connectivity loss without
  reaching into the private WS63 netif implementation or exposing frame data.

## [0.1.0-alpha.36] - 2026-07-28

### Changed

- Reworked the credential-free cancellation and timeout fixture to traverse
  the public `WifiController`, command/completion channels, incremental runner,
  and WS63 backend instead of driving the private backend driver directly.
- Classified the injected timeout at the real `connect` stage while preserving
  the stable cancellation and backend error identities.

### Added

- Added a host regression proving both injected terminal errors return through
  the public controller path. The same firmware image was verified on QEMU and
  real WS63 silicon.

## [0.1.0-alpha.35] - 2026-07-28

### Fixed

- Bound the upstream hostap key lifecycle to the real WS63 WAL command
  sequence: `NEW_KEY`, optional `SET_KEY`, and `DEL_KEY`.
- Preserved fail-closed rollback by deleting a newly installed key when
  default-key selection fails, with host tests covering normal removal and
  rollback payloads.

## [0.1.0-alpha.34] - 2026-07-28

### Changed

- Deferred incremental scan, connect, disconnect, and cancellation driver calls
  from `start`/`cancel` into individually budgeted `poll` turns.
- Updated `hisi-rf-core` to `0.1.0-alpha.16` so incremental operations receive an
  immediate bounded poll after start and cancellation notification.

## [0.1.0-alpha.33] - 2026-07-28

### Changed

- Replaced the public runtime-driver error variants with an opaque
  `InitError` plus stable `InitErrorKind` and secret-free `Diagnostic`.
- Replaced backend-typed Wi-Fi return values with facade-owned
  `WifiParts`/`WifiDevice`/token types implementing the standard smoltcp
  contracts, and removed the blocking controller's raw backend `split`
  escape hatch.
- Moved `hisi-rtos` to target-example dev dependencies. Enabling the
  incremental Embassy wait bridge no longer selects a concrete runtime for
  applications.

### Added

- Added a `cargo-public-api` CI gate that rejects runtime-driver,
  `Ws63WifiBackend`, and internal `Ws63Device` types in the composition API.

## [0.1.0-alpha.32] - 2026-07-28

### Changed

- Updated `hisi-rf-core` to `0.1.0-alpha.15`, preserving immediate
  incremental-backend continuation when a terminal deadline is also armed.

### Added

- Added an adversarial production-adapter test proving that cancellation
  releases key, queue, timer, and operation-slot ownership before a replacement
  operation starts, while stale generations remain isolated.

## [0.1.0-alpha.31] - 2026-07-28

### Added

- Added a credential-free target fixture that drives cancellation and scan
  timeout through the production incremental driver and WS63 backend state
  machines. It proves terminal cancellation, replacement-operation recovery,
  timeout classification, and post-timeout slot reuse on host, QEMU, and real
  WS63 silicon.

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

[Unreleased]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.89...HEAD
[0.1.0-alpha.89]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.88...v0.1.0-alpha.89
[0.1.0-alpha.88]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.87...v0.1.0-alpha.88
[0.1.0-alpha.87]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.86...v0.1.0-alpha.87
[0.1.0-alpha.86]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.85...v0.1.0-alpha.86
[0.1.0-alpha.85]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.84...v0.1.0-alpha.85
[0.1.0-alpha.84]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.83...v0.1.0-alpha.84
[0.1.0-alpha.83]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.82...v0.1.0-alpha.83
[0.1.0-alpha.82]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.81...v0.1.0-alpha.82
[0.1.0-alpha.81]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.80...v0.1.0-alpha.81
[0.1.0-alpha.80]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.79...v0.1.0-alpha.80
[0.1.0-alpha.73]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.72...v0.1.0-alpha.73
[0.1.0-alpha.72]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.71...v0.1.0-alpha.72
[0.1.0-alpha.71]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.70...v0.1.0-alpha.71
[0.1.0-alpha.70]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.69...v0.1.0-alpha.70
[0.1.0-alpha.69]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.68...v0.1.0-alpha.69
[0.1.0-alpha.68]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.67...v0.1.0-alpha.68
[0.1.0-alpha.67]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.66...v0.1.0-alpha.67
[0.1.0-alpha.66]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.65...v0.1.0-alpha.66
[0.1.0-alpha.65]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.64...v0.1.0-alpha.65
[0.1.0-alpha.64]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.63...v0.1.0-alpha.64
[0.1.0-alpha.63]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.62...v0.1.0-alpha.63
[0.1.0-alpha.62]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.61...v0.1.0-alpha.62
[0.1.0-alpha.61]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.60...v0.1.0-alpha.61
[0.1.0-alpha.60]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.59...v0.1.0-alpha.60
[0.1.0-alpha.59]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.58...v0.1.0-alpha.59
[0.1.0-alpha.58]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.57...v0.1.0-alpha.58
[0.1.0-alpha.57]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.56...v0.1.0-alpha.57
[0.1.0-alpha.56]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.55...v0.1.0-alpha.56
[0.1.0-alpha.55]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.54...v0.1.0-alpha.55
[0.1.0-alpha.44]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.43...v0.1.0-alpha.44
[0.1.0-alpha.43]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.42...v0.1.0-alpha.43
[0.1.0-alpha.42]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.41...v0.1.0-alpha.42
[0.1.0-alpha.41]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.40...v0.1.0-alpha.41
[0.1.0-alpha.40]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.39...v0.1.0-alpha.40
[0.1.0-alpha.39]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.38...v0.1.0-alpha.39
[0.1.0-alpha.38]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.37...v0.1.0-alpha.38
[0.1.0-alpha.37]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.36...v0.1.0-alpha.37
[0.1.0-alpha.36]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.35...v0.1.0-alpha.36
[0.1.0-alpha.35]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.34...v0.1.0-alpha.35
[0.1.0-alpha.34]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.33...v0.1.0-alpha.34
[0.1.0-alpha.33]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.32...v0.1.0-alpha.33
[0.1.0-alpha.32]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.31...v0.1.0-alpha.32
[0.1.0-alpha.31]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.30...v0.1.0-alpha.31
[0.1.0-alpha.30]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.29...v0.1.0-alpha.30
[0.1.0-alpha.29]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.28...v0.1.0-alpha.29
[0.1.0-alpha.28]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.27...v0.1.0-alpha.28
[0.1.0-alpha.27]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.26...v0.1.0-alpha.27
[0.1.0-alpha.26]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.25...v0.1.0-alpha.26
[0.1.0-alpha.25]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.24...v0.1.0-alpha.25
[0.1.0-alpha.24]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.23...v0.1.0-alpha.24
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
