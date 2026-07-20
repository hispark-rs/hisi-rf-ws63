# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/hispark-rs/hisi-rf-ws63/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/hispark-rs/hisi-rf-ws63/releases/tag/v0.1.0-alpha.1
