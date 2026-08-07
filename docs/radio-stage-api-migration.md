# WS63 Radio Stage API Migration Contract

Status: U0 behavior freeze. This document records migration inputs for the
future `hisi-rf` facade; it does not make the stage API stable.

## Frozen Evidence

| Protocol | Cargo profile | Archive profile | Silicon evidence |
|---|---|---|---|
| BLE | `ble-init` | `ws63-ble-b0-archive-abi-v1` | B3 GATT two-board 20-reset matrix |
| SLE | `sle-init` | `ws63-sle-s0-archive-abi-v1` | S3 SSAP two-board 20-reset matrix |

CI freezes the exact Rust surfaces as `ble-b3-stage.txt` and
`sle-s3-stage.txt`. These snapshots are compatibility inputs for migration,
not promises that applications should depend on `hisi-rf-ws63` directly.

## Ownership Migration

| Current internal surface | Future facade owner | Required preservation |
|---|---|---|
| `BleB1Controller` | `hisi_rf::ble::BleController` plus `RadioRunner` | B2 GAP and B3 GATT event order, bounded copies, dropped-event accounting |
| `BleB2Event` | `hisi_rf::ble::BleEvent` | No vendor pointer escapes; command completion remains distinct from unsolicited events |
| `BleGattClient` / `BleGattServer` | typed GATT client/server handles | Disconnect invalidates generation-tagged handles |
| `SleS1Controller` | `hisi_rf::sle::SleController` plus `RadioRunner` | S1-S3 announce, seek, connect, SSAP read and notification behavior |
| `SleS1Event` | `hisi_rf::sle::SleEvent` | Bounded payload copies, truncation and drop accounting remain observable |
| `SsapServerHandles` | typed SSAP server/client handles | Applications stop managing raw server, client and property identifiers |
| `init_ble_b1` / `init_sle_s1` | one `RadioController` composition root | Shared RF, IRQ, blob, arena and runtime resources are initialized exactly once |

## Non-Goals Of U0

- No stage type is renamed and declared stable.
- No BLE/SLE operation is made async by wrapping a synchronous vendor call.
- No fake `RadioRunner` is introduced while controllers still call vendor FFI
  and consume callback events directly.
- Pairing, authenticated SSAP, coexistence, raw DLI/HCI and stable API
  graduation remain separate gates.

U1 may change these internal snapshots only together with an explicit adapter,
host contract tests, updated migration mapping and the existing B3/S3 parity
markers.
