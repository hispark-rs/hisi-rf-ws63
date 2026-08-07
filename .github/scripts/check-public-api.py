#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Freeze the WS63 API and reject hidden backend/runtime types."""

from __future__ import annotations

import argparse
import difflib
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROFILES = {
    "wpa2": (
        "wpa2-personal,smoltcp,incremental-backend-experiment,"
        "incremental-embassy-wait"
    ),
    "wpa3": (
        "wpa3-personal,smoltcp,incremental-backend-experiment,"
        "incremental-embassy-wait"
    ),
    "ble-b3": "ble-init",
    "sle-s3": "sle-init",
}


PUBLIC_COMPOSITION_TYPES = (
    "hisi_rf_ws63::IncrementalRadioController",
    "hisi_rf_ws63::IncrementalRadioParts",
    "hisi_rf_ws63::IncrementalRadioRunner",
    "hisi_rf_ws63::InitError",
    "hisi_rf_ws63::WifiDevice",
    "hisi_rf_ws63::WifiParts",
    "hisi_rf_ws63::WifiRxToken",
    "hisi_rf_ws63::WifiTxToken",
)
FORBIDDEN_TOKENS = (
    "hisi_rf_rtos_driver",
    "Ws63Device",
    "Ws63WifiBackend",
)
REQUIRED_SIGNATURES = (
    "hisi_rf_ws63::IncrementalRadioController<P, EVENTS>::split(self, "
    "hisi_rf_core::incremental::WorkBudget) -> "
    "hisi_rf_ws63::IncrementalRadioParts<EVENTS>",
    "hisi_rf_ws63::WifiDevice::RxToken<'a> = hisi_rf_ws63::WifiRxToken",
    "hisi_rf_ws63::WifiDevice::TxToken<'a> = hisi_rf_ws63::WifiTxToken",
)
HIDDEN_STAGE_TOKENS = {
    "ble-b3": (
        "hisi_rf_ws63::BleB1Controller",
        "hisi_rf_ws63::BleB2Event",
        "hisi_rf_ws63::BleGattClient",
        "hisi_rf_ws63::BleGattServer",
        "hisi_rf_ws63::init_ble_b1",
    ),
    "sle-s3": (
        "hisi_rf_ws63::SleS1Controller",
        "hisi_rf_ws63::SleS1Event",
        "hisi_rf_ws63::SsapServerHandles",
        "hisi_rf_ws63::init_sle_s1",
    ),
}


def public_api(target: str, profile: str) -> list[str]:
    command = [
        "cargo",
        "public-api",
        "--target",
        target,
        "--features",
        PROFILES[profile],
        "-sss",
        "--color",
        "never",
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "cargo public-api failed; install cargo-public-api 0.52.0 first:\n"
            + completed.stderr.strip()
        )
    return completed.stdout.splitlines()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", choices=tuple(PROFILES), required=True)
    args = parser.parse_args()

    lines = public_api(args.target, args.profile)
    suffix = "incremental" if args.profile in {"wpa2", "wpa3"} else "stage"
    baseline = ROOT / ".github" / "public-api" / f"{args.profile}-{suffix}.txt"
    expected = baseline.read_text(encoding="utf-8").splitlines()
    if lines != expected:
        diff = "\n".join(
            difflib.unified_diff(
                expected,
                lines,
                fromfile=str(baseline.relative_to(ROOT)),
                tofile=f"actual-{args.profile}",
                lineterm="",
            )
        )
        raise RuntimeError(
            "the hisi-rf-ws63 public API changed; review the diff and update "
            f"the baseline only with an intentional API change:\n{diff}"
        )

    rendered = "\n".join(lines)
    if args.profile in {"wpa2", "wpa3"}:
        exposed = [
            line
            for line in lines
            if any(public_type in line for public_type in PUBLIC_COMPOSITION_TYPES)
            and any(token in line for token in FORBIDDEN_TOKENS)
        ]
        if exposed:
            raise RuntimeError(
                "facade-owned API exposes hidden backend/runtime types:\n  "
                + "\n  ".join(exposed)
            )
        required = REQUIRED_SIGNATURES
    else:
        leaked = [token for token in HIDDEN_STAGE_TOKENS[args.profile] if token in rendered]
        if leaked:
            raise RuntimeError(
                "internal stage API leaked into the documented public surface:\n  "
                + "\n  ".join(leaked)
            )
        required = ()

    missing = [signature for signature in required if signature not in rendered]
    if missing:
        raise RuntimeError(
            "expected profile signatures are missing:\n  "
            + "\n  ".join(missing)
        )

    print(
        f"WS63 {args.profile} public API matches its reviewed baseline"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
