#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Reject hidden WS63 backend/runtime types in the facade-owned API."""

from __future__ import annotations

import argparse
import subprocess


PUBLIC_COMPOSITION_TYPES = (
    "hisi_rf_ws63::IncrementalRadioController",
    "hisi_rf_ws63::IncrementalRadioParts",
    "hisi_rf_ws63::IncrementalRadioRunner",
    "hisi_rf_ws63::InitError",
    "hisi_rf_ws63::RadioController",
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
    "hisi_rf_ws63::RadioController<P, EVENTS>::start_runner(self) "
    "-> core::result::Result<hisi_rf_ws63::WifiParts<EVENTS>, "
    "hisi_rf_ws63::InitError>",
    "hisi_rf_ws63::WifiDevice::RxToken<'a> = hisi_rf_ws63::WifiRxToken",
    "hisi_rf_ws63::WifiDevice::TxToken<'a> = hisi_rf_ws63::WifiTxToken",
)


def public_api(target: str) -> list[str]:
    command = [
        "cargo",
        "public-api",
        "--target",
        target,
        "--features",
        (
            "wpa2-personal,smoltcp,incremental-backend-experiment,"
            "incremental-embassy-wait"
        ),
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
    args = parser.parse_args()

    lines = public_api(args.target)
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

    blocking_split = [
        line
        for line in lines
        if "hisi_rf_ws63::RadioController" in line and "::split(" in line
    ]
    if blocking_split:
        raise RuntimeError(
            "blocking composition root exposes the raw backend split escape hatch:\n  "
            + "\n  ".join(blocking_split)
        )

    rendered = "\n".join(lines)
    missing = [signature for signature in REQUIRED_SIGNATURES if signature not in rendered]
    if missing:
        raise RuntimeError(
            "expected opaque composition signatures are missing:\n  "
            + "\n  ".join(missing)
        )

    print("WS63 facade-owned public API contains no hidden backend/runtime types")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
