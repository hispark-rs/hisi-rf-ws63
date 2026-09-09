#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyelftools==0.32"]
# ///
"""Verify resolved host queue-4 hooks and their physical metadata footprint."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

from elftools.elf.elffile import ELFFile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("native_calls", Path(__file__).with_name("check-net0-cleanup.py"))
native_calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_calls)

EDGES = (
    ("uapi_ioctl_send_eapol", "__wrap_frw_host_post_data", 1),
    ("uapi_lwip_send", "__wrap_frw_host_post_data", 1),
    ("__wrap_frw_host_post_data", "frw_host_post_data", 2),
    ("frw_netbuf_que_handle", "__wrap_frw_netbuf_exec_callback", 1),
    ("__wrap_frw_netbuf_exec_callback", "frw_netbuf_exec_callback", 2),
    ("frw_host_post_data", "__wrap_oal_netbuf_free", 2),
    ("__wrap_oal_netbuf_free", "oal_netbuf_free", 1),
    ("__wrap_frw_host_post_data", "oal_netbuf_free", 1),
)


def inspect(path):
    report = native_calls.inspect(path, EDGES)
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        table = elf.get_section_by_name(".symtab")
        matches = table.get_symbol_by_name("__hisi_net0_host_tx_tracker") or []
        if len(matches) != 1:
            raise ValueError("missing or ambiguous host TX tracker")
        symbol = matches[0]
        if (symbol["st_info"]["type"] != "STT_OBJECT" or symbol["st_size"] != 576
                or not isinstance(symbol["st_shndx"], int)):
            raise ValueError("native TX metadata cost changed; review the resource budget")
        section = elf.get_section(symbol["st_shndx"])
        offset = symbol["st_value"] - section["sh_addr"]
        if section["sh_flags"] & 3 != 3 or offset < 0 or offset + symbol["st_size"] > section["sh_size"]:
            raise ValueError("host TX tracker must occupy writable allocated target memory")
        report["metadata"] = {"symbol": symbol.name, "bytes": symbol["st_size"],
                              "address": symbol["st_value"], "section": section.name,
                              "capacity": 32, "owner": "native host TX identity tracker",
                              "packet_payload_bytes": 0}
    report.update(schema="net0-host-tx-link/v1",
                  boundary="Resolved host queue-4 call routing and metadata only; not DMAC/RX quiescence or HIL")
    return report


def tamper(path):
    return native_calls.tamper(path, EDGES)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--tamper-test", action="store_true")
    args = parser.parse_args()
    report = inspect(args.elf)
    if args.tamper_test:
        report["rejected_call_mutations"] = tamper(args.elf)
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(content)
    print(content, end="")
