#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyelftools==0.32"]
# ///
"""Bind the direct-RX profile to the pinned producer's rejection/ownership ABI."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile

from elftools.elf.elffile import ELFFile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("native_calls", Path(__file__).with_name("check-net0-cleanup.py"))
native_calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_calls)

WRAPPER = "__wrap_frw_host_post_msg"
PRODUCER = "hmac_rx_data_event_adapt"
CALLERS = (PRODUCER, "hmac_tid_pause", "hmac_tid_resume")
EDGES = [(name, WRAPPER, 1) for name in CALLERS] + [
    (WRAPPER, "frw_host_post_msg", 1),
    (PRODUCER, "__wrap_oal_netbuf_free", 1),
    (PRODUCER, "hmac_rx_process_data_msg", 1),
]


def inspect(path):
    report = native_calls.inspect(path, EDGES)
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        table = elf.get_section_by_name(".symtab")
        sections = {}

        def symbol(name):
            values = table.get_symbol_by_name(name) or []
            if len(values) != 1 or not isinstance(values[0]["st_shndx"], int):
                raise ValueError("missing/ambiguous physical symbol: " + name)
            return values[0]

        def body(item):
            index = item["st_shndx"]
            if index not in sections:
                section = elf.get_section(index)
                sections[index] = (section, section.data())
            section, data = sections[index]
            start = item["st_value"] - section["sh_addr"]
            if start < 0 or start + item["st_size"] > section["sh_size"]:
                raise ValueError("symbol outside section")
            return data[start:start + item["st_size"]], section["sh_offset"] + start

        # The selected archive is non-relaxed. All inter-object calls must
        # retain AUIPC/JALR; this census does not claim to discover indirect calls.
        addresses = {symbol(WRAPPER)["st_value"]: WRAPPER,
                     symbol("frw_host_post_msg")["st_value"]: "frw_host_post_msg"}
        actual = []
        for item in table.iter_symbols():
            if (item["st_info"]["type"] != "STT_FUNC" or not isinstance(item["st_shndx"], int)
                    or not item["st_size"] or elf.get_section(item["st_shndx"])["sh_flags"] & 6 != 6):
                continue
            data, _ = body(item)
            for site, destination in native_calls.calls(data, item["st_value"]):
                if destination in addresses:
                    actual.append((item.name, addresses[destination], site))
        expected = sorted((edge["source"], edge["target"], edge["call_address"])
                          for edge in report["edges"] if edge["target"] in addresses.values())
        if sorted(actual) != expected:
            raise ValueError("native post caller set changed; review message and payload ownership")

        producer = symbol(PRODUCER)
        data, offset = body(producer)
        site = next(edge["call_address"] for edge in report["edges"]
                    if edge["source"] == PRODUCER and edge["target"] == WRAPPER) - producer["st_value"]
        # Pinned hmac_rx_data.c.obj, independently checked with the vendor
        # decoder: li a0,595; call; mv s1,a0; bnei a0,103,return; jal free;
        # j return; mv a0,s0; tail free. Internal branches are layout-relative.
        checks = [(offset + site - 4, bytes.fromhex("13053025")),
                  (offset + site + 8, bytes.fromhex("aa843b18e567112069bf2285"))]
        if producer["st_size"] != 144 or site != 116:
            raise ValueError("RX producer layout changed; re-audit the native free-on-103 branch")
        raw = path.read_bytes()
        for position, expected_bytes in checks:
            if raw[position:position + len(expected_bytes)] != expected_bytes:
                raise ValueError("RX message/rejection ownership branch differs from the pinned oracle")
        for name in CALLERS[1:]:
            data, _ = body(symbol(name))
            if data.count(struct.pack("<I", 0x25500513)) != 1:
                raise ValueError("TID notification no longer has the reviewed message-597 encoding")

        state = symbol("__hisi_net0_queued_rx_rejected")
        section = elf.get_section(state["st_shndx"])
        if state["st_size"] != 1 or state["st_info"]["type"] != "STT_OBJECT" or section["sh_flags"] & 3 != 3:
            raise ValueError("sticky RX rejection must occupy one physical writable byte")
        report["metadata"] = {"bytes": 1, "address": state["st_value"], "section": section.name,
                              "packet_payload_bytes": 0}
        report["ownership_checks"] = [{"file_offset": position, "bytes": data.hex()}
                                      for position, data in checks]
    report.update(schema="net0-direct-rx-link/v1", message=595, reject_status=103,
                  boundary="Pinned direct-call and free-on-103 ABI; not indirect-call completeness, DMA quiescence or reconnect")
    return report


def tamper(path):
    report = inspect(path)
    count = native_calls.tamper(path, EDGES)
    original = path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="rx-mode-link-") as directory:
        candidate = Path(directory) / "mutated.elf"
        for check in report["ownership_checks"]:
            data = bytearray(original)
            data[check["file_offset"]] ^= 1
            candidate.write_bytes(data)
            try:
                inspect(candidate)
            except ValueError:
                count += 1
                continue
            raise ValueError("changed native ownership branch was accepted")
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--tamper-test", action="store_true")
    args = parser.parse_args()
    report = inspect(args.elf)
    if args.tamper_test:
        report["rejected_mutations"] = tamper(args.elf)
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(content)
    print(content, end="")
