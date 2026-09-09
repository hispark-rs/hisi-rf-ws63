#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyelftools==0.32"]
# ///
"""Compare a target-built NET0 resource descriptor with its final ELF storage."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import unittest

from elftools.elf.elffile import ELFFile


def validate(words, control_size, shared_size, packet_size):
    if len(words) != 13 or words[:2] != [int.from_bytes(b"NET0", "little"), 1]:
        raise ValueError("missing or unknown NET0 target layout schema")
    keys = ("control_bytes", "l2_offset", "l2_bytes", "payload_bytes", "metadata_bytes",
            "rx_slots", "tx_slots", "mtu", "shared_arena_bytes", "main_stack_bytes",
            "packet_ram_bytes")
    report = dict(zip(keys, words[2:]))
    if report["control_bytes"] != control_size:
        raise ValueError("target report differs from actual NET0_CONTROL symbol size")
    if report["l2_offset"] + report["l2_bytes"] > control_size:
        raise ValueError("L2 allocation extends outside caller-owned control storage")
    if (report["rx_slots"], report["tx_slots"], report["mtu"]) != (4, 4, 1514):
        raise ValueError("unexpected NET0 queue shape; review profile change")
    if report["payload_bytes"] != (report["rx_slots"] + report["tx_slots"]) * report["mtu"]:
        raise ValueError("payload bytes do not match packet slot storage")
    if report["metadata_bytes"] <= 0 or report["payload_bytes"] + report["metadata_bytes"] != report["l2_bytes"]:
        raise ValueError("L2 payload/metadata sum does not match physical storage")
    if report["shared_arena_bytes"] != shared_size:
        raise ValueError(f"target report differs from linked shared arenas: report={report['shared_arena_bytes']}, linked={shared_size}")
    if report["packet_ram_bytes"] != packet_size or packet_size != 0xc000:
        raise ValueError("radio packet RAM was changed or misreported")
    if report["main_stack_bytes"] != 0x8000:
        raise ValueError("existing 32 KiB bootstrap stack contract was changed")
    return report


def inspect(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_RISCV":
            raise ValueError("expected the final RV32 little-endian ELF, not a host report")
        symbols = elf.get_section_by_name(".symtab")
        def symbol(name):
            matches = symbols.get_symbol_by_name(name) if symbols else None
            if not matches or len(matches) != 1:
                raise ValueError(f"missing or ambiguous ELF symbol: {name}")
            return matches[0]
        control = symbol("NET0_CONTROL")
        layout = symbol("NET0_STORAGE_LAYOUT")
        if layout["st_size"] != 52:
            raise ValueError("invalid NET0 layout byte length")
        section = elf.get_section(layout["st_shndx"])
        offset = layout["st_value"] - section["sh_addr"]
        words = list(struct.unpack("<13I", section.data()[offset:offset + 52]))
        shared = elf.get_section_by_name(".hisi_shared_arenas")
        packet = elf.get_section_by_name(".wifi_pkt_ram")
        if shared is None or packet is None:
            raise ValueError("missing shared arena or Wi-Fi packet section")
        report = validate(words, control["st_size"], shared["sh_size"], packet["sh_size"])
        stack_start = symbol("__stack_start__")["st_value"]
        stack_top = symbol("__stack_top__")["st_value"]
        if stack_top - stack_start != report["main_stack_bytes"]:
            raise ValueError("main stack report differs from actual linker symbols")
        if shared["sh_addr"] + shared["sh_size"] > stack_start:
            raise ValueError("shared arenas overlap the main stack")
        control_section = elf.get_section(control["st_shndx"])
        if not control_section["sh_flags"] & 1 or not control_section["sh_flags"] & 2:
            raise ValueError("control storage is not writable allocated target memory")
        begin = control["st_value"]
        end = begin + control["st_size"]
        if begin < control_section["sh_addr"] or end > control_section["sh_addr"] + control_section["sh_size"]:
            raise ValueError("control object is not contained in its linked section")
        report["control_address"] = begin
    report.update(schema="net0-linked-storage/v1", status="pass",
                  elf_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  boundary="Physical storage/link validation only; no native fence or HIL claim")
    return report


class ContractTests(unittest.TestCase):
    def test_rejects_size_sum_and_capacity_drift(self):
        words = [int.from_bytes(b"NET0", "little"), 1, 22000, 2304, 12736,
                 12112, 624, 4, 4, 1514, 299072, 32768, 49152]
        validate(words, 22000, 299072, 49152)
        for index in range(len(words)):
            wrong = words.copy()
            wrong[index] += 1
            if index == 3:
                wrong[index] = 22000
            with self.subTest(index=index), self.assertRaises(ValueError):
                validate(wrong, 22000, 299072, 49152)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path, nargs="?")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests))
        if not result.wasSuccessful():
            raise SystemExit(1)
    if args.elf:
        data = json.dumps(inspect(args.elf), sort_keys=True, indent=2) + "\n"
        if args.output:
            args.output.write_text(data)
        print(data, end="")
    elif not args.self_test:
        parser.error("provide an ELF or --self-test")


if __name__ == "__main__":
    main()
