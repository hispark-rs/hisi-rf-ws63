#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyelftools==0.32"]
# ///
"""Check resolved native cleanup calls, not just the presence of wrapper symbols."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from elftools.elf.elffile import ELFFile


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def calls(data, base):
    """Decode only adjacent RV32 AUIPC/JALR pairs in non-relaxed code."""
    result = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError("truncated function instruction")
        half = int.from_bytes(data[offset:offset + 2], "little")
        size = 2 if half & 3 != 3 else 4 if half & 31 != 31 else 6 if half & 63 == 31 else 8 if half & 127 == 63 else 0
        if not size or offset + size > len(data):
            raise ValueError("unsupported or truncated instruction length")
        if size == 4 and offset + 8 <= len(data):
            first, second = struct.unpack_from("<II", data, offset)
            register = (first >> 7) & 31
            if (first & 127 == 0x17 and register != 0
                    and second & 0x707f == 0x67 and (second >> 15) & 31 == register):
                target = (base + offset + signed(first & 0xfffff000, 32)
                          + signed(second >> 20, 12)) & 0xfffffffe
                result.append((base + offset, target))
        offset += size
    return result


EDGES = (
    ("hmac_config_kick_user_etc", "__wrap_hmac_user_del_etc"),
    ("__wrap_hmac_user_del_etc", "hmac_user_del_etc"),
    ("hmac_user_del_etc", "hmac_user_free_etc"),
    ("hmac_user_free_etc", "__wrap_hmac_res_free_mac_user_etc"),
    ("__wrap_hmac_res_free_mac_user_etc", "_mac_res_get_hmac_user"),
    ("__wrap_hmac_res_free_mac_user_etc", "hmac_res_free_mac_user_etc"),
)


def inspect(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_RISCV":
            raise ValueError("expected final RV32 little-endian ELF")
        table = elf.get_section_by_name(".symtab")
        def symbol(name):
            values = table.get_symbol_by_name(name) if table else None
            if not values or len(values) != 1 or values[0]["st_info"]["type"] != "STT_FUNC":
                raise ValueError(f"missing or ambiguous cleanup function: {name}")
            return values[0]
        edges = []
        for source, target in EDGES:
            function, callee = symbol(source), symbol(target)
            if not isinstance(function["st_shndx"], int) or function["st_size"] == 0:
                raise ValueError("cleanup function must have physical code and a bounded size")
            section = elf.get_section(function["st_shndx"])
            start = function["st_value"] - section["sh_addr"]
            end = start + function["st_size"]
            if section["sh_flags"] & 6 != 6 or start < 0 or end > section["sh_size"]:
                raise ValueError("cleanup function outside executable section")
            matches = [site for site, destination in calls(section.data()[start:end], function["st_value"])
                       if destination == callee["st_value"]]
            if len(matches) != 1:
                raise ValueError(f"expected one resolved cleanup call: {source} -> {target}, got {len(matches)}")
            edges.append({"source": source, "target": target, "call_address": matches[0],
                          "target_address": callee["st_value"],
                          "file_offset": section["sh_offset"] + matches[0] - section["sh_addr"]})
    return {"schema": "net0-cleanup-link/v1", "status": "pass", "edges": edges,
            "elf_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "boundary": "Resolved HMAC call routing only; not native quiescence or HIL"}


def tamper(path):
    report = inspect(path)
    original = path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="cleanup-link-") as temporary:
        candidate = Path(temporary) / "mutated.elf"
        for edge in report["edges"]:
            data = bytearray(original)
            # Remove exactly the checked call without changing layout/symbols.
            struct.pack_into("<II", data, edge["file_offset"], 0x13, 0x13)
            candidate.write_bytes(data)
            try:
                inspect(candidate)
            except ValueError:
                continue
            raise ValueError(f"missing-call mutation accepted: {edge['source']}")
    return len(report["edges"])


class Tests(unittest.TestCase):
    def test_calls_use_instruction_boundaries(self):
        pair = struct.pack("<II", 0x1097, 0x004080e7)
        data = b"\x01\x00" + b"\x1f\x05\x00\x00\x00\x00" + pair
        self.assertEqual(calls(data, 0x1000), [(0x1008, 0x200c)])
        self.assertEqual(calls(struct.pack("<II", 0x17, 0x00000067), 0), [])

    def test_signed_and_truncated_calls(self):
        self.assertEqual(calls(struct.pack("<II", 0xfffff097, 0xffc080e7), 0x2000), [(0x2000, 0xffc)])
        for data in (b"\x00", b"\x03\x00", b"\x7f\x00"):
            with self.assertRaises(ValueError):
                calls(data, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--tamper-test", action="store_true")
    args = parser.parse_args()
    if args.test:
        if not unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests)).wasSuccessful():
            raise SystemExit(1)
    if args.elf:
        report = inspect(args.elf)
        if args.tamper_test:
            report["rejected_call_mutations"] = tamper(args.elf)
        content = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(content)
        print(content, end="")
    elif not args.test:
        parser.error("provide --elf or --test")
