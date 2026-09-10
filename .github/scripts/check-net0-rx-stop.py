#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyelftools==0.32"]
# ///
"""Verify actual native RX stop calls, not a reusable hardware-fence claim."""
import argparse
import importlib.util
import json
import struct
from pathlib import Path
import sys
import tempfile

from elftools.elf.elffile import ELFFile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("native_calls", Path(__file__).with_name("check-net0-cleanup.py"))
native_calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_calls)

# Fixed WS63 mask-ROM definitions from hisi-rom-sys-ws63's ws63_acore_rom.lds.
# This verifier does not introduce production addresses or bypass its linker.
ROM_TARGETS = {
    "get_dmac_frw_ctrl": 0x12865e,
    "frw_dmac_msg_hook_unregister": 0x12874e,
    "frw_dmac_msg_hook_register": 0x128716,
    "hal_dev_fsm_destroy_rx_dscr": 0x12a1ca,
    "hal_dev_fsm_init_rx_dscr": 0x12a188,
    "hal_is_machw_enabled": 0x12f406,
    "hal_is_hw_rx_queue_empty": 0x13143e,
}
VENEERS = dict(zip(("control", "unregister", "register", "destroy", "init", "enabled", "empty"), ROM_TARGETS))
EDGES = [("__hisi_net0_rx_stop_handler", name, count) for name, count in (
    ("__hisi_net0_rom_destroy", 2),
    ("hal_disable_machw_phy_and_pa", 1),
    ("__hisi_net0_rom_enabled", 3),
    ("hal_chip_get_hal_device", 1),
    ("__hisi_net0_rom_empty", 1),
    ("frw_get_wifi_frw_task_id", 1),
    ("hmac_is_thruput_enable", 1),
    ("__hisi_net0_rx_rebuild_probe", 1),
)] + [("__hisi_net0_rx_rebuild_probe", name, count) for name, count in (
    ("__hisi_net0_rom_init", 1),
    ("__hisi_net0_rom_destroy", 1),
    ("__hisi_net0_rom_enabled", 4),
    ("hal_disable_machw_phy_and_pa", 1),
)]


def inspect(path):
    report = native_calls.inspect(path, EDGES)
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        table = elf.get_section_by_name(".symtab")
        report["veneers"] = []
        for suffix, target in VENEERS.items():
            name = "__hisi_net0_rom_" + suffix
            matches = table.get_symbol_by_name(name) or []
            targets = table.get_symbol_by_name(target) or []
            if (len(matches) != 1 or len(targets) != 1 or targets[0]["st_shndx"] != "SHN_ABS"
                    or targets[0]["st_value"] != ROM_TARGETS[target]):
                raise ValueError("missing veneer or changed ROM identity: " + name)
            symbol = matches[0]
            if symbol["st_size"] != 12 or not isinstance(symbol["st_shndx"], int):
                raise ValueError("expected fixed standard 12-byte veneer: " + name)
            section = elf.get_section(symbol["st_shndx"])
            offset = symbol["st_value"] - section["sh_addr"]
            first, second, third = struct.unpack_from("<III", section.data(), offset)
            if first & 0xfff != 0x2b7 or second & 0xfffff != 0x28293 or third != 0x28067:
                raise ValueError("expected LUI/ADDI/JR through t0: " + name)
            address = (native_calls.signed(first & 0xfffff000, 32)
                       + native_calls.signed(second >> 20, 12)) & 0xffffffff
            if address != ROM_TARGETS[target]:
                raise ValueError("incorrect resolved absolute ROM call: " + name)
            report["veneers"].append({"name": name, "target": target, "target_address": address,
                                       "file_offset": section["sh_offset"] + offset, "bytes": 12})
        matches = table.get_symbol_by_name("__hisi_net0_rx_stop_transaction") or []
        if len(matches) != 1 or matches[0]["st_info"]["type"] != "STT_OBJECT":
            raise ValueError("missing/ambiguous RX stop transaction")
        symbol = matches[0]
        if not isinstance(symbol["st_shndx"], int) or symbol["st_size"] != 112:
            raise ValueError("RX stop/rebuild/timing metadata differs from its reviewed 112-byte budget")
        section = elf.get_section(symbol["st_shndx"])
        offset = symbol["st_value"] - section["sh_addr"]
        if section["sh_flags"] & 3 != 3 or offset < 0 or offset + symbol["st_size"] > section["sh_size"]:
            raise ValueError("transaction must occupy physical writable memory")
        report["metadata"] = {"bytes": symbol["st_size"], "address": symbol["st_value"],
                              "section": section.name, "packet_payload_bytes": 0}
    report.update(schema="net0-rx-stop-link/v4",
                  boundary="Resolved stop/rebuild/cleanup ROM calls only. Runtime allocation counts and context need HIL; no DMA/host RX queue fence claim")
    return report


def tamper(path):
    report = inspect(path)
    rejected = native_calls.tamper(path, EDGES)
    original = path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="rx-stop-link-") as directory:
        candidate = Path(directory) / "mutated.elf"
        for veneer in report["veneers"]:
            data = bytearray(original)
            data[veneer["file_offset"] + 2] ^= 1
            candidate.write_bytes(data)
            try:
                inspect(candidate)
            except ValueError:
                rejected += 1
                continue
            raise ValueError("wrong-address veneer accepted: " + veneer["name"])
    return rejected


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--tamper-test", action="store_true")
    args = parser.parse_args()
    report = inspect(args.elf)
    if args.tamper_test:
        report["rejected_call_and_address_mutations"] = tamper(args.elf)
    content = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(content)
    print(content, end="")
