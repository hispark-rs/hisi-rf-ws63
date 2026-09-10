#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyelftools==0.32"]
# ///
"""Check the experimental RX descriptor hook and actual ROM patch routing."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile

from elftools.elf.elffile import ELFFile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('native_calls', Path(__file__).with_name('check-net0-cleanup.py'))
native_calls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_calls)

WRAPPER = '__wrap_hh503_rx_set_ctrl_dscr'
VENEER = '__hisi_net0_rom_rx_set_ctrl'
ROM = 'hh503_rx_set_ctrl_dscr'
EDGES = [('hh503_rx_alloc_netbuf_and_dscr_patch', WRAPPER, 1), (WRAPPER, VENEER, 1)]
PATCHES = {'hh503_rx_alloc_netbuf_and_dscr': 0x12c53c,
           'hal_rx_add_dscr': 0x12c63c, 'hal_rx_pre_add_dscr': 0x12c5de}


def inspect(path):
    report = native_calls.inspect(path, EDGES)
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        table = elf.get_section_by_name('.symtab')

        def symbol(name):
            values = table.get_symbol_by_name(name) or []
            if len(values) != 1:
                raise ValueError('missing/ambiguous symbol: ' + name)
            return values[0]

        def physical(name, size=None):
            item = symbol(name)
            if not isinstance(item['st_shndx'], int) or (size is not None and item['st_size'] != size):
                raise ValueError('invalid physical symbol: ' + name)
            section = elf.get_section(item['st_shndx'])
            offset = item['st_value'] - section['sh_addr']
            if offset < 0 or offset + item['st_size'] > section['sh_size']:
                raise ValueError('symbol outside section: ' + name)
            return item, section, offset

        rom = symbol(ROM)
        if rom['st_shndx'] != 'SHN_ABS' or rom['st_value'] != 0x12c1f2:
            raise ValueError('RX descriptor ROM ABI changed')
        item, section, offset = physical(VENEER, 12)
        first, second, third = struct.unpack_from('<III', section.data(), offset)
        address = ((first & 0xfffff000) + native_calls.signed(second >> 20, 12)) & 0xffffffff
        if (first & 0xfff != 0x2b7 or second & 0xfffff != 0x28293
                or third != 0x28067 or address != rom['st_value']):
            raise ValueError('RX descriptor veneer does not forward to the original ROM')
        mutations = [section['sh_offset'] + offset + 2]
        report['veneer'] = {'target': ROM, 'address': address, 'bytes': 12}

        # The existing sys-generated 37-entry table, not a new ROM patch.
        patch = elf.get_section_by_name('.patch')
        if patch is None:
            raise ValueError('missing physical ROM patch section')
        remap_base = symbol('__rom_patch_begin__')['st_value']
        compare_base = symbol('__rom_patch_cmp_begin__')['st_value']
        remap_offset = remap_base - patch['sh_addr']
        compare_offset = compare_base - patch['sh_addr']
        if (remap_offset < 0 or compare_offset != remap_offset + 0x610
                or compare_offset + 0x318 > patch['sh_size']):
            raise ValueError('ROM patch table outside physical section')
        _, base, count = struct.unpack_from('<III', patch.data(), compare_offset)
        if base != remap_base or count != 37:
            raise ValueError('unexpected ROM patch base/count')
        originals = struct.unpack_from('<' + 'I' * count, patch.data(), compare_offset + 12)
        if len(set(originals)) != count:
            raise ValueError('duplicate ROM compare entry')
        report['patches'] = []
        for name, original in PATCHES.items():
            if originals.count(original | 1) != 1:
                raise ValueError('missing mandatory descriptor patch: ' + name)
            index = originals.index(original | 1)
            offset = remap_offset + (2 + index) * 8
            # Patch hardware supplies these instructions at the original ROM
            # PC. sys's CALL addend compensates for the storage-slot address.
            destinations = native_calls.calls(patch.data()[offset:offset + 8], original)
            replacement = symbol(name + '_patch')
            if destinations != [(original, replacement['st_value'])]:
                raise ValueError('wrong descriptor patch replacement: ' + name)
            report['patches'].append({'original': name, 'original_address': original,
                                      'replacement_address': replacement['st_value'], 'index': index})
            mutations.extend([patch['sh_offset'] + compare_offset + 12 + 4 * index, patch['sh_offset'] + offset])

        item, section, offset = physical('__hisi_net0_rx_origins', 368)
        if section['sh_flags'] & 3 != 3 or item['st_info']['type'] != 'STT_OBJECT':
            raise ValueError('origin metadata must occupy physical writable storage')
        report['metadata'] = {'bytes': item['st_size'], 'slots': 16,
                              'address': item['st_value'], 'section': section.name,
                              'packet_payload_bytes': 0}
        report['mutation_offsets'] = mutations
    report.update(schema='net0-rx-origin-link/v1',
                  boundary='Resolved pre-publication descriptor hook and ROM patch destinations only; coverage, pointer identity and generation propagation require HIL; no reconnect permission')
    return report


def tamper(path):
    report = inspect(path)
    rejected = native_calls.tamper(path, EDGES)
    original = path.read_bytes()
    with tempfile.TemporaryDirectory(prefix='rx-origin-link-') as directory:
        candidate = Path(directory) / 'changed.elf'
        for offset in report['mutation_offsets']:
            data = bytearray(original)
            data[offset] ^= 1
            candidate.write_bytes(data)
            try:
                inspect(candidate)
            except ValueError:
                rejected += 1
                continue
            raise ValueError('wrong descriptor hook/patch mutation was accepted')
    return rejected


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--tamper-test', action='store_true')
    args = parser.parse_args()
    result = inspect(args.elf)
    if args.tamper_test:
        result['rejected_mutations'] = tamper(args.elf)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')
