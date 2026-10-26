#!/usr/bin/env python3
"""The FCDEXE1138 loader: unauthenticated code execution from a memory card.

Every Xplorer/Xploder PSX firmware carries a routine that opens a PlayStation
memory-card save named `bu00:FCDEXE1138`, reads it into RAM, and `jalr`s into
it - with no signature, checksum or magic-byte check of any kind. It is a
homebrew / arbitrary-code entry point baked into the cartridge, present in both
hardware generations, all three languages, and every release from 2.004 (1998)
to 4.52.

The on-card file is a normally-formed PSX save whose title frame carries the
loader's parameters in bytes the console ignores:

    file offset 0x03   block count      (standard PSX title-frame field)
    file offset 0x44   load address = entry point  (title-frame reserved area)
    file offset 0x200  payload          (right after title frame + 3 icon frames)

The loader reads the first 0x200 bytes (header + icon frames) to a scratch
buffer, then reads (blocks * 0x2000 - 0x200) bytes to [load address] and jumps
there.  `1138` is the THX-1138 in-joke; `FCDEXE` is "FCD executable".

This script proves the loader is present and unconditional in every image, by
finding the one reference to the filename string and walking the routine:

  * the load-address stack slot sits 0x44 past the first-read buffer,
  * the size byte sits 0x03 past it (blocks, << 0xd),
  * a jalr into the load buffer follows, and
  * the path from the final read to that jalr is straight-line - no branch
    inspects the bytes before they run.

Run from research/:  uv run --with capstone python plugin.py
"""
import glob
import os
import struct
import sys

import fwimage
import mipscan

NAME = b'bu00:FCDEXE1138'

# offsets the loader reads out of the memory-card file's first block
OFF_LOADADDR = 0x44   # 32-bit load address == entry point
OFF_SIZE = 0x03       # block count; size = byte << 13

# the ten images: nine audited firmwares plus release 2.005, bundled with the
# vendor's own X-Link and never counted by the rest of the research.
CANDIDATES = [
    'roms/xteng.dec', 'roms/xtepro.dec', 'roms/xtjpro.dec', 'roms/xtger.dec',
    'roms/Xploder V2 (USA) r2.004 1998-11-13 [!].rom',
    'roms/english.dec', 'roms/german-450.dec', 'roms/english-452.dec',
    'roms/v452d.rom',
    'pc/ROMS/Xteng.fcd',
]

BRANCHES = ('beq', 'bne', 'beqz', 'bnez', 'blez', 'bgtz', 'bltz', 'bgez', 'b')


def dis_image(path):
    raw = open(path, "rb").read()
    if raw.find(b"COMP01") < 0 and fwimage.fx_blob(raw) is None:
        import fcdcrypt
        raw = fcdcrypt.decrypt(bytearray(raw))
        import tempfile
        tf = tempfile.NamedTemporaryFile(suffix=".dec", delete=False)
        tf.write(raw); tf.close()
        img, base = fwimage.load(tf.name)
        os.unlink(tf.name)
    else:
        img, base = fwimage.load(path)
    return img, base, mipscan.dis(img, base)


def find_string_addr(img, base, needle):
    i = img.find(needle)
    if i < 0:
        raise ValueError('%s: no %r' % (path, needle))
    return base + i


def xrefs_to(ins, target):
    """Indices of a lui/(addiu|ori) pair that materialises `target`."""
    out = []
    for i, x in enumerate(ins):
        if x.mnemonic != 'lui':
            continue
        try:
            reg, imm = x.op_str.split(', ')
        except ValueError:
            continue
        hi = int(imm, 0) & 0xFFFF
        for j in range(i + 1, min(i + 8, len(ins))):
            y = ins[j]
            if y.mnemonic in ('addiu', 'ori') and y.op_str.startswith(reg + ', ' + reg + ', '):
                lo = int(y.op_str.rsplit(', ', 1)[1], 0)
                val = (hi << 16) + (lo if y.mnemonic == 'addiu' else (lo & 0xFFFF))
                if (val & 0xFFFFFFFF) == target:
                    out.append(i)
                break
            if y.mnemonic == 'lui' and y.op_str.startswith(reg + ','):
                break
    return out


def slot_of(op_str):
    """`0x54($sp)` -> 0x54, else None."""
    if op_str.endswith('($sp)'):
        return int(op_str.rsplit(', ', 1)[-1].split('(')[0], 0)
    return None


def analyse(path):
    img, base, ins = dis_image(path)
    saddr = find_string_addr(img, base, NAME)
    xr = xrefs_to(ins, saddr)
    assert len(xr) == 1, '%s: expected 1 xref to filename, got %d' % (path, len(xr))
    start = xr[0]

    # the jalr that runs the loaded file: a jalr on a register just loaded from
    # a stack slot.  Take the first one after the filename reference.
    load_slot = jalr_idx = None
    for k in range(start, min(start + 120, len(ins))):
        if ins[k].mnemonic == 'jalr':
            reg = ins[k].op_str.split(', ')[-1] if ', ' in ins[k].op_str else ins[k].op_str
            reg = reg.strip()
            for b in range(k - 1, k - 5, -1):
                if ins[b].mnemonic == 'lw' and ins[b].op_str.startswith(reg + ', '):
                    load_slot = slot_of(ins[b].op_str)
                    jalr_idx = k
                    break
            if jalr_idx is not None:
                break
    assert jalr_idx is not None, '%s: no jalr-into-loaded-buffer found' % path
    assert load_slot is not None, '%s: entry register not loaded from stack' % path

    # the size byte: lbu <r>, N($sp) feeding an sll <r>,<r>,0xd
    size_slot = None
    for k in range(start, jalr_idx):
        if ins[k].mnemonic == 'lbu':
            s = slot_of(ins[k].op_str)
            r = ins[k].op_str.split(', ')[0]
            for b in range(k + 1, min(k + 4, jalr_idx)):
                if ins[b].mnemonic == 'sll' and ins[b].op_str == '%s, %s, 0xd' % (r, r):
                    size_slot = s
                    break
        if size_slot is not None:
            break
    assert size_slot is not None, '%s: no `blocks << 13` size computation' % path

    # the first-read scratch buffer: the read (a1=buffer, a2=0x200) whose
    # destination slot is (size_slot - 3).  Its slot anchors the offsets.
    hdr_slot = size_slot - OFF_SIZE
    assert load_slot - hdr_slot == OFF_LOADADDR, (
        '%s: load addr at file+0x%X, not 0x%X' % (path, load_slot - hdr_slot, OFF_LOADADDR))

    # the path from the final read to the jalr must be straight-line: nothing
    # inspects the bytes before they execute.  Find the last read (the payload
    # read into the load buffer) and scan to the jalr.
    last_read = None
    for k in range(start, jalr_idx):
        # payload read: a1 = the load buffer (moved from the slot), a2 = size-0x200
        if ins[k].mnemonic == 'addiu' and ins[k].op_str.endswith(', -0x200'):
            last_read = k
    assert last_read is not None, '%s: no `size - 0x200` payload read' % path
    branches = [ins[k].mnemonic for k in range(last_read, jalr_idx)
                if ins[k].mnemonic in BRANCHES]
    assert not branches, '%s: %d branch(es) between load and execute: %r' % (
        path, len(branches), branches)

    return {
        'entry_va': ins[jalr_idx].address,
        'gen': 'FX' if base >= 0x80000000 else 'V2',
        'hdr_slot': hdr_slot, 'size_slot': size_slot, 'load_slot': load_slot,
    }


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    os.chdir(here)
    present = [p for p in CANDIDATES if os.path.exists(p)]
    if not present:
        print('no firmware images present (roms/ and pc/ are gitignored) - '
              'nothing to check')
        return
    v2 = fx = 0
    for path in present:
        r = analyse(path)
        v2 += r['gen'] == 'V2'
        fx += r['gen'] == 'FX'
        print('%-46s %-2s  loader jalr @ %08X  hdr+0x%02X=load hdr+0x%02X=size'
              % (os.path.basename(path), r['gen'], r['entry_va'],
                 r['load_slot'] - r['hdr_slot'], r['size_slot'] - r['hdr_slot']))
    print('\nFCDEXE1138 loader present in ALL %d image(s): %d V2, %d FX'
          % (len(present), v2, fx))
    if len(present) == len(CANDIDATES):
        assert v2 == 6 and fx == 4, 'expected 6 V2 + 4 FX, got %d + %d' % (v2, fx)
        print('all good: unauthenticated memory-card code execution in every '
              'firmware, both generations')


if __name__ == '__main__':
    main()
