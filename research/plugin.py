#!/usr/bin/env python3
"""The FCDEXE1138 loader: the memory-card upgrade runs unauthenticated code.

Every Xplorer/Xploder PSX firmware can upgrade itself from a memory card - the
V2 menu says "Press @s to upgrade via Memory Card.", FX has "Upgrade Via
Memory-Card", the Pro builds call it a "Memory Card Plugin".  The routine behind
it opens the save `bu00:FCDEXE1138`, reads it into RAM, and `jalr`s into it -
with no signature, checksum or magic-byte check of any kind.  It is present in
both hardware generations, all three languages, and every release from 2.004
(1998) to 4.52.  See PLUGIN.md.

The loader reads its parameters out of the save's title frame:

    file offset 0x03   block count; size = byte << 13  (psx-spx: "Block
                       Number ... Uh?" - FCD's reading, not a settled field)
    file offset 0x44   load address = entry point  (title-frame reserved area)
    file offset 0x200  payload  (right after the title frame + 3 icon frames)

It reads the first 0x200 bytes to a scratch buffer, seeks to file offset 0x200,
reads (blocks * 0x2000 - 0x200) bytes to [load address] and jumps there.  What
the name means is not recorded anywhere; "FCD executable" and a THX-1138 joke
are guesses.

This script checks the loader in every image from the bytes, by finding the one
reference to the filename string and walking the routine:

  * every call is identified by the BIOS function number in its thunk
    (`addiu $t0, 0xB0; jr $t0; addiu $t1, N`), not by its argument shape;
  * the header read is the B(34h) FileRead with length 0x200, and its
    destination is the header buffer;
  * the load-address stack slot sits 0x44 past that buffer, and the size byte
    (blocks, << 0xd, less 0x200) 0x03 past it;
  * the B(33h) FileSeek after it goes to offset 0x200 from the start of file;
  * the body is read to the address loaded from the 0x44 slot, and a jalr on
    that same slot follows;
  * the path from the body read to that jalr is straight-line - no branch
    inspects the bytes before they run.  Calls in that window (close, free, the
    Pro/FX screen updates) are allowed, and their callees are not checked.

Run from research/:  uv run --with capstone python plugin.py
"""
import os
import tempfile

import fwimage
import mipscan

NAME = b'bu00:FCDEXE1138'

# offsets the loader reads out of the memory-card file's first block
OFF_LOADADDR = 0x44   # 32-bit load address == entry point
OFF_SIZE = 0x03       # block count; size = byte << 13
HEADER = 0x200        # the header read, and the file offset of the payload

# the BIOS functions the routine calls, as (dispatch table, function number)
FILE_OPEN, FILE_SEEK, FILE_READ = (0xB0, 0x32), (0xB0, 0x33), (0xB0, 0x34)

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
CALLS = ('jal', 'jalr')


def dis_image(path):
    raw = open(path, "rb").read()
    if raw.find(b"COMP01") < 0 and fwimage.fx_blob(raw) is None:
        import fcdcrypt
        raw = fcdcrypt.decrypt(bytearray(raw))
        tf = tempfile.NamedTemporaryFile(suffix=".dec", delete=False)
        tf.write(raw); tf.close()
        img, base = fwimage.load(tf.name)
        os.unlink(tf.name)
    else:
        img, base = fwimage.load(path)
    return img, base, mipscan.dis(img, base)


def find_string_addr(path, img, base, needle):
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
    """`$s0, 0x54($sp)` -> 0x54, else None."""
    if op_str.endswith('($sp)'):
        return int(op_str.rsplit(', ', 1)[-1].split('(')[0], 0)
    return None


def thunk(ins, base, target):
    """(table, function) of the BIOS thunk at `target`, or None."""
    k = (target - base) // 4
    if not 0 <= k < len(ins) - 2:
        return None
    t0, jr, t1 = ins[k:k + 3]
    if (t0.mnemonic == 'addiu' and t0.op_str.startswith('$t0, $zero, ')
            and jr.mnemonic == 'jr' and jr.op_str == '$t0'
            and t1.mnemonic == 'addiu' and t1.op_str.startswith('$t1, $zero, ')):
        return (int(t0.op_str.rsplit(', ', 1)[1], 0),
                int(t1.op_str.rsplit(', ', 1)[1], 0))
    return None


def args(ins, k):
    """What $a0-$a3 hold at the call ins[k]: {reg: (kind, value)}.

    The window is everything after the previous call's delay slot, plus this
    call's own delay slot, which runs last.  A branch does not end it - its
    delay slot runs on the fall-through path too.  Only the forms this routine
    uses are decoded; anything else reads as ('?', text)."""
    p = k - 1
    while p >= 0 and ins[p].mnemonic not in CALLS:
        p -= 1
    out = {}
    for x in ins[p + 2:k] + [ins[k + 1]]:
        ops = x.op_str.split(', ')
        if not ops or ops[0] not in ('$a0', '$a1', '$a2', '$a3'):
            continue
        if x.mnemonic == 'addiu' and ops[1] == '$zero':
            out[ops[0]] = ('imm', int(ops[2], 0))
        elif x.mnemonic == 'addiu' and ops[1] == '$sp':
            out[ops[0]] = ('sp', int(ops[2], 0))
        elif x.mnemonic == 'move' and ops[1] == '$zero':
            out[ops[0]] = ('imm', 0)
        elif x.mnemonic == 'move':
            out[ops[0]] = ('reg', ops[1])
        else:
            out[ops[0]] = ('?', x.mnemonic + ' ' + x.op_str)
    return out


def analyse(path):
    img, base, ins = dis_image(path)
    saddr = find_string_addr(path, img, base, NAME)
    xr = xrefs_to(ins, saddr)
    assert len(xr) == 1, '%s: expected 1 xref to filename, got %d' % (path, len(xr))
    start = xr[0]

    def bios_calls(lo, hi):
        """[(index, (table, function))] of the BIOS calls in ins[lo:hi]."""
        out = []
        for k in range(lo, min(hi, len(ins) - 1)):
            if ins[k].mnemonic == 'jal':
                t = thunk(ins, base, int(ins[k].op_str, 0))
                if t:
                    out.append((k, t))
        return out

    calls = bios_calls(start, start + 120)
    opens = [k for k, t in calls if t == FILE_OPEN]
    assert opens, '%s: no B(32h) FileOpen after the filename' % path

    # the header read: FileRead(fd, sp + H, 0x200).  H anchors the offsets.
    hdr = [(k, args(ins, k)) for k, t in calls if t == FILE_READ and k > opens[-1]]
    assert hdr, '%s: no B(34h) FileRead after the last open' % path
    hdr_read, a = hdr[0]
    assert a.get('$a2') == ('imm', HEADER), (
        '%s: header read length %r, not 0x%X' % (path, a.get('$a2'), HEADER))
    assert a.get('$a1', ('?',))[0] == 'sp', (
        '%s: header read into %r, not a stack buffer' % (path, a.get('$a1')))
    hdr_slot = a['$a1'][1]

    # the seek: FileSeek(fd, 0x200, SEEK_SET), so the body starts at 0x200
    seeks = [k for k, t in calls if t == FILE_SEEK and k > hdr_read]
    assert seeks, '%s: no B(33h) FileSeek after the header read' % path
    seek = seeks[0]
    a = args(ins, seek)
    assert a.get('$a1') == ('imm', HEADER) and a.get('$a2') == ('imm', 0), (
        '%s: FileSeek(%r, %r), not (0x%X, SEEK_SET)'
        % (path, a.get('$a1'), a.get('$a2'), HEADER))

    # the body read: FileRead(fd, [hdr + 0x44], (hdr[3] << 13) - 0x200)
    body = [k for k, t in calls if t == FILE_READ and k > seek]
    assert body, '%s: no B(34h) FileRead after the seek' % path
    body_read = body[0]
    a = args(ins, body_read)
    assert a.get('$a1', ('?',))[0] == 'reg', (
        '%s: body read destination %r' % (path, a.get('$a1')))
    reg = a['$a1'][1]
    dst_slot = None
    for k in range(body_read - 1, hdr_read, -1):
        if ins[k].mnemonic == 'lw' and ins[k].op_str.startswith(reg + ', '):
            dst_slot = slot_of(ins[k].op_str)
            break
    assert dst_slot == hdr_slot + OFF_LOADADDR, (
        '%s: body read to header+%r, not +0x%X' % (
            path, None if dst_slot is None else hex(dst_slot - hdr_slot), OFF_LOADADDR))
    size_slot = None
    for k in range(seek, body_read + 2):
        if ins[k].mnemonic == 'lbu':
            r = ins[k].op_str.split(', ')[0]
            if any(ins[b].mnemonic == 'sll' and ins[b].op_str == '%s, %s, 0xd' % (r, r)
                   for b in range(k + 1, min(k + 4, body_read + 2))):
                size_slot = slot_of(ins[k].op_str)
    assert size_slot == hdr_slot + OFF_SIZE, (
        '%s: block count at header+%r, not +0x%X' % (
            path, None if size_slot is None else hex(size_slot - hdr_slot), OFF_SIZE))
    assert ins[body_read + 1].op_str.endswith(', -0x200'), (
        '%s: body read length is not blocks << 13 less 0x200' % path)

    # the jalr that runs the loaded file: on a register just loaded from the
    # same 0x44 slot.
    jalr_idx = None
    for k in range(body_read, min(body_read + 40, len(ins))):
        if ins[k].mnemonic == 'jalr':
            r = ins[k].op_str.split(', ')[-1].strip()
            for b in range(k - 1, k - 5, -1):
                if ins[b].mnemonic == 'lw' and ins[b].op_str.startswith(r + ', '):
                    assert slot_of(ins[b].op_str) == hdr_slot + OFF_LOADADDR, (
                        '%s: jalr target from 0x%X($sp), not the load address'
                        % (path, slot_of(ins[b].op_str)))
                    jalr_idx = k
                    break
            break
    assert jalr_idx is not None, '%s: no jalr into the loaded buffer' % path

    # nothing between the body read and the jalr inspects the bytes
    branches = [ins[k].mnemonic for k in range(body_read, jalr_idx)
                if ins[k].mnemonic in BRANCHES]
    assert not branches, '%s: %d branch(es) between load and execute: %r' % (
        path, len(branches), branches)

    return {
        'entry_va': ins[jalr_idx].address,
        'gen': 'FX' if base >= 0x80000000 else 'V2',
        'hdr_slot': hdr_slot, 'size_slot': size_slot, 'load_slot': dst_slot,
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
        print('%-46s %-2s  loader jalr @ %08X  hdr sp+0x%02X  +0x%02X=load '
              '+0x%02X=size  seek 0x%X'
              % (os.path.basename(path), r['gen'], r['entry_va'], r['hdr_slot'],
                 r['load_slot'] - r['hdr_slot'], r['size_slot'] - r['hdr_slot'],
                 HEADER))
    print('\nFCDEXE1138 loader present in ALL %d image(s): %d V2, %d FX'
          % (len(present), v2, fx))
    if len(present) == len(CANDIDATES):
        assert v2 == 6 and fx == 4, 'expected 6 V2 + 4 FX, got %d + %d' % (v2, fx)
        print('all good: unauthenticated memory-card upgrade in every '
              'firmware, both generations')


if __name__ == '__main__':
    main()
