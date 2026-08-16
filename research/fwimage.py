#!/usr/bin/env python3
"""Unpack the firmware image out of any Xplorer/Xploder PSX ROM.

Two generations, one container:

  V2 (Xplorer 2.x / Xploder V2)  the ROM holds a plain COMP01 stream.
  FX (Xplorer FX V3.x / V4.x)    the same COMP01 stream, scrambled byte by byte
                                 first - see fxunp.descramble.

Nothing here is keyed on a file name: the generation is detected from the bytes
and the load address is read back out of the firmware - see base_of().

V2 firmwares address themselves through KUSEG (0x001Axxxx) and FX ones through
KSEG0 (0x8005xxxx); the base that comes back is the one the jump table is written
against, so its entries can be looked up in the image directly.
"""
import struct

import comp01
import fxunp
import mipscan

TABLES = b' WB123'


def fx_blob(raw):
    """Offset of the scrambled COMP01 stream, or None if this is a V2 ROM."""
    # the descrambler's first output byte is rol8(raw[s + 4] ^ 0x99, 2), and the
    # stream starts "COMP01" - so most offsets can be rejected on one byte
    for s in range(len(raw) - 24):
        v = (raw[s + 4] ^ 0x99) & 0xFF
        if ((v << 2) | (v >> 6)) & 0xFF != ord('C'):
            continue
        if fxunp.descramble(raw, s, s + 10)[:6] == b'COMP01':
            return s
    return None


def base_of(img):
    """Recover the address the firmware image was linked at.

    The dispatcher bounds-checks its jump-table index and branches to the
    default route when it does not fit:

        andi  $v0, $v0, 0xf7
        addiu $v1, $v0, -4
        sltiu $v0, $v1, 0xf4
        beqz  $v0, <default route>

    That branch target is also what the table holds for every code type with no
    route of its own, so disassembling at zero and subtracting gives the base
    outright.  (Counting lui/addiu pairs that name the constant tables looks
    like it would work too, and does for most ROMs - but the German V2 firmware
    carries two sets of them, one exactly 0x1000 apart from the other, and the
    vote ties.)"""
    t = img.find(TABLES)
    if t < 0:
        raise ValueError('no constant tables - not an Xplorer firmware?')
    table = [struct.unpack_from('<I', img, t + 24 + 4 * i)[0] for i in range(244)]

    ins = mipscan.dis(img, 0)                   # branch targets come out relative
    idx = next(i for i, x in enumerate(ins)
               if x.mnemonic == 'sltiu' and x.op_str.endswith('0xf4'))
    br = ins[idx + 1]
    if br.mnemonic not in ('beqz', 'beq'):
        raise ValueError('unexpected dispatcher shape: %s %s' % (br.mnemonic, br.op_str))
    default = int(br.op_str.rsplit(', ', 1)[1], 0)

    # 0x24: first byte of a type-2 code, which no firmware gives a route to
    base = (table[(0x24 & 0xF7) - 4] - default) & 0xFFFFFFFF
    if not all(base <= e < base + len(img) for e in table):
        raise ValueError('load address %08X leaves the jump table dangling' % base)
    return base


def load(path):
    """Return (unpacked firmware image, base address)."""
    raw = open(path, 'rb').read()
    s = raw.find(b'COMP01')
    if s >= 0:
        img, _ = comp01.unpack(raw, s)
    else:
        s = fx_blob(raw)
        if s is None:
            raise ValueError('%s: no COMP01 stream, scrambled or otherwise' % path)
        img, _ = comp01.unpack(fxunp.descramble(raw, s, len(raw)))
    return img, base_of(img)
