#!/usr/bin/env python3
"""Where does an Xplorer keep its cheat codes?

In the ROM, in every image, at the address the firmware's support module names.
The module sits at `*(u32 *)(ROM + 0x7C)` and its branch vector table at +0x80;
the table's slot +0x38 (+0xB8 from the module) is data, not a branch, and holds
the database address.  What is there differs by generation:

  V2 / Pro   the plain record chain, at the offset db2.find_db() finds by
             framing alone - two locators, one answer, in all six V2 images.
  FX         a container: two little-endian words (packed, unpacked), then the
             same record chain, LZW-compressed.

The FX codec is LZW with fixed 14-bit codes packed MSB first, literals 0-255,
the first free code 256, no clear code - the dictionary just stops growing at
0x3FFE - and 0x3FFF to end the stream.  Read out of `english.dec`:

  0x80030C08  the getter:  lw $v0, 0x7C(0x1F000000); lw $v0, 0xB8($v0)
  0x80031008  the packed size, word 0 of the container
  0x80030B6C  load: copy the container out of flash, malloc(unpacked + 0x2000),
              decompress, free
  0x80030C38  save: store FF FF FF FF after the chain, compress, write it back
              behind a fresh (packed, unpacked) header
  0x80025E80  the decompressor.  It allocates 2 x 0x119E4, 0x4679 and 0xFA0
              bytes - 18041 four-byte codes, 18041 suffix bytes and a 4000-byte
              decode stack, the table sizes of Mark Nelson's 1989 LZW at 14
              bits - and decodes from container + 8.

So the unpacked database is the V2 record chain, terminator included, and
db2.parse_db() reads it unchanged.  This file decodes all four FX containers
with its own decoder, then *executes* the firmware's own decompressor out of
each image under fwemu.py and requires the two to agree byte for byte.

This file used to say the opposite: that no FX dump holds a database, because
the firmware names flash pages 0x7F000 and 0x80000, past the end of every dump.
Those pages are real - `0x8003BB20` in english.dec puts a descriptor at
0x1F07FFF8 and sizes a region up to 0x1F080000 - but the region starts at
`(container + 0x100 + packed) & 0xFFFFFF`: it is the free flash *above* the
shipped database, not the database.  A survey of `lui` immediates cannot see
the database itself, because the firmware reaches it through the module's
pointer slot and never builds its address.

The FX English 3.20 and 4.52 databases also carry the default-off hazard of
ENGINE.md 7, under defaultoff.py's rule: a dispatched code row that keeps bit 3
of byte 0 through decryption, carries no key bits, and is of a type whose
address the engine dereferences (3, 7, 8).  112 rows in each - nearly as many
as Pro 2.20's 120, which the notes used to treat as the only database with them.

    uv run --with capstone python fxdb.py
"""
import collections
import glob
import hashlib
import os
import struct
import sys

import db2
import dbtypes
import defaultoff
import fcdcrypt

ROMS = sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))
TENTH = os.path.join('pc', 'ROMS', 'Xteng.fcd')

MODULE_PTR = 0x7C               # *(u32 *)(ROM + 0x7C) = the support module
DB_SLOT = 0x80 + 0x38           # vector table +0x38: the database address

BITS = 14
FIRST = 0x100
END = (1 << BITS) - 1           # 0x3FFF

# addiu $a0, $zero, 0x4679 - the suffix-table allocation, once per FX image
SUFFIX_ALLOC = 0x24044679


# ------------------------------------------------------------------ expected

# image -> (database offset, game records, distinct names of the games with
#           cheats, empty records, cheats, code lines)
EXPECT_CHAINS = {
    'xteng.dec': (0x25000, 285, 285, 0, 2130, 3060),
    'xtepro.dec': (0x2B000, 285, 285, 0, 2134, 3082),
    'xtger.dec': (0x25000, 240, 240, 0, 1787, 2476),
    'xtjpro.dec': (0x2B000, 61, 61, 0, 1619, 1826),
    'Xploder V2 (USA) r2.004 1998-11-13 [!].rom':
        (0x25000, 252, 250, 0, 4048, 4905),
    'Xteng.fcd': (0x25000, 234, 233, 1, 1668, 2365),
    'english.dec': (0x44400, 265, 264, 0, 1922, 2825),
    'english-452.dec': (0x4FA00, 264, 263, 0, 1921, 2823),
    'v452d.rom': (0x40300, 264, 263, 0, 1921, 2823),
    'german-450.dec': (0x41200, 269, 264, 5, 2071, 2957),
}

# FX container: image -> (packed, unpacked, sha256 of the unpacked chain).  The
# two 4.52 dumps hold the same database.
EXPECT_FX = {
    'english.dec': (0x90C7, 0xCC34, '035a29ccc7d5'),
    'english-452.dec': (0x909D, 0xCC06, '1f0d73edcb6d'),
    'v452d.rom': (0x909D, 0xCC06, '1f0d73edcb6d'),
    'german-450.dec': (0x993D, 0xDE5F, '6b34b5c6b9ed'),
}

# defaultoff.py's three counts over each FX database: rows keeping bit 3,
# those with no key bits, those of an addressed type
EXPECT_DEFAULT_OFF = {
    'english.dec': (113, 113, 112),
    'english-452.dec': (112, 112, 112),
    'v452d.rom': (112, 112, 112),
    'german-450.dec': (4, 1, 1),
}


# ---------------------------------------------------------------- the codec

def lzw_unpack(data):
    """14-bit MSB-first LZW, codes from 0x100, no clear code, 0x3FFF ends it."""
    out = bytearray()
    prefix, suffix = {}, {}
    acc = nbits = pos = 0

    def code():
        nonlocal acc, nbits, pos
        while nbits < BITS:
            if pos == len(data):
                raise ValueError('stream ends without the end code')
            acc = (acc << 8) | data[pos]
            pos += 1
            nbits += 8
        nbits -= BITS
        return (acc >> nbits) & END

    def string(c):
        s = bytearray()
        while c >= FIRST:
            s.append(suffix[c])
            c = prefix[c]
        s.append(c)
        return s[::-1]

    old = code()
    if old == END:
        return bytes(out)
    out.append(old)
    nxt = FIRST
    while True:
        new = code()
        if new == END:
            return bytes(out)
        if new < nxt:
            s = string(new)
        elif new == nxt:
            s = string(old) + string(old)[:1]
        else:
            raise ValueError('code 0x%X before it was defined' % new)
        out += s
        if nxt < END:                   # the last code assigned is 0x3FFE
            prefix[nxt], suffix[nxt] = old, s[0]
            nxt += 1
        old = new


def module_slot(raw):
    """(support module offset, the database pointer it holds)."""
    module = struct.unpack_from('<I', raw, MODULE_PTR)[0] & 0xFFFFFF
    return module, struct.unpack_from('<I', raw, module + DB_SLOT)[0]


def container(raw, ptr):
    """(offset, packed, unpacked, unpacked bytes) of an FX database container."""
    off = ptr & 0xFFFFFF
    packed, unpacked = struct.unpack_from('<II', raw, off)
    return off, packed, unpacked, lzw_unpack(raw[off + 8:off + 8 + packed])


# ---------------------------------------------- the firmware's own decoder

HEAP, SRC, DST = 0x80200000, 0x80300000, 0x80340000
LOAD = 0x1D4C0                  # what 0x80030B6C copies out of flash


def firmware_unpack(path, raw, off, unpacked):
    """Run the image's own decompressor over its container.

    Found by its suffix-table allocation rather than by address; the routine
    starts at the stack frame above it.  malloc is the call that allocation
    sits in the delay slot of, and is answered from a bump heap; free is the
    other callee the routine calls four times, and does nothing.  Everything
    else - memset, the decode loop - runs as the firmware's own code."""
    import fwemu                # capstone, which the codec above does not need
    import fwimage

    img, base = fwimage.load(path)
    words = struct.unpack('<%dI' % (len(img) // 4), img[:len(img) & ~3])
    at = [i for i, w in enumerate(words) if w == SUFFIX_ALLOC]
    if len(at) != 1:
        raise ValueError('%d suffix-table allocations' % len(at))
    i = at[0]
    entry = next(base + 4 * j for j in range(i, 0, -1)
                 if words[j] >> 16 == 0x27BD and words[j] & 0x8000)
    jal = lambda w: (base & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
    malloc = jal(words[i - 1])
    body = words[(entry - base) // 4:i + 64]
    calls = collections.Counter(jal(w) for w in body if w >> 26 == 3)
    free = next(t for t, n in calls.items() if n == 4 and t != malloc)

    mem = fwemu.Mem()
    mem.map(base, img)
    mem.map(base + len(img), bytes(0x80100000 - base - len(img)))   # .bss
    mem.map(HEAP, bytes(0x80000))
    # the load path copies a fixed 0x1D4C0 bytes out of flash, and the decoder
    # reads a little past the end of the stream: give it the same window
    mem.map(SRC, raw[off:off + LOAD].ljust(LOAD, b'\xff'))
    mem.map(DST, bytes(unpacked + 0x2000))
    mem.map(fwemu.RAM, bytes(0x100000))                             # stack
    top = [HEAP]

    def bump(m, r):
        r[2], top[0] = top[0], (top[0] + r[4] + 15) & ~15

    def resolve(addr):
        return bump if addr == malloc else (fwemu.nop_stub if addr == free
                                            else None)

    # the loader hands it container - 2, and it starts reading at + 0xA
    r = fwemu.run(mem, entry, (SRC - 2, DST), resolve, limit=50000000)
    return entry, r[2], mem.read(DST, unpacked)


# ------------------------------------------------------------------- report

def census(chain):
    """(records, names, empty, cheats, lines, default-off counts)."""
    db = db2.parse_db(chain, 0)
    recs = db2.game_records(chain, 0)
    flagged = keyless = wrong = 0
    for _, _, lines in db:
        for _, c, role in dbtypes.walk(lines):
            if role != 'code' or not c[0] & defaultoff.FLAG:
                continue
            flagged += 1
            if not c[0] & 7:
                keyless += 1
                wrong += (c[0] >> 4) in defaultoff.ADDRESSED
    return (len(recs), len(set(g for g, _, _ in db)),
            sum(1 for _, _, n in recs if n == 0), len(db),
            sum(len(c[2]) for c in db), (flagged, keyless, wrong))


def main():
    problems = []
    images = [(p, open(p, 'rb').read()) for p in ROMS]
    if os.path.exists(TENTH):
        images.append((TENTH, fcdcrypt.decrypt(open(TENTH, 'rb').read())))
    seen = set()

    for path, raw in images:
        name = os.path.basename(path)
        seen.add(name)
        module, ptr = module_slot(raw)
        start, _ = db2.find_db(raw)
        print('%-42s module @0x%05X, slot +0x38 -> %08X'
              % (name[:42], module, ptr))

        if start is not None:
            chain, off = raw[start:], start
            print('   in-ROM record chain at 0x%05X (framing agrees: %s)'
                  % (start, start == ptr & 0xFFFFFF))
            if start != ptr & 0xFFFFFF:
                problems.append('%s: framing finds 0x%05X, the module names '
                                '0x%05X' % (name, start, ptr & 0xFFFFFF))
        else:
            off, packed, unpacked, chain = container(raw, ptr)
            digest = hashlib.sha256(chain).hexdigest()[:12]
            print('   LZW container at 0x%05X: packed 0x%X -> 0x%X, decoded '
                  '0x%X bytes, ends %s, sha256 %s'
                  % (off, packed, unpacked, len(chain), chain[-4:].hex(), digest))
            if len(chain) != unpacked or chain[-4:] != b'\xff' * 4:
                problems.append('%s: decoded 0x%X bytes ending %s, header says '
                                '0x%X ending ffffffff'
                                % (name, len(chain), chain[-4:].hex(), unpacked))
            if (packed, unpacked, digest) != EXPECT_FX.get(name):
                problems.append('%s: container (0x%X, 0x%X, %s), expected %s'
                                % (name, packed, unpacked, digest,
                                   EXPECT_FX.get(name)))
            entry, ret, out = firmware_unpack(path, raw, off, unpacked)
            print('   the firmware\'s decompressor @%08X returns 0x%X, output '
                  '%s' % (entry, ret, 'identical' if out == chain else 'DIFFERS'))
            if out != chain or ret != unpacked:
                problems.append('%s: the firmware decodes 0x%X bytes, %s ours'
                                % (name, ret, 'same as' if out == chain
                                   else 'different from'))

        try:
            recs, names, empty, cheats, lines, dflt = census(chain)
        except ValueError as e:
            problems.append('%s: the database does not parse as a record '
                            'chain (%s)' % (name, e))
            print()
            continue
        print('   %d game records (%d names, %d empty), %d cheats, %d code lines'
              % (recs, names, empty, cheats, lines))
        got = (off, recs, names, empty, cheats, lines)
        if got != EXPECT_CHAINS.get(name):
            problems.append('%s: %s, expected %s'
                            % (name, got, EXPECT_CHAINS.get(name)))
        if name in EXPECT_DEFAULT_OFF:
            print('   default-off: %d rows keep bit 3, %d of them keyless, %d at '
                  'an addressed type' % dflt)
            if dflt != EXPECT_DEFAULT_OFF[name]:
                problems.append('%s: default-off %s, expected %s'
                                % (name, dflt, EXPECT_DEFAULT_OFF[name]))
        print()

    missing = sorted(set(EXPECT_CHAINS) - seen)
    if missing:
        print('skipped, not present: %s' % ', '.join(missing))
    fx = [n for n in EXPECT_FX if n in seen]
    if not fx:
        problems.append('no FX image in roms/ - nothing decoded')

    for p in problems:
        print('\n   ' + p)
    print('\n%s' % ('every image keeps its database where its module points; '
                    '%d FX container(s) decoded, by us and by the firmware'
                    % len(fx) if not problems
                    else '%d expectation(s) not met - not a pass' % len(problems)))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
