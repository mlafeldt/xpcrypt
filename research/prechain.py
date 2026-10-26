#!/usr/bin/env python3
"""What is in front of the cheat-database record chains.

ENGINE.md 16 listed this as open: `db2.find_db()` returns the chain it can
parse, every count in 8 and 14 is over what was recovered, and nobody had said
what the bytes before the chain are.  This script says, for all nine images.

**They are not cheat data.**  The gap between the end of the packed firmware
stream and the first record is, in every V2/Pro image, exactly four kinds of
thing and nothing else:

  * `pad`       0 to 5 zero bytes rounding the packed stream up to a word;
  * `erased`    0xFF, unwritten flash;
  * `banner`    + `module`, the cartridge-resident support module - the one
                `*(u32 *)0x7C` names (ENGINE.md 9).  Its first 0x40 bytes are
                the ASCII release banner and build stamp that made this region
                look like "printable game data"; its body starts at +0x80 with
                the branch vector table;
  * `inplace`   on the two Pro builds only, an uncompressed code block appended
                straight after the packed stream.  In `xtjpro.dec` it holds the
                code engine itself at 0x22B20 (ENGINE.md 10).

plus one specimen of deleted-but-not-erased flash: `xtjpro.dec` carries, at the
Pro patch-list base 0x24600, the factory canary

    "This is only used for checking that the workspace is not used!"

and 0x5C0 zero bytes after it.  No other image has it.

So of the five hypotheses the region could have been - an older record chain, a
second record format, an index, deleted flash from a previous upload, or
something else - it is *something else*, with a one-pointer index inside it:
the support module's vector table holds the chain's address at +0x38, and that
pointer equals the offset `db2.find_db()` derives from framing alone in all
five images.  Two independent locators, same answer, so nothing is missing in
front.  Two harder checks agree: none of the 10,054 distinct game and cheat
names of the five recovered chains occurs anywhere below the chain start, and
no second framed chain parses there either.

The four FX images have no in-ROM chain, and the same +0x38 slot says where
their database is instead: at the next 0x100 boundary after the firmware blob,
behind an 8-byte header of two little-endian words, `(packed, unpacked)`.  The
packed word runs to the last live byte in all four dumps - so the shipped FX
database *is* in these files, entire, contrary to FINDINGS.md 6.3, which ruled
on the flash region at the top of the window and read the first 0x8F bytes of
this one (leftover resource bytes; the ones in english-452.dec read as x86) as the whole
tail.  What compresses it is not decoded here: it is not COMP01, not COMP01
under the FX descrambler, and not a byte-aligned or bit-flagged LZSS in any of
the 336 shapes tried.  The container is asserted below; the contents are not.

    uv run python prechain.py
"""
import glob
import re
import struct
import sys

import comp01
import db2
import fxunp

# The support module's branch vector table sits at base + 0x80 and its ninth
# slot is data, not a branch: the address of the cheat database (ENGINE.md 9).
VECTORS = 0x80
DB_SLOT = 0x38

BANNER = re.compile(rb'\((C)\) [0-9/\-]+ FCD[\t ]+release ([0-9.]+(?: PRO)?)')
STAMP = re.compile(rb'\A[0-3][0-9]/[01][0-9]/[12][90][0-9][0-9]-[0-2][0-9]:[0-5][0-9]')

WORKSPACE = b'This is only used for checking that the workspace is not used!'

# Patch-list bases, ENGINE.md 2.  A live region starting at one of these is the
# workspace, not code.
LIST_BASES = (0x22600, 0x24600)

MIN_ERASED = 16          # shorter 0xFF runs are data that happens to be 0xFF


# ------------------------------------------------------------------ geometry

def firmware_end(raw):
    """Offset one past the last byte of the packed firmware stream."""
    s = raw.find(b'COMP01')
    if s >= 0:
        return s + comp01.unpack(raw, s)[1]
    s = fxunp.blob_start(raw)
    if s is None:
        raise ValueError('no COMP01 stream, scrambled or otherwise')
    # descramble() skips the four bytes it is handed before decoding
    return s + comp01.unpack(fxunp.descramble(raw, s, len(raw)))[1] + 4


def last_live(raw):
    return max(i for i, b in enumerate(raw) if b != 0xFF) + 1


def regions(raw, lo, hi):
    """[(kind, start, end)] over [lo, hi), splitting on erased runs.

    A run of 0xFF shorter than MIN_ERASED stays part of the live region around
    it - 0xFF is a perfectly ordinary byte inside code and inside a name."""
    out, i = [], lo
    while i < hi:
        j = i
        while j < hi:
            if raw[j] == 0xFF:
                k = j
                while k < hi and raw[k] == 0xFF:
                    k += 1
                if k - j >= MIN_ERASED:
                    break
                j = k
            else:
                j += 1
        if j > i:
            out.append(('live', i, j))
        if j >= hi:
            break
        k = j
        while k < hi and raw[k] == 0xFF:
            k += 1
        out.append(('erased', j, k))
        i = k
    return out


def role(raw, start, end, base, blob_end):
    """Name one live region of the gap."""
    if start == base:
        return 'banner'
    if start == base + VECTORS:
        return 'module'
    if start in LIST_BASES and raw[start:start + len(WORKSPACE)] == WORKSPACE:
        return 'workspace'
    if start == blob_end and set(raw[start:end]) == {0}:
        return 'pad'
    return 'inplace'


# ------------------------------------------------------------------- probing

def names_below(raw, start):
    """Game and cheat names of the chain that also occur before it.

    Short names would collide with ordinary code by chance, so only names long
    enough to be evidence are searched: 4 bytes for a game, 6 for a cheat."""
    _, db = db2.find_db(raw)
    names, head = set(), raw[:start]
    for game, cheat, _ in db:
        for text, floor in ((game, 4), (cheat, 6)):
            b = text.encode('latin-1')
            if len(b) >= floor:
                names.add(b)
    return len(names), sorted(n for n in names if n in head)


def chains_below(raw, start):
    """Offsets below @start where a second framed record chain parses."""
    out = []
    for o in range(4, start):
        if raw[o - 4:o] != b'\xFF' * 4:
            continue
        try:
            db2.parse_db(raw, o)
        except (ValueError, IndexError):
            continue
        out.append(o)
    return out


def fx_blob(raw, blob_end, slot):
    """(header offset, packed, unpacked, end) for the FX database container."""
    off = slot & 0xFFFFFF
    packed, unpacked = struct.unpack_from('<II', raw, off)
    return off, packed, unpacked, off + 8 + packed


# ------------------------------------------------------------------ expected
#
# Offsets and lengths, as conditions rather than as output.  The gap inventory
# is the claim this file exists to make, so it is spelled out per image: a run
# that changed kind, moved or changed length would otherwise still print.

EXPECT_ROMS = 9

# image -> (release, support base, chain start or None, gap inventory)
# inventory entries are (kind/role, start, length).
EXPECT = {
    'Xploder V2 (USA) r2.004 1998-11-13 [!].rom': ('2.004', 0x23000, 0x25000, [
        ('erased', 0x020F54, 8364),
        ('banner', 0x023000, 64),
        ('erased', 0x023040, 64),
        ('module', 0x023080, 3904),
        ('erased', 0x023FC0, 4160)]),
    'xteng.dec': ('2.008', 0x23000, 0x25000, [
        ('pad', 0x02164B, 5),
        ('erased', 0x021650, 6576),
        ('banner', 0x023000, 66),
        ('erased', 0x023042, 62),
        ('module', 0x023080, 3904),
        ('erased', 0x023FC0, 4160)]),
    'xtger.dec': ('2.0081', 0x23000, 0x25000, [
        ('pad', 0x021817, 5),
        ('erased', 0x02181C, 6116),
        ('banner', 0x023000, 66),
        ('erased', 0x023042, 62),
        ('module', 0x023080, 3904),
        ('erased', 0x023FC0, 4160)]),
    'xtjpro.dec': ('2.14 PRO', 0x25000, 0x2B000, [
        ('inplace', 0x022AD1, 1847),
        ('erased', 0x023208, 5112),
        ('workspace', 0x024600, 1536),
        ('erased', 0x024C00, 1024),
        ('banner', 0x025000, 64),
        ('erased', 0x025040, 64),
        ('module', 0x025080, 20812),
        ('erased', 0x02A1CC, 3636)]),
    'xtepro.dec': ('2.20 PRO', 0x25000, 0x2B000, [
        ('inplace', 0x022362, 3222),
        ('erased', 0x022FF8, 8200),
        ('banner', 0x025000, 64),
        ('erased', 0x025040, 64),
        ('module', 0x025080, 21180),
        ('erased', 0x02A33C, 3268)]),
    'english.dec': ('3.20 PRO', 0x1500, None, []),
    'german-450.dec': ('4.50 PRO', 0x1500, None, []),
    'english-452.dec': ('4.52 PRO', 0x1500, None, []),
    'v452d.rom': ('4.52 PRO', 0x1500, None, []),
}

# FX database container: image -> (header offset, packed, unpacked)
EXPECT_FX = {
    'english.dec': (0x044400, 0x90C7, 0xCC34),
    'german-450.dec': (0x041200, 0x993D, 0xDE5F),
    'english-452.dec': (0x04FA00, 0x909D, 0xCC06),
    'v452d.rom': (0x040300, 0x909D, 0xCC06),
}

# Names searched for below the chain, summed over the five V2/Pro images, and
# how many were found there.  The second number is the finding.
EXPECT_NAMES = 10054
EXPECT_NAMES_BELOW = 0
EXPECT_CHAINS_BELOW = 0


def main():
    problems = []
    roms = sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))
    if len(roms) != EXPECT_ROMS:
        problems.append('%d image(s) in roms/, expected %d - the inventory '
                        'below is for that corpus' % (len(roms), EXPECT_ROMS))

    names_total = names_found = chains_found = 0
    for path in roms:
        name = path.split('/')[-1]
        raw = open(path, 'rb').read()
        blob_end = firmware_end(raw)
        base = struct.unpack_from('<I', raw, 0x7C)[0] & 0xFFFFFF
        slot = struct.unpack_from('<I', raw, base + VECTORS + DB_SLOT)[0]
        start, _ = db2.find_db(raw)

        m = BANNER.match(raw, base)
        release = m.group(2).decode() if m else None
        stamp = raw[base + 0x20:base + 0x30]
        print('%-42s 0x%06X  module @0x%05X release %-8s built %s'
              % (name, len(raw), base, release, stamp.decode('latin-1')))
        print('     vector table +0x38 -> %08X   record chain %s'
              % (slot, '0x%05X' % start if start else 'none in this image'))

        want_release, want_base, want_start, want_gap = EXPECT[name]
        if release != want_release:
            problems.append('%s: release %r, expected %r'
                            % (name, release, want_release))
        if not STAMP.match(stamp):
            problems.append('%s: build stamp %r is not dd/mm/yyyy-hh:mm'
                            % (name, stamp))
        if base != want_base:
            problems.append('%s: support module at 0x%X, expected 0x%X'
                            % (name, base, want_base))
        if start != want_start:
            problems.append('%s: chain at %s, expected %s'
                            % (name, start, want_start))

        if start is not None:
            # the two locators have to agree: framing (db2) and the pointer the
            # firmware itself follows.  That is what settles "nothing in front".
            if slot & 0xFFFFFF != start:
                problems.append('%s: module names 0x%06X as the database, '
                                'framing finds the chain at 0x%06X'
                                % (name, slot & 0xFFFFFF, start))

            gap = [(role(raw, a, b, base, blob_end) if k == 'live' else k, a, b - a)
                   for k, a, b in regions(raw, blob_end, start)]
            print('     firmware blob ends 0x%06X, %d bytes to the chain:'
                  % (blob_end, start - blob_end))
            for kind, a, n in gap:
                print('        %-9s 0x%06X  %7d' % (kind, a, n))
            if sum(n for _, _, n in gap) != start - blob_end:
                problems.append('%s: the inventory does not cover the gap' % name)
            if gap != want_gap:
                problems.append('%s: gap inventory %s, expected %s'
                                % (name, gap, want_gap))

            total, below = names_below(raw, start)
            found = chains_below(raw, start)
            names_total += total
            names_found += len(below)
            chains_found += len(found)
            print('     %d distinct chain names, %d of them below the chain %s'
                  % (total, len(below), below[:3]))
            print('     %d further framed chains below it %s'
                  % (len(found), ['0x%06X' % o for o in found[:3]]))
        else:
            off, packed, unpacked, end = fx_blob(raw, blob_end, slot)
            live = last_live(raw)
            aligned = (blob_end + 0xFF) & ~0xFF
            print('     firmware blob ends 0x%06X -> database container '
                  '0x%06X  packed 0x%X unpacked 0x%X, data ends 0x%06X'
                  % (blob_end, off, packed, unpacked, end))
            print('        %s past the container, last live byte 0x%06X'
                  % ('zero padding' if end < live else 'nothing', live))
            if (off, packed, unpacked) != EXPECT_FX[name]:
                problems.append('%s: container (0x%06X, 0x%X, 0x%X), expected '
                                '(0x%06X, 0x%X, 0x%X)'
                                % ((name, off, packed, unpacked) + EXPECT_FX[name]))
            if off != aligned:
                problems.append('%s: container at 0x%06X, not the 0x100 '
                                'boundary 0x%06X after the firmware'
                                % (name, off, aligned))
            if not end <= live or any(raw[end:live]):
                problems.append('%s: the container does not run to the end of '
                                'the written flash (0x%06X vs 0x%06X)'
                                % (name, end, live))
        print()

    print('across the five V2/Pro chains: %d distinct names, %d occur below a '
          'chain, %d second chains' % (names_total, names_found, chains_found))
    if names_total != EXPECT_NAMES:
        problems.append('%d distinct names, expected %d'
                        % (names_total, EXPECT_NAMES))
    if names_found != EXPECT_NAMES_BELOW:
        problems.append('%d name(s) below a chain, expected %d - there would '
                        'be cheat data in front after all'
                        % (names_found, EXPECT_NAMES_BELOW))
    if chains_found != EXPECT_CHAINS_BELOW:
        problems.append('%d framed chain(s) below a chain, expected %d'
                        % (chains_found, EXPECT_CHAINS_BELOW))

    for p in problems:
        print('\n   ' + p)
    print('\n%s' % ('nothing in front of any chain is cheat data'
                    if not problems
                    else '%d expectation(s) not met - not a pass' % len(problems)))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
