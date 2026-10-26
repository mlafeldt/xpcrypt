#!/usr/bin/env python3
"""How the shipped cheat databases actually use the sixteen code types.

Block-aware, which is the whole point: the rows following a Supercode (5),
Megacode (6) or inline data block (A) header are payload, and counting them as
codes of whatever type their first nibble happens to spell is exactly the mistake
this script exists to avoid.  ENGINE.md §8 has the table this produces.

Two things the numbers are not. They cover the complete record chain found in
each of the five ROMs, but that is still not proof that these are every database
ever shipped, so a zero means "none in this corpus". And a type 5 or 6 row
counts a *header*, well-formed or not: two of the 44 type 5 headers declare a
payload of zero bytes and one of the 11 type 6 headers declares 9,212 rows that
are not there.

    uv run python dbtypes.py             # per-type counts, one column per database
    uv run python dbtypes.py 5           # whole cheat entries that use type 5
    uv run python dbtypes.py C 20 xtjpro # ... at most 20, from one database
"""
import collections
import os
import sys

import db2
import romcrypt

ROMS = [
    ('xteng.dec', 'Xplorer 2.008 UK'),
    ('xtger.dec', 'Xplorer 2.0081 DE'),
    ('xtjpro.dec', 'Xplorer Pro 2.14 JP'),
    ('xtepro.dec', 'Xplorer Pro 2.20 UK'),
    ('Xploder V2 (USA) r2.004 1998-11-13 [!].rom', 'Xploder V2 2.004 US'),
]


def fmt(c):
    return '%02X%02X%02X%02X %02X%02X' % tuple(c)


def block(c):
    """(payload key, payload rows) for a block header, or None.

    Follows xp_parse_block(): a Supercode of declared size 0 is not a block, and
    a Megacode's byte count does not include its 10-byte breakpoint descriptor.
    That first rule is about reading a *stream* of codes, where the line below a
    size-0 header really is an ordinary code.  The cartridge does not agree: it
    stages the header anyway and its engine then hangs (ENGINE.md §7).
    """
    t = c[0] >> 4
    if t == 5:
        n = ((c[4] & 0xF) << 8) | c[5]
        return None if n < 1 else (c[4] >> 4, (n + 5) // 6)
    if t == 6:
        return c[3] & 0xF, (((c[4] << 8) | c[5]) + 10 + 5) // 6
    return None


def walk(lines):
    """[(index, six decrypted bytes, role), ...] for one cheat entry.

    Role is 'code' for a line the engine dispatches on, 'data-N' for a payload
    row of a type N block.
    """
    out, i = [], 0
    while i < len(lines):
        c = romcrypt.decrypt(list(lines[i]))
        t = c[0] >> 4
        out.append((i, c, 'code'))
        if t == 0xA:                    # runs to the end of the cheat entry
            out += [(j, list(lines[j]), 'data-A') for j in range(i + 1, len(lines))]
            return out
        b = block(c)
        if b is None:
            i += 1
            continue
        key, rows = b
        for j in range(i + 1, min(len(lines), i + rows + 1)):
            p = list(lines[j])
            if key in (6, 7):
                p = romcrypt.decrypt(p, key)
            out.append((j, p, 'data-%X' % t))
        i += rows + 1
    return out


def databases():
    for fn, label in ROMS:
        rom = open(os.path.join('roms', fn), 'rb').read()
        _, db = db2.find_db(rom)
        yield label, db


# The published table's total column (ENGINE.md 8), by type nibble 0 to F.  The
# Makefile only prints this table, and a printed table nobody compares against
# is not a check - so the totals are a condition of exit status 0.  Types 2, A
# and E are shipped by none of the five recovered chains; that zero is a result,
# not a placeholder, and moving it would be news.  These are *stored* types.  The
# console sees others: staging turns every odd-address type 3 or 8 into an E and
# every C0 and unhoisted D0 into a 7 (ENGINE.md 13), which this does not model.
EXPECT_TOTALS = [1, 134, 0, 2988, 6, 44, 11, 589,
                 10689, 43, 0, 159, 27, 3, 0, 245]


def counts():
    tot, per = collections.Counter(), {}
    for label, db in databases():
        c = collections.Counter()
        for _, _, lines in db:
            for _, code, role in walk(lines):
                if role == 'code':
                    c[code[0] >> 4] += 1
                    tot[code[0] >> 4] += 1
        per[label] = c
    labels = [l for _, l in ROMS]
    print('type ' + ' '.join('%-20s' % l for l in labels) + ' total')
    for t in range(16):
        print(' %X   ' % t + ' '.join('%-20d' % per[l][t] for l in labels) +
              ' %d' % tot[t])

    if len(per) != len(ROMS):
        print('   %d database(s) recovered, expected %d' % (len(per), len(ROMS)))
        return 1
    got = [tot[t] for t in range(16)]
    if got != EXPECT_TOTALS:
        print('   totals %s' % got)
        print('   expected %s' % EXPECT_TOTALS)
        return 1
    return 0


def specimens(want, limit, sub):
    n = 0
    for label, db in databases():
        if sub and sub not in label and not any(sub in fn for fn, l in ROMS if l == label):
            continue
        for game, cheat, lines in db:
            w = walk(lines)
            if not any(r == 'code' and c[0] >> 4 == want for _, c, r in w):
                continue
            n += 1
            if n > limit:
                return
            print('%s | %s | %s' % (label, game, cheat))
            for i, c, r in w:
                print('    %s   %-7s  stored %s' % (fmt(c), r, fmt(lines[i])))
            print()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        specimens(int(sys.argv[1], 16),
                  int(sys.argv[2]) if len(sys.argv) > 2 else 8,
                  sys.argv[3] if len(sys.argv) > 3 else '')
    else:
        sys.exit(counts())
