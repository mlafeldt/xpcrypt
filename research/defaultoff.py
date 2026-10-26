#!/usr/bin/env python3
"""The default-off bit in Xplorer Pro 2.20, and where else those codes appear.

ENGINE.md 7 and FINDINGS.md 7 rest on four counts from this database: how many
rows carry the bit after decryption, how many of those are stored with no key
bits, how many then reach the wrong address, and how many of those codes also
ship in another database without the bit. All 133 rows that carry it keep it
through decryption: 121 because they are stored with key bits 0, so the copy
route keeps byte 0, and 12 because they are type C, which has no route at all.
The first three are simple predicates. The fourth is a *matching* claim, and the
number it produces depends entirely on the rule, so the rule is here:

  a flagged Pro 2.20 row matches if the same six bytes, with bit 3 of byte 0
  cleared, occur as a dispatched code row in one of the other four recovered
  databases.

Block payload rows are not code rows and are excluded on both sides, which is
what dbtypes.walk() is for. The variants below are printed with it so that the
sensitivity of the headline number is visible rather than assumed.

  python3 defaultoff.py
"""
import collections
import os
import sys

import db2
import dbtypes

PRO220 = 'xtepro.dec'
FLAG = 0x08                     # "switched off by default"

# The two populations to search, because "the encrypted V2 databases" is
# ambiguous: Pro 2.14 stores none of its 1826 rows with key bits, and Pro 2.20
# itself stores only 191 of 3082 that way. Both are gated. "121 either way" is
# the published claim, so a pool that disagreed has to fail rather than be
# printed next to one that agreed.
ALL_FOUR = 'the other four databases'
ENCRYPTED = 'the three that ship encrypted'

# The published counts (ENGINE.md 7). The first three are what the notes always
# said. With the complete database chains, every one of the 121 keyless rows
# has an unflagged counterpart, whichever pool is searched.
EXPECT = {'flagged': 133, 'keyless': 121, 'wrong address': 120,
          'also shipped, ' + ALL_FOUR: 121,
          'also shipped, ' + ENCRYPTED: 121}
# Types whose address the engine dereferences for a store or a compare, so the
# surviving bit sends the operation 0x08000000 away.
ADDRESSED = (0x3, 0x7, 0x8)


def code_rows(path):
    """(dispatched code rows, how many rows are *stored* with key bits,
    the stored first byte of each dispatched row).

    Payload rows are not dispatched and are left out of the first and the
    third. The second reads the stored bytes, not the decrypted ones - after
    decryption the key bits are gone, and what is left set belongs to the types
    with no route.
    """
    _, db = db2.find_db(open(path, 'rb').read())
    if db is None:
        return [], 0, []
    out, keyed, stored = [], 0, []
    for _, _, lines in db:
        for i, c, role in dbtypes.walk(lines):
            if role == 'code':
                out.append(bytes(c))
                stored.append(lines[i][0])
        keyed += sum(1 for l in lines if l[0] & 7)
    return out, keyed, stored


def nibble(b):
    """What a dispatched row's stored low nibble says: key bits and off bit."""
    k, off = b & 7, b & FLAG
    name = {0: 'clear', 4: 'key 4', 6: 'key 6'}.get(k)
    if name is None or (off and k == 4):
        return 'other'
    return name + (' + off' if off else '')


# ENGINE.md 7's table of stored key nibbles, per database, over dispatched code
# rows.  It is what shows that Pro 2.20 is the first database to set the off bit
# on rows with no key - and that Pro 2.14 before it was already in the clear.
# "other" is everything that is neither clear nor key 4/6: 2.0081's F2 (key 2)
# line, its key 5 Megacode header and a CD; Pro 2.20's twelve CD lines; the USA
# database's 31001643 (key 1) and four CD.
EXPECT_NIBBLES = {
    'xteng.dec':   {'key 6': 2767, 'key 6 + off': 121},
    'xtger.dec':   {'key 6': 2371, 'key 6 + off': 66, 'other': 3},
    'xtjpro.dec':  {'clear': 1826},
    'xtepro.dec':  {'clear': 2693, 'key 6': 84, 'clear + off': 121, 'other': 12},
    'Xploder V2 (USA) r2.004 1998-11-13 [!].rom':
                   {'key 6': 4007, 'key 4': 552, 'key 6 + off': 311, 'other': 5},
}


def main():
    rows, stored_keyed, nibbles = {}, {}, {}
    for fn, label in dbtypes.ROMS:
        p = os.path.join('roms', fn)
        if not os.path.exists(p):
            print('skipped: no roms/%s' % fn)
            return 0
        rows[fn], stored_keyed[fn], stored = code_rows(p)
        nibbles[fn] = dict(collections.Counter(nibble(b) for b in stored))
        print('%-22s %5d code rows, %5d stored with key bits;  stored nibbles %s'
              % (label, len(rows[fn]), stored_keyed[fn],
                 ', '.join('%s %d' % kv for kv in sorted(nibbles[fn].items()))))
    print()

    pro = rows[PRO220]
    flagged = [c for c in pro if c[0] & FLAG]
    keyless = [c for c in flagged if not c[0] & 7]
    wrong = [c for c in keyless if (c[0] >> 4) in ADDRESSED]
    got = {'flagged': len(flagged), 'keyless': len(keyless),
           'wrong address': len(wrong)}
    for k in ('flagged', 'keyless', 'wrong address'):
        print('%-14s %4d   (expected %d)' % (k, got[k], EXPECT[k]))

    pools = {
        ALL_FOUR: [fn for fn, _ in dbtypes.ROMS if fn != PRO220],
        ENCRYPTED: [fn for fn, _ in dbtypes.ROMS
                    if fn != PRO220 and stored_keyed[fn] > len(rows[fn]) // 2],
    }
    for label, names in pools.items():
        pool = collections.Counter()
        for fn in names:
            pool.update(rows[fn])
        print('\nsame code without the bit, in %s:' % label)
        for name, pop in (('flagged (133)', flagged), ('keyless (121)', keyless),
                          ('wrong address (120)', wrong)):
            hit = [c for c in pop if bytes([c[0] & ~FLAG]) + c[1:] in pool]
            print('   of the %-20s %4d row(s), %d distinct'
                  % (name, len(hit), len(set(hit))))
            if pop is keyless:
                got['also shipped, ' + label] = len(hit)

    bad = [k for k in EXPECT if got[k] != EXPECT[k]]
    bad += ['stored nibbles of %s' % fn for fn in EXPECT_NIBBLES
            if nibbles[fn] != EXPECT_NIBBLES[fn]]
    if bad:
        print('\n%s differ from the published count - not a pass'
              % ', '.join(sorted(bad)))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
