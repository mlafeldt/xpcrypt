#!/usr/bin/env python3
"""The default-off bit in Xplorer Pro 2.20, and where else those codes appear.

ENGINE.md 7 and FINDINGS.md 7 rest on four counts from this database: how many
rows carry the bit, how many keep it through decryption, how many then reach the
wrong address, and how many of those codes also ship in another database without
the bit. The first three are simple predicates. The fourth is a *matching* claim,
and the number it produces depends entirely on the rule, so the rule is here:

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
    """(dispatched code rows, how many rows are *stored* with key bits).

    Payload rows are not dispatched and are left out of the first. The second
    reads the stored bytes, not the decrypted ones - after decryption the key
    bits are gone, and what is left set belongs to the types with no route.
    """
    _, db = db2.find_db(open(path, 'rb').read())
    if db is None:
        return [], 0
    out, keyed = [], 0
    for _, _, lines in db:
        out += [bytes(c) for _, c, role in dbtypes.walk(lines) if role == 'code']
        keyed += sum(1 for l in lines if l[0] & 7)
    return out, keyed


def main():
    rows, stored_keyed = {}, {}
    for fn, label in dbtypes.ROMS:
        p = os.path.join('roms', fn)
        if not os.path.exists(p):
            print('skipped: no roms/%s' % fn)
            return 0
        rows[fn], stored_keyed[fn] = code_rows(p)
        print('%-22s %5d code rows, %5d stored with key bits'
              % (label, len(rows[fn]), stored_keyed[fn]))
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
    if bad:
        print('\n%s differ from the published count - not a pass'
              % ', '.join(sorted(bad)))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
