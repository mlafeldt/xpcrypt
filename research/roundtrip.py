#!/usr/bin/env python3
"""Does `xpcrypt -e K` produce something `xpcrypt -d` turns back into the input?

The cartridge has no encrypt side, so nothing can check xpcrypt's against the
firmware directly - oracle_test.py gets at it by having the firmware decrypt
what xpcrypt encrypted, over generated codes. This does the other half over the
*real* population: every code line of every recovered database, decrypted by
xpcrypt and then run through `-e K | -d` for each of the four keys.

One cheat entry at a time wherever a block is involved. A cheat entry is where
the cartridge starts reading, so a type 5, 6 or A header at the end of one
cheat must not take the codes of the next as its payload; feeding a whole
database as one stream does exactly that. Cheats with no header in them have no
such state to leak and are batched, which is what keeps this to about as many
xpcrypt runs as the oracle's database suite already does.

  python3 roundtrip.py [path/to/xpcrypt]
"""
import glob
import os
import sys

import oracle_test
from oracle_test import run

BATCH = 256                     # header-free cheats per xpcrypt run
KEYS = (4, 5, 6, 7)
BLOCK_NIBBLES = (0x5, 0x6, 0xA)  # types that start a payload block

# Every complete chain in the five ROM databases, which is the population the
# notes cite for this check.
EXPECT_LINES = 15349


def has_header(cheat):
    return any((c[0] >> 4) in BLOCK_NIBBLES for c in cheat)


def roundtrip(chunk, keys=KEYS):
    """Number of lines in @chunk that fail to come back, over every key."""
    bad = 0
    for k in keys:
        back = run(['-d'], run(['-e', str(k)], chunk))
        bad += sum(1 for a, b in zip(chunk, back) if a != b)
    return bad


def main():
    roms = sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))
    if not roms:
        print('skipped: no roms/ - drop the firmware dumps in and re-run')
        return 0
    import db2

    total = bad = 0
    for path in roms:
        _, db = db2.find_db(open(path, 'rb').read())
        if db is None:
            continue

        # Decrypt each cheat on its own, then sort the plaintext into the
        # cheats that carry a block and the ones that do not.
        blocked, plain, lines = [], [], 0
        for _, _, cheat in db:
            dec = run(['-d'], [bytes(l) for l in cheat])
            lines += len(dec)
            (blocked if has_header(dec) else plain).append(dec)

        n = sum(roundtrip(c) for c in blocked)
        for i in range(0, len(plain), BATCH):
            n += roundtrip([c for cheat in plain[i:i + BATCH] for c in cheat])

        print('%-42s %5d lines, %4d cheats (%d with a block), '
              '%d line(s) not reproduced'
              % (os.path.basename(path), lines, len(db), len(blocked), n))
        total += lines
        bad += n

    print('\n%d code lines x %d keys, %d not reproduced'
          % (total, len(KEYS), bad))
    if total != EXPECT_LINES:
        print('   %d lines, expected %d - the published figure is for the '
              'five complete database chains' % (total, EXPECT_LINES))
    return 1 if bad or total != EXPECT_LINES else 0


if __name__ == '__main__':
    if not os.path.exists(oracle_test.XPCRYPT):
        sys.exit('no xpcrypt at %s - build it first, or pass its path'
                 % oracle_test.XPCRYPT)
    sys.exit(main())
