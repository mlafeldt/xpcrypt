#!/usr/bin/env python3
"""Audit every type 5/6 block in a real ROM database with xpcrypt's block logic.

A cheat entry declares its own line count, so a wrong row-count formula shows up
as a block that overruns its entry or ends short of it.

    python3 audit2.py                 # every ROM with a recoverable database
    python3 audit2.py roms/xteng.dec  # just that one, with the per-block list

Only the five images `db2.find_db()` recovers a chain from have a database to
audit; the FX ones do not, and are not a failure (see FINDINGS.md 5.1).
"""
import os
import sys
from dbscan import decrypt_line
from db2 import find_db
from dbtypes import ROMS

def rows(mega, size, variant):
    if mega:
        n = size + (0x0A if variant == 'direct' else 0x12)
    else:
        n = size if variant == 'direct' else size + 6
    return (n + 5) // 6

def parse_header(dec):
    mega = (dec[0] & 0xF0) == 0x60
    if mega:
        return True, dec[3] & 0x0F, (dec[4] << 8) | dec[5]
    size = ((dec[4] & 0x0F) << 8) | dec[5]
    return False, dec[4] >> 4, size

def audit(path, detail):
    rom = open(path, 'rb').read()
    start, db = find_db(rom)
    if db is None:
        print('%-42s no recoverable database' % os.path.basename(path))
        return 0
    blocks, overrun, exact_end, keys = scan(db)
    print('%-42s db %#08x  %d type 5/6 blocks, %d fit, %d exact'
          % (os.path.basename(path), start, len(blocks),
             len(blocks) - overrun, exact_end))
    if detail:
        report(start, db, blocks, overrun, exact_end, keys)
    return overrun


def scan(db):
    blocks, overrun, exact_end, keys = [], 0, 0, {}
    for game, name, lines in db:
        pending = 0
        for i, raw in enumerate(lines):
            if pending:
                pending -= 1
                continue
            dec, ok = decrypt_line(raw)
            if (dec[0] & 0xF0) not in (0x50, 0x60):
                continue
            mega, pkey, size = parse_header(dec)
            if not mega and size < 1:
                continue
            n_direct = rows(mega, size, 'direct')
            n_old = rows(mega, size, 'old')
            avail = len(lines) - i - 1
            blocks.append((game, name, i, len(lines), mega, pkey, size,
                           n_direct, n_old, avail))
            keys[(6 if mega else 5, pkey)] = \
                keys.get((6 if mega else 5, pkey), 0) + 1
            if n_direct > avail:
                overrun += 1
            if n_direct == avail:
                exact_end += 1
            pending = min(n_direct, avail)
    return blocks, overrun, exact_end, keys


def report(start, db, blocks, overrun, exact_end, keys):
    print(f"database at {start:#x}: {len(db)} cheats, "
          f"{sum(len(c[2]) for c in db)} code lines")
    print(f"type 5/6 blocks: {len(blocks)}")
    print(f"  fit inside their cheat entry: {len(blocks) - overrun}/{len(blocks)}")
    print(f"  end exactly at the entry end: {exact_end}/{len(blocks)}")
    print(f"  payload keys seen: " +
          ", ".join(f"type{t} key{k}: {n}" for (t, k), n in sorted(keys.items())))
    old_fits = sum(1 for b in blocks if b[8] <= b[9])
    print(f"  would fit with the old +6/+0x12 formula: {old_fits}/{len(blocks)}")
    print()
    for game, name, i, total, mega, pkey, size, nd, no_, avail in blocks:
        flag = "OVERRUN" if nd > avail else ("exact" if nd == avail else "short")
        print(f"  type{'6' if mega else '5'} key={pkey} size={size:#06x} "
              f"rows={nd:3d} avail={avail:3d} [{flag}] "
              f"old={no_:3d}{'' if no_ <= avail else ' (overruns)'}"
              f"  {game} / {name}")


# One stored block really is malformed: `Metal Gear Solid - Jp / Verliere Chaff`
# in xtger.dec declares 0xD7DD payload bytes - 9212 rows - at the very end of its
# cheat entry, with nothing after it.  It is a corrupt entry, not a formula
# error, and it is the "8 of 9" in the notes.  Everything else has to fit.
EXPECT_OVERRUN = 1


if __name__ == '__main__':
    if len(sys.argv) > 1:
        audit(sys.argv[1], True)
        sys.exit(0)
    bad = 0
    for fn, _ in ROMS:
        p = os.path.join('roms', fn)
        if os.path.exists(p):
            bad += audit(p, False)
    print('%d block overruns its cheat entry, expected %d%s'
          % (bad, EXPECT_OVERRUN,
             '' if bad == EXPECT_OVERRUN else ' - so this is a change'))
    sys.exit(0 if bad == EXPECT_OVERRUN else 1)
