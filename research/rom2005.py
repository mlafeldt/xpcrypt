#!/usr/bin/env python3
"""Xplorer release 2.005 - the tenth firmware, and what its database says.

`pc/ROMS/Xteng.fcd` ships with the vendor's own PC tool and was never counted:
the audited corpus is nine images, and this one sits between 2.004 (built
13/11/1998) and 2.008 (03/03/1999), eleven days after 2.004.  Everything below
is a condition of exit status 0.

Two results are worth the file on their own.

**`xpcrypt -x` recovers nothing from it, and the reason is one byte.**  2.005 is
the only image in the corpus with a game record that declares *zero* cheats -
`Moto Racer 2` at 0x2A8C5, an empty placeholder sitting between `Mortal Kombat
4 (US IMPORT)` and `Moto Racer`.  Both locators reject a zero count outright
(`db2.parse_db`: "cheat count"; `xpcrypt.c:db_cursor_next`: `if (ncheats == 0)
return -1;`), so the chain fails to parse, no framed candidate survives, and
`find_database()` reports no database at all.  A zero count is not corruption:
the record is well formed and the chain continues correctly straight after it.
Accepting it - skip to the next game record instead of failing the chain -
recovers 233 games, 1,668 cheats and 2,365 code lines that are lost today.

**2.005 stores every block payload in the clear, 2.008 encrypts the same bytes
with payload key 6.**  Seven Supercode/Megacode headers change key 0 -> key 6
between the two releases, 95 stored payload rows differ, and all 95 decrypt to
identical plaintext.  That is a second, six times larger known-plaintext oracle
for the payload cipher than the 16-block xteng/xtepro pair FINDINGS.md 4.3
rests on, and it dates the switch to between November 1998 and March 1999.
Payload key 6 then disappears again in Pro 2.20.

The rest is negative and just as useful: the .fcd cipher, the COMP01 container,
the code cipher and the anti-tamper check are all indistinguishable from the
other nine images, and 2.005 uses no code type the corpus did not already have.

    uv run python rom2005.py            # needs capstone for the firmware half
"""
import collections
import os
import random
import re
import struct
import subprocess
import sys
import tempfile

import comp01
import db2
import dbtypes
import fcdcrypt

FCD = os.path.join('pc', 'ROMS', 'Xteng.fcd')

ABBR = (None, 'Infinite', 'Unlimited', ' Lives', 'Player', ' Energy',
        ' Time', 'Money')

# ------------------------------------------------------------------ expected

EXPECT_SHA1 = '07b8d228132db9cdcbedf650ba751d4aeec22d55'
EXPECT_SIZE = 0x2FF6A
EXPECT_BANNER = b'(C) 1997/8 FCD  release 2.005\0\0\x0024/11/1998-09:50'
EXPECT_MODULE = 0x23000
EXPECT_CHAIN = 0x25000
EXPECT_TERM = 0x2FF66

EXPECT_EMPTY = [(0x2A8C5, 'Moto Racer 2')]
EXPECT_GAMES = 233              # games that carry at least one cheat
EXPECT_CHEATS = 1668
EXPECT_LINES = 2365

# by type nibble 0 to F, block-aware, the same walk dbtypes.py publishes
EXPECT_TYPES = [0, 21, 0, 402, 2, 7, 3, 65, 1686, 13, 0, 31, 0, 0, 0, 14]
EXPECT_PAYLOAD = 121

# type 5/6 headers by declared payload key, this image and 2.008
EXPECT_KEYS_2005 = {(5, 0): 7, (6, 0): 3}
EXPECT_KEYS_2008 = {(5, 0): 1, (5, 6): 16, (6, 0): 4}

# 2.005 -> 2.008, over expanded (game, cheat) keys
EXPECT_DIFF = dict(games_added=63, games_removed=11, games_common=222,
                   cheats_added=495, cheats_removed=59, cheats_common=1522,
                   cheats_changed=7)
# 2.004 US is a different product for a different region, not a step on the way
EXPECT_US = dict(games_common=54, cheats_common=12)

EXPECT_ORACLE_BLOCKS = 7
EXPECT_ORACLE_ROWS = 95

EXPECT_BASE = 0x001A0000
EXPECT_IMAGE = 0x2BBC4
EXPECT_ENTRY = 0x001ABC48
EXPECT_KEYED = 0xABFB           # XP_KEYED_TYPES, as in all nine
EXPECT_CHECKER = 0x001A4338     # the anti-tamper call site (fxprot.py)
EXPECT_CHECKER_ROUTES = ['Special32', 'key7']
EXPECT_SIGNATURE = (0x2B598, 0xFF, b'(C) 1997/8 FCD')

EXPECT_COMP01 = 0x580
EXPECT_ESCAPES = b'\xDB\x99\xF2\xDD'
EXPECT_PACKED = 0x20E88
# packstats.py's published ranges, which this image has to land inside
EXPECT_RANGE = {'rle16': (4, 19, 56, 108), 'arith-run': (9, 14, 58, 73)}

EXPECT_PB_KEY, EXPECT_PB_ROWS = 6, 30


# --------------------------------------------------------------------- chain

def expand(name):
    return ''.join(ABBR[ord(c)] if 1 <= ord(c) <= 7 else c for c in name)


def records(rom, start, allow_empty=True):
    """Walk a record chain, optionally tolerating a game with no cheats.

    This is `db2.parse_db` with one guard relaxed, and the relaxation is the
    whole point of the file: it returns (cheats, empty game records, offset of
    the terminator)."""
    pos, out, empty = start, [], []
    while pos + 4 <= len(rom):
        if rom[pos:pos + 4] == b'\xFF\xFF\xFF\xFF':
            return out, empty, pos
        end = db2.cstr_end(rom, pos, 127)
        if end < 0 or not db2.ok_name(rom, pos, end):
            raise ValueError('game name at %#x' % pos)
        game, at = rom[pos:end].decode('latin-1'), pos
        pos = end + 1
        ncheats = rom[pos]
        pos += 1
        if ncheats == 0:
            if not allow_empty:
                raise ValueError('cheat count 0 at %#x' % at)
            empty.append((at, game))
            continue
        for _ in range(ncheats):
            end = db2.cstr_end(rom, pos, 255)
            if end < 0 or not db2.ok_name(rom, pos, end):
                raise ValueError('cheat name at %#x' % pos)
            cheat = rom[pos:end].decode('latin-1')
            pos = end + 1
            nlines = rom[pos]
            pos += 1
            if nlines > 200 or pos + nlines * 6 > len(rom):
                raise ValueError('line count at %#x' % pos)
            out.append((game, cheat,
                        [rom[pos + 6 * i:pos + 6 * i + 6] for i in range(nlines)]))
            pos += nlines * 6
    raise ValueError('ran off the end')


def keyed(db):
    return {(expand(g), expand(c)): tuple(lines) for g, c, lines in db}


def block_key(code):
    """The declared payload key of a type 5 or 6 header, or None."""
    t = code[0] >> 4
    if t == 5:
        return code[4] >> 4
    if t == 6:
        return code[3] & 0xF
    return None


def key_census(db):
    c = collections.Counter()
    for _, _, lines in db:
        for _, code, role in dbtypes.walk(lines):
            if role == 'code' and block_key(code) is not None:
                c[(code[0] >> 4, block_key(code))] += 1
    return dict(c)


# ------------------------------------------------------------------ the runs

def chain_half(rom, problems):
    print('== record chain')
    try:
        db2.parse_db(rom, EXPECT_CHAIN)
        strict = 'parsed'
    except ValueError as e:
        strict = str(e)
    start, _ = db2.find_db(rom)
    print('   db2.parse_db at 0x%05X: %s' % (EXPECT_CHAIN, strict))
    print('   db2.find_db:            %s'
          % ('0x%05X' % start if start else 'no database'))
    if strict != 'cheat count' or start is not None:
        problems.append('the strict locator now accepts 2.005 (%s, %s) - the '
                        'zero-cheat record is what it used to reject'
                        % (strict, start))

    db, empty, term = records(rom, EXPECT_CHAIN)
    games = sorted(set(g for g, _, _ in db))
    lines = sum(len(c[2]) for c in db)
    print('   relaxed walk: %d games + %d empty game record(s), %d cheats, '
          '%d code lines, terminator 0x%05X'
          % (len(games), len(empty), len(db), lines, term))
    for at, name in empty:
        print('      empty game record at 0x%05X: %r' % (at, name))
    if [(a, n) for a, n in empty] != EXPECT_EMPTY:
        problems.append('empty game records %s, expected %s'
                        % (empty, EXPECT_EMPTY))
    if (len(games), len(db), lines, term) != (EXPECT_GAMES, EXPECT_CHEATS,
                                              EXPECT_LINES, EXPECT_TERM):
        problems.append('%d/%d/%d to 0x%05X, expected %d/%d/%d to 0x%05X'
                        % (len(games), len(db), lines, term, EXPECT_GAMES,
                           EXPECT_CHEATS, EXPECT_LINES, EXPECT_TERM))

    types, payload = collections.Counter(), 0
    for _, _, ls in db:
        for _, code, role in dbtypes.walk(ls):
            if role == 'code':
                types[code[0] >> 4] += 1
            else:
                payload += 1
    got = [types[t] for t in range(16)]
    print('   code types: %s'
          % '  '.join('%X=%d' % (t, n) for t, n in enumerate(got) if n))
    print('   %d dispatched codes + %d payload rows = %d lines'
          % (sum(got), payload, lines))
    if got != EXPECT_TYPES or payload != EXPECT_PAYLOAD:
        problems.append('types %s / %d payload, expected %s / %d'
                        % (got, payload, EXPECT_TYPES, EXPECT_PAYLOAD))
    return db


def diff_half(db, problems):
    print('\n== database diff')
    uk = keyed(db)
    other = {}
    for label, path, start in (('2.008', 'roms/xteng.dec', 0x25000),
                               ('2.004 US',
                                'roms/Xploder V2 (USA) r2.004 1998-11-13 [!].rom',
                                0x25000)):
        raw = open(path, 'rb').read()
        other[label] = keyed(records(raw, start)[0])

    later = other['2.008']
    ga, gb = set(g for g, _ in uk), set(g for g, _ in later)
    common = set(uk) & set(later)
    changed = sorted(k for k in common if uk[k] != later[k])
    got = dict(games_added=len(gb - ga), games_removed=len(ga - gb),
               games_common=len(ga & gb), cheats_added=len(set(later) - set(uk)),
               cheats_removed=len(set(uk) - set(later)),
               cheats_common=len(common), cheats_changed=len(changed))
    print('   2.005 -> 2.008: %s' % got)
    print('      games added   %s ...' % sorted(gb - ga)[:4])
    print('      games removed %s ...' % sorted(ga - gb)[:4])
    for k in changed:
        print('      changed: %s | %s' % k)
    if got != EXPECT_DIFF:
        problems.append('2.005 -> 2.008 diff %s, expected %s'
                        % (got, EXPECT_DIFF))

    us = other['2.004 US']
    gu = set(g for g, _ in us)
    got_us = dict(games_common=len(ga & gu), cheats_common=len(set(uk) & set(us)))
    print('   2.004 US vs 2.005 UK: %s (%d games only in 2.004, %d only in 2.005)'
          % (got_us, len(gu - ga), len(ga - gu)))
    if got_us != EXPECT_US:
        problems.append('2.004 vs 2.005 %s, expected %s' % (got_us, EXPECT_US))
    return later


def payload_half(db, problems):
    """2.005 stores block payloads in the clear; 2.008 keys them with 6."""
    print('\n== payload keys')
    later_db = records(open('roms/xteng.dec', 'rb').read(), 0x25000)[0]
    here, there = key_census(db), key_census(later_db)
    print('   2.005: %s' % {'type %d key %d' % k: v for k, v in sorted(here.items())})
    print('   2.008: %s' % {'type %d key %d' % k: v for k, v in sorted(there.items())})
    if here != EXPECT_KEYS_2005 or there != EXPECT_KEYS_2008:
        problems.append('payload keys %s / %s, expected %s / %s'
                        % (here, there, EXPECT_KEYS_2005, EXPECT_KEYS_2008))

    uk, later = keyed(db), keyed(later_db)
    rekeyed = rows = wrong = 0
    for k in sorted(set(uk) & set(later)):
        a, b = uk[k], later[k]
        if len(a) != len(b):
            continue
        wa, wb = dbtypes.walk(list(a)), dbtypes.walk(list(b))
        for (ia, ca, ra), (ib, cb, rb) in zip(wa, wb):
            if ra == 'code' and rb == 'code' \
                    and block_key(ca) == 0 and block_key(cb) == 6:
                rekeyed += 1
            if ra.startswith('data') and rb.startswith('data') and a[ia] != b[ib]:
                rows += 1
                if bytes(ca) != bytes(cb):
                    wrong += 1
    print('   %d block headers re-keyed 0 -> 6, %d stored payload rows differ, '
          '%d decrypt differently' % (rekeyed, rows, wrong))
    if (rekeyed, rows, wrong) != (EXPECT_ORACLE_BLOCKS, EXPECT_ORACLE_ROWS, 0):
        problems.append('payload oracle %d/%d/%d, expected %d/%d/0'
                        % (rekeyed, rows, wrong, EXPECT_ORACLE_BLOCKS,
                           EXPECT_ORACLE_ROWS))


def container_half(rom, raw, problems):
    print('\n== .fcd cipher and COMP01 container')
    print('   %s 0x%X bytes, round-trips: %s, "Sony" at 0x10: %s'
          % (FCD, len(raw), fcdcrypt.encrypt(rom) == raw,
             rom[0x10:0x14] == b'Sony'))
    if fcdcrypt.encrypt(rom) != raw or rom[0x10:0x14] != b'Sony':
        problems.append('the .fcd cipher does not round-trip this image')

    off = rom.find(b'COMP01')
    stats = {}
    img, packed = comp01.unpack(rom, off, stats=stats)
    esc = bytes(b ^ m for b, m in zip(rom[off:off + 10], comp01.MASK))[6:10]
    print('   COMP01 @0x%X escapes %s  packed 0x%X -> 0x%X  ratio %.2f'
          % (off, ' '.join('%02X' % e for e in esc), packed, len(img),
             packed / len(img)))
    for op in ('literal', 'lz-match', 'rle8', 'rle16', 'arith-run',
               'literal-escape'):
        n, saved = stats.get(op, (0, 0))
        print('      %-15s %7d uses  %+8d bytes' % (op, n, saved))
    if (off, esc, packed, len(img)) != (EXPECT_COMP01, EXPECT_ESCAPES,
                                        EXPECT_PACKED, EXPECT_IMAGE):
        problems.append('COMP01 (0x%X, %s, 0x%X, 0x%X), expected '
                        '(0x%X, %s, 0x%X, 0x%X)'
                        % (off, esc.hex(), packed, len(img), EXPECT_COMP01,
                           EXPECT_ESCAPES.hex(), EXPECT_PACKED, EXPECT_IMAGE))
    for op, (ulo, uhi, slo, shi) in EXPECT_RANGE.items():
        n, saved = stats.get(op, (0, 0))
        if not (ulo <= n <= uhi and slo <= saved <= shi):
            problems.append('%s fires %d times saving %d bytes, outside '
                            "packstats.py's %d-%d / %d-%d"
                            % (op, n, saved, ulo, uhi, slo, shi))
    return img


def firmware_half(path, img, problems):
    print('\n== firmware')
    try:
        import fwemu
        import fwimage
        import fxprot
        import romcrypt
    except ImportError as e:                        # capstone
        print('   skipped: %s' % e)
        return

    loaded, base = fwimage.load(path)
    fw = fwemu.Firmware(path)
    print('   load address %08X, image 0x%X, decrypt routine @%08X, '
          'XP_KEYED_TYPES 0x%04X' % (base, len(loaded), fw.entry, fw.keyed))
    if (base, len(loaded), fw.entry, fw.keyed) != (EXPECT_BASE, EXPECT_IMAGE,
                                                   EXPECT_ENTRY, EXPECT_KEYED):
        problems.append('firmware (%08X, 0x%X, %08X, 0x%04X), expected '
                        '(%08X, 0x%X, %08X, 0x%04X)'
                        % (base, len(loaded), fw.entry, fw.keyed, EXPECT_BASE,
                           EXPECT_IMAGE, EXPECT_ENTRY, EXPECT_KEYED))

    # the anti-tamper check: presence only.  What it does is fxprot.py's.
    sig = [(o, m, t) for o, m, t, _ in fxprot.signature(img) if m]
    routes = fxprot.routes_reaching(fw)
    for first in (0x04, 0x05, 0x06, 0x07, 0x32, 0x33):
        fw.decrypt([first, 1, 2, 3, 4, 5])
    sites = fw.skipped()
    print('   copyright signature %s' % sig)
    print('   checker at %s, reached from %s'
          % (['%08X' % a for a in sites], routes))
    if sig != [EXPECT_SIGNATURE] or sites != [EXPECT_CHECKER] \
            or routes != EXPECT_CHECKER_ROUTES:
        problems.append('anti-tamper %s / %s / %s, expected %s / [%08X] / %s'
                        % (sig, ['%08X' % a for a in sites], routes,
                           [EXPECT_SIGNATURE], EXPECT_CHECKER,
                           EXPECT_CHECKER_ROUTES))

    enc = [list(bytes.fromhex(l.replace(' ', ''))) for l in open('pb.enc')]
    clear = [list(bytes.fromhex(l.replace(' ', ''))) for l in open('pb.clear')]
    pkey = fw.decrypt(enc[0])[4] >> 4
    bad = sum(1 for e, c in zip(enc[1:], clear[1:]) if fw.decrypt(e, pkey) != c)
    print('   Punky Bear known plaintext: payload key %d, %d/%d rows match'
          % (pkey, len(enc) - 1 - bad, len(enc) - 1))
    if (pkey, len(enc) - 1, bad) != (EXPECT_PB_KEY, EXPECT_PB_ROWS, 0):
        problems.append('known plaintext key %d, %d bad of %d rows'
                        % (pkey, bad, len(enc) - 1))

    # fxtest.py's comparison, this image against the release either side of it
    ref = fwemu.Firmware('roms/xteng.dec')
    random.seed(20090510)
    fill = bytes([0xAA] * 6)
    n = vs_ref = vs_model = 0
    for first in range(256):
        for _ in range(2):
            code = [first] + [random.randrange(256) for _ in range(5)]
            for key in [-1] + list(range(16)):
                n += 1
                want = fw.decrypt(code, key, fill)
                if ref.decrypt(code, key, fill) != want:
                    vs_ref += 1
                if romcrypt.decrypt(list(code), key, dst=list(fill)) != want:
                    vs_model += 1
    print('   %d cases: %d disagreement(s) vs xteng.dec (2.008), %d vs '
          'romcrypt.py' % (n, vs_ref, vs_model))
    if vs_ref or vs_model:
        problems.append('the code cipher differs: %d vs 2.008, %d vs the model'
                        % (vs_ref, vs_model))


def tool_half(problems):
    """What the shipped binary does with the file today."""
    print('\n== xpcrypt -x')
    binary = os.path.join('..', 'xpcrypt')
    if not os.path.exists(binary):
        print('   skipped: build ../xpcrypt first')
        return
    p = subprocess.run([binary, '-x', FCD], capture_output=True)
    print('   exit %d, stdout %d bytes, stderr %r'
          % (p.returncode, len(p.stdout), p.stderr.decode().strip()))
    if p.returncode == 0 or b'no cheat database' not in p.stderr:
        problems.append('xpcrypt -x no longer fails on 2.005 - if the '
                        'zero-cheat record is now accepted, this file is stale')


def main():
    problems = []
    raw = open(FCD, 'rb').read()
    rom = fcdcrypt.decrypt(raw)

    import hashlib
    sha1 = hashlib.sha1(rom).hexdigest()
    banner = rom[EXPECT_MODULE:EXPECT_MODULE + len(EXPECT_BANNER)]
    module = struct.unpack_from('<I', rom, 0x7C)[0] & 0xFFFFFF
    print('== image')
    print('   %s -> 0x%X bytes, sha1 %s' % (FCD, len(rom), sha1))
    print('   support module 0x%05X: %r' % (module, banner))
    if sha1 != EXPECT_SHA1 or len(rom) != EXPECT_SIZE:
        problems.append('decrypted image is 0x%X bytes, sha1 %s - expected '
                        '0x%X / %s' % (len(rom), sha1, EXPECT_SIZE, EXPECT_SHA1))
    if module != EXPECT_MODULE or banner != EXPECT_BANNER:
        problems.append('module 0x%05X %r, expected 0x%05X %r'
                        % (module, banner, EXPECT_MODULE, EXPECT_BANNER))
    if not re.search(rb'release 2\.005', rom):
        problems.append('this is not release 2.005')

    db = chain_half(rom, problems)
    diff_half(db, problems)
    payload_half(db, problems)
    img = container_half(rom, raw, problems)

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'xteng-2005.dec')
        open(path, 'wb').write(rom)
        firmware_half(path, img, problems)
    tool_half(problems)

    for p in problems:
        print('\n   ' + p)
    print('\n%s' % ('2.005 places cleanly as the tenth image'
                    if not problems
                    else '%d expectation(s) not met - not a pass' % len(problems)))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
