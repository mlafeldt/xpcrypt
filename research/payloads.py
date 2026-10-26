#!/usr/bin/env python3
"""Every Supercode, Megacode and inline data block that ships in a real database,
disassembled.

`ENGINE.md` §5, §6 and §8 establish the *mechanism*: a type 5 Supercode copies a
byte block to an address, a type 6 Megacode arms the R3000 debug unit and installs
its payload at the breakpoint vector `0x80000040`, and a type A block copies
everything below it.  What nobody had looked at is the *content*.  This file
extracts the payload of every block in the corpus, disassembles it as MIPS R3000
little-endian at the address it actually runs from, and asserts what it finds.

    uv run --with capstone python payloads.py          # census + checks
    uv run --with capstone python payloads.py -v       # ... and every listing

Corpus: the five in-ROM chains `db2.find_db()` recovers from `roms/`, plus the
tenth image `pc/ROMS/Xteng.fcd` (Xplorer UK 2.005), whose chain holds the one
empty game record of the in-ROM corpus - `db2` skips it now, see `TENTH.md` and
`rom2005.py`.  Not yet in it: the four FX databases, which ship LZW-packed and
which `fxdb.py` decodes.

The five results this file exists to pin down:

1. **65 blocks, 51 Supercodes and 14 Megacodes, no type A anywhere**, holding 33
   distinct payloads.  Two Supercodes declare zero bytes and one Megacode
   declares 9,212 rows that are not there (§7, `audit2.py`); the other 62 are
   well formed.

2. **Ten of the 65 are corrupt as shipped.**  Their payload rows have been
   rewritten as if they were *code* lines - type nibble and key nibble
   reassigned, the other five bytes re-enciphered with the ordinary code cipher.
   A payload row's byte 0 is payload *data* (payload key 6 computes plaintext
   bytes 1 and 5 from it), and the code cipher zeroes byte 0's low nibble and has
   no decrypt route for types 2, A, C and E, so the rewrite does not invert.  The
   engine decrypts payload rows with the payload key only, so what reaches
   `0x80000040` or the game's RAM is garbage.  Seven of the ten are in the German
   2.0081 database, two in the Xploder V2 2.004 US one, one in 2.008 UK.

3. **Three Supercodes target PSX RAM below `0x10000`** - the kernel's own area.
   Two of them (`0x7610`, `0x7690`) park a routine there and a second code in the
   same cheat hooks the game into it; the third writes to `0x702`, inside the
   support module's poke table, and declares a length of zero, which hangs the
   copy loop (§7).

4. **The X-Link PC tool contains the templates.**  `pc/XLink.exe` holds the
   assembled Megacode-plus-Supercode pair that the Bust-A-Move 3DX and Puzzle
   Bobble 4 cheats are instances of, including the `60 FC D0 00` header with
   "FCD" stamped in the unused address field, and two MOD-code templates built
   around Rayman's addresses - which is what "works similiar to the rayman super
   code we have" in the X-Link 1.09 release notes means.  The generator declares
   12 payload bytes for an 8-byte handler, so the block swallows the type 9
   "already installed?" guard line that follows it.

5. **`ray.txt` and `br.txt` are working notes**, byte-for-byte the stored rows of
   `Rayman / Rayman can fly` and `Bloody Roar / Infinite Energy Player 1` in
   `xtepro.dec`, the one database that stores every row in the clear.
"""
import collections
import hashlib
import os
import sys

import db2
import dbtypes
import fcdcrypt
import romcrypt

M = 0xFF
ROMS = 'roms'
TENTH = os.path.join('pc', 'ROMS', 'Xteng.fcd')

# Bytes 1..7 in a game or cheat name (xpcrypt.c:db_abbr).
ABBR = (None, 'Infinite', 'Unlimited', ' Lives', 'Player', ' Energy', ' Time',
        'Money')


def expand(name):
    return ''.join(ABBR[ord(c)] if 1 <= ord(c) <= 7 else c for c in name)


# --------------------------------------------------------------- the databases

def databases():
    """(label, [(game, cheat, [row, ...]), ...]) for every database we can read."""
    for fn, label in dbtypes.ROMS:
        path = os.path.join(ROMS, fn)
        if not os.path.exists(path):
            continue
        rom = open(path, 'rb').read()
        _, db = db2.find_db(rom)
        if db is not None:
            yield label, db
    if os.path.exists(TENTH):
        _, db = db2.find_db(bytes(fcdcrypt.decrypt(open(TENTH, 'rb').read())))
        yield 'Xplorer 2.005 UK', db


# ------------------------------------------------------------------ the blocks

class Block(object):
    __slots__ = ('db', 'game', 'cheat', 'index', 'type', 'key', 'addr',
                 'declared', 'rows', 'avail', 'header', 'stored', 'payload')

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    @property
    def sha(self):
        return hashlib.sha256(self.payload).hexdigest()[:8]

    @property
    def descriptor(self):
        """(break address, DCIC, break mask) of a Megadode, or None."""
        if self.type != 6 or len(self.payload) < 10:
            return None
        d = self.payload
        return (int.from_bytes(d[0:4], 'big'),
                (d[4] << 24) | (d[5] << 16),
                int.from_bytes(d[6:10], 'big'))

    @property
    def code(self):
        """The bytes that end up executable, and the address they run at."""
        if self.type == 6:
            return self.payload[10:], 0x80000040
        return self.payload, 0x80000000 | (self.addr or 0)

    def __repr__(self):
        where = ('%08X' % self.addr) if self.addr is not None else '   -    '
        return ('t%X key%d %s decl=%-5d rows=%-4d avail=%-3d len=%-3d %s'
                % (self.type, self.key, where, self.declared, self.rows,
                   self.avail, len(self.payload), self.sha))


def blocks(db, label):
    """Every type 5/6/A header in a database, with its decrypted payload.

    Follows the staging code, not a stream reader: a Supercode of declared size
    zero is still a header (the cartridge stages it and then hangs, §7), and a
    type A block runs to the end of the cheat entry.
    """
    for game, cheat, lines in db:
        i = 0
        while i < len(lines):
            c = romcrypt.decrypt(list(lines[i]))
            t = c[0] >> 4
            common = dict(db=label, game=game, cheat=cheat, index=i,
                          header=bytes(c))
            if t == 0xA:
                rows = lines[i + 1:]
                yield Block(type=0xA, key=0,
                            addr=(c[1] << 16) | (c[2] << 8) | c[3],
                            declared=6 * len(rows) + 2, rows=len(rows),
                            avail=len(rows), stored=rows,
                            payload=bytes(c[4:6]) + b''.join(rows), **common)
                break
            if t not in (5, 6):
                i += 1
                continue
            b = dbtypes.block(c)
            if t == 5:
                addr = ((c[0] & 0xF) << 24) | (c[1] << 16) | (c[2] << 8) | c[3]
                declared = ((c[4] & 0xF) << 8) | c[5]
            else:
                addr, declared = None, (c[4] << 8) | c[5]
            key, nrows = b if b else (c[4] >> 4, 0)
            avail = len(lines) - i - 1
            stored = lines[i + 1:i + 1 + min(nrows, avail)]
            pay = b''.join(bytes(romcrypt.decrypt(list(r), key))
                           if key in (6, 7) else r for r in stored)
            yield Block(type=t, key=key, addr=addr, declared=declared,
                        rows=nrows, avail=avail, stored=stored,
                        payload=pay[:declared] if t == 5 else pay, **common)
            i += nrows + 1


# ------------------------------------------------------------- disassembly

def disassemble(data, base):
    """[(address, word, text), ...] - one word at a time, so alignment is kept."""
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    out = []
    for off in range(0, len(data) - 3, 4):
        w = data[off:off + 4]
        word = int.from_bytes(w, 'little')
        try:
            i = next(md.disasm(w, base + off))
            text = ('%-8s %s' % (i.mnemonic, i.op_str)).strip()
        except StopIteration:
            text = '.word 0x%08x' % word
        out.append((base + off, word, text))
    return out


# COP0 registers, which capstone prints as general-purpose names.
COP0 = {3: 'BPC', 5: 'BDA', 6: 'TAR', 7: 'DCIC', 9: 'BDAM', 11: 'BPCM',
        12: 'SR', 13: 'Cause', 14: 'EPC'}
GPR = ('zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 '
       's6 s7 t8 t9 k0 k1 gp sp fp ra').split()


def annotate(word, text):
    """Undo capstone's `mtc0 $zero, $a3` for the COP0 registers we care about."""
    if text.startswith(('mtc0', 'mfc0')) and (word >> 26) == 0x10:
        rd = (word >> 11) & 0x1F
        return '%s $%s, $%d      ; %s' % (text[:4], GPR[(word >> 16) & 0x1F],
                                          rd, COP0.get(rd, 'cop0 r%d' % rd))
    if word == 0x42000010:
        return 'rfe'
    return text


def listing(b, note=lambda addr: ''):
    data, base = b.code
    out = []
    for addr, word, text in disassemble(data, base):
        out.append('  %08X  %08X  %-34s%s'
                   % (addr, word, annotate(word, text), note(addr)))
    tail = len(data) % 4
    if tail:
        out.append('  %08X  %s  (%d trailing byte%s)'
                   % (base + len(data) - tail, data[-tail:].hex(), tail,
                      '' if tail == 1 else 's'))
    return out


# ------------------------------------------------------------------- the checks

# Per database: type 5 headers, type 6 headers, type A headers.  The five in-ROM
# numbers are ENGINE.md §8's; the 2.005 column is new.
EXPECT_CENSUS = {
    'Xplorer 2.008 UK':    (17, 4, 0),
    'Xplorer 2.0081 DE':   (8, 3, 0),
    'Xplorer Pro 2.14 JP': (0, 0, 0),
    'Xplorer Pro 2.20 UK': (17, 4, 0),
    'Xploder V2 2.004 US': (2, 0, 0),
    'Xplorer 2.005 UK':    (7, 3, 0),
}
EXPECT_DISTINCT = 33          # distinct (type, target, payload) triples

# The three blocks that are not well formed, by (database, game, cheat).
EXPECT_MALFORMED = {
    ('Xplorer 2.0081 DE', 'Metal Gear Solid - Jp', 'Verliere Chaff'):
        'declares 55261 bytes - 9212 rows - with nothing after it',
    ('Xplorer 2.0081 DE', 'War Games', 'Oeffnet alle Levels fuer NORAD'):
        'declares 0 bytes at 0x000702: the copy loop counts down from 0',
    ('Xplorer 2.0081 DE', 'War Games', 'Oeffnet alle Levels fuer WOPR'):
        'declares 0 bytes at 0x000702: the copy loop counts down from 0',
}

# Every block whose payload was rewritten as if it were code, paired with the
# database that has the same cheat intact.  `Tomb Raider 3 - GER` is the one
# pair whose target address differs (0x4CBCC against 0x4CBC4): it is the German
# build of the same two instructions, and the payload is the same eight bytes.
CORRUPT = [
    ('Xplorer 2.008 UK', ('Tomb Raider 3', "Quad Bike In Lara's House"), 0,
     'Xplorer Pro 2.20 UK', ('Tomb Raider 3', "Quad Bike In Lara's House"), 0),
    ('Xplorer 2.0081 DE', ('Bloody Roar', 'Unendlich Energie Spieler 1'), 0,
     'Xplorer Pro 2.20 UK', ('Bloody Roar', 'Infinite Energy Player 1'), 0),
    ('Xplorer 2.0081 DE', ('Rayman - Bitte O druecken', 'Fliegen koennen'), 0,
     'Xplorer Pro 2.20 UK', ('Rayman', 'Rayman can fly'), 0),
    ('Xplorer 2.0081 DE', ('Small Soldiers', 'Unendlich Energie'), 0,
     'Xplorer Pro 2.20 UK', ('Small Soldiers', 'Infinite Energy'), 0),
    ('Xplorer 2.0081 DE', ('Tenchu - Stealth Assassins', 'Unendlich Energie'), 0,
     'Xplorer Pro 2.20 UK', ('Tenchu - Stealth Assassins', 'Infinite Energy'), 0),
    ('Xplorer 2.0081 DE', ('Tenchu - Stealth Assassins', 'Alle Waffen'), 0,
     'Xplorer Pro 2.20 UK', ('Tenchu - Stealth Assassins', 'All Weapons'), 0),
    ('Xplorer 2.0081 DE', ('Tomb Raider 3 V1.1', 'Unendlich Energie'), 0,
     'Xplorer Pro 2.20 UK', ('Tomb Raider 3 V1.1', 'Infinite Energy'), 0),
    ('Xplorer 2.0081 DE', ('Tomb Raider 3 - GER', 'Unendlich Leben'), 0,
     'Xplorer Pro 2.20 UK', ('Tomb Raider 3', 'Infinite Energy'), 0),
    ('Xploder V2 2.004 US', ('Res evil 2 disk 1', 'Code'), 0,
     'Xplorer Pro 2.20 UK',
     ('Resident Evil 2 Disk 1, U. S. Import',
      'Super Code (Inventory Screen. Use R1, R2, L1, L2)'), 0),
    ('Xploder V2 2.004 US', ('Res evil 2 disk 1', 'Code'), 1,
     'Xplorer Pro 2.20 UK',
     ('Resident Evil 2 Disk 1, U. S. Import',
      'Super Code (Inventory Screen. Use R1, R2, L1, L2)'), 1),
]
EXPECT_ROW_CLASSES = {
    'intact': 37,
    'code cipher, exact': 9,
    'code cipher, byte 0 low nibble lost': 10,
    'code cipher into a route-less type': 4,
    'type nibble rewritten': 2,
    'code cipher and type nibble rewritten': 1,
}


def payload_encrypt(row, key):
    """The payload cipher, encrypting - the inverse of `romcrypt.decrypt(_, key)`."""
    if key == 0:
        return bytes(row)
    if key == 6:
        c = [0] * 6
        c[0] = (row[1] + 0x34) & M
        c[1] = (~row[0]) & M
        c[2] = (row[5] + c[0]) & M
        c[3] = (row[3] ^ c[1]) & M
        c[4] = (row[2] + 0x1B) & M
        c[5] = (row[4] + 0x55) & M
        return bytes(c)
    if key == 7:
        return bytes((row[5 - i] + 0x55) & M for i in range(6))
    raise ValueError(key)


def code_encrypt6(row):
    """The *code* cipher's key 6 route, encrypting (romcrypt.py, `key6`)."""
    return bytes([(row[0] & 0xF0) | 6] +
                 [((row[i] ^ i) + 0x55) & M for i in range(1, 6)])


def classify_row(actual, expect):
    """How one stored payload row was damaged, relative to what it should hold."""
    if actual == expect:
        return 'intact'
    # A rewrite that only touched byte 0's type nibble: the row's key nibble was
    # already 4..7, so decrypting and re-encrypting it round-trips exactly.
    if actual[1:] == expect[1:] and actual[0] & 0x0F == expect[0] & 0x0F:
        return 'type nibble rewritten'
    d = bytes(romcrypt.decrypt(list(actual)))
    if d == expect:
        return 'code cipher, exact'
    if d[1:] == expect[1:]:
        return ('code cipher, byte 0 low nibble lost'
                if d[0] & 0xF0 == expect[0] & 0xF0
                else 'code cipher and type nibble rewritten')
    if code_encrypt6(expect)[1:] == actual[1:] and \
            actual[0] & 0xF0 == expect[0] & 0xF0:
        return 'code cipher into a route-less type'
    return 'unexplained'


# ------------------------------------------------------------------- reporting

def census(all_blocks, labels):
    print('== the blocks ==')
    per = collections.defaultdict(lambda: [0, 0, 0])
    for label in labels:               # Pro 2.14 JP has none at all
        per[label]
    for b in all_blocks:
        per[b.db][{5: 0, 6: 1, 0xA: 2}[b.type]] += 1
    print('  %-22s %6s %6s %6s' % ('database', 'type5', 'type6', 'typeA'))
    for label in sorted(per):
        print('  %-22s %6d %6d %6d' % ((label,) + tuple(per[label])))
    tot = [sum(per[l][i] for l in per) for i in range(3)]
    print('  %-22s %6d %6d %6d' % ('total', tot[0], tot[1], tot[2]))
    for label, got in per.items():
        assert tuple(got) == EXPECT_CENSUS[label], (label, got)
    assert len(per) == len(EXPECT_CENSUS), sorted(per)
    return tot


def report_blocks(all_blocks, verbose):
    print()
    print('== every block, in database order ==')
    seen = {}
    for b in all_blocks:
        key = (b.type, b.addr, b.payload)
        dup = seen.get(key)
        seen.setdefault(key, b)
        print('  %-22s %s %s | %s'
              % (b.db, b, expand(b.game)[:26], expand(b.cheat)[:34]))
        if dup is not None:
            print('      same payload as %s | %s' % (dup.db, expand(dup.game)))
        elif verbose and b.payload:
            for line in listing(b):
                print('    ' + line)
    assert len(seen) == EXPECT_DISTINCT, len(seen)
    print('  %d blocks, %d distinct (type, target, payload) triples'
          % (len(all_blocks), len(seen)))
    return seen


def report_malformed(all_blocks):
    print()
    print('== headers whose declared length does not match what follows ==')
    bad = {}
    for b in all_blocks:
        if b.type == 5 and b.declared == 0:
            bad[(b.db, b.game, b.cheat)] = \
                'declares 0 bytes at %#08x: the copy loop counts down from 0' \
                % b.addr
        elif b.rows > b.avail:
            bad[(b.db, b.game, b.cheat)] = \
                'declares %d bytes - %d rows - with %s after it' \
                % (b.declared, b.rows,
                   'nothing' if not b.avail else '%d rows' % b.avail)
    for k in sorted(bad):
        print('  %s | %s | %s' % (k[0], expand(k[1]), expand(k[2])))
        print('      %s' % bad[k])
    assert bad == EXPECT_MALFORMED, bad
    return bad


def report_addresses(all_blocks):
    """Where the payloads land, and what they reach for."""
    print()
    print('== targets and the address ranges the payloads touch ==')
    kernel, ranges = [], collections.Counter()
    for b in all_blocks:
        if b.type == 5:
            if b.addr < 0x10000:
                kernel.append(b)
            ranges['RAM %06X' % (b.addr & 0xFF0000)] += 1
    for b in sorted(set((x.addr, x.declared) for x in kernel)):
        print('  Supercode target %08X, %d bytes - PSX kernel RAM' % b)
    print('  Supercode targets by 64 KiB page: %s'
          % ', '.join('%s x%d' % (k, v) for k, v in sorted(ranges.items())))
    # Megacode descriptors.
    print('  Megacode break addresses:')
    for b in all_blocks:
        d = b.descriptor
        if d is None:
            continue
        seg = ('scratchpad' if 0x1F800000 <= (d[0] & 0x1FFFFFFF) < 0x1F800400
               else 'RAM')
        print('    %08X mask %08X DCIC %08X  %-11s %s | %s'
              % (d[0], d[2], d[1], seg, b.db, expand(b.cheat)[:30]))
    # Anything reaching cartridge, BIOS or I/O space would show up as a lui of
    # one of these.  Nothing does except the Bloody Roar handler's scratchpad.
    danger = collections.Counter()
    for b in all_blocks:
        data, base = b.code
        for _, word, text in disassemble(data, base):
            if text.startswith('lui'):
                danger[word & 0xFFFF] += 1
    reach = {i for i in danger
             if 0x1F00 <= i <= 0x1F08 or i == 0xBFC0 or i == 0x1F80
             or i == 0x9F00}
    print('  lui immediates in cartridge/BIOS/scratchpad space: %s'
          % (sorted('%04X' % i for i in reach) or 'none'))
    assert sorted(set((x.addr, x.declared) for x in kernel)) == \
        [(0x000702, 0), (0x007610, 176), (0x007690, 161)], kernel
    # 0x1F80 is the scratchpad (Bloody Roar); no payload names the cartridge at
    # 0x1F00xxxx / 0x9F00xxxx, the BIOS at 0xBFC00000 or an I/O register.
    assert reach == {0x1F80}, reach
    return kernel


def report_corruption(by_cheat):
    print()
    print('== blocks whose payload rows were rewritten as code lines ==')
    classes = collections.Counter()
    for cdb, ck, ci, gdb, gk, gi in CORRUPT:
        bad = by_cheat[(cdb,) + ck][ci]
        good = by_cheat[(gdb,) + gk][gi]
        assert bad.payload != good.payload, (cdb, ck)
        rows = collections.Counter()
        for r, canon in enumerate(good.stored):
            if r >= len(bad.stored):
                rows['missing'] += 1
                continue
            expect = payload_encrypt(list(romcrypt.decrypt(list(canon), good.key))
                                     if good.key in (6, 7) else list(canon),
                                     bad.key)
            rows[classify_row(bad.stored[r], expect)] += 1
        classes.update(rows)
        print('  %-20s %-26s %-30s' % (cdb, expand(ck[0])[:26], expand(ck[1])[:30]))
        print('      t%X %s' % (bad.type, dict(rows)))
    print('  row classes over all %d: %s' % (len(CORRUPT), dict(classes)))
    assert dict(classes) == EXPECT_ROW_CLASSES, dict(classes)
    return classes


def report_notes():
    """`ray.txt` and `br.txt`: what they are."""
    print()
    print('== ray.txt and br.txt ==')
    path = os.path.join(ROMS, 'xtepro.dec')
    if not os.path.exists(path):
        print('  skipped: no roms/xtepro.dec')
        return
    _, db = db2.find_db(open(path, 'rb').read())
    stored = {(g, c): [bytes(x) for x in lines] for g, c, lines in db}
    for fn, key in (('ray.txt', ('Rayman', 'Rayman can fly')),
                    ('br.txt', ('Bloody Roar', 'Infinite Energy Player 1'))):
        rows = [bytes.fromhex(l.strip().replace(' ', ''))
                for l in open(fn) if l.strip() and not l.startswith(';')]
        assert rows == stored[key], fn
        print('  %-8s %2d rows, byte-for-byte %s | %s in xtepro.dec'
              % (fn, len(rows), key[0], key[1]))


XLINK = os.path.join('pc', 'XLink.exe')
# The generator's own copies, at these file offsets in the DOS X-Link binary.
XLINK_TEMPLATES = (
    (0x497F0, 'ACG super code: type 6 header + descriptor + j 0x80007610, then '
              'a type 9 guard, a type 5 header and the 176-byte handler'),
    (0x49DC8, 'MOD code: type 6 header, 52 bytes - read a word, multiply it by a '
              'constant, write it back'),
    (0x4A1DC, 'MOD code: read the halfword at 0x001FAB92, and on a button match '
              'increment the halfword at 0x001E4230'),
)


def report_xlink(by_cheat):
    print()
    print('== the templates inside pc/XLink.exe ==')
    if not os.path.exists(XLINK):
        print('  skipped: no %s' % XLINK)
        return
    exe = open(XLINK, 'rb').read()
    for off, what in XLINK_TEMPLATES:
        assert off < len(exe), off
        print('  %06X  %s' % (off, what))
    # The shipped Bust-A-Move cheat is an instance of the first template: its
    # header, descriptor DCIC, mask and both payload instructions come straight
    # out of the binary, and so does the whole 176-byte handler's frame.
    head = exe[0x497F0:0x497F0 + 6]
    assert head == bytes.fromhex('60fcd000000c'), head.hex()
    print('  template header %s - "FCD0" stamped in the type 6 address field, '
          '12 payload bytes' % head.hex().upper())
    key = ('Xplorer Pro 2.20 UK', 'Bust-A-Move 3DX',
           'Change colour of  current ball Press L2 R2')
    if key in by_cheat:
        mega, superc = by_cheat[key]
        assert mega.header == head, mega.header.hex()
        assert mega.payload[10:14] == exe[0x49800:0x49804], 'stub'
        assert mega.declared == 12 and mega.payload[10:18].hex() == \
            '841d000800000000', mega.payload[10:18].hex()
        # 12 declared bytes for an 8-byte handler is one row too many: rows =
        # ceil((12 + 10) / 6) = 4, so the type 9 guard below is eaten as payload.
        assert (12 + 10 + 5) // 6 == 4 and (8 + 10 + 5) // 6 == 3
        guard = romcrypt.decrypt(list(mega.stored[3]))
        assert guard[0] >> 4 == 9, guard
        assert (guard[1] << 16) | (guard[2] << 8) | guard[3] == \
            superc.addr + 2, guard
        assert (guard[4] << 8) | guard[5] == \
            int.from_bytes(superc.payload[2:4], 'little'), guard
        print('  the 12-byte declaration eats one row: %s is a type 9 guard '
              '("skip the next code if *(u16)%06X == %04X", the top half of the '
              'handler\'s first instruction), and it never reaches the dispatcher'
              % (bytes(guard).hex().upper(), superc.addr + 2,
                 (guard[4] << 8) | guard[5]))
        # ... and the handler body is the template with the addresses filled in.
        tpl = exe[0x49814:0x49814 + 176]
        same = sum(1 for a, b in zip(tpl, superc.payload) if a == b)
        assert same >= 150, same
        print('  the 176-byte handler matches the template in %d of 176 bytes; '
              'the rest is the watched address, the target and the limits'
              % same)


# ------------------------------------------------------- the two best specimens

def show_resident_evil(by_cheat):
    key = ('Xplorer Pro 2.20 UK', 'Resident Evil 2 Disk 1, U. S. Import',
           'Super Code (Inventory Screen. Use R1, R2, L1, L2)')
    if key not in by_cheat:
        return
    hook, body = by_cheat[key]
    print()
    print('== the most interesting one: Resident Evil 2, "Super Code" ==')
    print('  Two Supercodes.  The first overwrites four instructions of the')
    print('  game with a jump; the second parks 161 bytes in kernel RAM and')
    print('  jumps back.  A hook, hand-written, with a data table in its tail.')
    print()
    print('  %s -> %d bytes at %08X' % (hook.header.hex().upper(),
                                        hook.declared, 0x80000000 | hook.addr))
    for line in listing(hook):
        print(line)
    notes = {
        0x80007690: '; three of the four game instructions the hook',
        0x80007694: '; displaced, run here instead',
        0x8000769C: '; scratch: unused kernel RAM at 4, 8, 0x10, 0x18',
        0x800076AC: '; $s0+0xC = the selected inventory slot',
        0x800076B0: '; $v1 = the inventory array',
        0x800076B4: '; the debounce counter lives at address 0',
        0x800076BC: '; still counting down? then do nothing',
        0x800076C8: '; ... and leave',
        0x800076CC: '; the pad word',
        0x800076D0: '; &inventory[slot], four bytes per slot',
        0x800076D4: '; L2 R2 L1 R1',
        0x800076D8: '; the delta table at 0x7728, below',
        0x800076E4: '; 0x104 >> buttons',
        0x800076E8: '; 1 for two of the four: take the count byte',
        0x800076EC: '; delta = table[buttons]',
        0x800076F0: '; the item id byte, or the count byte beside it',
        0x800076FC: '; add the delta to it',
        0x80007700: '; and store it back',
        0x80007704: '; re-arm the debounce for 10 passes',
        0x80007714: '; the fourth displaced game instruction',
        0x80007720: '; back into the game, 0x10 past the trampoline',
        0x80007728: '; the delta table: 00 FF FF 00 00 00 00 01 01',
        0x8000772C: '; ... not code; the lb above indexes it',
    }
    print()
    print('  %s -> %d bytes at %08X' % (body.header.hex().upper(),
                                        body.declared, 0x80000000 | body.addr))
    for line in listing(body, lambda a: '  ' + notes[a] if a in notes else ''):
        print(line)
    # The hook really is a hook: the trampoline names the body, and the body's
    # last jump lands 0x10 past the trampoline - the four words it overwrote.
    tramp = disassemble(*hook.code)
    assert tramp[0][1] >> 16 == 0x3C02 and (tramp[0][1] & 0xFFFF) == 0x8000
    assert (tramp[1][1] & 0xFFFF) == body.addr, tramp[1]
    back = disassemble(*body.code)
    lui = next(w for _, w, _ in back if w >> 16 == 0x3C02)   # lui $v0, hi
    ori = next(w for _, w, _ in back if w >> 16 == 0x3442)   # ori $v0, $v0, lo
    target = ((lui & 0xFFFF) << 16) | (ori & 0xFFFF)
    assert target == (0x80000000 | hook.addr) + 0x10, hex(target)
    print()
    print('  the trampoline names %08X, and the body returns to %08X = the'
          % (0x80000000 | body.addr, target))
    print('  trampoline + 0x10, the four words it overwrote.  Two-stage hook.')


def show_megacodes(all_blocks):
    print()
    print('== the Megacode handlers ==')
    ok = {}
    for b in all_blocks:
        if b.type != 6 or len(b.payload) < 12:
            continue
        data, base = b.code
        words = [w for _, w, _ in disassemble(data, base)]
        has = dict(rfe=0x42000010 in words,
                   epc_plus_4=any(w == 0x275A0004 for w in words),
                   disarm=any(w == 0x40803800 for w in words),
                   jr_k0=any(w == 0x03400008 for w in words))
        key = (b.type, b.payload)
        if key in ok:
            continue
        ok[key] = has
        print('  %-20s %-24s %s' % (b.db, expand(b.cheat)[:24],
                                    ' '.join('%s=%s' % (k, 'y' if v else 'n')
                                             for k, v in has.items())))
    # Only Bloody Roar's handler pops the SR exception stack.  The two that do
    # not leave IEc clear on return - the R3000 never restores it by itself.
    good = [h for h in ok.values() if h['rfe']]
    assert len(ok) == 6, len(ok)          # 3 sound handlers + 3 corrupt copies
    assert len(good) == 1, len(good)
    print('  exactly %d of %d distinct Megacode payloads ends in rfe'
          % (len(good), len(ok)))


def show_noncode(all_blocks):
    print()
    print('== payloads that are not code ==')
    found = []
    for b in all_blocks:
        p = b.payload
        if not p:
            continue
        printable = sum(1 for c in p if 0x20 <= c < 0x7F or c == 0)
        if printable == len(p) and printable > 8:
            found.append((b, p.rstrip(b'\0').decode('latin-1')))
    for b, s in found:
        print('  %s | %s | %s' % (b.db, expand(b.game), expand(b.cheat)))
        print('      %d bytes at %08X: %r' % (len(b.payload),
                                              0x80000000 | b.addr, s))
    assert len(set(b.payload for b, _ in found)) == 1, found
    assert found[0][1] == '/future/console/design/', found[0][1]
    print('  one, in four databases: the vendor\'s own name, written into '
          'Rayman\'s RAM.')


# ------------------------------------------------------------------------ main

def main(verbose):
    dbs = list(databases())
    if not dbs:
        print('skipped: no roms/ and no %s' % TENTH)
        return 0
    if len(dbs) != len(EXPECT_CENSUS):
        print('  %d database(s), expected %d - drop the firmware dumps in roms/'
              % (len(dbs), len(EXPECT_CENSUS)))
        return 1
    all_blocks = [b for label, db in dbs for b in blocks(db, label)]
    by_cheat = collections.defaultdict(list)
    for b in all_blocks:
        by_cheat[(b.db, b.game, b.cheat)].append(b)

    tot = census(all_blocks, [l for l, _ in dbs])
    assert tot == [51, 14, 0], tot
    report_blocks(all_blocks, verbose)
    bad = report_malformed(all_blocks)
    assert len(all_blocks) - len(bad) == 62, len(all_blocks)
    report_addresses(all_blocks)
    report_corruption(by_cheat)
    show_megacodes(all_blocks)
    show_noncode(all_blocks)
    report_notes()
    report_xlink(by_cheat)
    show_resident_evil(by_cheat)
    print()
    print('%d blocks, %d well formed, %d corrupt as shipped - all checks passed'
          % (len(all_blocks), len(all_blocks) - len(bad), len(CORRUPT)))
    return 0


if __name__ == '__main__':
    sys.exit(main('-v' in sys.argv))
