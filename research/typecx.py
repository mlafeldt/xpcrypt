#!/usr/bin/env python3
"""Type 2 and type C: closing the two questions ENGINE.md 16 left open.

    uv run --with capstone python typecx.py [-v]

ENGINE.md 16 says of type 2 "no handler, no route, no specimen, no reference in
any staging path - nothing here says what it was for", and of the Japanese Pro's
type C joker codes "a build we do not have, FCD's PC tooling, or an import from
another device are all consistent with what is here".  This script is the
evidence for narrowing both, and it asserts every number in it.

What it adds to the corpus and to the argument:

  * a **tenth firmware image** - `pc/ROMS/Xteng.fcd`, release 2.005, the ROM the
    DOS tool ships to flash.  Same eleven-type engine, and a sixth database of
    1,668 cheats that nothing here had ever counted;
  * a **wider classifier scan**.  ENGINE.md 13 enumerates one idiom, `andi
    rX, rY, 0xF0`.  Three are enumerated here - that one, `srl rX, rY, 0x1C`
    (which is how the engine itself does it) and `andi rX, rY, 0xF000`.  Union
    over ten images: types 3 to F except C.  The idioms cannot see whole-byte
    compares, and that is where C is looked at: the pass-4 normaliser turns a
    `C0` line into a type 7 guard in all ten images, executed here.  Nothing
    anywhere looks at 2;
  * the **three conventions** the 27 shipped type C lines split into, each
    checked rather than described: 17 filler lines that share a byte 0, 4 lines
    in the USA database that are *disabled type 8 codes* - re-type the first
    nibble to 8, decrypt with the key the line's own flag nibble declares, and
    the address is exactly the address of the type 8 line below it - and 6
    Japanese joker codes.  The first two carry a flag nibble (`CD`, `C6`) and
    stay inert; the jokers are stored `C0` and work, as type 7 guards;
  * **two joker conventions in one database.**  The Japanese Pro database tests
    the pad in two mutually inconsistent ways.  Five cheats use type 7 with an
    active-high mask in the byte order FCD's own tool documents; six use type C
    with an active-low mask in the *hardware's* byte order.  Both are decoded
    here against the buttons their Japanese cheat names name;
  * **FCD's own joypad table and joker generator, out of `XLink.exe`.**  The
    "PlayStation Joypad Values" table the tool prints is the pad halfword
    byte-swapped, and the Advanced Code Generator's Joker emits types 7, 9 and
    3.  Never type C.  So type C is not what FCD's tooling produces;
  * the **X-Terminator**, which turns out not to be another device at all: it is
    the Japanese name of this one.  Seven brand strings in the packed firmware,
    the same seven places in all three languages, reading Xplorer / Xploder /
    X-Terminator.

Everything asserted here is drawn from the binaries in `roms/` and `pc/`; no
network. For the off-corpus corroboration - that every contemporary write-up of
the format documented type C as a Datel-compatibility if-then conditional, which
is what the firmware makes of a `C0` line, and that psx-spx lists X-Terminator
(Japan) as one device with the Xplorer/Xploder - see ENGINE.md 16, which cites
the web sources.

`ENGINE.md` has the instruction set, `dbtypes.py` the per-type database counts,
`engine.py` the dispatch chains, `ENCRYPT.md` and `FCD.md` the PC binaries.
"""
import collections
import os
import re
import struct
import sys
import tempfile

import db2
import dbtypes
import engine
import engineemu
import fwimage
import mipscan
import romcrypt
import xlink

VERBOSE = '-v' in sys.argv[1:]

TENTH = os.path.join('pc', 'ROMS', 'Xteng.fcd')
XLINK = os.path.join('pc', 'XLink.exe')
KILLER = os.path.join('pc', 'x-killer.exe')
WIN = [os.path.join('pc', f) for f in ('Xlink95.exe', 'Xlink95-19990702.exe')]

problems = []

# Several numbers here are properties of *this* corpus - ten images, six
# databases, 17,183 code lines, 27 type C records.  They are conditions of exit
# status 0 when the whole corpus is on disk and are skipped, loudly, when it is
# not, because `roms/` and `pc/` are gitignored and a partial run must not claim
# to have checked something it could not see.
FULL = False


def check(ok, why):
    if not ok:
        problems.append(why)
    return ok


def check_full(ok, why):
    """`check`, but only when the whole corpus is present."""
    return check(ok, why) if FULL else ok


def say(*a):
    if VERBOSE:
        print(*a)


def fmt(c):
    return '%02X%02X%02X%02X %02X%02X' % tuple(c)


def jp(s):
    """A database name back to the Shift-JIS it was stored as."""
    try:
        return s.encode('latin-1').decode('cp932')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


# --------------------------------------------------------------- the corpus

def tenth_plaintext():
    """`pc/ROMS/Xteng.fcd` decrypted to a temporary file, or None.

    It is an image in its own right - release 2.005, between the 2.004 and 2.008
    in `roms/` - and it is the only one whose plaintext is nowhere else.
    """
    if not os.path.exists(TENTH):
        return None
    import fcdcrypt
    raw = fcdcrypt.decrypt(bytearray(open(TENTH, 'rb').read()))
    tf = tempfile.NamedTemporaryFile(suffix='.dec', delete=False)
    tf.write(raw)
    tf.close()
    return tf.name


def tenth_database(path):
    """The 2.005 record chain, via `rom2005.records`.

    `db2.find_db` returns nothing for this image: one game record in it declares
    zero cheats and `db2.parse_db` rejects that outright.  `rom2005.py` is the
    file about that image and about that byte; this only borrows its walk.
    """
    import rom2005
    rom = open(path, 'rb').read()
    for at in (rom2005.EXPECT_CHAIN,):
        try:
            cheats, _empty, _term = rom2005.records(rom, at)
        except (ValueError, IndexError):
            continue
        if len(cheats) > 50:
            return cheats
    return None


def databases(tenth):
    """[(label, [(game, cheat, [six-byte lines]), ...]), ...] - six of them."""
    for fn, label in dbtypes.ROMS:
        rom = open(os.path.join('roms', fn), 'rb').read()
        _, db = db2.find_db(rom)
        if db:
            yield label, db
    if tenth:
        db = tenth_database(tenth)
        if db:
            yield 'Xplorer 2.005 UK', db


# --------------------------------------------- 1. no handler, no classifier

# Three ways this compiler isolates a type nibble, and the shift each leaves it
# at.  ENGINE.md 13 enumerates the middle one only; the engine itself uses the
# first, and the third turns up in the menu.  A classifier written as a range
# test or a jump table would still not appear - this is a lower bound on where a
# type is looked at, which is exactly what a negative result needs to be.
IDIOMS = {'srl28': 0, 'andi f0': 4, 'andi f000': 12}
CONST = re.compile(r'^\$\w+, \$zero, (0x[0-9a-f]+|\d+)$')
BACK, FWD = 32, 400


def classifier_sites(ins):
    for k, i in enumerate(ins):
        if i.mnemonic == 'srl' and i.op_str.endswith('0x1c'):
            yield k, 'srl28'
        elif i.mnemonic == 'andi' and i.op_str.endswith(', 0xf0'):
            yield k, 'andi f0'
        elif i.mnemonic == 'andi' and i.op_str.endswith(', 0xf000'):
            yield k, 'andi f000'


def classifiers(path):
    """[(address, idiom, [type nibble tested, ...]), ...] for one image."""
    img, base = fwimage.load(path)
    ins = mipscan.dis(img, base)
    out = []
    for k, kind in classifier_sites(ins):
        shift = IDIOMS[kind]
        reg = ins[k].op_str.split(',')[0]
        seen, consts = [], {}
        for j in range(max(0, k - BACK), min(len(ins), k + FWD)):
            x = ins[j]
            if x.mnemonic in ('addiu', 'ori'):
                m = CONST.match(x.op_str)
                if m:
                    consts[x.op_str.split(',')[0]] = int(m.group(1), 0)
                    continue
            if x.mnemonic in ('beq', 'bne'):
                a, b = x.op_str.split(', ')[:2]
                other = b if a == reg else a if b == reg else None
                if other in consts:
                    v = consts[other]
                    if v and v <= (0xF << shift) and not v & ((1 << shift) - 1):
                        t = v >> shift
                        if t not in seen:
                            seen.append(t)
        out.append(('%08X' % ins[k].address, kind, seen))
    return out


# The idioms above all isolate a nibble.  The last staging pass does not: every
# line it emits goes through a normaliser after decryption, and that compares
# whole first bytes - so it is invisible to all three, and it is where type C
# is looked at.  `engine.normaliser` finds it and `engineemu.Stager` runs it, and
# which types it rewrites is measured here by executing it over one line of
# each type at an odd address, not read off its constants.
NORM_TYPES = {0x0, 0x3, 0x7, 0x8, 0xB, 0xC, 0xD}


def normalised_types(stager):
    out = set()
    for t in range(16):
        c = '%X0100001 ABCD' % t
        if stager.normalise(c) != c:
            out.add(t)
    return out


def part1(paths):
    print('== 1. handlers and classifiers, in ten images ==')
    union, norm = set(), set()
    for label, path in paths:
        chain = [t for t, _ in engine.dispatch(path)]
        sites = classifiers(path)
        u = sorted({t for _, _, v in sites for t in v})
        union |= set(u)
        st = engineemu.Stager(path, label)
        nt = normalised_types(st)
        norm |= nt
        check(not ({1, 2, 0xC} & set(chain)),
              '%s: dispatch chain contains 1, 2 or C' % label)
        check(2 not in u, '%s: a classifier reads type 2' % label)
        check(nt == NORM_TYPES, '%s: the normaliser rewrites types %s, expected %s'
              % (label, ' '.join('%X' % t for t in sorted(nt)),
                 ' '.join('%X' % t for t in sorted(NORM_TYPES))))
        check(st.normalise('C006A2EA B7FF') == '7006A2EA B7FF',
              '%s: a C0 line does not come out as a type 7' % label)
        print('  %-28s engine %-22s classifiers %2d sites, types %-24s '
              'normaliser %08X rewrites %s'
              % (label, ' '.join('%X' % t for t in chain), len(sites),
                 ' '.join('%X' % t for t in u), st.norm,
                 ' '.join('%X' % t for t in sorted(nt))))
        for a, k, v in sites:
            say('       %s %-9s %s' % (a, k, ' '.join('%X' % x for x in v)
                                       or '(constant not resolved)'))
    every = union | norm
    print('  union over the corpus: idioms %s; with the normaliser %s'
          % (' '.join('%X' % t for t in sorted(union)),
             ' '.join('%X' % t for t in sorted(every))))
    print('      -> C is looked at, by whole byte: a C0 line leaves staging as a '
          'type 7.\n         Nothing in ten images looks at 1 or 2.')
    check_full(union == set(range(3, 16)) - {0xC},
          'classifier union is %s, expected 3..F without C'
          % ' '.join('%X' % t for t in sorted(union)))
    check_full(every == set(range(16)) - {1, 2},
          'union with the normaliser is %s, expected everything but 1 and 2'
          % ' '.join('%X' % t for t in sorted(every)))


# ------------------------------------------------------- 2. no type 2 anywhere

def census(dbs):
    print('\n== 2. six databases, no type 2 in any of them ==')
    tot, lines = collections.Counter(), 0
    for label, db in dbs:
        c = collections.Counter()
        for _, _, ls in db:
            for _, code, role in dbtypes.walk(ls):
                if role == 'code':
                    c[code[0] >> 4] += 1
        tot += c
        lines += sum(c.values())
        print('  %-22s %5d code lines   type 2: %d   type C: %d'
              % (label, sum(c.values()), c[2], c[0xC]))
    print('  %-22s %5d code lines   type 2: %d   type C: %d'
          % ('total', lines, tot[2], tot[0xC]))
    check_full(tot[2] == 0, 'type 2 appears %d times' % tot[2])
    check_full(tot[0xC] == 27, 'type C appears %d times, expected 27' % tot[0xC])
    check_full(lines == EXPECT_LINES,
          '%d code lines over six databases, expected %d' % (lines, EXPECT_LINES))
    return tot


EXPECT_LINES = 17183          # 14,939 in the five of ENGINE.md 8, 2,244 more in 2.005


# ------------------------------------------------- 3. what the type C lines are

# The PlayStation pad halfword, as the hardware returns it and as an `lhu`
# reads it: bit clear = pressed.
RAW = {0: 'Select', 1: 'L3', 2: 'R3', 3: 'Start', 4: 'Up', 5: 'Right',
       6: 'Down', 7: 'Left', 8: 'L2', 9: 'R2', 10: 'L1', 11: 'R1',
       12: 'Triangle', 13: 'Circle', 14: 'Cross', 15: 'Square'}
# ... and the same table byte-swapped, which is what XLink.exe prints as
# "PlayStation Joypad Values" (asserted in part 5) and what its own generators
# expect.
SWAPPED = {b: RAW[(b + 8) % 16] for b in range(16)}

# Buttons a Japanese cheat name can name.  Only applied to the cheats already
# selected as button tests, because a name like `ショットセレクト` ("shot
# select") is not talking about the Select button.
JP_BUTTON = [('セレクト', 'Select'), ('スタート', 'Start'),
             ('L1', 'L1'), ('L2', 'L2'), ('R1', 'R1'), ('R2', 'R2'),
             ('×', 'Cross'), ('○', 'Circle'), ('△', 'Triangle'),
             ('□', 'Square'), ('上', 'Up'), ('下', 'Down'),
             ('左', 'Left'), ('右', 'Right')]


def named_buttons(name):
    return {b for tok, b in JP_BUTTON if tok in name}


def clear_bits(v):
    return [b for b in range(16) if not v >> b & 1]


def set_bits(v):
    return [b for b in range(16) if v >> b & 1]


def part3(dbs):
    print('\n== 3. the 27 type C lines are three different conventions ==')
    filler, disabled, joker = [], [], []
    for label, db in dbs:
        for game, cheat, ls in db:
            w = dbtypes.walk(ls)
            for i, code, role in w:
                if role != 'code' or code[0] >> 4 != 0xC:
                    continue
                stored = list(ls[i])
                nxt = romcrypt.decrypt(list(ls[i + 1])) if i + 1 < len(ls) else None
                rec = (label, game, cheat, stored, nxt)
                # Sorted by what the line *is*, not by which database it came
                # from - and, for the jokers, not by the answer either: they are
                # picked out by their *cheat name* naming pad buttons, and the
                # decoding is then the result rather than the criterion.
                as8 = romcrypt.decrypt([0x80 | (stored[0] & 0x0F)] + stored[1:])
                if nxt is not None and as8[1:4] == nxt[1:4]:
                    disabled.append(rec)       # a code with its type turned off
                elif named_buttons(jp(cheat)):
                    joker.append(rec)          # the cheat name names buttons
                else:
                    filler.append(rec)         # the name is the whole message

    # (a) filler.  The cheat name is the message and the code line only exists
    # because a cheat entry needs one.  Seventeen of them, and every one shares
    # byte 0 and the top address nibble - one line copied and edited, not
    # seventeen independent decisions.
    print('  (a) filler, %d lines' % len(filler))
    check_full(len(filler) == 17, 'expected 17 filler lines, got %d' % len(filler))
    check(all(r[3][0] == 0xCD and r[3][1] >> 4 == 0xE for r in filler),
          'the filler lines do not all read CD E?')
    for r in filler[:3] if not VERBOSE else filler:
        print('      %-22s %-28s %s' % (r[0], r[2][:28], fmt(r[3])))

    # (b) disabled code.  Four lines in the USA database, all in Wipeout.  Put
    # an 8 back in the type nibble and decrypt with the key the line's own flag
    # nibble declares, and out comes the address of the type 8 line below it.
    # A code turned off by giving it a type nothing implements, its ciphertext
    # left intact.
    print('  (b) disabled type 8 codes, %d lines' % len(disabled))
    check_full(len(disabled) == 4, 'expected 4, got %d' % len(disabled))
    for label, game, cheat, stored, nxt in disabled:
        as8 = romcrypt.decrypt([0x80 | (stored[0] & 0x0F)] + stored[1:])
        ok = nxt is not None and as8[1:4] == nxt[1:4]
        print('      %-16s %-16s stored %s -> as type 8 %s   next %s  %s'
              % (game.strip(), cheat.strip(), fmt(stored), fmt(as8),
                 fmt(nxt) if nxt else '-', 'same address' if ok else 'DIFFERENT'))
        check(ok, '%s / %s: re-typed line does not share its neighbour address'
              % (game, cheat))

    # (c) joker.  Six lines, two games, two address ranges.  Decoded against the
    # buttons the Japanese cheat name names - under the hardware's byte order,
    # and under the byte order FCD's own tool documents.  One of them is right
    # six times out of six and the other none.
    print('  (c) joker codes, %d lines - every type C line whose cheat name '
          'names a button' % len(joker))
    check_full(len(joker) == 6, 'expected 6, got %d' % len(joker))
    raw_ok = swap_ok = 0
    for label, game, cheat, stored, nxt in joker:
        name = jp(cheat)
        want = named_buttons(name)
        v = (stored[4] << 8) | stored[5]
        got_raw = {RAW[b] for b in clear_bits(v)}
        got_swap = {SWAPPED[b] for b in clear_bits(v)}
        raw_ok += got_raw == want
        swap_ok += got_swap == want
        print('      %-22s %s  name says %-22s hardware order %-22s swapped %s'
              % (jp(game)[:22], fmt(stored), '+'.join(sorted(want)),
                 '+'.join(sorted(got_raw)), '+'.join(sorted(got_swap))))
    print('      -> hardware byte order %d/6, FCD\'s own byte order %d/6'
          % (raw_ok, swap_ok))
    check_full(raw_ok == 6, 'the joker masks do not decode in the hardware byte order')
    check_full(swap_ok == 0, 'the joker masks also decode in the swapped byte order')

    # What the cartridge makes of all 27, by running the Japanese firmware's own
    # pass-4 normaliser over each decrypted line.  It matches whole first bytes:
    # the filler and the disabled codes carry a flag nibble (CD, C6) and pass
    # through untouched, so the engine skips them; the jokers are stored C0, the
    # cipher copies them, and each leaves staging as a type 7 equality guard over
    # the write below it.
    jpro = os.path.join('roms', 'xtjpro.dec')
    if os.path.exists(jpro):
        st = engineemu.Stager(jpro)
        same = lambda r: st.normalise(fmt(romcrypt.decrypt(list(r[3]))))
        inert = sum(same(r) == fmt(r[3]) for r in filler + disabled)
        live = sum(same(r)[:2] == '70' for r in joker)
        for r in joker:
            say('      %s -> staged %s' % (fmt(r[3]), same(r)))
        print('  staged by Pro 2.14\'s own normaliser: %d/%d filler and disabled '
              'lines untouched,\n      %d/%d jokers come out as type 7 guards'
              % (inert, len(filler) + len(disabled), live, len(joker)))
        check(inert == len(filler) + len(disabled),
              'the normaliser rewrites a filler or disabled type C line')
        check(live == len(joker), 'a joker is not staged as a type 7 guard')
    return joker


# ------------------------- 4. two joker conventions in the Japanese database

SHOULDER = ('L1', 'L2', 'R1', 'R2')
# XLink.exe's own "Reverse Value" column, asserted against the binary in part 5.
FCD_REVERSE = {'L2': 0x0001, 'R2': 0x0002, 'L1': 0x0004, 'R1': 0x0008,
               'Triangle': 0x0010, 'Circle': 0x0020, 'Cross': 0x0040,
               'Square': 0x0080, 'Select': 0x0100, 'Start': 0x0800,
               'Up': 0x1000, 'Right': 0x2000, 'Down': 0x4000, 'Left': 0x8000}


def part4(dbs):
    print('\n== 4. the Japanese database tests the pad two different ways ==')
    jpdb = [db for label, db in dbs if label.endswith('JP')]
    if not check(jpdb, 'the Japanese Pro database is not in the corpus'):
        return
    hits = []
    for game, cheat, ls in jpdb[0]:
        w = dbtypes.walk(ls)
        codes = [c for _, c, r in w if r == 'code']
        if not codes or codes[0][0] >> 4 != 7:
            continue
        name = jp(cheat)
        if not any(t in name for t in SHOULDER):
            continue
        hits.append((game, name, codes[0]))
    print('  type 7 button tests: %d' % len(hits))
    check_full(len(hits) == 5, 'expected 5 type 7 button tests, got %d' % len(hits))
    ok = 0
    for game, name, code in hits:
        want = named_buttons(name)
        v = (code[4] << 8) | code[5]
        mask = sum(FCD_REVERSE[b] for b in want)
        ok += v == mask
        print('      %-16s %-34s %s  value %04X  FCD reverse mask %04X  %s'
              % (jp(game)[:16], name[:34], fmt(code), v, mask,
                 'match' if v == mask else 'MISMATCH'))
    print('      -> active-high, FCD byte order, %d/%d' % (ok, len(hits)))
    check(ok == len(hits),
          'the type 7 button masks are not FCD\'s own reverse values')
    print('  so: type 7 guards use FCD\'s published values, active high;')
    print('      type C guards use the raw pad halfword, active low.')


# ------------------------------- 5. what FCD's own tooling does with a joker

def load_xlink():
    raw = open(XLINK, 'rb').read()
    objs = xlink.load_le(XLINK, raw)
    code = min(objs)
    data = max(objs)
    return objs, code, data


def data_xref(code_blob, code_base, data_base, addr):
    """Call sites holding `addr` as its offset within the data object.

    LE fixups are not applied (see `xlink.py`), so an absolute data reference
    still reads as the target's offset inside its own object.
    """
    pat = struct.pack('<I', addr - data_base)
    return [code_base + m.start() for m in re.finditer(re.escape(pat), code_blob)]


def part5():
    print('\n== 5. FCD\'s own joypad table and joker generator (XLink.exe) ==')
    if not os.path.exists(XLINK):
        print('  pc/XLink.exe not present - skipped')
        return
    import capstone
    objs, code_base, data_base = load_xlink()
    code, data = objs[code_base], objs[data_base]

    # (a) the "PlayStation Joypad Values" table.  Found by its button-name
    # pointer array; the two value columns sit at fixed offsets below it, which
    # is how the printing loop at 0x26C07 addresses them.
    names = [b'X (Cross)', b'O (Circle)', b'/\\ (Triangle)', b'[] (Square)',
             b'Left 1', b'Left 2', b'Right 1', b'Right 2', b'Start', b'Select',
             b'Up', b'Down', b'Left', b'Right']
    ptrs = []
    for n in names:
        m = re.search(re.escape(n + b'\0'), data)
        if not check(m, 'XLink.exe: no button name %r' % n):
            return
        ptrs.append(m.start())
    tbl = struct.pack('<%dI' % len(ptrs), *ptrs)
    at = data.find(tbl)
    if not check(at >= 0, 'XLink.exe: no button-name pointer table'):
        return
    normal = struct.unpack_from('<14H', data, at - 0x38)
    reverse = struct.unpack_from('<14H', data, at - 0x1C)
    label = {b'X (Cross)': 'Cross', b'O (Circle)': 'Circle',
             b'/\\ (Triangle)': 'Triangle', b'[] (Square)': 'Square',
             b'Left 1': 'L1', b'Left 2': 'L2', b'Right 1': 'R1',
             b'Right 2': 'R2', b'Start': 'Start', b'Select': 'Select',
             b'Up': 'Up', b'Down': 'Down', b'Left': 'Left', b'Right': 'Right'}
    print('  "PlayStation Joypad Values", %d entries at data+%#x' % (len(ptrs), at))
    swapped = 0
    for i, n in enumerate(names):
        who = label[n]
        lo, hi = clear_bits(normal[i]), set_bits(reverse[i])
        one = len(lo) == 1 and lo == hi
        swapped += one and SWAPPED[lo[0]] == who
        print('      %-10s normal %04X  reverse %04X  bit %2d  hardware layout '
              'calls that bit %s' % (who, normal[i], reverse[i],
                                     lo[0] if lo else -1,
                                     RAW[lo[0]] if lo else '-'))
        check(one, 'XLink joypad table: %s is not one bit' % who)
        check(FCD_REVERSE[who] == reverse[i],
              'XLink joypad table: %s reverse %04X, expected %04X'
              % (who, reverse[i], FCD_REVERSE[who]))
    check(swapped == 14,
          'XLink\'s table is not the hardware layout byte-swapped (%d/14)' % swapped)
    print('      -> every entry is the hardware pad bit + 8 (mod 16), so the '
          'table is\n         the pad halfword byte-swapped.  That is FCD\'s '
          'convention for its own\n         generators; whether it was anyone '
          'else\'s is not settled by this binary.')

    # (b) the Advanced Code Generator's Joker.  Found by its own comment header,
    # then read for the constants it puts in a code's first byte.
    m = re.search(re.escape(b'//\r\n// ACG CodeType : Joker'), data)
    if not check(m, 'XLink.exe: no ACG Joker header string'):
        return
    refs = data_xref(code, code_base, data_base, data_base + m.start())
    if not check(refs, 'XLink.exe: ACG Joker header is never referenced'):
        return
    calls = xlink.call_targets([(code_base, code)])
    start = max(t for t in calls if t <= refs[0])
    after = sorted(t for t in calls if t > start)
    end = after[0] if after else code_base + len(code)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    nibbles = set()
    for i in md.disasm(code[start - code_base:end - code_base], start):
        if i.mnemonic != 'or':
            continue
        v = re.search(r', (0x[0-9a-f]+)$', i.op_str)
        if v and int(v.group(1), 16) in {x << 4 for x in range(16)}:
            nibbles.add(int(v.group(1), 16) >> 4)
            say('      %08X  or %s' % (i.address, i.op_str))
    print('  ACG Joker generator at %08X emits type nibbles %s'
          % (start, ' '.join('%X' % n for n in sorted(nibbles))))
    check(nibbles == {7, 9, 3},
          'the ACG Joker emits %s, expected 7 9 3'
          % ' '.join('%X' % n for n in sorted(nibbles)))
    print('      -> a joker out of FCD\'s own tool is a type 7 or type 9 guard '
          'over a\n         type 3 write.  It is never a type C.')


# ---------------------------------------------- 6. the X-Terminator is this one

BRANDS = [('roms/xteng.dec', 'Xplorer'), ('roms/xtger.dec', 'Xploder'),
          ('roms/xtepro.dec', 'Xplorer'), ('roms/xtjpro.dec', 'X-Terminator')]

# The one brand string that is *not* localised: the processor-exception banner
# on the two Pro builds, which the Japanese one carries in English like the UK
# one.  It is a crash screen, not UI, and counting it would hide the result.
NOT_LOCALISED = b'** Xplorer 2 (c) FCD 1997/98 **'


def returns_zero(code, code_base, at, limit=0x40):
    """True if the function at `at` is `xor eax, eax` and nothing else.

    Watcom left 14 bytes of `lea r, [r]` padding in the middle of this one,
    which is why it is walked rather than matched as three bytes.
    """
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    first = True
    for i in md.disasm(code[at - code_base:at - code_base + limit], at):
        if first:
            if (i.mnemonic, i.op_str) != ('xor', 'eax, eax'):
                return False
            first = False
            continue
        if i.mnemonic == 'ret':
            return True
        if i.mnemonic == 'nop':
            continue
        if i.mnemonic == 'lea' and re.fullmatch(r'(e\w\w), \[\1\]', i.op_str):
            continue
        if i.mnemonic == 'mov' and re.fullmatch(r'(e\w\w), \1', i.op_str):
            continue
        return False
    return False


def part6():
    print('\n== 6. "X-Terminator" is the Japanese name of this cartridge ==')
    if not all(os.path.exists(p) for p, _ in BRANDS):
        print('  roms/ incomplete - skipped')
    else:
        for path, brand in BRANDS:
            img, _ = fwimage.load(path)
            img = img.replace(NOT_LOCALISED, b'')
            counts = {b: img.count(b.encode())
                      for b in ('Xplorer', 'Xploder', 'X-Terminator')}
            print('  %-14s %s' % (os.path.basename(path),
                                  '  '.join('%s=%d' % kv for kv in counts.items())))
            check(counts[brand] == 7,
                  '%s: %d occurrences of %s, expected 7'
                  % (path, counts[brand], brand))
            check(sum(v for k, v in counts.items() if k != brand) == 0,
                  '%s carries a brand name other than %s' % (path, brand))
        print('      -> the same seven strings in three languages, with the '
              'product name\n         localised.  The Japanese UI says '
              '"X-Terminator plug-in CD" exactly\n         where the UK one '
              'says "Xplorer Plugin CD`s".')

    if os.path.exists(XLINK):
        objs, code_base, data_base = load_xlink()
        code, data = objs[code_base], objs[data_base]
        banners = {}
        for tag in (b'// X-Terminator Codes', b'// Xplorer Codes'):
            m = re.search(re.escape(tag), data)
            if not check(m, 'XLink.exe: no %r banner' % tag):
                return
            banners[tag] = data_base + m.start()
        print('  XLink.exe carries both saved-code banners: %s'
              % ', '.join('%s at %08X' % (t.decode()[3:], a)
                          for t, a in banners.items()))
        first = min(data_xref(code, code_base, data_base, a)[0]
                    for a in banners.values())
        stub = None
        for off in range(first - 0x40, first):
            if code[off - code_base] != 0xE8:
                continue
            rel, = struct.unpack_from('<i', code, off - code_base + 1)
            t = off + 5 + rel
            if code_base <= t < code_base + len(code) and returns_zero(code, code_base, t):
                stub = t
        print('  the branch ahead of them calls %s, a function whose whole '
              'body is `xor eax, eax` and a `ret`'
              % ('%08X' % stub if stub else '(not found)'))
        check(stub is not None,
              'XLink.exe: no always-zero device predicate before the banners')
        print('      -> one runtime predicate picks the banner, and in this UK '
              'build it is\n         a stub returning 0.  Everything downstream '
              'of it is a name and a\n         contact address - no second code '
              'format, no second cipher.')

    for p in WIN:
        if os.path.exists(p):
            raw = open(p, 'rb').read()
            n = raw.count(b'X-Terminator') + raw.count(b'Gametech')
            print('  %-22s X-Terminator/Gametech strings: %d'
                  % (os.path.basename(p), n))
            check(n == 0, '%s mentions the X-Terminator' % p)


# --------------------------------------- 7. what a contemporary stranger thought

KILLER_TYPES = [
    (b' "0" : supported - write dword [0000xxxx]', '0'),
    (b' "1" : ??', '1'),
    (b' "2" : ??', '2'),
    (b' "3" : supported - write byte [xx]', '3'),
    (b' "4" : supported - slow motion code', '4'),
    (b' "5" : not supported - super code (write bytes)', '5'),
    (b' "6" : not supported - mega code (insert asm)', '6'),
    (b' "7" : supported - skip if false, 1 code', '7'),
    (b' "8" : supported - write word [xxxx]', '8'),
    (b' "9" : supported - skip if true', '9'),
    (b' "A" : ??', 'A'),
    (b' "B" : supported - slide code (repeat)', 'B'),
    (b' "C" : supported - Datel code, obsolete', 'C'),
    (b' "D" : supported - Datel code, obsolete', 'D'),
    (b' "E" : ??', 'E'),
    (b' "F" : supported - skip if false, all cheats', 'F'),
]


def part7():
    print('\n== 7. x-killer.exe, a stranger\'s reading of the same format, 1999 ==')
    if not os.path.exists(KILLER):
        print('  pc/x-killer.exe not present - skipped')
        return
    raw = open(KILLER, 'rb').read()
    missing = [t for s, t in KILLER_TYPES if raw.find(s) < 0]
    for s, t in KILLER_TYPES:
        print('     %s' % s.decode())
    check(not missing,
          'x-killer.exe: type list entries %s not found' % ' '.join(missing))
    print('      -> a stranger writing down the same format in 1999 had "??" '
          'against\n         exactly 1, 2, A and E, and called C and D obsolete '
          'Datel\n         compatibility.  He is right about every type the '
          'engine implements,\n         and about C and D as well: neither has '
          'an engine handler, but staging\n         turns a C0 into a type 7 '
          'guard and a D0 into a 7 or a hoisted F.  What\n         he could not '
          'have known is that a C or D with its flag nibble set does\n'
          '         nothing.  Nothing anywhere in his binary dispatches on a type '
          'nibble,\n         so this is his documentation of the format, not '
          'his implementation of it.')


# ---------------------------------------------------------------------- main

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    tenth = tenth_plaintext()
    paths = [(os.path.basename(p), p) for p in engine.ROMS]
    if tenth:
        paths.append(('Xteng.fcd (2.005)', tenth))
    if not paths:
        print('no firmware images present (roms/ and pc/ are gitignored) - '
              'nothing to check')
        return 0
    global FULL
    FULL = len(paths) == 10
    print('corpus: %d firmware image(s)%s'
          % (len(paths), '' if FULL else '  - PARTIAL, the corpus-wide counts '
             'below are reported but not asserted'))
    try:
        part1(paths)
        dbs = list(databases(tenth))
        FULL = FULL and len(dbs) == 6
        check_full(len(dbs) == 6, '%d databases, expected 6' % len(dbs))
        census(dbs)
        part3(dbs)
        part4(dbs)
        part5()
        part6()
        part7()
    finally:
        if tenth:
            os.unlink(tenth)

    print('\n== verdict ==')
    print("""  Type 2 is an unused opcode, not a lost feature.  Ten firmwares have no
  handler for it and no classifier that looks at it, the cipher gives it no
  route, and six databases and 17,183 code lines hold not one.  No PC binary
  has a sixteen-way type dispatch either - XLink's only type test anywhere is
  the 5/6 block detection in its encrypt caller (ENCRYPT.md 1) - and the one
  contemporary third party who wrote the type list down had "??" against it.
  What would still settle it: FCD documentation, the X-Link PRO / v1.10 that
  RelNotes.txt promises, or a cartridge dump with a database nobody here has.

  Type C has no engine handler, and staging decides what a C line is.  A C0 -
  no key, no flag - leaves the pass-4 normaliser as a type 7 equality guard; a
  C with its flag nibble set passes through untouched and the engine skips it.
  The 27 shipped lines use both.  Filler (17 lines, one line copied and edited)
  and disabled type 8 codes (4 lines, ciphertext intact, address confirmed
  against the line below) are CD and C6, and inert.  The six Japanese joker
  codes are stored C0 and work, as type 7 guards over the write below them.
  Their masks are the raw pad halfword, active low - not the byte order FCD's
  own tool documents, and not what FCD's own joker generator emits, which is a
  type 7 or 9 guard.  The same database tests the pad the FCD way five times
  over, in other games.  So the type C jokers follow another convention than
  the type 7 ones: another hand's, which the "(X-T用)" / "(X-Tのみ)" markers
  elsewhere in that database would fit, or another game's way of storing the
  pad.  The firmware does not say which.

  And the lead that opened this - X-Link's second device - is not one.  The
  X-Terminator is the Japanese name of the Xplorer: seven brand strings in the
  packed firmware, the same seven places in three languages, Xplorer / Xploder /
  X-Terminator.  In XLink.exe the whole X-Terminator branch is a banner and a
  contact address behind a predicate stubbed to zero, and running all 3,920
  call targets of the four PC binaries (`make encrypt`, `make fcd`) finds eighteen
  cipher routines, every one of them this device's.""")

    for p in problems:
        print('   ' + p)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
