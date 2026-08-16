#!/usr/bin/env python3
"""Find and read the Xplorer/Xploder in-game code engine in any of the ROMs.

The engine is not part of the firmware the menu runs in.  It is a ~0x24C-byte
blob that the firmware copies into PSX kernel RAM at 0x00000A00, plus a four-word
trampoline it drops on the BIOS B-function entry point at 0x000000B0.  Every
`ReturnFromException` - B(17h), so every interrupt - then walks the patch list in
cartridge flash and applies the codes.  That loop is the only place in any of the
nine firmwares that dispatches on a code's type nibble at run time, so it is the
authoritative answer to "what does type X do".

Located by the trampoline rather than by an address: the three oldest images
carry the engine inside the packed firmware, the other six keep it unpacked in
the ROM.

What it all means is written up in ENGINE.md.

    uv run --with capstone python engine.py            # dispatch chain, all ROMs
    uv run --with capstone python engine.py -v xteng   # annotated listing
    uv run --with capstone python engine.py -s         # staging classification sites
"""
import glob
import os
import re
import sys

import fwimage
import mipscan

ROMS = sorted(p for p in glob.glob('roms/*') if not p.endswith('.fcd'))

# lui $t0, 0 ; addiu $t0, $t0, 0xa00  - the head of the trampoline that goes to
# 0xB0.  The engine body follows it, and its own entry point is 0xA00.
TRAMPOLINE = (0x3C080000).to_bytes(4, 'little') + (0x25080A00).to_bytes(4, 'little')

RAM_ENTRY = 0xA00


def find_engine(path):
    """(data, base, offset of the trampoline, RAM address of the blob start).

    `base` is what the *containing* image is addressed at, so `base + offset` is
    a real address in that image; `ram` is where the engine actually executes.
    """
    raw = open(path, 'rb').read()
    img, imgbase = fwimage.load(path)
    for data, base in ((img, imgbase), (raw, 0x1F000000)):
        o = data.find(TRAMPOLINE)
        if o >= 0:
            # the trampoline is 4 words; the body starts right after it and is
            # what lands at RAM_ENTRY
            return data, base, o, RAM_ENTRY - 0x10
    raise ValueError('%s: no engine trampoline' % path)


def dispatch(path):
    """[(type nibble, [instruction text, ...]), ...] in the order tested."""
    data, base, off, ram = find_engine(path)
    ins = mipscan.dis(data, base, off, off + 0x300)
    k = next(i for i, x in enumerate(ins)
             if x.mnemonic == 'srl' and x.op_str.endswith('0x1c'))
    out, cur, body = [], None, []
    for i in ins[k:]:
        if i.mnemonic == 'ori' and i.op_str.startswith('$t0, $zero, '):
            v = int(i.op_str.rsplit(', ', 1)[1], 0)
            if v == 0x5E0:                      # the tail: back to the BIOS
                break
            if cur is not None:
                out.append((cur, body))
            cur, body = v, []
            continue
        if i.mnemonic == 'bne' and i.op_str.startswith('$zero, $v0'):
            if cur is not None:
                out.append((cur, body))
            cur, body = 0, []
            continue
        body.append('%-9s %s' % (i.mnemonic, i.op_str))
    if cur is not None:
        out.append((cur, body))
    return out


def listing(path):
    """The whole engine, addressed the way it runs."""
    data, base, off, ram = find_engine(path)
    delta = base + off - ram
    for i in mipscan.dis(data, base, off, off + 0x25C):
        w = int.from_bytes(data[i.address - base:i.address - base + 4], 'little')
        # branch targets come out of capstone in image space; move them too
        ops = re.sub(r'0x[0-9a-f]{4,8}',
                     lambda m: ('0x%X' % ((int(m.group(), 0) - delta) & 0xFFFFFFFF)
                                if base <= int(m.group(), 0) < base + len(data)
                                else m.group()),
                     i.op_str)
        print('%04X  %08X  %-9s %s' % (i.address - delta, w, i.mnemonic, ops))


CONST = re.compile(r'^\$\w+, \$zero, (0x[0-9a-f]+|\d+)$')


BACK, FWD = 32, 400            # instruction window either side of an `andi`


def staging(path):
    """[(address, [type nibble, ...]), ...] for every `andi rX, rY, 0xf0`.

    That instruction is the idiom this compiler emits where the firmware
    isolates a type nibble - not a property every classifier must have.  A
    classifier written as a shift, a different mask, a range test or a jump
    table would not appear here at all, so this enumerates one shape, and the
    result is a lower bound on where the firmware looks at a type.

    *Every* occurrence is returned, including the ones whose compared-against
    constant the window does not resolve; those come back with an empty list
    rather than being dropped, because "an `andi 0xf0` we could not read" is a
    gap in the evidence and should be visible as one.  Roughly a third of them
    stay unresolved: some compare against a register loaded further away than
    @BACK, some are not classifiers at all.

    The forward window is deliberately generous (the stager's type A branch sits
    0x24C bytes past its `andi`), so neighbouring sites bleed into one another
    and the per-site lists are indicative only.  What the enumeration supports is
    the *union*: the set of type nibbles the firmware is seen to test outside the
    run-time engine.  That union is `5 6 7 9 A D F` at every window size tried.
    """
    img, base = fwimage.load(path)
    ins = mipscan.dis(img, base)
    out = []
    for k, i in enumerate(ins):
        if not (i.mnemonic == 'andi' and i.op_str.endswith(', 0xf0')):
            continue
        reg = i.op_str.split(',')[0]                     # holds the type nibble
        seen, consts = [], {}
        for j in range(max(0, k - BACK), min(len(ins), k + FWD)):
            x = ins[j]
            if x.mnemonic in ('addiu', 'ori'):
                m = CONST.match(x.op_str)
                if m:
                    v = int(m.group(1), 0)
                    consts[x.op_str.split(',')[0]] = v
                    continue
            if x.mnemonic in ('beq', 'bne'):
                a, b = x.op_str.split(', ')[:2]
                other = b if a == reg else a if b == reg else None
                if other is not None and other in consts:
                    v = consts[other]
                    if v and v <= 0xF0 and not v & 0x0F and (v >> 4) not in seen:
                        seen.append(v >> 4)
        out.append(('%08X' % i.address, seen))
    return out


# The two published tables (ENGINE.md 6 and 13), as conditions rather than as
# output.  The dispatch chain is the same eleven types in the same order in the
# five V2/Pro builds and the same minus type 4 in the four FX ones; the staging
# scan finds 13 to 15 `andi ..., 0xF0` sites per image, resolves 9 of them, and
# the resolved constants union to the same seven types everywhere.
EXPECT_ROMS = 9
EXPECT_CHAIN_V2 = 'F 4 B 7 9 3 E 8 0 5 6'
EXPECT_CHAIN_FX = 'F B 7 9 3 E 8 0 5 6'
EXPECT_SITES = (13, 15)
EXPECT_READ = 9
EXPECT_TYPES = '5 6 7 9 A D F'


def report(problems):
    for p in problems:
        print('   ' + p)
    return 1 if problems else 0


if __name__ == '__main__':
    if len(ROMS) != EXPECT_ROMS:
        print('%d image(s) in roms/, expected %d - the published tables are '
              'for that corpus' % (len(ROMS), EXPECT_ROMS))
        sys.exit(1)
    if len(sys.argv) > 1 and sys.argv[1] == '-s':
        problems = []
        for p in ROMS:
            s = staging(p)
            union = sorted({t for _, v in s for t in v})
            read = [x for x in s if x[1]]
            types = ' '.join('%X' % t for t in union)
            print('%-42s %2d andi sites, %2d read, types %s' %
                  (os.path.basename(p), len(s), len(read), types))
            for a, v in s:
                print('    %s  %s' % (a, ' '.join('%X' % x for x in v)
                                      or '(constant not resolved)'))
            if not EXPECT_SITES[0] <= len(s) <= EXPECT_SITES[1]:
                problems.append('%s: %d andi sites, expected %d to %d'
                                % (os.path.basename(p), len(s), *EXPECT_SITES))
            if len(read) != EXPECT_READ:
                problems.append('%s: %d sites read, expected %d'
                                % (os.path.basename(p), len(read), EXPECT_READ))
            if types != EXPECT_TYPES:
                problems.append('%s: types %s, expected %s'
                                % (os.path.basename(p), types, EXPECT_TYPES))
        sys.exit(report(problems))
    elif len(sys.argv) > 1 and sys.argv[1] == '-v':
        want = sys.argv[2] if len(sys.argv) > 2 else 'xteng'
        for p in ROMS:
            if want in os.path.basename(p):
                print('##### %s' % os.path.basename(p))
                listing(p)
                break
    else:
        problems = []
        for p in ROMS:
            c = dispatch(p)
            chain = ' '.join('%X' % t for t, _ in c)
            print('%-42s %s' % (os.path.basename(p), chain))
            if chain not in (EXPECT_CHAIN_V2, EXPECT_CHAIN_FX):
                problems.append('%s: chain %s, expected %s (V2/Pro) or %s (FX)'
                                % (os.path.basename(p), chain,
                                   EXPECT_CHAIN_V2, EXPECT_CHAIN_FX))
        print('\n(order is the order of the bne chain, not sorted)')
        sys.exit(report(problems))
