#!/usr/bin/env python3
"""Compare the code-decrypt routine across every Xplorer/Xploder PSX firmware.

Finds the routine the same way in each image - the ' WB123' / 'WHBX' / 'FCD!'
constant tables, the 244-entry jump table that follows them, the `andi 0xF7` of
the dispatcher - and then diffs it three ways:

  * the constant tables, byte for byte;
  * which of the sixteen code types carry a key, as a bit set (crypto.c
    calls this XP_KEYED_TYPES);
  * every crypto route, canonicalised.

The routes sit in a different order in the FX firmware, so they are matched by
role - the jump-table slot they are reachable from - not by position.  Absolute
addresses are dropped; every crypto constant is small enough to survive.
"""
import difflib
import glob
import os
import re as _re
import struct
import sys

import fwimage
import mipscan


def _label(path):
    blob = open(path, 'rb').read()
    m = _re.search(rb'release ([0-9.]+)', blob)
    return '%s (%s)' % (os.path.basename(path).rsplit('.', 1)[0][:16],
                        m.group(1).decode() if m else '?')


IMAGES = [(_label(p), p)
          for p in sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))]

# A first byte, and the route the firmware picks for it.  The jump-table slot
# is (first byte & 0xF7) - 4, and the firmware bounds-checks it *unsigned*, so
# 0x00-0x0B all land below zero and take the default route.  0x24 is a real
# slot that happens to point at the default route: type 2 carries no key.
ROLES = {0x04: 'key 4', 0x05: 'key 5', 0x06: 'key 6', 0x07: 'key 7',
         0x32: 'Special32', 0x33: 'Special33', 0x24: 'gap type (copy)'}


def canon(x):
    """One instruction, with anything that is an address rather than a
    crypto constant replaced by '@'."""
    out = []
    for tok in x.op_str.replace(',', ' ').split():
        try:
            big = abs(int(tok, 0)) >= 0x800
        except ValueError:
            big = False
        out.append('@' if big else tok)
    return x.mnemonic + ' ' + ' '.join(out)


def route(ins, idx, addr, limit=64):
    """A route runs from @addr to the first unconditional jump, delay slot
    included.

    The low half of a lui/addiu pair is masked out along with the high half,
    however small it is - the constant tables sit at a different offset in every
    build, and the German V2 firmware puts them close enough to a page boundary
    (-0x474) that the offset would otherwise pass for a crypto constant."""
    i = idx[addr]
    body, hi = [], None
    while len(body) < limit:
        x = ins[i]
        if x.mnemonic == 'lui':
            hi = x.op_str.split(',')[0]
            body.append(canon(x))
        elif hi and x.mnemonic in ('addiu', 'ori') and x.op_str.startswith(hi + ', ' + hi):
            body.append('%s %s %s @' % (x.mnemonic, hi, hi))
            hi = None
        else:
            hi = None
            body.append(canon(x))
        if x.mnemonic in ('j', 'jr'):
            body.append(canon(ins[i + 1]))
            break
        i += 1
    return body


def find(path):
    d, base = fwimage.load(path)
    t = d.find(b' WB123')
    tables = d[t:t + 24]
    table = [struct.unpack_from('<I', d, t + 24 + 4 * i)[0] for i in range(244)]

    ins = mipscan.dis(d, base)
    idx = {x.address: i for i, x in enumerate(ins)}
    disp = next(i for i, x in enumerate(ins)
                if x.mnemonic == 'andi' and x.op_str.endswith('0xf7'))
    entry = next(i for i in range(disp, 0, -1)
                 if ins[i].mnemonic == 'addiu'
                 and ins[i].op_str.startswith('$sp, $sp, -'))

    keyed = sum(1 << n for n in range(16)
                if table[(((n << 4) | 4) & 0xF7) - 4] == table[0])
    routes = {name: route(ins, idx, table[(first & 0xF7) - 4])
              for first, name in ROLES.items()}
    return ins[entry].address, tables, keyed, routes


# What this has to find, not merely print.  Nine images; the same keyed-type
# set in every one; the other four V2/Pro routines matching the reference; and
# the four FX ones differing in exactly these four routes and no others.  The
# Makefile greps the output, and a grep is satisfied by one matching line - so
# the exit status has to carry the result.
EXPECT_IMAGES = 9
EXPECT_KEYED = 0xABFB
EXPECT_IDENTICAL = 4
EXPECT_FX_DIFFER = ['key 4', 'key 6', 'key 7', 'Special32']


def main():
    problems = []
    identical = 0
    if len(IMAGES) != EXPECT_IMAGES:
        problems.append('%d image(s) in roms/, expected %d'
                        % (len(IMAGES), EXPECT_IMAGES))
    ref = None
    for name, path in IMAGES:
        addr, tables, keyed, routes = find(path)
        print('%-22s routine @ %08X   XP_KEYED_TYPES = 0x%04X' % (name, addr, keyed))
        if keyed != EXPECT_KEYED:
            problems.append('%s: XP_KEYED_TYPES = 0x%04X, expected 0x%04X'
                            % (name, keyed, EXPECT_KEYED))
        if ref is None:
            ref = (name, tables, keyed, routes)
            print('   (reference)')
            continue
        rn, rt, rk, rr = ref
        bad = []
        if tables != rt:
            bad.append('constant tables')
        if keyed != rk:
            bad.append('keyed types (0x%04X)' % rk)
        for role in ROLES.values():
            if routes[role] != rr[role]:
                bad.append(role)
                print('   --- %s' % role)
                for line in difflib.unified_diff(rr[role], routes[role],
                                                 rn, name, n=2, lineterm=''):
                    print('      %s' % line)
        print('   %s %s' % ('!' if bad else '=',
                            ', '.join(bad) + ' differ' if bad
                            else 'identical to %s' % rn))
        if not bad:
            identical += 1
        elif bad != EXPECT_FX_DIFFER:
            problems.append('%s differs in %s, expected %s'
                            % (name, bad, EXPECT_FX_DIFFER))
    if identical != EXPECT_IDENTICAL:
        problems.append('%d routine(s) identical to the baseline, expected %d'
                        % (identical, EXPECT_IDENTICAL))
    print('\nThe FX routes differ only in how the compiler scheduled them: the'
          '\nshared tail is a `j` away instead of inlined, and the one call the'
          '\nroutine makes sits at the top instead of the bottom.  fxtest.py is'
          '\nthe authority on whether that changes anything - it does not.')
    for p in problems:
        print('   ' + p)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
