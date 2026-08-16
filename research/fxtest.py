#!/usr/bin/env python3
"""Does the Xplorer FX decrypt cheat codes the way the Xplorer V2 does?

Executes the decrypt routine out of all nine firmware images (fwemu.py) and
compares them against each other, against romcrypt.py - the hand transcription
xpcrypt is checked with - and against a known-plaintext Supercode.

The destination is prefilled with a byte no route writes zero over, so the
routes that never write destination byte 0 are compared on that too.
"""
import glob
import os
import random
import re as _re
import sys

import fwemu
import romcrypt


def _label(path):
    """Name a firmware by the release string it carries."""
    blob = open(path, 'rb').read()
    m = _re.search(rb'release ([0-9.]+)', blob)
    return '%s (%s)' % (os.path.basename(path).rsplit('.', 1)[0],
                        m.group(1).decode() if m else '?')


ROMS = [(_label(p), p)
        for p in sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))]

random.seed(20090510)

# destination prefill: not a value any route would produce by accident
FILL = bytes([0xAA] * 6)

# What this run has to *find*, not merely print.  "No two firmwares disagreed"
# is not the claim the notes rest on, and it is the one thing a corpus that had
# lost eight of its nine images would still satisfy - so the population, the
# keyed-type set and the known plaintext are all conditions of a pass.
EXPECT_ROMS = 9
EXPECT_KEYED = 0xABFB
EXPECT_PKEY = 6                 # the Punky Bear payload key
EXPECT_ROWS = 30                # ... and how many rows follow its header


def cases(n=6):
    """Every first byte with random tails, as a normal code and as a payload
    row under every possible payload key."""
    for first in range(256):
        for _ in range(n):
            c = [first] + [random.randrange(256) for _ in range(5)]
            yield c, -1
            for key in range(16):
                yield c, key


def known_plaintext(fw):
    """The one Supercode we have both halves of: a type 5 header with payload
    key 6, then 30 payload rows.

    The two files are compared with zip(), which stops at the shorter one, so
    their lengths are checked first: a pb.clear one row short would otherwise
    report 30/30 rows matching while a row went untested."""
    enc = [list(bytes.fromhex(l.replace(' ', ''))) for l in open('pb.enc')]
    clear = [list(bytes.fromhex(l.replace(' ', ''))) for l in open('pb.clear')]
    if len(enc) != len(clear):
        raise SystemExit('pb.enc has %d rows, pb.clear %d - the fixture halves '
                         'must line up' % (len(enc), len(clear)))
    head = fw.decrypt(enc[0])
    pkey = head[4] >> 4
    bad = sum(1 for e, c in zip(enc[1:], clear[1:]) if fw.decrypt(e, pkey) != c)
    return pkey, len(enc) - 1, bad


def main():
    problems = []
    fws = []
    for name, path in ROMS:
        fw = fwemu.Firmware(path)
        fws.append((name, fw))
        print('%-22s routine @ %08X  XP_KEYED_TYPES = 0x%04X'
              % (name, fw.entry, fw.keyed))
        if fw.keyed != EXPECT_KEYED:
            problems.append('%s: XP_KEYED_TYPES = 0x%04X, expected 0x%04X'
                            % (name, fw.keyed, EXPECT_KEYED))
    if len(fws) != EXPECT_ROMS:
        problems.append('%d firmware image(s) in roms/, expected %d - the '
                        'published results are for that corpus'
                        % (len(fws), EXPECT_ROMS))

    print('\nknown plaintext (Punky Bear Supercode, %d payload rows)' % EXPECT_ROWS)
    for name, fw in fws:
        pkey, rows, bad = known_plaintext(fw)
        print('   %-22s payload key %d, %d/%d rows match' % (name, pkey, rows - bad, rows))
        if bad or pkey != EXPECT_PKEY or rows != EXPECT_ROWS:
            problems.append('%s: %d of %d known-plaintext rows wrong, '
                            'payload key %d (expected %d rows, key %d)'
                            % (name, bad, rows, pkey, EXPECT_ROWS, EXPECT_PKEY))

    print('\nexecuting every firmware over the same codes')
    ref_name, ref = fws[0]
    diff = {name: 0 for name, _ in fws[1:]}
    vs_model = n = 0
    for code, key in cases():
        want = ref.decrypt(code, key, FILL)
        n += 1
        if romcrypt.decrypt(list(code), key, dst=list(FILL)) != want:
            vs_model += 1
        for name, fw in fws[1:]:
            if fw.decrypt(code, key, FILL) != want:
                diff[name] += 1
    print('   %d codes x 17 key settings' % (n // 17))
    print('   %-22s %d disagreement(s)' % ('romcrypt.py (the model)', vs_model))
    if vs_model:
        problems.append('romcrypt.py: %d disagreement(s) with %s'
                        % (vs_model, ref_name))
    for name, _ in fws[1:]:
        print('   %-22s %d disagreement(s) vs %s' % (name, diff[name], ref_name))
        if diff[name]:
            problems.append('%s: %d disagreement(s) vs %s'
                            % (name, diff[name], ref_name))

    print('\nfunctions the routine calls that were stubbed out')
    for name, fw in fws:
        print('   %-22s strncpy %s, skipped %s'
              % (name,
                 ', '.join('%08X' % a for a, f in sorted(fw.stubs.items())
                           if f is fwemu.strncpy) or '-',
                 ', '.join('%08X' % a for a in fw.skipped()) or 'none'))

    for p in problems:
        print('\n   ' + p)
    print('\n%s' % ('all %d firmwares agree' % len(fws) if not problems
                    else '%d expectation(s) not met - not a pass' % len(problems)))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
