#!/usr/bin/env python3
"""What COMP01 actually spends its opcodes on.

The format has four: an LZ back-reference, RLE8, RLE16 and an arithmetic run.
Measured across all nine firmwares, two of the four barely earn their encoding:
rle16 fires 4 to 19 times per image and arith-run 9 to 14, saving under 110
bytes each out of tens of thousands. That is a fact about these nine streams;
what it says about how the format was designed is an inference (5.1b).

Also prints the budget for re-packing an image, which the "no packer" note in
TODO.md rests on: a store-only encoder is valid but too big to fit, while the LZ
opcode alone recovers 96-97% of what FCD's own compressor saved on eight of the
nine images, and 70% on english-452.dec.
"""
import glob
import sys

import comp01
import fxunp

ORDER = ['literal', 'lz-match', 'rle8', 'rle16', 'arith-run', 'literal-escape']

# The published ranges (FINDINGS.md 5.1b), as conditions rather than as output.
# The Makefile greps one line out of this, and a grep passes on one matching
# line however wrong the rest is.
EXPECT_ROMS = 9
EXPECT_RANGE = {                # opcode: (uses lo, uses hi, saved lo, saved hi)
    'rle16':     (4, 19, 56, 108),
    'arith-run': (9, 14, 58, 73),
}
EXPECT_STORE_OVER = (9, 42)     # store-only re-pack, percent over the packed size
EXPECT_LZ_SHARE = (70, 97)      # percent of the saving the LZ opcode alone gets


def stream(path):
    """(packed bytes, offset, whether it had to be descrambled first)."""
    raw = open(path, 'rb').read()
    s = raw.find(b'COMP01')
    if s >= 0:
        return raw, s, False
    s = fxunp.blob_start(raw)
    return fxunp.descramble(raw, s, len(raw)), 0, True


def main():
    problems = []
    roms = sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))
    if len(roms) != EXPECT_ROMS:
        problems.append('%d image(s) in roms/, expected %d - the published '
                        'ranges are for that corpus' % (len(roms), EXPECT_ROMS))
    for path in roms:
        data, off, fx = stream(path)
        st = {}
        out, used = comp01.unpack(data, off, stats=st)
        esc = bytes(b ^ m for b, m in zip(data[off:off + 10], comp01.MASK))[6:10]

        print('%-26s %s  escapes %s  0x%X -> 0x%X  ratio %.2f'
              % (path.split('/')[-1][:26], 'FX' if fx else 'V2',
                 ' '.join('%02X' % e for e in esc), used, len(out), used / len(out)))
        for op in ORDER:
            n, saved = st.get(op, (0, 0))
            print('   %-15s %7d uses  %+8d bytes' % (op, n, saved))

        # A store-only re-pack: every byte a literal, escapes doubled. Counted
        # with the 14-byte header, the same way `used` is, so the two compare.
        store = 0xE + len(out) + st.get('literal-escape', (0, 0))[0]
        over = 100.0 * (store - used) / used
        lz = 100.0 * st.get('lz-match', (0, 0))[1] \
            / max(1, sum(v[1] for v in st.values() if v[1] > 0))
        print('   %-15s %7s        store-only re-pack 0x%X (%+.0f%% vs packed), '
              'LZ opcode alone recovers %.0f%% of the saving'
              % ('', '', store, over, lz))
        print()

        name = path.split('/')[-1][:26]
        for op, (ulo, uhi, slo, shi) in EXPECT_RANGE.items():
            n, saved = st.get(op, (0, 0))
            if not ulo <= n <= uhi:
                problems.append('%s: %s fires %d times, expected %d to %d'
                                % (name, op, n, ulo, uhi))
            if not slo <= saved <= shi:
                problems.append('%s: %s saves %d bytes, expected %d to %d'
                                % (name, op, saved, slo, shi))
        if not EXPECT_STORE_OVER[0] <= round(over) <= EXPECT_STORE_OVER[1]:
            problems.append('%s: store-only re-pack is %+.0f%% over, expected '
                            '%d to %d' % (name, over, *EXPECT_STORE_OVER))
        if not EXPECT_LZ_SHARE[0] <= round(lz) <= EXPECT_LZ_SHARE[1]:
            problems.append('%s: the LZ opcode alone recovers %.0f%%, expected '
                            '%d to %d' % (name, lz, *EXPECT_LZ_SHARE))

    for p in problems:
        print('   ' + p)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
