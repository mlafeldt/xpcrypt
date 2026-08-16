#!/usr/bin/env python3
"""How rare are COMP01's four escape bytes in the stream they were chosen for?

The notes say the compressor picks its escapes by scanning the input for rare
bytes. That is a statement about an encoder nobody has - FCD's - and cannot be
recovered from the decoder, which only reads the four bytes out of the header.

What *is* measurable is whether the bytes it picked are the rare ones. They are,
and not marginally: in all nine images the first escape is the rarest byte of the
unpacked output, and all four sit among the 14 rarest of 256. So "chosen from the
data by frequency" stays an inference, but an evidenced one rather than a guess.

  python3 escrank.py
"""
import collections
import glob
import sys

import comp01
import packstats

# The published claim, and nothing looser: nine images, every one of them with
# the rarest byte of 256 as its first escape, and no escape anywhere in the
# corpus ranked worse than 13. A bound of "the rarest few dozen" would be a
# different, weaker claim than the one FINDINGS.md 5.1b makes.
EXPECT_ROMS = 9
EXPECT_FIRST_RANK = 0
EXPECT_WORST_RANK = 13


def main():
    roms = sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))
    if not roms:
        print('skipped: no roms/ - drop the firmware dumps in and re-run')
        return 0

    worst = first_bad = 0
    for path in roms:
        data, off, _ = packstats.stream(path)
        out, _ = comp01.unpack(data, off)
        esc = bytes(b ^ m for b, m in zip(data[off:off + 10], comp01.MASK))[6:10]

        freq = collections.Counter(out)
        for b in range(256):
            freq.setdefault(b, 0)
        # rank 0 is the rarest byte of the unpacked stream
        rank = {b: i for i, (b, _) in
                enumerate(sorted(freq.items(), key=lambda kv: (kv[1], kv[0])))}
        ranks = [rank[e] for e in esc]
        worst = max(worst, max(ranks))
        first_bad += ranks[0] != EXPECT_FIRST_RANK

        print('%-28s escapes %s  ranks %-14s counts %s'
              % (path.split('/')[-1][:28],
                 ' '.join('%02X' % e for e in esc),
                 ' '.join('%d' % r for r in ranks),
                 ' '.join('%d' % freq[e] for e in esc)))

    print('\nrarest byte of 256 is the first escape in %d of %d images, '
          'worst rank of any escape %d'
          % (len(roms) - first_bad, len(roms), worst))
    problems = []
    if len(roms) != EXPECT_ROMS:
        problems.append('%d image(s) in roms/, expected %d - the published '
                        'figure is for that corpus' % (len(roms), EXPECT_ROMS))
    if first_bad:
        problems.append('%d image(s) whose first escape is not the rarest byte'
                        % first_bad)
    if worst > EXPECT_WORST_RANK:
        problems.append('worst escape rank %d, expected %d or less'
                        % (worst, EXPECT_WORST_RANK))
    for p in problems:
        print('   ' + p)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
