#!/usr/bin/env python3
"""Where does an Xplorer keep its cheat codes?

Run against all nine ROMs, this shows why none of the four FX dumps has a
database in it - and that it is not a crypto or a container problem.

Three pieces of evidence, in order of how much they settle:

  1. which 4K pages of the ROM window the firmware actually names.  The V2
     firmware names the pages its database sits in; the FX firmware names
     0x7F000 and 0x80000, which are past the end of both dump files.
  2. whether a second scrambled COMP01 blob hides anywhere.  None does - the
     firmware is the only one.
  3. what the bytes past the firmware blob are.

The FX carts keep codes in a flash region that ends at 0x1F080000, with an
8-byte descriptor at 0x1F07FFF8 (16-bit field at +6).  0x1F080000 is the top of
the PSX expansion window: 512 KB.  Every FX dump here ends below 0x80000 -
english.dec is 317 KB, v452d.rom 384 KB with its tail erased - so none of them
reaches it.
"""
import collections
import glob
import re
import sys

import comp01
import fwimage
import fxunp
import mipscan

ROMS = sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))


def rom_pages(img, base):
    """Every ROM-window address the firmware builds with lui (+ addiu/ori)."""
    ins = mipscan.dis(img, base)
    pages = collections.Counter()
    for i, x in enumerate(ins):
        if x.mnemonic != 'lui':
            continue
        m = re.match(r'(\$\w+), (0x[0-9a-f]+)', x.op_str)
        if not m:
            continue
        hi = int(m.group(2), 0)
        if not (0x9F00 <= hi <= 0x9F0F or 0x1F00 <= hi <= 0x1F0F):
            continue
        reg, addr = m.group(1), hi << 16
        for y in ins[i + 1:i + 6]:
            if y.mnemonic in ('addiu', 'ori') and y.op_str.startswith(reg + ', ' + reg):
                v = int(y.op_str.rsplit(', ', 1)[1], 0)
                addr = (addr + v) & 0xFFFFFFFF if y.mnemonic == 'addiu' else addr | v
                break
        pages[(addr & 0xFFFFFF) >> 12] += 1
    return pages


def blobs(raw):
    """Offsets where a scrambled COMP01 stream starts (FX), or a plain one (V2)."""
    out = [s for s in range(len(raw) - 24)
           if fxunp.descramble(raw, s, s + 10)[:6] == b'COMP01']
    return out or ([raw.find(b'COMP01')] if b'COMP01' in raw else [])


def main():
    for path in ROMS:
        raw = open(path, 'rb').read()
        img, base = fwimage.load(path)
        name = path.split('/')[-1][:26]

        start = blobs(raw)[0]
        packed = comp01.unpack(fxunp.descramble(raw, start, len(raw))
                               if raw[start:start + 6] != b'COMP01' else raw[start:])[1]
        end = start + packed + (4 if raw[start:start + 6] != b'COMP01' else 0)

        tail = raw[end:]
        live = max((i for i, b in enumerate(tail) if b not in (0, 0xFF)), default=-1) + 1
        pages = rom_pages(img, base)
        top = [p for p in pages if p >= 0x7F]

        print('%-26s file 0x%06X  firmware blob 0x%06X..0x%06X' % (name, len(raw), start, end))
        print('   tail 0x%X bytes, 0x%X live then erased' % (len(tail), live))
        print('   ROM pages named: %s'
              % ' '.join('0x%05X(%d)' % (k << 12, v) for k, v in sorted(pages.items())))
        print('   %s' % ('flash code area at the top of the window (0x%s) - past this dump'
                         % ', 0x'.join('%05X' % (p << 12) for p in sorted(top))
                         if top else 'no reference above the dump; database is in-ROM'))
        print()


if __name__ == '__main__':
    sys.exit(main())
