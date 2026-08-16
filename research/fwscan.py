#!/usr/bin/env python3
"""Constant scanner and range dumper over the *unpacked* firmware of any ROM.

`mipscan.py` and `fxdis.py` work on the raw ROM file, where most of the firmware
is still inside a COMP01 stream. This one runs the same two operations on what
`fwimage.load()` unpacks, so the addresses it prints are the ones the firmware
was linked at and can be followed between images.

    fwscan.py <rom> -c 0xaa,0x55 [window]     constants within a window
    fwscan.py <rom> -d 0x1A1A50 [count]       disassemble from an address
    fwscan.py <rom> -x 0x1a35e4               who calls this address

Used for section 2 of `FCD.md` - the flash driver, the page programmer, the link
dispatcher and the receive loop.
"""
import sys

import fwimage
import mipscan


def main(argv):
    img, base = fwimage.load(argv[1])
    mode = argv[2]
    arg = argv[3]
    n = int(argv[4], 0) if len(argv) > 4 else None

    if mode == '-c':
        consts = [int(x, 0) for x in arg.split(',')]
        ins = mipscan.dis(img, base)
        hits = mipscan.scan(ins, consts, n or 40)
        print('# %s @%08X: %d hit(s) for %s'
              % (argv[1], base, len(hits), [hex(c) for c in consts]))
        for h in hits:
            print('  %08X' % ins[h].address)
    elif mode == '-d':
        addr = int(arg, 0)
        off = addr - base
        if not 0 <= off < len(img):
            raise SystemExit('%08X is outside the image (%08X..%08X)'
                             % (addr, base, base + len(img)))
        for i in mipscan.dis(img, base, off, min(len(img), off + (n or 32) * 4)):
            print('%08X  %-9s %s' % (i.address, i.mnemonic, i.op_str))
    elif mode == '-x':
        target = int(arg, 0)
        callers = [i.address for i in mipscan.dis(img, base)
                   if i.mnemonic in ('jal', 'j')
                   and int(i.op_str, 0) == target]
        print('# callers of %08X: %s'
              % (target, ' '.join('%08X' % c for c in callers) or 'none'))
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    main(sys.argv)
