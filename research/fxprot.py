#!/usr/bin/env python3
"""The anti-tamper check hidden in the Xplorer/Xploder code-decrypt routine.

Every firmware's decrypt routine calls exactly two functions.  One is strncpy,
loading a constant table.  The other - `f(0x1F000000, 0x18000)` in the V2 builds
- is a copyright check on the cheat database, and it bites.

Which route reaches it is not the same in the two generations, and it is not
every route: the V2 builds call it from key 7 and from Special32, the FX builds
from key 4.  Nothing else in the routine goes near it - run this script to see
the list it measures.

V2 (0x1A4620 in xteng), at the tail of the key-7 and Special32 routes:

    sig = *(u32 *)(ROM + 0x7C)              // -> 0x1F023000, the database header
    for (i = 0; i < strlen(masked) - 1; i++)
        if (~masked[i] != sig[i])
            flash_write(0x3E8, 0x1F000000, 0x18000);

FX (0x80024BE8 in english.dec) does the same thing, harder to spot:

    * the masked string is staged onto the stack with lwl/lwr rather than read
      in place, together with a function pointer;
    * only six characters are compared - positions 0, 1, 2, 12, 11, 13, i.e.
      "(C)" and "FCD" - driven by an index list stored after the string and
      walked out of order, so no contiguous compare loop appears;
    * the punisher is reached indirectly through that staged pointer plus 0x66,
      so the call site cross-references nothing.

`flash_write(src, dst, len)` is the cart's own flash programmer, the same one
that saves settings elsewhere (`flash_write(buf, 0x1F022600, 0x10)`): JEDEC
unlock - 0xAA to 0x5555, 0x55 to 0x2AAA, 0xA0 - then a page at a time, skipping
bytes that already match.  Both generations aim it at the first 0x18000 bytes of
the cartridge and source it from 0x3E8, which is PSX kernel RAM, not a staged
image - what is there at that moment is unknown, and nothing in the ROM puts a
firmware copy there.  Strip FCD's copyright from the database and the cart
programs 96 KB of it over its own boot stub and packed firmware.

The string never shows up in a `strings` dump: the V2 builds store it bitwise
NOTed, the FX builds XOR it with 0xEB.  (The plaintext banner every ROM also
carries - "(C) 1998 Future Console Design Ltd." - is what the menu prints, and
is not what the checker reads.)

Curiously the check is absent from Xplorer Pro 2.20: the callee is `jr $ra; nop`
and the masked string is not in the image at all.  It is back in every later
build.
"""
import glob
import sys

import fwemu
import fwimage
import romcrypt

PLAIN = b'(C) 199'

ROUTE_NAME = {'fcd': 'Special32', 'not': 'Special33'}


def signature(img):
    """Every copy of the copyright string, masked or not.

    Mask 0 is the visible banner; the interesting hits are the masked ones.  The
    stored buffer is NUL-terminated - the mask is applied per byte at compare
    time, not to the terminator."""
    out = []
    for mask in range(256):
        i = img.find(bytes(b ^ mask for b in PLAIN))
        if i < 0:
            continue
        end = i
        while end < len(img) and img[end] and end - i < 48:
            end += 1
        out.append((i, mask, bytes(b ^ mask for b in img[i:end]), end))
    return out


def indices(img, end):
    """The FX builds follow the string with the list of character positions to
    check, terminated by -1.  The V2 builds just walk the whole string."""
    out = []
    p = (end + 3) & ~3   # the leading 0 doubles as the string terminator
    while p + 4 <= len(img) and len(out) < 16:
        v = int.from_bytes(img[p:p + 4], 'little', signed=True)
        if v < 0:
            return out
        if v > 64:
            return []
        out.append(v)
        p += 4
    return []


def routes_reaching(fw):
    """The routes that actually call the checker, found by running each of
    them.  It is not the whole table: the V2 builds get there from key 7 and
    Special32, the FX builds from key 4."""
    out = []
    for first in range(256):
        fw.stubs.clear()
        fw.decrypt([first, 1, 2, 3, 4, 5])
        if fw.skipped():
            r = romcrypt.ROUTES.get(first & 0xF7)
            out.append(ROUTE_NAME.get(r, r))
    for key in range(16):
        fw.stubs.clear()
        fw.decrypt([0x50, 1, 2, 3, 4, 5], key)
        if fw.skipped():
            out.append('payload key %d' % key)
    return sorted(set(out), key=str)


def main():
    for path in sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom')):
        img, _ = fwimage.load(path)
        fw = fwemu.Firmware(path)
        reached = routes_reaching(fw)
        for first in (0x04, 0x05, 0x06, 0x07, 0x32, 0x33):
            fw.decrypt([first, 1, 2, 3, 4, 5])
        state = ', '.join(
            '%08X %s' % (a, 'STUBBED (jr $ra)'
                         if fw.ins[fw.idx[a]].mnemonic == 'jr' else 'live')
            for a in fw.skipped())
        print('%-26s checker %s' % (path.split('/')[-1][:26], state or 'none'))
        print('     called from %s' % (', '.join(reached) or 'nothing'))
        for off, mask, text, end in signature(img):
            if not mask:
                continue
            idxs = indices(img, end)
            print('     %-7s image 0x%05X  %r%s'
                  % ('NOT' if mask == 0xFF else 'XOR %02X' % mask, off, text,
                     '  checks %s = %r' % (idxs, bytes(text[i] for i in idxs))
                     if idxs else '  checks all of it'))


if __name__ == '__main__':
    sys.exit(main())
