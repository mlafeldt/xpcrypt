#!/usr/bin/env python3
"""Execute the self-bricking copyright check, instead of reading it.

FINDINGS 5.3b / REVERSING 11 describe a check hidden in the code-decrypt
routine that aims the cartridge's own flash programmer at the cartridge's own
firmware, and both say the same thing about it: it is a static reading, nobody
has watched it run.  This runs it, on all *ten* images - the nine published
ones plus release 2.005, which ships inside the PC X-Link distribution as
`pc/ROMS/Xteng.fcd` and has never been counted.

What is executed.  The real decrypt routine out of each image, under `fwemu.py`
- the interpreter `fxtest.py` and `engineemu.py` already use - with the checker
left *live* rather than stubbed, and with the cartridge modelled as the part it
is rather than as a read-only blob:

    Flash   a JEDEC/SST page-mode NOR chip.  Writes to 0x5555 and 0x2AAA are
            command cycles; AA/55/A0 opens a page load and AA/55/90 the
            autoselect (chip id) window; programming can only *clear* bits, so
            a programmed byte becomes `old & new`.  That last property is the
            whole recoverability question, so it is modelled rather than
            assumed.
    Bus     2 MB of PSX main RAM, aliased into KUSEG/KSEG0/KSEG1 because both
            generations run their firmware from RAM (V2 at 0x001A0000, FX at
            0x80010000) and reach the flash through the 0x1F000000 window;
            plus the cartridge control port at 0x1F060000, which the FX
            programmer writes to select a bank.

One thing is stubbed, and it is timing only: the busy-wait `delay(500)` the
programmer runs after each page - 500 * 100 iterations * 768 pages is 38
million interpreted instructions of nothing.  The chip-id routine, the JEDEC
command cycles, the page loop and the toggle-bit poll all run for real, and so
does every call the decrypt routine makes except the BIOS `strncpy` trampoline
that `fwemu.py` already stubs.

The page-load window closes on any read of the flash array, which is what a
real part's byte-load timeout does and what this code assumes: it opens one
page load *before* its scan loop and then never uses it.

What it comes to, on all ten images:

* The programmer really is entered as `flash_write(0x3E8, 0x1F000000, 0x18000)`
  - not read off `$a0` but off the far end: RAM is seeded with a marker
  pattern and every byte the chip is handed is `marker(0x3E8 + k)`.  It
  programs cartridge offsets `0x000000`-`0x017FFF`, whole pages at a time, 384
  pages of 256 bytes on the parts these carts use.  That covers the ROM header,
  the whole boot stub, and the first 90-odd KB of the packed firmware.  On the
  V2 layout the cheat database is behind all of it and survives untouched; on
  the FX layout the version header the checker itself reads, at `0x1500`, is
  inside the wiped region.
* **Release 2.14 fires on its own untouched cartridge.**  Its compare string is
  still `"(C) 1997/8 FCD"` while its database header had already moved on to
  `"(C) 1997-9 FCD  "`; the compare mismatches at index 8 and 9 and the cart
  programs 98304 bytes over itself the first time anyone decrypts a key-7 or
  Special32 code.  Putting the two bytes `'/8'` back at cart `0x25008` stops it,
  which is executed here too.  Pro 2.20, the very next build, is the one with
  the check removed - and 3.20 onwards compares six characters that avoid the
  date entirely.  That is what the missing check in 2.20 was about.
* The damage is **not** the bit-clearing FINDINGS 6.0 assumes.  The device codes
  the chip-id routine accepts are Atmel AT29C parts, which erase a page before
  programming it - and the 4.52 programmer settles it by construction: it
  re-reads each page it just wrote and programs it again until it matches, so
  under bit-clearing semantics it never terminates.  Run it that way and it
  reprograms page 0 for ever, which is not what a shipped product does.
* One byte defuses it in every build, and it is executed here, not asserted
  from a reading: see `Cart.defuse`.

    uv run --with capstone python selfdestruct.py
    uv run --with capstone python selfdestruct.py -v     # per-image detail

Every number is asserted rather than printed and hoped over - see TODO.md
"Verifying the current state".
"""
import glob
import os
import struct
import sys
import tempfile

import fcdcrypt
import fwemu
import fwimage
import fxprot
import mipscan
import romcrypt

PC_FCD = 'pc/ROMS/Xteng.fcd'        # the tenth image, shipped encrypted

CART_WINDOWS = (0x1F000000, 0x9F000000, 0xBF000000)
PORT, PORTSZ = 0x1F060000, 0x10
IO, IOSZ = 0x1F800000, 0x4000        # PSX scratchpad + hardware registers
RAMSZ = 0x200000
UNLOCK1, UNLOCK2 = 0x5555, 0x2AAA

SRC_ARG = 0x3E8                     # the source the checker hands the programmer
LEN_ARG = 0x18000                   # ... and the length
DST_ARG = 0x1F000000                # ... and, after masking, the destination

# Which part the model answers the chip-id probe as.  Every build reads the
# device code at cart offset 1 in autoselect mode and folds it into a "chip
# type" that picks the page size; the V2 routine (0x1A3444) accepts exactly
# 0xD5, 0xDA and 0xA4 and treats the first as a 128-byte-page part and the
# other two as 256.  Those are the Atmel AT29C010A / AT29C020 / AT29C040
# device codes, and those parts have exactly those page sizes - so the family
# is not a guess, and neither is what a page write does to it (below).
#
# All three are recognised by all nine live checkers; SST's 0xBF/0x07 is not
# (release 4.50 refuses to program at all), which is why they are the ones
# used here.  A 256 KB V2 cart is an AT29C020 and a 512 KB FX cart an
# AT29C040, so 256-byte pages are what real hardware would use.
CHIPS = {
    'AT29C010A': (0x1F, 0xD5),          # 128 KB, 128-byte page
    'AT29C020':  (0x1F, 0xDA),          # 256 KB, 256-byte page  <- the V2 cart
    'AT29C040':  (0x1F, 0xA4),          # 512 KB, 256-byte page  <- the FX cart
    'mfr DA':    (0xDA, 0x07),          # an id the V2 routine calls "type 2"
}


class Flash:
    """A JEDEC page-programmable NOR flash, as far as this code drives it.

    @program picks the semantics of a page write, which is the whole
    recoverability question and is therefore a parameter rather than a
    guess:

      'page'  the page is erased before it is programmed, so a page write
              replaces it and bits can go 0 -> 1.  This is what the parts the
              firmware identifies actually do - the device codes it accepts,
              0xD5 / 0xDA / 0xA4, are Atmel AT29C010A / AT29C020 / AT29C040,
              and 0xBF is SST's 29EE010: one family, all page-erase-then-
              program, with exactly the 128- and 256-byte pages the code
              picks between.
      'and'   programming can only clear bits, the assumption FINDINGS 6.0
              reasons from.  Kept because the 4.50/4.52 programmer settles
              which one is right by *not terminating* under it.
    """

    def __init__(self, data, mfr=0xBF, dev=0x07, program='page'):
        self.orig = bytes(data)
        self.data = bytearray(data)
        self.mfr, self.dev, self.program = mfr, dev, program
        self.mode, self.seq = 'read', []
        self.cmds = []              # (offset, value) command cycles
        self.pages = []             # [start, length] of each page load
        self.written = {}           # offset -> value handed to the chip
        self._page = None

    def _commit(self, *_):
        if self.mode == 'program':
            if self._page is not None:
                self.pages.append(tuple(self._page))
            self.mode, self._page = 'read', None

    def read(self, off):
        if self.mode == 'autoselect':
            return self.mfr if (off & 1) == 0 else self.dev
        self._commit()              # an array read ends a page load
        return self.data[off] if off < len(self.data) else 0xFF

    def write(self, off, v):
        v &= 0xFF
        if self.mode == 'program':
            self.written[off] = v
            if off < len(self.data):
                self.data[off] = v if self.program == 'page' else self.data[off] & v
            if self._page is None:
                self._page = [off, 1]
            else:
                self._page[1] += 1
            return
        self.cmds.append((off, v))
        self.seq.append((off & 0x7FFF, v))
        if v == 0xF0:                               # reset
            self.mode, self.seq = 'read', []
            return
        s = self.seq[-3:]
        if (len(s) == 3 and s[0] == (UNLOCK1, 0xAA) and s[1] == (UNLOCK2, 0x55)
                and s[2][0] == UNLOCK1):
            self.mode = {0xA0: 'program',
                         0x90: 'autoselect'}.get(s[2][1], self.mode)
            self.seq = []

    def touched(self):
        """Offsets whose stored value the programming changed."""
        return [i for i in range(len(self.orig)) if self.orig[i] != self.data[i]]


class Bus(fwemu.Mem):
    """PSX main RAM, the cartridge control port, and the cartridge."""

    def __init__(self, rom, mfr=0xBF, dev=0x07, program='page'):
        super().__init__()
        self.flash = Flash(rom, mfr, dev, program)
        self.ram = bytearray(RAMSZ)
        # one RAM, three windows: V2 links its firmware into KUSEG and FX into
        # KSEG0, and the punisher is handed a KUSEG source pointer either way
        for b in (0x00000000, 0x80000000, 0xA0000000):
            self.segs.append((b, b + RAMSZ, self.ram))
        self.segs.append((PORT, PORT + PORTSZ, bytearray(PORTSZ)))
        # the PSX's own I/O page and scratchpad, in both windows the FX flash
        # code forms pointers in.  It masks interrupts around a program cycle
        # (I_MASK is 0x1F801074), which is a real access and has to land
        # somewhere rather than raise.
        io = bytearray(IOSZ)
        for b in (IO, IO | 0x80000000, IO | 0xA0000000):
            self.segs.append((b, b + IOSZ, io))
        self.segs.append((fwemu.RAM, fwemu.RAM + 0x100000, bytearray(0x100000)))
        self.stack = []             # the callees currently entered
        self.writer = None          # ... as they stood for the first byte
                                    #     the chip was actually handed

    def coff(self, a):
        """Cartridge offset of @a, or None if @a is not the cartridge."""
        a &= 0xFFFFFFFF
        if PORT <= a < PORT + PORTSZ:
            return None
        for w in CART_WINDOWS:
            if w <= a < w + 0x100000:
                return a - w
        return None

    def r8(self, a):
        o = self.coff(a)
        return self.flash.read(o) if o is not None else super().r8(a)

    def w8(self, a, v):
        o = self.coff(a)
        if o is None:
            super().w8(a, v)
            return
        if self.writer is None and self.flash.mode == 'program':
            self.writer = tuple(self.stack)
        self.flash.write(o, v)

    def r16(self, a):
        o = self.coff(a)
        if o is None:
            return super().r16(a)
        return self.flash.read(o) | (self.flash.read(o + 1) << 8)

    def r32(self, a):
        o = self.coff(a)
        if o is None:
            return super().r32(a)
        return sum(self.flash.read(o + i) << (8 * i) for i in range(4))

    def w16(self, a, v):
        o = self.coff(a)
        if o is None:
            super().w16(a, v)
        else:
            for i in range(2):
                self.flash.write(o + i, v >> (8 * i))

    def w32(self, a, v):
        o = self.coff(a)
        if o is None:
            super().w32(a, v)
        else:
            for i in range(4):
                self.flash.write(o + i, v >> (8 * i))


MEM_OPS = frozenset(('lb', 'lbu', 'lh', 'lhu', 'lw', 'lwl', 'lwr', 'll',
                     'sb', 'sh', 'sw', 'swl', 'swr', 'sc'))


def loops_back(x):
    """Is @x a branch to itself or backwards - i.e. the top of a loop?"""
    if not x.mnemonic.startswith('b') or x.mnemonic == 'break':
        return False
    try:
        return int(x.op_str.rsplit(', ', 1)[-1], 0) <= x.address
    except ValueError:
        return False


def end_page(mem, r):
    """The programmer's per-page busy-wait, which is also where a real part's
    page-load window closes."""
    mem.flash._commit()


def marker(i):
    """A byte pattern with no period the flash contents could match by luck.

    Seeded into RAM to answer "is 0x3E8 really a source pointer?" by reading
    the answer off the far end: if the value the chip is handed for cart offset
    k is marker(0x3E8 + k), then it is.
    """
    return (i * 181 + 0x5A) & 0xFF


class Cart:
    """One firmware image, with the checker executable."""

    def __init__(self, path, name=None):
        self.path, self.name = path, name or os.path.basename(path)
        self.raw = open(path, 'rb').read()
        self.img, self.base = fwimage.load(path)
        self.ins = mipscan.dis(self.img, self.base)
        self.idx = {x.address: i for i, x in enumerate(self.ins)}
        self.header = struct.unpack_from('<I', self.raw, 0x7C)[0]
        self.header_off = self.header & 0xFFFFFF

        f = fwemu.Firmware(path)
        self.entry = f.entry
        for first in (0x04, 0x05, 0x06, 0x07, 0x32, 0x33):
            f.decrypt([first, 1, 2, 3, 4, 5])
        assert len(f.skipped()) == 1, (self.name, f.skipped())
        self.checker = f.skipped()[0]
        self.empty = self.ins[self.idx[self.checker]].mnemonic == 'jr'
        self.callers = [x.address for x in self.ins
                        if x.mnemonic == 'jal' and int(x.op_str, 0) == self.checker]

        self.waits = {}         # addr -> is it a pure busy-wait?

        # the masked string and, on FX, the index list stored behind it
        self.string = None
        for off, mask, text, end in fxprot.signature(self.img):
            if mask:
                self.string = (off, mask, text, fxprot.indices(self.img, end))
        # what the checker will actually compare, and against what
        self.compare = self._compare()

    def _compare(self):
        """(index, wanted, got) for every character the checker looks at."""
        if self.string is None:
            return []
        off, mask, text, idxs = self.string
        hdr = self.raw[self.header_off:self.header_off + 64]
        # V2 walks the whole string but stops one short of strlen(); FX walks
        # the index list stored behind it
        idxs = idxs or list(range(len(text) - 1))
        return [(i, text[i], hdr[i]) for i in idxs]

    def fires(self):
        """Does the check fire on this image's own, unmodified header?"""
        return any(w != g for _, w, g in self.compare)

    def busywait(self, addr):
        """Is @addr a function that only counts?

        The programmer waits out the page-program time with a nested counting
        loop - 500 * 100 iterations, called once per page, which is 38 million
        interpreted instructions of nothing over one 96 KB write.  It is the
        only thing here that is stubbed, and the test is structural rather than
        by address: a function that touches no memory and loops cannot do
        anything but pass time.  The toggle-bit poll next to it *does* read the
        chip, so it does not match and runs for real.
        """
        if addr in self.waits:
            return self.waits[addr]
        out, i = False, self.idx.get(addr)
        if i is not None:
            body = []
            for x in self.ins[i:i + 40]:
                body.append(x)
                if x.mnemonic == 'jr' and x.op_str == '$ra':
                    out = (not any(y.mnemonic in MEM_OPS for y in body)
                           and any(loops_back(y) for y in body))
                    break
        self.waits[addr] = out
        return out

    def defuse(self):
        """One byte that turns the check off, or None.

        Both generations reach the programmer through a single conditional, and
        in both the branch that *skips* it is already in the instruction - so
        the punishment can be unhooked without touching anything else:

          V2  `bne $v0, $v1, <punish>` in the compare loop.  Its displacement
              field is one byte, and the loop's own exit label is inside the
              range, so pointing the mismatch arm at "done" is a single byte.
          FX  `beqz $a1, <return>` after the index walk.  Clearing the `rs`
              field turns it into `beq $zero, $zero` - unconditional - which
              is again one byte, and is the whole of it.

        Returns (image offset, old byte, new byte, what it becomes).
        """
        body = self.ins[self.idx[self.checker]:self.idx[self.checker] + 96]
        arm = next((x for x, n in zip(body, body[1:])
                    if n.mnemonic == 'addiu'
                    and n.op_str == '$a0, $zero, 0x3e8'), None)
        if arm is None:
            return None
        w = struct.unpack_from('<I', self.img, arm.address - self.base)[0]
        if arm.mnemonic == 'bne':                       # V2
            done = next(x for x in body
                        if x.mnemonic == 'beqz' and x.op_str.startswith('$v0, '))
            imm = (int(done.op_str.rsplit(', ', 1)[1], 0) - arm.address - 4) >> 2
            assert 0 < imm < 0x100 and not (w & 0xFF00), (imm, w)
            return (arm.address - self.base, w & 0xFF, imm,
                    'bne -> branch to the loop exit instead of the programmer')
        # $rs spans the byte boundary; this is only a one-byte edit while it
        # fits in the low three bits, which it does for $a1 = 5
        assert arm.mnemonic == 'beqz' and w >> 26 == 4 and (w >> 21) & 31 < 8
        return (arm.address - self.base + 2, (w >> 16) & 0xFF, (w >> 16) & 0x1F,
                'beqz $a1 -> beq $zero, $zero: the programmer is never reached')

    def routes(self):
        """Every first byte / payload key whose route reaches the checker."""
        f = fwemu.Firmware(self.path)
        names = set()
        for first in range(256):
            f.stubs.clear()
            f.decrypt([first, 1, 2, 3, 4, 5])
            if f.skipped():
                r = romcrypt.ROUTES.get(first & 0xF7)
                names.add(fxprot.ROUTE_NAME.get(r, r))
        for key in range(16):
            f.stubs.clear()
            f.decrypt([0x50, 1, 2, 3, 4, 5], key)
            if f.skipped():
                names.add('payload key %d' % key)
        return names

    def reaching_code(self):
        """One code whose decryption reaches the checker."""
        f = fwemu.Firmware(self.path)
        for first in range(256):
            f.stubs.clear()
            f.decrypt([first, 1, 2, 3, 4, 5])
            if f.skipped():
                return first
        return None

    def run(self, first, rom=None, chip='AT29C020', ram=None, program='page',
            img=None, limit=8_000_000):
        """Decrypt one code with the checker live.

        @rom is the cartridge contents (default: this image's own).
        @ram seeds PSX main RAM under the firmware - the source the programmer
        is pointed at.

        Returns (Bus, [(callee, a0, a1, a2), ...], finished).  Running out of
        instructions is a *result* here rather than an error - one of the two
        flash models makes a programmer loop forever - so the budget is caught
        and the flash is handed back either way.
        """
        mfr, dev = CHIPS[chip]
        m = Bus(self.raw if rom is None else rom, mfr, dev, program)
        if ram is not None:
            m.ram[:len(ram)] = ram
        m.write(self.base & 0x1FFFFFFF, self.img if img is None else img)
        m.write(fwemu.SRC, bytes([first, 1, 2, 3, 4, 5]))
        m.write(fwemu.DST, bytes(6))

        log, inside = [], set()

        def resolve(addr):
            if addr in inside:                  # the re-entered call itself
                return None
            if self.busywait(addr):
                return end_page
            # only at depth 0: the decrypt routine calls exactly two functions,
            # strncpy and the checker, and is_strncpy separates those two.  It
            # is not a general classifier - the flash chip-id routine has a
            # byte-copy shape too - so nothing deeper is offered to it.
            if not inside and addr in self.idx and \
                    fwemu.Firmware.is_strncpy(self.ins, self.idx, addr):
                return fwemu.strncpy

            def trampoline(mem, r):
                """Record the arguments, then run the function for real.

                fwemu hands a stub the register file, so this is the only place
                a callee's arguments can be read - and skipping the call is not
                an option here, since the call *is* the experiment."""
                log.append((addr, r[4], r[5], r[6]))
                inside.add(addr)
                m.stack.append(len(log) - 1)
                try:
                    out = fwemu.run(mem, addr, (r[4], r[5], r[6], r[7]),
                                    resolve, limit=limit, sp=r[29])
                finally:
                    inside.discard(addr)
                    m.stack.pop()
                r[2], r[3] = out[2], out[3]     # $v0/$v1; the rest is callee-saved
            return trampoline

        try:
            fwemu.run(m, self.entry, (fwemu.SRC, fwemu.DST, 0xFFFFFFFF),
                      resolve, limit=limit)
        except RuntimeError:
            return m, log, False
        return m, log, True


# --------------------------------------------------------------- the corpus

# Nine images are published; `Xteng.fcd` inside the PC X-Link distribution is a
# tenth, and the notes have never counted it.
RELEASES = ['2.004', '2.005', '2.008', '2.0081', '2.14', '2.20',   # V2
            '3.20', '4.50', '4.52', '4.52']                        # FX

V2_STRING = b'(C) 1997/8 FCD'
FX_STRING = b'(C) 1997-9 FCD  '
FX_INDICES = [0, 1, 2, 12, 11, 13]

def regions(cart):
    """What is in the cartridge image, in offset order.

    The two generations lay the flash out differently, and the difference
    matters here: the V2 builds put the cheat database *behind* the packed
    firmware, well past the 96 KB the punisher writes, while the thing the FX
    builds check sits at 0x1500, inside it.
    """
    packed = cart.raw.find(b'COMP01')
    if packed < 0:                      # FX: the stream is scrambled first
        packed = fwimage.fx_blob(cart.raw)
    marks = [(0, 'header + boot stub'), (packed, 'packed firmware'),
             (cart.header_off, 'the header the checker reads')]
    marks.sort()
    return [(n, a, b) for (a, n), (b, _) in
            zip(marks, marks[1:] + [(len(cart.raw), '')])]


def images():
    """The ten firmware images, newest container last."""
    out, keep = [], []
    for p in sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom')):
        out.append(Cart(p))
    if os.path.exists(PC_FCD):
        f = tempfile.NamedTemporaryFile(suffix='.dec')
        f.write(fcdcrypt.decrypt(open(PC_FCD, 'rb').read()))
        f.flush()
        keep.append(f)                  # deleted when the list goes out of scope
        out.append(Cart(f.name, name=os.path.basename(PC_FCD)))
    return out, keep


def release(cart):
    """The release this image calls itself, out of the header it checks."""
    hdr = cart.raw[cart.header_off:cart.header_off + 48]
    i = hdr.find(b'release ')
    return hdr[i + 8:i + 14].split()[0].split(b'\0')[0].decode() if i >= 0 else '?'


def low_ram(cart):
    """PSX main RAM as the run seeds it: a marker pattern everywhere, with the
    firmware itself where this build links it.  The pattern is what proves the
    source pointer; the firmware is there because on a V2 cart it really is
    (0x001A0000), and on an FX cart it really is inside the 96 KB the
    programmer reads (0x80010000 -> RAM 0x10000, and the source runs to
    0x183E8)."""
    ram = bytearray(marker(i) for i in range(RAMSZ))
    base = cart.base & 0x1FFFFFFF
    ram[base:base + len(cart.img)] = cart.img
    return ram


def main(verbose=False):
    carts, _keep = images()
    problems = []

    def check(cond, msg):
        if not cond:
            problems.append(msg)
        return cond

    have = sorted(release(c) for c in carts)
    if not have:
        print('  skipped: no firmware images - drop the dumps in roms/ '
              'and/or %s' % PC_FCD)
        return 0
    check(have == sorted(RELEASES) or have == sorted(set(RELEASES) - {'2.005'})
          or have == ['2.005'],
          'the images present are %s, expected the ten of %s' % (have, RELEASES))

    print('%d firmware images, checker executed\n' % len(carts))
    verifying, live = [], []
    for c in carts:
        rel = release(c)
        fx = c.base >= 0x80000000
        ram = low_ram(c)
        first = c.reaching_code()
        routes = c.routes()

        # --- who can reach it, and with what
        check(routes == ({'key4'} if fx else {'Special32', 'key7'}),
              '%s: reached from %s' % (rel, sorted(routes)))
        check(len(c.callers) == (1 if fx else 2),
              '%s: %d call sites to the checker, expected %d'
              % (rel, len(c.callers), 1 if fx else 2))

        if c.empty:
            print('%-6s %-22s checker %08X  jr $ra, and no masked string'
                  % (rel, c.name[:22], c.checker))
            check(c.string is None, '%s: empty checker but the string is there' % rel)
            check(rel == '2.20', '%s: the checker is missing from a build that is '
                                 'not Pro 2.20' % rel)
            live.append(False)
            continue
        live.append(True)

        off, mask, text, idxs = c.string
        want = FX_STRING if fx else V2_STRING
        check(text == want and mask == (0xEB if fx else 0xFF),
              '%s: masked string is %r under %02X' % (rel, text, mask))
        check(idxs == (FX_INDICES if fx else []),
              '%s: index list %s' % (rel, idxs))
        check([i for i, _, _ in c.compare] ==
              (FX_INDICES if fx else list(range(13))),
              '%s: compares %s' % (rel, [i for i, _, _ in c.compare]))

        # Nothing else in the image passes 0x3E8 as a pointer: it is not a
        # buffer the firmware fills, it is an address in PSX kernel RAM and
        # this is the only place it is ever named as one.  (The V2 builds do
        # carry a second `addiu $a2, $zero, 0x3e8` elsewhere - 1000 as a
        # count, in an unrelated routine.)
        loads = [x.address for x in c.ins if x.mnemonic == 'addiu'
                 and x.op_str == '$a0, $zero, 0x3e8']
        check(len(loads) == 1 and c.checker < loads[0] < c.checker + 0x200,
              '%s: 0x3E8 goes into $a0 at %s, checker at %08X'
              % (rel, ['%08X' % a for a in loads], c.checker))

        # --- (a) the cartridge as shipped
        m, log, done = c.run(first, ram=bytes(ram))
        f = m.flash
        check(done, '%s: the stock decrypt did not finish' % rel)
        check(bool(f.written) == c.fires(),
              '%s: predicted fires=%s but %d bytes were programmed'
              % (rel, c.fires(), len(f.written)))
        # The string this is reading is the one the checker reads: corrupt the
        # first character it compares, in the image, and the verdict has to
        # change.  (On V2 the strlen call in the log names the address too.)
        if not fx:
            check(log[1][1] == c.base + off,
                  '%s: strlen() got %08X, the masked string is at %08X'
                  % (rel, log[1][1], c.base + off))
        spoilt = bytearray(c.img)
        spoilt[off + c.compare[0][0]] ^= 0x01
        m2, _, ok2 = c.run(first, ram=bytes(ram), img=bytes(spoilt))
        check(ok2 and len(m2.flash.written) == LEN_ARG,
              '%s: corrupting the masked string did not set it off' % rel)

        bad = [i for i, w, g in c.compare if w != g]
        print('%-6s %-22s checker %08X  header %08X %r  stock: %s'
              % (rel, c.name[:22], c.checker, c.header,
                 c.raw[c.header_off:c.header_off + 14],
                 'PASSES' if not bad else
                 'FIRES, mismatch at %s (%r vs %r)'
                 % (bad, bytes(text[i] for i in bad),
                    bytes(c.raw[c.header_off + i] for i in bad))))
        if bad:
            # the shipped image destroys itself.  Two bytes of its own header
            # are the difference, so put them back and watch it stop.
            print('       -> on an untouched cartridge: %d bytes programmed '
                  'over cart %06X..%06X' % (len(f.written), min(f.written),
                                            max(f.written) + 1))
            check(sorted(f.written) == list(range(LEN_ARG)),
                  '%s: the stock image programmed %d bytes' % (rel, len(f.written)))
            fixed = bytearray(c.raw)
            fixed[c.header_off + bad[0]:c.header_off + bad[-1] + 1] = \
                bytes(text[i] for i in bad)
            m2, _, ok2 = c.run(first, rom=bytes(fixed), ram=bytes(ram))
            check(ok2 and not m2.flash.written,
                  '%s: correcting header %06X+%s did not stop it'
                  % (rel, c.header_off, bad))
            print('       -> writing %r back over cart %06X stops it dead'
                  % (bytes(text[i] for i in bad), c.header_off + bad[0]))

        # --- (b) the same cartridge with one byte of the header changed
        rom = bytearray(c.raw)
        rom[c.header_off] ^= 0xFF
        for chip, page in (('AT29C020', 0x100), ('AT29C010A', 0x80)):
            m, log, done = c.run(first, rom=bytes(rom), chip=chip, ram=bytes(ram))
            f = m.flash
            check(done, '%s/%s: did not finish' % (rel, chip))
            # not "some call had these arguments": the function that was on
            # the stack when the chip was handed its first byte
            prog = log[m.writer[-1]] if m.writer else None
            check(prog is not None and prog[1:] == (SRC_ARG, DST_ARG, LEN_ARG),
                  '%s/%s: the programmer ran as %s'
                  % (rel, chip, prog and ('%08X(%X, %X, %X)' % prog)))
            check(sorted(f.written) == list(range(LEN_ARG)),
                  '%s/%s: programmed %d bytes, %X..%X'
                  % (rel, chip, len(f.written), min(f.written), max(f.written)))
            check(all(n == page for _, n in f.pages)
                  and len(f.pages) == LEN_ARG // page
                  and len(set(a for a, _ in f.pages)) == len(f.pages),
                  '%s/%s: %d page loads, sizes %s'
                  % (rel, chip, len(f.pages), sorted(set(n for _, n in f.pages))))
            # the source pointer, read off the far end rather than off $a0
            check(all(f.written[o] == ram[SRC_ARG + o] for o in f.written),
                  '%s/%s: the bytes programmed are not RAM 0x3E8..0x183E8'
                  % (rel, chip))
            if chip == 'AT29C020':
                changed = len(f.touched())
                expect = sum(c.raw[i] != ram[SRC_ARG + i] for i in range(LEN_ARG))
                check(changed == expect, '%s: %d bytes changed, expected %d'
                      % (rel, changed, expect))
                lose = sum(1 for i in range(LEN_ARG)
                           if c.raw[i] & ram[SRC_ARG + i] != c.raw[i])
                print('       -> flash_write(src=%08X, dst=%08X, len=%05X): '
                      '%d pages x %d, %d of %d bytes change; %d lose bits'
                      % (SRC_ARG, DST_ARG, LEN_ARG, len(f.pages), page,
                         changed, LEN_ARG, lose))

        # --- (c) which flash model the programmer itself rules out.
        # Under 'and' a page cannot be made to read back as the source, and a
        # programmer that checks gets stuck on it.  A short probe is enough to
        # see that - the same page start twice - and where it does not happen
        # the run is finished properly instead.
        m, _, _ = c.run(first, rom=bytes(rom), ram=bytes(ram),
                        program='and', limit=60_000)
        starts = [a for a, _ in m.flash.pages]
        stuck = len(starts) != len(set(starts))
        verifying.append(rel if stuck else None)
        note = '%d page loads, %d distinct' % (len(starts), len(set(starts)))
        if stuck:
            note += ' - it reprograms the page it just wrote, forever'
        else:
            m, _, done = c.run(first, rom=bytes(rom), ram=bytes(ram),
                               program='and')
            check(done, '%s: the and-only run did not finish' % rel)
            check(len(m.flash.written) == LEN_ARG,
                  '%s: and-only wrote %d bytes' % (rel, len(m.flash.written)))
            note += '; runs to the end, %d bytes lose bits' % len(m.flash.touched())
        if verbose:
            print('       and-only model: %s' % note)

        # --- what the 0x18000 bytes cover
        for what, lo, hi in regions(c):
            if verbose:
                print('       %-26s %06X..%06X  %s'
                      % (what, lo, hi,
                         'destroyed' if lo < LEN_ARG else 'untouched'))
        # --- (d) one byte, and it never fires again
        off, was, now, what = c.defuse()
        img = bytearray(c.img)
        check(img[off] == was, '%s: defusal offset %05X holds %02X' % (rel, off, img[off]))
        img[off] = now
        m, log, done = c.run(first, rom=bytes(rom), ram=bytes(ram), img=bytes(img))
        check(done and not m.flash.written,
              '%s: the one-byte defusal left %d bytes programmed'
              % (rel, len(m.flash.written)))
        if verbose:
            print('       defused by image 0x%05X: %02X -> %02X   (%s)'
                  % (off, was, now, what))

        # --- (e) and one chip on which it does nothing at all.  The program
        # command is 0xA0 unless the chip-id routine returns 2, and then it is
        # 0x90 - autoselect, not program - so the page never reaches the array.
        if not fx:
            m, log, done = c.run(first, rom=bytes(rom), ram=bytes(ram),
                                 chip='mfr DA')
            check(done and not m.flash.written and len(m.flash.cmds) > LEN_ARG,
                  '%s: chip type 2 programmed %d bytes' % (rel, len(m.flash.written)))
            if verbose:
                print('       chip type 2 (manufacturer 0xDA): command 0x90 '
                      'instead of 0xA0, %d writes reach the array'
                      % len(m.flash.written))

        # the V2 cheat database is behind the firmware and out of reach; the
        # FX header the checker itself reads is not
        db = [(n, a, b) for n, a, b in regions(c)
              if n == 'the header the checker reads'][0]
        check((db[1] >= LEN_ARG) is not fx,
              '%s: the header it checks sits at %06X, %s the 96 KB'
              % (rel, db[1], 'outside' if db[1] >= LEN_ARG else 'inside'))

    check(sum(live) == 9, '%d of %d images carry a live checker' % (sum(live), len(carts)))
    check(sorted(x for x in verifying if x) == ['4.52', '4.52'],
          'the programmers that verify their own write are %s'
          % sorted(x for x in verifying if x))

    print('\n%d of %d images carry the check; it fires on an *unmodified* '
          'cartridge in %d of them.\nIn every one it programs cart '
          '000000..%06X from PSX RAM 0x%X, and one byte turns it off.'
          % (sum(live), len(carts), sum(c.fires() for c in carts),
             LEN_ARG, SRC_ARG))
    for p in problems:
        print('   ' + p)
    if problems:
        print('so this is a change - not a pass')
        return 1
    print('all assertions hold')
    return 0


if __name__ == '__main__':
    sys.exit(main('-v' in sys.argv))
