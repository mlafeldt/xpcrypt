#!/usr/bin/env python3
"""Execute the Xploder code engine out of any of the nine ROMs.

`engine.py` reads the engine; this runs it, and ENGINE.md §5 has the results.
The blob is loaded where the firmware puts it - PSX kernel RAM at 0x00000A00 -
fed a synthetic patch list, entered the way the BIOS hook enters it (`$t1` =
0x17, ReturnFromException), and the accesses it makes are recorded (all of them,
outside four quiet regions - see below).  So "what does code type X do" stops
being a reading of the disassembly and becomes an observation.

What this does and does not execute.  The engine is what runs on the console,
and it is run here for real, over 26 patch lists constructed by hand as
already-staged word pairs and control blocks - so each case is about one type,
not about what staging would have made of it.

The four *staging* passes that build the list before it is programmed into flash
are run as well, separately (Stager): the menu firmware's own code from the call
of pass 1 to the end of the pass-4 loop, over a handful of selections, with only
the BIOS strncpy and the copyright checker stubbed.  That is where type A
becomes a 5, a single D an F at the head of the list, and C0, D0 and odd-address
byte writes something else entirely (the pass-4 normaliser, which is also run
on its own over a table of codes).  What staging does *not* run here is the menu
that builds the selection: the descriptor and pointer arrays it hands the passes
are constructed by hand.

Memory map.  An access outside it is *recorded and allowed to proceed* - reading
zero, writing nowhere - rather than raising, because "the engine dereferences an
address this console does not have" is an observation worth keeping rather than
a crash.  Such accesses are marked in the trace, and three of the test cases
exist entirely to produce them.

    0x00000000 +0x200000   PSX RAM: the engine at 0xA00, cheat targets, kernel
    0x00700000 +0x100000   fwemu's scratch and stack
    0x1F02x600 +0x900      the patch list, payload buffer and Megacode control
                           block.  Where exactly is per firmware and is read out
                           of the engine itself
    0x1F060000 +0x10       the cartridge control port
    0x1F000000 +len(rom)   the cartridge, aliased at 0x9F000000 - FX forms its
                           pointers in KSEG1 and reads back what KSEG wrote
    0xA0000000 +0x1000     the uncached window a Megacode payload is copied into

The list and the port sit inside the cartridge's own address range and are
mapped ahead of it, so that they read as a programmed patch list and a port
rather than as whatever the shipped image happens to hold at that offset.

Four regions are quiet: their accesses are not recorded, because the engine
walks its own code, its stack and the list itself on every pass and none of that
is a code doing something.  "Every access" below means every access outside
them.

Images: the nine in roms/, plus release 2.005 out of pc/ROMS/Xteng.fcd for the
staging and normaliser runs when it is there.

    uv run --with capstone python engineemu.py          # every type, every ROM
    uv run --with capstone python engineemu.py -v       # ... with the store trace
"""
import glob
import hashlib
import os
import re
import struct
import sys
import tempfile

import engine
import fwemu
import fwimage
import mipscan
from fwemu import Mem, RET

ROMS = sorted(p for p in glob.glob('roms/*') if not p.endswith('.fcd'))

RAM = 0x00000000
RAMSZ = 0x200000
ENTRY = 0xA00
BIOS_B = 0x5E0                  # where the original 0xB0 stub jumped
LIST = 0x1F022600               # fallback only: Engine reads the real one out of
                                # each build, and the Pro firmwares use 0x1F024600
LISTSZ = 0x900                  # entries, payload buffer, Megacode block, title
PORT = 0x1F060000
UNCACHED = 0xA0000000

TRAMPOLINE = (0x3C080000).to_bytes(4, 'little') + (0x25080A00).to_bytes(4, 'little')
TAIL = (0x340805E0).to_bytes(4, 'little') + (0x01000008).to_bytes(4, 'little')


class Trace(Mem):
    """Mem that records what the engine touches.

    An access outside the map is recorded and allowed to proceed - reading zero,
    writing nowhere - rather than raising, because "the engine dereferences an
    address the console does not have" is exactly the observation wanted here.
    What a real PlayStation does with such an access is a separate question this
    does not answer: the model is a memory map, not a bus.
    """

    def __init__(self):
        super().__init__()
        self.log = []
        self.quiet = set()          # regions whose accesses are not interesting
        self.cop0 = Cop0(self.log)  # so that mtc0 shows up in the trace too

    def _note(self, kind, a, v):
        a &= 0xFFFFFFFF
        for lo, hi in self.quiet:
            if lo <= a < hi:
                return False
        try:
            self.seg(a)
            mapped = True
        except MemoryError:
            mapped = False
        self.log.append((kind, a, v, mapped))
        return not mapped

    def _load(self, kind, a, fn):
        try:
            v = fn(a)
        except MemoryError:
            self._note(kind, a, None)
            return 0
        self._note(kind, a, v)
        return v

    def r8(self, a):
        return self._load('lb', a, super().r8)

    def r16(self, a):
        return self._load('lh', a, super().r16)

    def r32(self, a):
        return self._load('lw', a, super().r32)

    def w8(self, a, v):
        self._note('sb', a, v & 0xFF)
        try:
            super().w8(a, v)
        except MemoryError:
            pass

    def w16(self, a, v):
        self._note('sh', a, v & 0xFFFF)
        try:
            super().w16(a, v)
        except MemoryError:
            pass

    def w32(self, a, v):
        self._note('sw', a, v & 0xFFFFFFFF)
        try:
            super().w32(a, v)
        except MemoryError:
            pass


class Cop0(list):
    """The COP0 register file, logging writes - type 6 programs the R3000's
    hardware breakpoint through it, and that is the whole of what type 6 does."""

    NAMES = {3: 'BPC', 5: 'BDA', 6: 'TAR', 7: 'DCIC', 9: 'BDAM', 11: 'BPCM'}

    def __init__(self, log):
        super().__init__([0] * 32)
        self.log = log

    def __setitem__(self, i, v):
        self.log.append(('mtc0', self.NAMES.get(i, 'cop0r%d' % i), v, True))
        super().__setitem__(i, v)


class Engine:
    """The in-game code engine of one ROM, callable."""

    def __init__(self, path):
        self.path = path
        raw = open(path, 'rb').read()
        img, base = fwimage.load(path)
        # the engine lives either in the packed firmware or in the ROM itself
        for data in (img, raw):
            o = data.find(TRAMPOLINE)
            if o >= 0:
                # the body runs from just after the 4-word trampoline to the tail
                # that hands control back to the BIOS: ori $t0,$zero,0x5e0; jr $t0
                end = data.index(TAIL, o) + len(TAIL) + 4
                blob = data[o + 0x10:end]
                break
        else:
            raise ValueError('%s: no engine' % path)
        self.blob, self.raw = blob, raw
        self.support = struct.unpack_from('<I', raw, 0x7C)[0] & 0x1FFFFFFF
        self.fx = 0x1F001000 <= self.support < 0x1F002000
        # where this build keeps its patch list.  Not a constant: the V2 builds
        # name it inline (0x1F022600, but 0x1F024600 on the two Pro firmwares),
        # the FX builds load a pointer from their support module.
        self.list = None
        ins = mipscan.dis(blob, ENTRY)
        for a, b in zip(ins, ins[1:]):
            if (a.mnemonic == 'lui' and a.op_str == '$a0, 0x1f02'
                    and b.mnemonic == 'ori' and b.op_str.startswith('$a0, $a0, ')):
                self.list = 0x1F020000 | int(b.op_str.rsplit(', ', 1)[1], 0)
                break
        # Two entries of the cartridge's own vector table, stubbed.  The engine
        # calls +0xB0 once per pass with $a0 = 'W' and FX calls +0x100 on the way
        # out; neither is handed the patch list or a code, and on the V2 builds -
        # where both run to completion unstubbed - they touch nothing outside the
        # cartridge.  On FX the first one polls a port that is not modelled here
        # and never returns, which is why they are stubbed at all.  Everything
        # else the engine calls, including the type 4 delay helper, runs for real.
        # (V2 forms the vector address in KSEG, FX in KSEG1 - stub both)
        self.stubbed = {b + o for b in (self.support, self.support | 0x80000000)
                        for o in (0xB0, 0x100)}

    def reset(self):
        m = Trace()
        m.map(RAM, bytes(RAMSZ))
        m.map(0x00700000, bytes(0x100000))
        # the list and the port are inside the cartridge's address range, and
        # the first matching segment wins - so map them first, or the engine
        # reads the shipped image's bytes at that offset instead of the patch
        # list the flash writer would have programmed there
        m.map(self.list or LIST, bytes(LISTSZ))
        m.map(PORT, bytes(0x10))
        # one cartridge, two windows: FX forms its pointers in KSEG1 and V2 in
        # KSEG, and the FX engine reads back what the firmware wrote through the
        # other one - so this has to be a real alias, not a second copy
        rom = bytearray(self.raw)
        m.segs.append((0x1F000000, 0x1F000000 + len(rom), rom))
        m.segs.append((0x9F000000, 0x9F000000 + len(rom), rom))
        m.map(UNCACHED, bytes(0x1000))
        m.quiet = {
            (0x00000000, 0x00000C80),               # the engine, the vectors, its flags
            (0x00700000, 0x00800000),               # the stack
            (0x1F000000, 0x20000000),               # the cartridge: code, list, payload
            (0x9F000000, 0xA0000000),               # ... and its KSEG1 alias
        }
        m.write(ENTRY, self.blob)
        # the engine leaves through 0x5E0, the BIOS B-function dispatcher; park a
        # jump to the interpreter's return sentinel there instead of the kernel
        m.w32(BIOS_B, 0x08000000 | ((RET >> 2) & 0x03FFFFFF))
        m.w32(BIOS_B + 4, 0)                        # delay slot
        m.w8(PORT, 1)                               # codes enabled (V2 gate)
        m.w8(0x178, 1)                              # codes enabled (FX gate)
        m.w32(0x700, 0xFFFFFFFF)                    # as the installer leaves it
        m.log.clear()
        return m

    def resolve(self, addr):
        """Run the cartridge's own helpers; stub only what leaves the map."""
        if addr in self.stubbed:
            return fwemu.nop_stub
        return None

    def run(self, entries, payload=b'', seed=(), limit=400000, tail=(),
            t1=0x17, keep_entry=False):
        """@entries is a list of (word0, word1); @seed is [(addr, u16), ...].

        @tail goes *after* the zero terminator, for the cases that walk past it.
        @t1 is the BIOS B-function number the hook is entered with.
        """
        m = self.reset()
        base = self.list or LIST
        for i, (w0, w1) in enumerate(list(entries) + [(0, 0)] + list(tail)):
            if w1 is PAYLOAD:                       # "the payload buffer", whose
                w1 = base + 0x400                   # address is per firmware
            m.w32(base + 8 * i, w0)                 # the (0, 0) is the terminator
            m.w32(base + 8 * i + 4, w1)
        m.write(base + 0x400, payload)
        if self.fx:                                 # FX reads the list pointer
            m.w32(self.support + 0xBC, base)        # out of its support module
        for a, v in seed:
            m.w16(a, v)
        m.log.clear()
        try:
            fwemu.run(m, ENTRY, (), self.resolve, limit=limit,
                      regs={9: t1}, sp=0x0070F000)
        except RuntimeError:                        # the instruction limit: a
            m.log.append(('runaway', '', None, True))   # loop with no way out
        # The FX builds disarm the hardware breakpoint in the delay slot of the
        # very first branch - the one that tests for B(17h) - so they do it on
        # every BIOS B() call, before a single code has been looked at.  It is a
        # real difference between the families, but it is not about any code
        # type, so it is taken out of the per-type traces here and gated on its
        # own in entry_check().  `entry` says whether it happened.
        self.entry = self.fx and m.log[:1] == [('mtc0', 'DCIC', 0, True)]
        if self.entry and not keep_entry:
            del m.log[0]
        return m.log


class Stager:
    """The four staging passes of one ROM, callable.

    They are not a function of their own: the menu firmware runs pass 1, 2 and 3
    as calls and pass 4 inline, in the middle of a much larger routine.  So the
    window that is run is found rather than assumed - it ends after the pass-4
    loop, which is the loop around the only call of the normaliser
    (engine.normaliser), and it starts at the argument set-up of the first of
    the three calls ahead of it.  The registers and stack slots the passes are
    handed are read out of that set-up, because they differ between builds.
    """

    BUF = fwemu.RAM + 0x10000           # the 0x1000-byte image being staged
    DESC = fwemu.RAM + 0x12000          # one descriptor byte per selection line
    PTRS = fwemu.RAM + 0x13000          # one pointer per line, to its six bytes
    CODES = fwemu.RAM + 0x14000
    # the instruction after the pass-4 loop becomes "return to the interpreter"
    STOP = struct.pack('<4I', 0x3C010000 | RET >> 16, 0x34210000 | RET & 0xFFFF,
                       0x00200008, 0)   # lui $at; ori $at; jr $at; nop

    def __init__(self, path, name=None):
        self.path, self.name = path, name or os.path.basename(path)
        self.raw = open(path, 'rb').read()
        self.img, self.base = fwimage.load(path)
        ins = mipscan.dis(self.img, self.base)
        idx = {x.address: i for i, x in enumerate(ins)}
        found = engine.normaliser(path, ins)
        if len(found) != 1 or len(found[0][1]) != 1:
            raise ValueError('%s: normaliser %s, expected one with one caller'
                             % (self.name, found))
        (self.norm, (call,)), = found
        k = idx[call]
        # the pass-4 loop closes with the first branch back past the call
        j = next(j for j in range(k, k + 80) if ins[j].mnemonic in ('bnez', 'bne')
                 and int(ins[j].op_str.rsplit(', ', 1)[1], 0) < call)
        self.stop = ins[j].address + 8
        # the three passes: calls whose delay slot (or the slot before) hands
        # over the descriptor array in a saved register
        passes = [j for j in range(k - 1, k - 80, -1) if ins[j].mnemonic == 'jal'
                  and any(x.mnemonic == 'move' and x.op_str.startswith('$a2, $s')
                          for x in (ins[j - 1], ins[j + 1]))][:3]
        first = min(passes)
        s = next(j for j in range(first, first - 12, -1) if ins[j].mnemonic == 'lw'
                 and re.match(r'\$v0, 0x[0-9a-f]+\(\$sp\)$', ins[j].op_str))
        self.start = ins[s].address
        self.args = {}
        for x in ins[s:first + 2]:
            if x.mnemonic == 'move' and re.match(r'\$a[0-2], \$s\d$', x.op_str):
                a, r = x.op_str.split(', ')
                self.args[a] = 16 + int(r[2])
            elif x.mnemonic == 'lw' and re.match(r'\$(v0|a3), 0x[0-9a-f]+\(\$sp\)$',
                                                 x.op_str):
                r, off = x.op_str.split(', ')
                self.args[r] = int(off.split('(')[0], 0)
        # how the decrypt routine's two callees are handled: strncpy runs as a
        # stub, the copyright checker is skipped.  Classified the way fxtest.py
        # does it, by decrypting one code down each route that reaches them.
        fw = fwemu.Firmware(path)
        for c in ([0x07, 1, 2, 3, 4, 5], [0x32, 1, 2, 3, 4, 5], [0x04, 1, 2, 3, 4, 5]):
            fw.decrypt(c)
        self.stubs = dict(fw.stubs)
        # where this build's list lives, for the pointers staging writes into it
        support = struct.unpack_from('<I', self.raw, 0x7C)[0] & 0x1FFFFFFF
        if 0x1F001000 <= support < 0x1F002000:      # FX: a slot in the module
            self.list = struct.unpack_from('<I', self.raw,
                                           support - 0x1F000000 + 0xBC)[0]
        else:
            self.list = Engine(path).list

    def memory(self):
        m = Mem()
        img = bytearray(self.img)
        o = self.stop - self.base
        img[o:o + len(self.STOP)] = self.STOP
        m.map(self.base, img)
        rom = bytearray(self.raw)
        m.segs.append((0x1F000000, 0x1F000000 + len(rom), rom))
        m.segs.append((0x9F000000, 0x9F000000 + len(rom), rom))
        m.map(fwemu.RAM, bytes(0x100000))
        m.map(0x80000000, bytes(0x1000))   # FX reads a flag at 0x8000002F
        return m

    def stage(self, lines, limit=2000000):
        """Stage one selection.  @lines are 12-hex-digit code lines, all enabled,
        with None for a cheat-name line between two cheats.  Returns 'RUNAWAY'
        or (list entries, the four control-block words, descriptors after)."""
        m = self.memory()
        for i, l in enumerate(lines):
            m.w32(self.PTRS + 4 * i, self.CODES + 8 * i)
            if l is None:
                m.w8(self.DESC + i, 0x1A)               # an enabled cheat's name
                continue
            m.write(self.CODES + 8 * i, bytes.fromhex(l.replace(' ', '')))
            m.w8(self.DESC + i, 0x18)                   # an enabled code line
        m.w8(self.DESC + len(lines), 0x02)              # an unselected name
        sp = fwemu.SP
        m.w32(sp + self.args['$v0'], len(lines))
        m.w32(sp + self.args['$a3'], self.PTRS)
        regs = {self.args['$a0']: self.BUF, self.args['$a1']: 0,
                self.args['$a2']: self.DESC}
        try:
            fwemu.run(m, self.start, (), self.stubs.get, limit=limit,
                      regs=regs, sp=sp)
        except RuntimeError:
            return 'RUNAWAY'
        out = []
        for i in range(0x80):
            w0, w1 = m.r32(self.BUF + 8 * i), m.r32(self.BUF + 8 * i + 4)
            if not (w0 or w1):
                break
            out.append('%08X %08X' % (w0, w1))
        return (out, ['%08X' % m.r32(self.BUF + 0x780 + 4 * i) for i in range(4)],
                ['%02X' % m.r8(self.DESC + i) for i in range(len(lines))])

    def normalise(self, code):
        """Run the normaliser alone over one decrypted six-byte code."""
        m = self.memory()
        m.write(fwemu.SRC, bytes.fromhex(code.replace(' ', '')))
        fwemu.run(m, self.norm, (fwemu.SRC,), lambda a: None)
        return '%02X%02X%02X%02X %02X%02X' % tuple(m.read(fwemu.SRC, 6))


def sig(log):
    out = []
    for k, a, v, m in log:
        if k == 'runaway':          # the rest of the trace is the same forever
            out = out[:3] + ['... RUNAWAY']
            break
        where = a if isinstance(a, str) else '%08X' % a
        out.append('%s %s%s%s' % (k, where, '' if v is None else '=%X' % v,
                                  '' if m else '!'))
    return ' | '.join(out) or '(nothing)'


T, U = 0x100000, 0x100100
PAYLOAD = object()      # stands in for the payload buffer of whichever
                        # firmware is running; its address is not a constant

# a Megacode control block: DCIC, break address, mask, word count, payload
MEGA = struct.pack('<IIII', 0xEA800000, 0x80012340, 0xFFFFFFFC, 2) + \
       struct.pack('<II', 0x11111111, 0x22222222)
# ... and one declaring no payload at all, which the stager will happily build
MEGA0 = struct.pack('<IIII', 0xEA800000, 0x80012340, 0xFFFFFFFC, 0)

SHORT = 40000           # enough to see a loop that has no way out

# The whole point of running all nine is that they agree.  They do, on every
# case but the two that use type 4 - the one handler the FX builds dropped.
#
# Naming the cases rather than counting them is deliberate: a count of two
# accepts two *different* cases differing, which is exactly the regression this
# is here to catch.  Same for the two groups: they have to be *these* five
# V2/Pro engines against *these* four FX ones, which is how the blob hashes
# group them too (ENGINE.md 6), and not any other five-and-four.
EXPECT_V2 = {'Xploder V2 (USA) r2.004 1998-11-13 [!].rom', 'xteng.dec',
             'xtepro.dec', 'xtger.dec', 'xtjpro.dec'}
EXPECT_FX = {'english.dec', 'english-452.dec', 'german-450.dec', 'v452d.rom'}
EXPECT_ROMS = EXPECT_V2 | EXPECT_FX
EXPECT_DIFFER = {'4 slow motion', '4 + default-off'}


def digest(groups):
    """One value standing for a case's whole result: every distinct trace, and
    exactly which images produced it.

    The traces themselves are what the notes quote, and several run to a few
    hundred characters, so they are gated by digest rather than pasted in.  A
    mismatch prints the trace beside it - the digest says *that* something moved,
    the trace says what.  Regenerate the table with `engineemu.py --record`, and
    only after establishing that the change is intended.
    """
    h = hashlib.sha256()
    for s, roms in sorted((s, sorted(r)) for s, r in groups.items()):
        h.update(('%s|%s\n' % (s, ','.join(roms))).encode())
    return h.hexdigest()[:16]


# Recorded 2026-07-29 with `engineemu.py --record`, all nine images.  Cases that
# do nothing share a digest, which is the point: `1 no-op`, `2 no-op`, `A inline
# data` and `C no-op` all reduce to the same two dispatcher reads, `D anchor` to
# the same trace as `7 if equal, yes`, and `7 miss, list end` to the same as
# `D inert on a miss`.
EXPECT_SIG = {
    '0 32-bit write':      '5ff6b51a47573a30',
    '1 no-op':             '36cdc5324ac47b9d',
    '2 no-op':             '36cdc5324ac47b9d',
    '3 8-bit write':       '82324fc9ab93a2c2',
    '4 slow motion':       '7d79fb858bd2d53c',
    '5 Supercode':         '3d1f44f26b343c01',
    '6 Megacode':          'c20a2a320540f676',
    '7 if equal, yes':     'ccf6367a2c93c5d0',
    '7 if equal, no':      '98d13b1acf77f68d',
    '8 16-bit write':      'daf93b49f78b80a1',
    '9 if differs, yes':   '12e0e54a21c1ddad',
    '9 if differs, no':    '1dec235ee773bdb9',
    'A inline data':       '36cdc5324ac47b9d',
    'B slide':             'e4ca215542ffa9f4',
    'C no-op':             '36cdc5324ac47b9d',
    'D anchor':            'ccf6367a2c93c5d0',
    'D inert on a miss':   '76dea5c476136861',
    'E 8-bit write +1':    '0d94cf880578f1f8',
    'F anchor, match':     '0f6039ad0c94b5eb',
    'F anchor, miss':      'f073c397a701eab8',
    '8 + default-off':     '77cd3ed3b18e9afe',
    '4 + default-off':     'a4e1326fd16efcdb',
    'C + default-off':     '2b60ef6a15c1e376',
    '5 of length 0':       '5c030107f7e0c16e',
    '6 of length 0':       '46840edff65369e2',
    '7 miss, list end':    '76dea5c476136861',
}

CASES = [
    ('0 32-bit write',   [(0x00000000 | T, 0xABCD)], b'', ()),
    ('1 no-op',          [(0x10000000 | T, 0xABCD)], b'', ()),
    ('2 no-op',          [(0x20000000 | T, 0xABCD)], b'', ()),
    ('3 8-bit write',    [(0x30000000 | T, 0x00CD)], b'', ()),
    # the address field is the delay helper's to ignore, but the dispatcher
    # dereferences it on the way past regardless - so it is not address zero
    ('4 slow motion',    [(0x40000000 | T, 0x0001)], b'', ()),
    ('5 Supercode',      [(0x50000000 | T, PAYLOAD)],
                         struct.pack('<HH', 4, 0) + b'\xde\xad\xbe\xef', ()),
    # staging emits word0 = 0x60000000, and the handler does ignore the address
    # - but the dispatcher reads it on the way past, and at address zero those
    # two reads land in a quiet region and go unrecorded.  So: not zero.
    ('6 Megacode',       [(0x60000000 | T, PAYLOAD)], MEGA, ()),
    ('7 if equal, yes',  [(0x70000000 | T, 0x1234), (0x80000000 | U, 0xBEEF)],
                         b'', ((T, 0x1234),)),
    ('7 if equal, no',   [(0x70000000 | T, 0x1234), (0x80000000 | U, 0xBEEF)],
                         b'', ((T, 0x9999),)),
    ('8 16-bit write',   [(0x80000000 | T, 0xABCD)], b'', ()),
    ('9 if differs, yes',[(0x90000000 | T, 0x1234), (0x80000000 | U, 0xBEEF)],
                         b'', ((T, 0x9999),)),
    ('9 if differs, no', [(0x90000000 | T, 0x1234), (0x80000000 | U, 0xBEEF)],
                         b'', ((T, 0x1234),)),
    ('A inline data',    [(0xA0000000 | T, 0xABCD)], b'', ()),
    ('B slide',          [(0xB0030004, 0x0001), (0x10000000 | T, 0x0010)], b'', ()),
    # C and D are what the *engine* does with one - nothing.  Staging never
    # hands it a C0 or a D0: it turns them into a 7, or a lone D into an F
    # (STAGED, below), so on a cartridge only a C or D whose flag nibble
    # survived decryption gets this far.
    ('C no-op',          [(0xC0000000 | T, 0xABCD)], b'', ()),
    ('D anchor',         [(0xD0000000 | T, 0x1234), (0x80000000 | U, 0xBEEF)],
                         b'', ((T, 0x1234),)),
    ('D inert on a miss',[(0xD0000000 | T, 0x1234), (0x80000000 | U, 0xBEEF)],
                         b'', ((T, 0x9999),)),
    ('E 8-bit write +1', [(0xE0000000 | T, 0x00CD)], b'', ()),
    ('F anchor, match',  [(0xF0000000 | T, 0x1234), (0x80000000 | U, 0xBEEF)],
                         b'', ((T, 0x1234),)),
    ('F anchor, miss',   [(0xF0000000 | T, 0x1234), (0x80000000 | U, 0xBEEF)],
                         b'', ((T, 0x9999),)),
    # the default-off bit survives decryption of a code stored in the clear, and
    # the dispatcher's 0x0FFFFFFF mask keeps it - see ENGINE.md 7.  Type 4's
    # helper ignores the address and the engine has no type C handler (a C8 is
    # also left alone by staging, which turns only a C0 into a type 7), but
    # neither is spared the two reads every entry gets.
    ('8 + default-off',  [(0x88000000 | T, 0xABCD)], b'', ()),
    ('4 + default-off',  [(0x48000000 | T, 0x0001)], b'', ()),
    ('C + default-off',  [(0xC8000000 | T, 0xABCD)], b'', ()),
    # three boundaries.  A block that declares no payload copies one unit, then
    # decrements and tests, so the count wraps; two shipped cheats are written
    # that way.  A conditional whose skip arm fires as the last entry steps over
    # the terminator and dispatches whatever is behind it.
    ('5 of length 0',    [(0x50000000 | T, PAYLOAD)],
                         struct.pack('<HH', 0, 0), (), SHORT),
    ('6 of length 0',    [(0x60000000, PAYLOAD)], MEGA0, (), SHORT),
    ('7 miss, list end', [(0x70000000 | T, 0x1234)], b'', ((T, 0x9999),),
                         400000, [(0x80000000 | U, 0xBEEF)]),
]


# ------------------------------------------------------- the FX entry, on its own

# Every FX engine disarms the hardware breakpoint (DCIC = 0) from the delay slot
# of its first branch - the test for B(17h) - so on *every* BIOS B() call, codes
# or no codes, and a Megacode is armed again only by the next ReturnFromException
# pass with codes switched on.  V2 and Pro leave DCIC alone.  The FX installer
# can take it out again: if the byte at 0x8000002F is set it stores a zero over
# that instruction (`sw $zero, 0xa08($zero)`), and no V2 or Pro image holds that
# store.  B(33h) is any function that is not ReturnFromException.
OTHER_B = 0x33
FX_INSTALLER_PATCH = struct.pack('<I', 0xAC000A08)


def entry_check(engines, entry_seen):
    problems = []
    for rom, e in engines:
        fx = rom in EXPECT_FX
        want = [('mtc0', 'DCIC', 0, True)] if fx else []
        for t1 in (0x17, OTHER_B):              # an empty list, nothing filtered
            got = e.run([], t1=t1, keep_entry=True)
            if got != want:
                problems.append('%s: B(%02Xh) entry traces %s, expected %s'
                                % (rom, t1, sig(got), sig(want)))
        # ... and the filter above took out exactly that write in every case
        if fx and entry_seen[rom] != {True}:
            problems.append('%s: DCIC was not cleared on entry in every case'
                            % rom)
        patch = any(d[o:o + 4] == FX_INSTALLER_PATCH
                    for d in (e.raw, fwimage.load(e.path)[0])
                    for o in range(0, len(d) - 3, 4))
        if patch != fx:
            problems.append('%s: installer %s the DCIC clear'
                            % (rom, 'can nop' if patch else 'never nops'))
    fxs = sorted(r for r, _ in engines if r in EXPECT_FX)
    print('FX entry clears DCIC on every B() call, B(17h) and B(%02Xh) alike: %s;'
          % (OTHER_B, ', '.join(fxs)))
    print('    never on V2/Pro.  Taken out of the per-type traces above; the FX'
          ' installer nops it when 0x8000002F is set')
    return problems


# ----------------------------------------------------- staging, executed (Stager)

TENTH = os.path.join('pc', 'ROMS', 'Xteng.fcd')
TENTH_NAME = 'Xteng.fcd (2.005)'


def tenth_image():
    """Release 2.005 out of the DOS tool's .fcd, as a temporary plaintext file."""
    if not os.path.exists(TENTH):
        return None
    import fcdcrypt
    tf = tempfile.NamedTemporaryFile(suffix='.dec', delete=False)
    tf.write(fcdcrypt.decrypt(bytearray(open(TENTH, 'rb').read())))
    tf.close()
    return tf.name


# The normaliser alone: decrypted code in, what pass 4 makes of it.  It matches
# whole first bytes, so a flag nibble that survived decryption (CD, C6, C8, D8,
# 88, 38) is left alone - which is why the shipped filler and disabled type C
# lines stay inert while a C0 joker becomes an equality guard.
NORMALISED = [
    ('C006A2EA B7FF', '7006A2EA B7FF'),     # type C is a type 7 - the 2.14 jokers
    ('C006A2EB B7FF', '7006A2EA B7FF'),     # ... at an even address
    ('D01A5C01 0880', '701A5C00 0880'),     # a D that was not hoisted: a type 7
    ('70100001 BEEF', '70100000 BEEF'),
    ('70100002 BEEF', '70100002 BEEF'),
    ('30100001 ABCD', 'E0100000 ABCD'),     # odd byte write: type E, one down
    ('30100002 ABCD', '30100002 ABCD'),
    ('80100001 ABCD', 'E0100000 ABCD'),     # odd halfword write: a byte write
    ('80100002 ABCD', '80100002 ABCD'),
    ('00100001 ABCD', 'E0100000 ABCD'),     # misaligned word write, both steps
    ('00100002 ABCD', '80100002 ABCD'),
    ('00100004 ABCD', '00100004 ABCD'),
    ('B00D0005 0000', 'B00D0004 0000'),     # slide: even address step
    ('B00D0004 0000', 'B00D0004 0000'),
    ('CDEEF45C 0008', 'CDEEF45C 0008'),     # flag nibble set: nothing matches
    ('C6671C0E 505A', 'C6671C0E 505A'),
    ('C8100000 ABCD', 'C8100000 ABCD'),
    ('D8100001 1234', 'D8100001 1234'),
    ('88100001 ABCD', '88100001 ABCD'),
    ('38100001 ABCD', '38100001 ABCD'),
    ('90100001 BEEF', '90100001 BEEF'),     # types it does not look at
    ('F0100001 BEEF', 'F0100001 BEEF'),
    ('E0100001 ABCD', 'E0100001 ABCD'),
    ('10100001 ABCD', '10100001 ABCD'),
    ('20100001 ABCD', '20100001 ABCD'),
    ('40100001 ABCD', '40100001 ABCD'),
    ('50100001 000C', '50100001 000C'),
    ('60100001 000C', '60100001 000C'),
    ('A0100001 ABCD', 'A0100001 ABCD'),
]

# Whole selections through all four passes.  Every line is plaintext with key
# bits 0, so the cipher only copies, and None is the name line of the next
# enabled cheat.  P+n is the payload buffer (list + 0x400 + n) and CTRL the
# Megacode control block (list + 0x780), both per build.  Each expectation is
# (list entries, the control block's first four words, descriptors after) with
# None for "not asserted", or 'RUNAWAY'.
EVERY = 'every image'
HANG = frozenset({'Xploder V2 (USA) r2.004 1998-11-13 [!].rom', 'xteng.dec',
                  'xtger.dec', 'xtjpro.dec', TENTH_NAME})
PRO220 = frozenset({'xtepro.dec'})
FX = frozenset(EXPECT_FX)
STAGED = [
    ('C0, D0 and odd addresses',
     ['C006A2EA B7FF', '8006E9C0 03E7', 'D0100000 1234', '80100100 BEEF',
      'D0100200 5678', '30100401 00AB', '80100501 CDEF', '00100602 ABCD',
      'B00D0005 0002', '100F60D4 0030', 'CDEEF45C 0008', '88100700 FFFF'],
     {EVERY: (['7006A2EA 0000B7FF', '8006E9C0 000003E7', '70100000 00001234',
               '80100100 0000BEEF', '70100200 00005678', 'E0100400 000000AB',
               'E0100500 0000CDEF', '80100602 0000ABCD', 'B00D0004 00000002',
               '100F60D4 00000030', 'CDEEF45C 00000008', '88100700 0000FFFF'],
              None, None)}),
    ('one D: hoisted as an F',
     ['80100000 0001', 'D01A5C01 0880', '801A5A38 0014'],
     {EVERY: (['F01A5C00 00000880', '80100000 00000001', '801A5A38 00000014'],
              None, None)}),
    ('an F and a D: the D is a 7',
     ['80100000 0001', 'D01A5C00 0880', 'F0100001 1234', '801A5A38 0014'],
     {EVERY: (['F0100000 00001234', '80100000 00000001', '701A5C00 00000880',
               '801A5A38 00000014'], None, None)}),
    ('guards in front of blocks',
     ['70100000 AAAA', '50102000 0004', 'DEADBEEF 0000', 'D0100000 0001',
      '50103000 0002', 'CAFE0000 0000', '50000702 0000', '800AA370 0101'],
     {EVERY: (['70100000 0000AAAA', '50102000 P+0', 'D0100000 00000001',
               '50103000 P+A', '50000702 P+14', '800AA370 00000101'],
              None, None)}),
    ('two Megacodes',
     ['80100000 0001', None, '60000000 0004', '1F800198 EA80', 'FFFFFFFC 1111',
      '12223333 0000', None, '60000000 0004', '1F800200 EA80', 'FFFFFFFC 4444',
      '12226666 0000', None, '80100002 0002'],
     {EVERY: (['F01FE3C9 0000120F', '60000000 CTRL', '80100000 00000001',
               '60000000 00000004', '108B5EEF 0000F84B', '12226666 00000000',
               '80100002 00000002'], ['EA800000', '1F800198', 'FFFFFFFC', '00000001'],
              None)}),
    # the shipped record, `Metal Gear Solid - Jp / Verliere Chaff` in 2.0081:
    # its descriptor and mask are whatever the next two selected lines are - here
    # the next cheat's name line, whose bytes the harness leaves zero, and its
    # first code - and the word count is (0xD7DD + 3) / 4
    ('MGS Verliere Chaff',
     ['65FAA065 A5AA', None, '80100000 0001', '80100002 0002', None,
      '80100004 0004'],
     {EVERY: (['60000000 CTRL', '80100004 00000004'],
              ['AB000000', 'FFCCE500', 'EF4CE510', '000035F8'],
              ['00', '00', '00', '00', '1A', '18'])}),
    # pass 3 makes a hoisted anchor's address even on the *stored* bytes, before
    # decrypting it.  For a line stored in the clear that is the address; for an
    # encrypted one it is ciphertext.  Golden Nugget's shipped anchor (USA, key
    # 4) decrypts to F000857C 00FF and is hoisted as this.
    ('a hoisted encrypted F',
     ['F4257FAF 25E6', '801E26A2 FFFF'],
     {EVERY: (['F000857D 000003FD', '801E26A2 0000FFFF'], None, None)}),
    # pass 1 skips a Supercode's rows using ((hi & 0xF) << 8) | (lo + 5) where
    # pass 2 adds (ENGINE.md 7).  At 0x1FB bytes that is 42 rows instead of 85,
    # so pass 1 reads the 43rd payload row as a line of its own - harmless
    # unless it starts with a 6, and then it stages a Megacode out of the
    # payload and takes three rows pass 2 then finds missing.  The control is
    # the same Supercode without the 6.
    ('a 507-byte Supercode',
     ['50100000 01FB'] + ['11111111 1111'] * 85 + [None, '80100002 0002'],
     {EVERY: (['50100000 P+0', '80100002 00000002'], None, None)}),
    ('... with a 6 in its 43rd row',
     ['50100000 01FB'] + ['11111111 1111'] * 42 + ['60000000 0004'] +
     ['11111111 1111'] * 42 + [None, '80100002 0002'],
     {HANG: 'RUNAWAY',
      PRO220: (['60000000 CTRL', '50100000 P+0'], None, None),
      FX: (['60000000 CTRL'] + ['11111111 00001111'] * 39 +
           ['80100002 00000002'], None, None)}),
    # a Supercode declaring a payload row its cheat does not have
    ('a Supercode longer than its cheat',
     ['70100000 AAAA', '50102000 0004', None, '80100006 0006', '80100008 0008'],
     {HANG: 'RUNAWAY',
      PRO220: (['70100000 0000AAAA', '50102000 P+0'], None, None),
      FX: (['80100006 00000006', '80100008 00000008'], None, None)}),
]


def expected(st, want):
    if want == 'RUNAWAY':
        return want
    entries, ctrl, desc = want

    def fill(e):
        w0, w1 = e.split()
        if w1 == 'CTRL':
            w1 = '%08X' % (st.list + 0x780)
        elif w1.startswith('P+'):
            w1 = '%08X' % (st.list + 0x400 + int(w1[2:], 16))
        return '%s %s' % (w0, w1)
    return [fill(e) for e in entries], ctrl, desc


def abstract(st, got):
    """@got with this build's list addresses put back as CTRL and P+n, so that
    builds which stage alike print alike."""
    if got == 'RUNAWAY':
        return got
    out = []
    for e in got[0]:
        w0, w1 = e.split()
        v = int(w1, 16)
        if v == st.list + 0x780:
            w1 = 'CTRL'
        elif st.list + 0x400 <= v < st.list + 0x780:
            w1 = 'P+%X' % (v - st.list - 0x400)
        out.append('%s %s' % (w0, w1))
    return ' | '.join(out)


def staging_check(stagers):
    print('\nstaging, executed: %d firmwares x %d selections, %d codes through '
          'the normaliser' % (len(stagers), len(STAGED), len(NORMALISED)))
    problems = []
    bad = [(st.name, i, st.normalise(i), o) for st in stagers
           for i, o in NORMALISED if st.normalise(i) != o]
    for name, i, got, o in bad:
        problems.append('%s: normaliser %s -> %s, expected %s' % (name, i, got, o))
    print('%-34s %s' % ('pass-4 normaliser', 'all %d as expected' % len(stagers)
                        if not bad else '%d DIFFER' % len(bad)))
    for name, lines, spec in STAGED:
        groups = {}
        for st in stagers:
            got = st.stage(lines)
            want = next((w for g, w in spec.items()
                         if g == EVERY or st.name in g), None)
            if want is None:
                problems.append('%s: %s has no expectation' % (name, st.name))
                continue
            want = expected(st, want)
            if want == 'RUNAWAY' or got == 'RUNAWAY':
                ok = got == want
            else:
                ok = got[0] == want[0] and all(
                    w is None or g == w for g, w in zip(got[1:], want[1:]))
            if not ok:
                problems.append('%s, %s: staged %s, expected %s'
                                % (name, st.name, got, want))
            groups.setdefault(abstract(st, got), []).append(st.name)
        if len(groups) == 1:
            print('%-34s all %-2d  %s' % (name, len(stagers), next(iter(groups))[:90]))
        else:
            print('%-34s by build' % name)
            for shown, roms in groups.items():
                print('    %-2d rom(s) %-30s %s' % (len(roms),
                      ','.join(r[:10] for r in roms)[:30], shown[:70]))
    return problems


def main(verbose=False, record=False):
    engines = [(os.path.basename(p), Engine(p)) for p in ROMS]
    print('%d firmwares x %d cases, executed\n' % (len(engines), len(CASES)))
    problems = []
    if set(n for n, _ in engines) != EXPECT_ROMS:
        problems.append('roms/ holds %s, expected the %d published images'
                        % (sorted(n for n, _ in engines), len(EXPECT_ROMS)))
    differ, seen = set(), {}
    entry_seen = {rom: set() for rom, _ in engines}
    for name, entries, payload, seed, *rest in CASES:
        groups = {}
        for rom, e in engines:
            groups.setdefault(sig(e.run(entries, payload, seed, *rest)),
                              []).append(rom)
            entry_seen[rom].add(e.entry)
        seen[name] = digest(groups)
        if len(groups) == 1:
            s = next(iter(groups))
            print('%-20s all 9   %s' % (name, s if verbose else s[:96]))
        else:
            differ.add(name)
            print('%-20s DIFFERS' % name)
            for s, roms in groups.items():
                print('    %-2d rom(s) %-46s %s' %
                      (len(roms), ','.join(r[:12] for r in roms)[:46],
                       s if verbose else s[:70]))
            # Not "some five against some four": the group that still has a
            # type 4 handler has to be exactly the V2/Pro five.
            if sorted(map(sorted, groups.values())) != \
                    sorted([sorted(EXPECT_FX), sorted(EXPECT_V2)]):
                problems.append('%s groups as %s, expected the V2/Pro five '
                                'against the FX four'
                                % (name, sorted(sorted(v) for v in groups.values())))
        want = EXPECT_SIG.get(name)
        if want is not None and seen[name] != want:
            problems.append('%s: traces or group membership changed (%s, '
                            'recorded %s)' % (name, seen[name], want))
        elif want is None and not record:
            problems.append('%s: no recorded result to compare against' % name)

    if record:
        print('\nEXPECT_SIG = {')
        for name, _, _, _, *_ in CASES:
            print("    %-22s %r," % ("'%s':" % name, seen[name]))
        print('}')
        return 0

    if differ != EXPECT_DIFFER:
        problems.append('cases that differ: %s, expected %s'
                        % (sorted(differ) or 'none', sorted(EXPECT_DIFFER)))
    print()
    problems += entry_check(engines, entry_seen)

    tenth = tenth_image()
    try:
        stagers = [Stager(p) for p in ROMS]
        if tenth:
            stagers.append(Stager(tenth, TENTH_NAME))
        problems += staging_check(stagers)
    finally:
        if tenth:
            os.unlink(tenth)

    print('\n%d of %d cases differ between firmwares' % (len(differ), len(CASES)))
    # Anything but the two type 4 cases, in their two known groups, is a result
    # and not a run - so say so in the exit status, or a harness that pipes this
    # through `tail` will read a regression as a pass.
    for p in problems:
        print('   ' + p)
    if problems:
        print('so this is a change - not a pass')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main('-v' in sys.argv, '--record' in sys.argv))
