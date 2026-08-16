#!/usr/bin/env python3
"""Execute the Xploder code engine out of any of the nine ROMs.

`engine.py` reads the engine; this runs it, and ENGINE.md §5 has the results.
The blob is loaded where the firmware puts it - PSX kernel RAM at 0x00000A00 -
fed a synthetic patch list, entered the way the BIOS hook enters it (`$t1` =
0x17, ReturnFromException), and the accesses it makes are recorded (all of them,
outside four quiet regions - see below).  So "what does code type X do" stops
being a reading of the disassembly and becomes an observation.

What this does and does not execute.  The engine is what runs on the console,
and it is run here for real.  The four *staging* passes that rewrite the code
list before it is programmed into flash are not: their output is constructed by
hand, as already-staged word pairs and control blocks.  So type A's rewriting,
type D's hoisting, and the construction of a type 5 or 6 control block remain
readings of the disassembly (ENGINE.md 13); what the runtime does with the
result is observed.

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

    uv run --with capstone python engineemu.py          # every type, every ROM
    uv run --with capstone python engineemu.py -v       # ... with the store trace
"""
import glob
import hashlib
import os
import struct
import sys

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

    def run(self, entries, payload=b'', seed=(), limit=400000, tail=()):
        """@entries is a list of (word0, word1); @seed is [(addr, u16), ...].

        @tail goes *after* the zero terminator, for the cases that walk past it.
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
                      regs={9: 0x17}, sp=0x0070F000)
        except RuntimeError:                        # the instruction limit: a
            m.log.append(('runaway', '', None, True))   # loop with no way out
        # the FX builds disarm the hardware breakpoint in the entry delay slot,
        # before a single code has been looked at.  That is prologue, not
        # per-type behaviour, so drop it to keep the comparison about the types.
        if self.fx and m.log[:1] == [('mtc0', 'DCIC', 0, True)]:
            del m.log[0]
        return m.log


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
    # helper ignores the address and nothing implements type C, but neither is
    # spared the two reads every entry gets.
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


def main(verbose=False, record=False):
    engines = [(os.path.basename(p), Engine(p)) for p in ROMS]
    print('%d firmwares x %d cases, executed\n' % (len(engines), len(CASES)))
    problems = []
    if set(n for n, _ in engines) != EXPECT_ROMS:
        problems.append('roms/ holds %s, expected the %d published images'
                        % (sorted(n for n, _ in engines), len(EXPECT_ROMS)))
    differ, seen = set(), {}
    for name, entries, payload, seed, *rest in CASES:
        groups = {}
        for rom, e in engines:
            groups.setdefault(sig(e.run(entries, payload, seed, *rest)),
                              []).append(rom)
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
