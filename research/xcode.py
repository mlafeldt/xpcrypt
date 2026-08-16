#!/usr/bin/env python3
"""Find the *code* cipher in the PC tools, and prove it by running it.

`xlink.py` does this for the `.fcd` image cipher, which is a whole-file
transform. This is its counterpart for the other cipher - the code keys 4 to 7
and the Supercode/Megacode payload keys that `REVERSING.md` reads out of the
cartridge firmware and `romcrypt.py` transcribes. The firmware only ever
decrypts; the question here is what the PC side does, and the answer turns out
to be the missing half.

    uv run --with capstone --with unicorn python xcode.py [-s] [binary ...]

`-s` also disassembles each routine found. With no file arguments it takes every
`pc/*.exe`; like `roms/`, `pc/` is not in the repo - `FCD.md` section 4 has where
the four binaries come from.

No routine here is found by its constants. They are found by *running* every
function in the binary: take every direct call target, run it under a 32-bit x86
emulator with six bytes of input, and ask whether what comes out is one of the
sixteen transforms `romcrypt.py` describes. A function that is the cipher answers
on the first probe and then has to keep answering over a hundred more random
inputs; everything else faults, loops, or writes something that is not any of
them. `CONV` is the list of ways to hand a routine its arguments, and which one a
routine wants is discovered the same way rather than asserted.

The point of doing it that way: a search for `0x76`, `0xEF` and `0x73` finds the
DOS tool's key 7 and would have walked straight past X-Killer's, which computes
the same function out of `0x73`, `0x90`, `0x16`, `0x5A` and `0x35`. There was no
reason to expect two spellings until both were in front of us.

`check_constants()` does run a constant sweep, but only as a second opinion on
the *negative* result - "no code cipher in `Xlink95.exe`" means each of its 1,491
functions was executed and none answered, and separately that the constants one
would need are not in its code at all.

Two things the emulator cannot settle, so they are measured separately:

  * **byte 0** is not part of the cipher and every implementation treats it
    differently, so routines are identified on bytes 1 to 5 and their byte 0 is
    then classified by probing it (`byte0_kind`);
  * **which key an argument selects** is the tool's business, not the cipher's.
    The DOS tool takes a method index that is not the key nibble; the report
    prints the index it was called with next to the key it turned out to be.
"""
import glob
import os
import re
import struct
import sys

import romcrypt
from xlink import call_targets, load_le, load_pe

CODE_LEN = 6

# Where the emulator puts things. Far away from any image we load.
STACK, SRC, DST, RETADDR = 0x70010000, 0x71000000, 0x72000000, 0x7FFF0000

# How to hand a routine (src, dst) and, for the ones that take it, a selector.
# 'r' names registers in order, 's' names stack arguments in push order; 'S'
# marks the selector position. Watcom's /3r passes in registers, MSVC's default
# on the stack, and either may transform one buffer in place - hence 'b'.
CONV = {
    'watcom_regs':  (('eax', 'edx', 'ebx'), 'sdS', ''),
    'watcom_2':     (('eax', 'edx'), 'sd', ''),
    'cdecl_sd':     ((), '', 'sd'),
    'cdecl_ds':     ((), '', 'ds'),
    'cdecl_b':      ((), '', 'b'),
    'cdecl_sdS':    ((), '', 'sdS'),
    'cdecl_bS':     ((), '', 'bS'),
}
SELECTORS = range(8)


# ------------------------------------------------------- the reference cipher

# romcrypt.py is the firmware, and the firmware only decrypts. The encrypt side
# below is the algebraic inverse of it, written out rather than searched for,
# and `check_inverses()` makes every one of them round-trip through romcrypt
# before anything else runs - so "the PC tool encrypts" is a claim about the
# firmware's own routine, not about a second transcription of it.

M = 0xFF


def enc_key4(c):
    """Inverse of romcrypt's key 4. The window is fed the plaintext byte in
    both directions, which is the whole reason the chain inverts at all."""
    o, w = [0] * CODE_LEN, list(romcrypt.KEY4)
    for i in range(1, CODE_LEN):
        v = (w[0] + 0x38) + w[1] + (w[2] ^ 0x12) + (w[3] | 0xEE)
        o[i] = (c[i] ^ v) & M
        w = w[1:] + [c[i]]
    return o


def enc_key5(c):
    return [0] + [(c[i] - romcrypt.KEY5[i]) & M for i in range(1, CODE_LEN)]


def enc_key6(c):
    return [0] + [((c[i] ^ i) + 0x55) & M for i in range(1, CODE_LEN)]


def enc_key7(c):
    o, w = [0] * CODE_LEN, list(romcrypt.KEY7)
    for i in range(CODE_LEN - 1, 0, -1):
        v = (w[0] + 0x76) + w[1] + (w[2] ^ 0xEF) + (w[3] & 0x73)
        o[i] = (c[i] - v) & M
        w = w[1:] + [c[i]]
    return o


def enc_payload6(p):
    o = [0] * CODE_LEN
    o[0] = (p[1] + 0x34) & M
    o[1] = (~p[0]) & M
    o[2] = (p[5] + o[0]) & M
    o[3] = (p[3] ^ o[1]) & M
    o[4] = (p[2] + 0x1B) & M
    o[5] = (p[4] + 0x55) & M
    return o


def enc_payload7(p):
    return [(p[CODE_LEN - 1 - i] + 0x55) & M for i in range(CODE_LEN)]


def enc_special32(c):
    return [0] + [(c[1] - 0x46) & M, (c[2] - 0x43) & M, (c[3] - 0x44) & M,
                  c[4], c[5]]


def enc_special33(c):
    return [0] + [(~c[1]) & M, (~c[2]) & M, (~c[3]) & M, c[4], c[5]]


def _dec(route=None, key=-1):
    return lambda c: romcrypt.decrypt(list(c), key=key, route=route)


# label -> transform. Keyed on what it computes, not on what any tool calls it.
TRANSFORMS = {
    ('key4', 'decrypt'):     _dec(route='key4'),
    ('key4', 'encrypt'):     enc_key4,
    ('key5', 'decrypt'):     _dec(route='key5'),
    ('key5', 'encrypt'):     enc_key5,
    ('key6', 'decrypt'):     _dec(route='key6'),
    ('key6', 'encrypt'):     enc_key6,
    ('key7', 'decrypt'):     _dec(route='key7'),
    ('key7', 'encrypt'):     enc_key7,
    ('payload6', 'decrypt'): _dec(key=6),
    ('payload6', 'encrypt'): enc_payload6,
    ('payload7', 'decrypt'): _dec(key=7),
    ('payload7', 'encrypt'): enc_payload7,
    ('special32', 'decrypt'): _dec(route='fcd'),
    ('special32', 'encrypt'): enc_special32,
    ('special33', 'decrypt'): _dec(route='not'),
    ('special33', 'encrypt'): enc_special33,
}


def check_inverses(n=4096):
    """Every encrypt above must be the inverse of the firmware's decrypt.

    Bytes 1 to 5 only: byte 0 carries the key nibble rather than ciphertext and
    no two implementations here agree on what to do with it.
    """
    import random
    rnd = random.Random(0x5741594E)
    pairs = [('key4', None), ('key5', None), ('key6', None), ('key7', None),
             ('payload6', 6), ('payload7', 7),
             ('special32', None), ('special33', None)]
    for name, key in pairs:
        dec = TRANSFORMS[(name, 'decrypt')]
        enc = TRANSFORMS[(name, 'encrypt')]
        for _ in range(n):
            p = [rnd.randrange(256) for _ in range(CODE_LEN)]
            assert dec(enc(p))[1:] == p[1:], (name, p)
            assert enc(dec(p))[1:] == p[1:], (name, p)
    return len(pairs)


# ------------------------------------------------------------------- loading

def apply_le_fixups(raw, objs):
    """Patch the absolute addresses an LE image leaves to its loader.

    `xlink.py` deliberately does not do this - the `.fcd` routines are
    self-contained, and an unfixed image is what lets a data reference be found
    by searching for its offset within its object. The code cipher is not
    self-contained: the DOS tool's dispatch is an indirect jump through a table
    whose entries are all fixups, and its key 4, 5 and 7 seeds are reached
    through pointers that are fixups too. Unfixed, the routine jumps to the
    start of the code object.
    """
    le = struct.unpack_from('<I', raw, 0x3C)[0]
    g = lambda o: struct.unpack_from('<I', raw, le + o)[0]
    npages, psize, objtab, nobj = g(0x14), g(0x28), g(0x40), g(0x44)
    fixpage, fixrec = le + g(0x68), le + g(0x6C)

    bases, pageobj = [], {}
    for i in range(nobj):
        _size, base, _flags, pgidx, npg, _ = struct.unpack_from(
            '<IIIIII', raw, le + objtab + i * 24)
        bases.append(base)
        for k in range(npg):
            pageobj[pgidx + k] = (base, k * psize)

    mem = {b: bytearray(v) for b, v in objs.items()}
    applied = 0
    for p in range(1, npages + 1):
        if p not in pageobj:
            continue
        obase, pofs = pageobj[p]
        o = fixrec + struct.unpack_from('<I', raw, fixpage + (p - 1) * 4)[0]
        end = fixrec + struct.unpack_from('<I', raw, fixpage + p * 4)[0]
        while o < end:
            src, flags = raw[o], raw[o + 1]
            o += 2
            if src & 0x20:                       # source list
                cnt, srcoffs = raw[o], None
                o += 1
            else:
                srcoffs = [struct.unpack_from('<h', raw, o)[0]]
                o += 2
            kind = flags & 3
            target = None
            if kind == 0:                        # internal reference
                if flags & 0x40:
                    tobj, = struct.unpack_from('<H', raw, o)
                    o += 2
                else:
                    tobj = raw[o]
                    o += 1
                toff = 0
                if (src & 0x0F) != 2:            # not selector-only
                    fmt, n = ('<I', 4) if flags & 0x10 else ('<H', 2)
                    toff, = struct.unpack_from(fmt, raw, o)
                    o += n
                target = bases[tobj - 1] + toff
            elif kind == 1:                      # import by ordinal
                o += 2 if flags & 0x40 else 1
                o += 1 if flags & 0x80 else (4 if flags & 0x10 else 2)
            elif kind == 2:                      # import by name
                o += 2 if flags & 0x40 else 1
                o += 4 if flags & 0x10 else 2
            else:                                # internal entry table
                o += 2
            if flags & 0x04:                     # additive
                o += 4 if flags & 0x20 else 2
            if srcoffs is None:
                srcoffs = list(struct.unpack_from('<%dh' % cnt, raw, o))
                o += 2 * cnt
            if target is None or (src & 0x0F) not in (7, 8):
                continue                         # not a 32-bit address slot
            for so in srcoffs:
                at = pofs + so
                buf = mem[obase]
                if not 0 <= at <= len(buf) - 4:
                    continue                     # spills past the object
                v = target if (src & 0x0F) == 7 else target - (obase + at + 4)
                struct.pack_into('<I', buf, at, v & 0xFFFFFFFF)
                applied += 1
    return {b: bytes(v) for b, v in mem.items()}, applied


def executable_bases(path):
    """The segment bases the file's own headers mark executable.

    Wanted for the constant sweep: a data section is full of bytes that read as
    an ALU immediate, and one that happens to hold a run of `E8`s reads as full
    of call targets too, so "a segment something calls into" is not a usable
    stand-in for "a segment holding code".
    """
    raw = open(path, 'rb').read()
    e = struct.unpack_from('<I', raw, 0x3C)[0] if len(raw) > 0x40 else 0
    out = set()
    if raw[e:e + 4] == b'PE\0\0':
        nsec, = struct.unpack_from('<H', raw, e + 6)
        optsz, = struct.unpack_from('<H', raw, e + 20)
        imgbase, = struct.unpack_from('<I', raw, e + 24 + 28)
        for i in range(nsec):
            o = e + 24 + optsz + i * 40
            va, = struct.unpack_from('<I', raw, o + 12)
            chars, = struct.unpack_from('<I', raw, o + 36)
            if chars & 0x20000020:        # CNT_CODE | MEM_EXECUTE
                out.add(imgbase + va)
        return out
    le = struct.unpack_from('<I', raw, 0x3C)[0]
    g = lambda o: struct.unpack_from('<I', raw, le + o)[0]
    objtab, nobj = g(0x40), g(0x44)
    for i in range(nobj):
        _size, base, flags = struct.unpack_from('<III', raw, le + objtab + i * 24)
        if flags & 0x0004:                # executable
            out.add(base)
    return out


def load(path):
    """Return ({base: bytes}, kind), with LE fixups applied."""
    raw = open(path, 'rb').read()
    e = struct.unpack_from('<I', raw, 0x3C)[0] if len(raw) > 0x40 else 0
    if raw[e:e + 4] == b'PE\0\0':
        return load_pe(path, raw), 'PE'
    objs, _ = apply_le_fixups(raw, load_le(path, raw))
    return objs, 'LE'


# ------------------------------------------------------------------- running

class Machine:
    """One mapped image, reused across every probe.

    The image is mapped read-only. That is not only tidiness: we are about to
    run thousands of functions that were never meant to be entered this way, and
    a stray store into a global would otherwise change what the next probe sees.
    Read-only turns that into a fault, which is a result we can discard.
    """

    def __init__(self, segs):
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
        from unicorn import UC_PROT_READ, UC_PROT_EXEC, UC_PROT_ALL
        from unicorn import x86_const as X
        self.X = X
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base, blob in segs:
            page = base & ~0xFFF
            size = (len(blob) + (base - page) + 0xFFF) & ~0xFFF
            self.uc.mem_map(page, size, UC_PROT_READ | UC_PROT_EXEC)
            self.uc.mem_write(base, blob)
        for a, n in ((STACK - 0x10000, 0x10000), (SRC, 0x1000), (DST, 0x1000),
                     (RETADDR & ~0xFFF, 0x1000)):
            self.uc.mem_map(a, n, UC_PROT_ALL)
        self.reg = {'eax': X.UC_X86_REG_EAX, 'edx': X.UC_X86_REG_EDX,
                    'ebx': X.UC_X86_REG_EBX, 'ecx': X.UC_X86_REG_ECX}
        self.clean = self.uc.context_save()

    def call(self, entry, conv, sel, src, fill=0xCC):
        """Run one routine over `src`; return the six bytes it produced.

        Returns None if it faulted or ran away. `fill` is what the destination
        held beforehand, which is how a route that writes only some of the six
        bytes is told from one that writes all of them.
        """
        from unicorn import UcError
        regs, rkind, skind = CONV[conv]
        inplace = 'b' in rkind + skind
        # Start every probe from the state the machine was built in. Most of the
        # functions we are about to enter were never meant to be called this way
        # and will fault, and some faults leave the emulated CPU in a state that
        # writing the registers back does not clear - after one of those, every
        # later probe faults at its first instruction and the binary reads as
        # having no cipher in it. Restoring the context is what makes a sweep of
        # thousands of functions mean anything.
        self.uc.context_restore(self.clean)
        self.uc.mem_write(SRC, bytes(src))
        self.uc.mem_write(DST, bytes([fill]) * CODE_LEN)
        arg = {'s': SRC, 'd': DST, 'b': SRC, 'S': sel}
        for r, k in zip(regs, rkind):
            self.uc.reg_write(self.reg[r], arg[k])
        frame = b''.join(struct.pack('<I', arg[k]) for k in skind)
        sp = STACK - 4 - len(frame)
        self.uc.mem_write(sp, struct.pack('<I', RETADDR) + frame)
        self.uc.reg_write(self.X.UC_X86_REG_ESP, sp)
        try:
            self.uc.emu_start(entry, RETADDR, count=200_000)
        except UcError:
            return None
        return list(self.uc.mem_read(SRC if inplace else DST, CODE_LEN))


# ------------------------------------------------------------------- probing

def probe_input(seed):
    """Six bytes with a keyed high nibble, so no route is a no-op on it."""
    import random
    rnd = random.Random(seed)
    return [0x10] + [rnd.randrange(1, 256) for _ in range(CODE_LEN - 1)]


def byte0_kind(mach, entry, conv, sel, name):
    """How a routine treats byte 0, for the routes where it is not ciphertext.

    The firmware clears the whole low nibble on the way out; the DOS tool masks
    it and ORs the key in, which keeps the "switched off by default" bit 3; and
    X-Killer XORs the key, like xpcrypt. All three agree whenever bit 3 and the
    key bits are already clear, and that is the only case a published code is
    in, so nothing downstream sees the difference.
    """
    if name.startswith('payload'):
        # A payload code is six bytes of data with no key nibble in it, so byte
        # 0 goes through the cipher like the rest and there is nothing to
        # classify. Both payload routes transform it; only these do.
        return 'ciphertext'
    key = int(name[-1])
    forms = {
        '(b & 0xF8) | k': lambda b: (b & 0xF8) | key,
        'b ^ k':          lambda b: b ^ key,
        'b & 0xF0':       lambda b: b & 0xF0,
        'b':              lambda b: b,
    }
    ins = (0x00, 0x08, 0x10, 0x18, 0x13, 0x35, 0xF8)
    got = []
    for b in ins:
        out = mach.call(entry, conv, sel, [b, 1, 2, 3, 4, 5])
        if out is None:
            return '?'
        got.append(out[0])
    for name, f in forms.items():
        if all(g == f(b) & 0xFF for g, b in zip(got, ins)):
            return name
    if all(g == 0xCC for g in got):
        return 'left as found'
    return 'other (%s)' % ' '.join('%02X' % g for g in got)


def identify(mach, entry, conv, sel, first, rounds=128):
    """Which transform a routine computes, or None.

    `first` is what it produced for probe 0 - matched on bytes 1 to 5, since
    byte 0 is the key nibble and no two of these tools stamp it the same way.
    A first-probe match is only a candidate: it then has to agree over `rounds`
    more inputs, which is what stops a six-byte coincidence from being reported.
    """
    for label, f in TRANSFORMS.items():
        if f(probe_input(0))[1:] != first[1:]:
            continue
        for r in range(1, rounds):
            src = probe_input(r)
            out = mach.call(entry, conv, sel, src)
            if out is None or out[1:] != f(src)[1:]:
                break
        else:
            return label
    return None


def functions(segs):
    """Every direct call target, plus the segment starts, as candidate entries."""
    targets = set(call_targets(segs))
    return sorted(targets)


def canonicalize(hits):
    """One line per (routine, transform), under the least assuming convention.

    A routine that ignores its third argument answers under `cdecl_sdS` for all
    eight selectors as readily as under `cdecl_sd`, and one that takes a real
    selector answers under exactly one. Grouping by what a routine *computes*
    separates the two without having to know which it is: the selectors that
    survive for a given transform are the ones that select it, and the shortest
    convention that still works is the one to report.
    """
    order = list(CONV)

    def slots(conv):
        _regs, rkind, skind = CONV[conv]
        return len(rkind) + len(skind), order.index(conv)

    by = {}
    for entry, conv, sel, label, b0 in hits:
        by.setdefault((entry, label), []).append((conv, sel, b0))

    out = []
    for (entry, label), lst in sorted(by.items()):
        conv = min({c for c, _, _ in lst}, key=slots)
        sels = sorted(s for c, s, _ in lst if c == conv)
        b0 = next(b for c, _, b in lst if c == conv)
        takes_sel = 'S' in ''.join(CONV[conv][1:])
        out.append((entry, conv, sels if takes_sel else None, label, b0))
    return out


def find_ciphers(segs, progress=None):
    """Run every function under every convention; keep the ones that answer."""
    mach = Machine(segs)
    ref = {}
    for label, f in TRANSFORMS.items():
        ref.setdefault(tuple(f(probe_input(0))[1:]), []).append(label)

    out, entries = [], functions(segs)
    for n, entry in enumerate(entries):
        if progress and n % 500 == 0:
            progress(n, len(entries))
        for conv in CONV:
            sels = SELECTORS if 'S' in ''.join(CONV[conv][1:]) else (0,)
            for sel in sels:
                first = mach.call(entry, conv, sel, probe_input(0))
                if first is None or tuple(first[1:]) not in ref:
                    continue
                label = identify(mach, entry, conv, sel, first)
                if label is None:
                    continue
                out.append((entry, conv, sel, label,
                            byte0_kind(mach, entry, conv, sel, label[0])))
    return canonicalize(out), len(entries), mach


# ------------------------------------------- the negative result, a second way

# The sweep above finds a routine only if it is a direct call target that takes
# six bytes in and puts six bytes out under one of seven conventions. A cipher
# inlined into a larger function, or reached only through a vtable, would not
# answer - so "no code cipher in Xlink95.exe" wants a check that does not care
# how the code is shaped. Whatever shape it is in, it has to spell its
# constants: these are the smallest sets that pin a key down, in both of the
# forms anything here writes it. Key 6 is the exception - it is a xor with the
# byte index and one addition - so it is reported as a count of the only
# constant it can use.
CONSTANT_SETS = {
    'key4 window': (0x38, 0x12, 0xEE),
    'key4 closed': (0x25, 0xFA, 0x40, 0x82, 0xDA),
    'key5':        (0x57, 0x42, 0x31, 0x32, 0x33),
    'key7 window': (0x76, 0xEF, 0x73),
    'key7 closed': (0x73, 0x90, 0x16, 0x5A, 0x35),
    'payload6':    (0x34, 0x1B, 0x55),
}
SEEDS = (b'WHBX', b'FCD!', b' WB123')

# ALU op with an 8-bit immediate: the short accumulator forms and the group-1
# `80 /n ib`. The immediate is the byte after the match.
IMM8 = re.compile(rb'(?:[\x04\x0c\x14\x1c\x24\x2c\x34\x3c]|\x80[\xc0-\xff])',
                  re.S)
# ... and the same narrowed to `add`/`sub`, which is all key 6 can be built from.
ADDSUB8 = re.compile(rb'(?:[\x04\x2c]|\x80[\xc0-\xc7\xe8-\xef])[\x55\xab]', re.S)
SPAN = 0x120            # how far apart a routine may spell its own constants


def check_constants(segs, code):
    """Which key constants appear anywhere in the image, however arranged.

    Immediates are looked for in the executable segments only; the seed tables
    are looked for everywhere, because that is where the DOS tool keeps them.
    """
    imm = {}
    for base, blob in segs:
        if base not in code:
            continue
        for m in IMM8.finditer(blob):
            if m.end() < len(blob):
                imm.setdefault(blob[m.end()], []).append(base + m.end())

    out = []
    for name, consts in CONSTANT_SETS.items():
        here = sorted(a for c in consts for a in imm.get(c, []))
        best = None
        for a in here:
            reach = [min((x for x in imm.get(c, ()) if x >= a), default=None)
                     for c in consts]
            if any(x is None or x >= a + SPAN for x in reach):
                continue
            width = max(reach) - a
            if best is None or width < best[1]:
                best = (a, width)
        if best:
            # The width is what separates a routine from a coincidence: three
            # constants that happen to fall within 0x120 bytes of each other are
            # common, the same three inside twenty are not.
            out.append('%s @%08X+%d' % (name, best[0], best[1]))
    for seed in SEEDS:
        for base, blob in segs:
            i = blob.find(seed)
            if i >= 0:
                out.append('%r @%08X' % (seed.decode(), base + i))
    # Key 6 is a xor with the byte index and one addition, so it has no set to
    # match - all it can be pinned by is its single constant, and a lone byte is
    # a candidate rather than a finding. Reported as a count to be looked at by
    # hand; in these four binaries every candidate outside a routine already
    # listed above turns out to be a misaligned decode.
    n55 = sum(len(ADDSUB8.findall(blob)) for base, blob in segs if base in code)
    out.append('%d candidate add/sub 0x55 or 0xAB (key 6 needs one)' % n55)
    return ', '.join(out)


# ------------------------------------------------------- against the C source

# High nibbles the firmware's route table gives no crypto route, and the ones
# that start a block of payload codes. Neither can appear in a plain code test:
# the first would come back unencrypted, the second would swallow the codes
# below it.
GAP_NIBBLES = (0x2, 0xA, 0xC, 0xE)
BLOCK_NIBBLES = (0x5, 0x6, 0xA)


def check_xpcrypt(mach, hits, n=500):
    """The vendor's own encrypter against the one in the repo, code for code.

    This is the check the encrypt side never had. `oracle_test.py` can only ask
    whether the firmware decrypts back what xpcrypt encrypted, which leaves
    every choice the firmware does not see - and the round trip does not see
    either - resting on xpcrypt's own inverse being the intended one. XLink is
    the vendor's, it predates the cartridge dumps by a decade, and it settles
    those choices by being a second encrypter rather than by being read.

    Byte 0 is included. The two disagree on it in general - XLink masks the key
    bits and ORs, xpcrypt XORs and refuses a code that already carries any - but
    a code with those bits clear is the only kind either will encrypt, and on
    those they agree exactly.
    """
    import pathlib
    import random
    import subprocess

    exe = pathlib.Path(__file__).resolve().parent.parent / 'xpcrypt'
    if not exe.exists():
        return 'no ../xpcrypt built - skipped'
    rnd = random.Random(0x58504331)

    def xp(args, codes):
        text = '\n'.join('%02X%02X%02X%02X %02X%02X' % tuple(c) for c in codes)
        r = subprocess.run([str(exe)] + args, input=text.encode(),
                           capture_output=True)
        assert r.returncode == 0, r.stderr.decode(errors='replace')
        w = r.stdout.decode().split()
        got = [list(bytes.fromhex(a + b)) for a, b in zip(w[0::2], w[1::2])]
        assert len(got) == len(codes), (len(codes), len(got))
        return got

    good = [h for h in range(16)
            if h not in GAP_NIBBLES and h not in BLOCK_NIBBLES]
    checked = 0
    for entry, conv, sels, (name, way), _ in hits:
        if way != 'encrypt':
            continue
        sel = sels[0] if sels else 0
        if name.startswith('payload'):
            key = int(name[-1])
            # A Supercode header carries the payload key in the high nibble of
            # byte 4; xpcrypt's -e argument is the header's own key and does not
            # touch the rows below it.
            rows = [[rnd.randrange(256) for _ in range(CODE_LEN)]
                    for _ in range(n)]
            head = [0x50, 0, 0, 0, (key << 4) | ((n * CODE_LEN) >> 8),
                    (n * CODE_LEN) & 0xFF]
            ours = xp(['-e', '6'], [head] + rows)[1:]
        else:
            key = int(name[-1])
            rows = [[(rnd.choice(good) << 4) | rnd.choice((0, 8))]
                    + [rnd.randrange(256) for _ in range(CODE_LEN - 1)]
                    for _ in range(n)]
            ours = xp(['-e', str(key)], rows)
        for src, want in zip(rows, ours):
            got = mach.call(entry, conv, sel, src)
            assert got == want, (name, src, got, want)
        checked += len(rows)
    return '%d codes, byte for byte' % checked if checked else None


# -------------------------------------------------------------------- output

def show(segs, addr, n=0x60):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    base, code = max(((b, c) for b, c in segs if b <= addr < b + len(c)))
    for i in md.disasm(code[addr - base:addr - base + n], addr):
        print('    %08X  %-16s %s %s' % (i.address, i.bytes.hex(),
                                         i.mnemonic, i.op_str))
        if i.mnemonic.startswith('ret'):
            break


# What is in pc/. As in xlink.py this is a record of the answer, not a gate on
# finding it: a build not listed is probed and reported like the rest.
EXPECTED = {
    'XLink.exe': [
        (('key4', 'encrypt'), 'watcom_regs', (1,)),
        (('key5', 'encrypt'), 'watcom_regs', (2,)),
        (('key6', 'encrypt'), 'watcom_regs', (3,)),
        (('key7', 'encrypt'), 'watcom_regs', (4,)),
        (('payload6', 'encrypt'), 'watcom_regs', (6,)),
        (('payload7', 'encrypt'), 'watcom_regs', (7,)),
    ],
    'Xlink95.exe': [],
    'Xlink95-19990702.exe': [],
    'x-killer.exe': [
        (('key6', 'decrypt'), 'cdecl_sd', None),
        (('key6', 'encrypt'), 'cdecl_sd', None),
        (('key7', 'decrypt'), 'cdecl_sd', None),
        (('key7', 'encrypt'), 'cdecl_sd', None),
    ],
}


def main(argv):
    show_asm = '-s' in argv
    quiet = '-q' in argv
    paths = ([a for a in argv if not a.startswith('-')]
             or sorted(glob.glob('pc/*.exe')))
    if not paths:
        print('no pc/*.exe - skipped (see FCD.md section 4 for where to get them)')
        return 0

    n = check_inverses()
    print('%d encrypt routines are the inverse of romcrypt.py, checked on '
          '4096 codes each' % n)

    found, probed = {}, 0
    for path in paths:
        objs, kind = load(path)
        segs = sorted(objs.items())
        report = None if quiet else (
            lambda i, t: sys.stderr.write('\r  %s %d/%d   ' % (path, i, t)))
        hits, nfun, mach = find_ciphers(segs, report)
        if report:
            sys.stderr.write('\r' + ' ' * 44 + '\r')
        probed += nfun
        print('%s: %s, %d segments, %d functions probed, %d routines'
              % (path, kind, len(segs), nfun, len(hits)))
        print('  constants: %s' % check_constants(segs, executable_bases(path)))
        for entry, conv, sels, (name, way), b0 in hits:
            arg = conv if sels is None else '%s sel=%s' % (
                conv, ','.join(str(s) for s in sels))
            print('  %08X  %-9s %-7s %-18s byte 0 -> %s'
                  % (entry, name, way, arg, b0))
            if show_asm:
                show(segs, entry)
        against = check_xpcrypt(mach, hits)
        if against:
            print('  vs ../xpcrypt -e: %s' % against)
        found[os.path.basename(path)] = [
            (l, c, tuple(s) if s is not None else None)
            for _, c, s, l, _ in hits]

    for name, got in found.items():
        if name in EXPECTED:
            assert sorted(got) == sorted(EXPECTED[name]), (name, got)
    total = sum(len(v) for v in found.values())
    print('%d routines in %d binaries out of %d functions probed; every one '
          'agrees with romcrypt.py over 128 codes' % (total, len(found), probed))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
