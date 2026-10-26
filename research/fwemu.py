#!/usr/bin/env python3
"""Run the real code-decrypt routine out of an Xplorer/Xploder PSX firmware.

A MIPS I interpreter just big enough for that one routine, so the question
"do the FX carts decrypt codes the same way the V2 carts do?" can be answered
by *executing* both rather than by reading them.

The routine calls exactly two functions, and both are stubbed:

  strncpy      loads a 4-byte constant table onto the stack.  V2 reaches the
               BIOS A(0x1A); FX has its own copy (0x80012AA8 in 3.20,
               0x80012B28 in 4.50 and 4.52).
  the checker  V2 calls it as f(0x1F000000, 0x18000) at the end of a route, FX
               as f(6, 0x18000) at the start.  It is the copyright check on the
               cheat database - see fxprot.py - and on real hardware it can
               overwrite the cartridge's own firmware.  It is stubbed here
               because it cannot affect a *decrypted code*: it is handed neither
               the source nor the destination, and the ABI keeps $s0/$s1 for us.
               The known-plaintext check then confirms that empirically.

Stubbing is decided when control first reaches a function through jal/jalr, not
by working out where the routine ends - it has no end to find.  Its routes are
reached through a jump table, so nothing says they sit next to the dispatcher.
(In every image here they do.  An earlier note had the German V2 routes 0x1000
bytes away; that was a load address 0x1000 too low, see fwimage.base_of.)

Anything the routine touches outside the mapped image and scratch RAM raises,
so a wrong guess about the memory map shows up instead of silently reading 0.
"""
import struct

import fwimage
import mipscan

RET = 0x0BADF00C        # $ra sentinel: the routine has returned
RAM = 0x00700000        # 1 MB of scratch, clear of every image we load
SRC, DST, SP = RAM + 0x1000, RAM + 0x2000, RAM + 0xF000


class Mem:
    def __init__(self):
        self.segs = []
        self.cop0 = [0] * 32

    def map(self, base, data):
        self.segs.append((base, base + len(data), bytearray(data)))

    def seg(self, a):
        for lo, hi, d in self.segs:
            if lo <= a < hi:
                return lo, d
        raise MemoryError('unmapped address %08X' % a)

    def r8(self, a):
        lo, d = self.seg(a)
        return d[a - lo]

    def w8(self, a, v):
        lo, d = self.seg(a)
        d[a - lo] = v & 0xFF

    def r16(self, a):
        lo, d = self.seg(a)
        return struct.unpack_from('<H', d, a - lo)[0]

    def w16(self, a, v):
        lo, d = self.seg(a)
        struct.pack_into('<H', d, a - lo, v & 0xFFFF)

    def r32(self, a):
        lo, d = self.seg(a)
        return struct.unpack_from('<I', d, a - lo)[0]

    def w32(self, a, v):
        lo, d = self.seg(a)
        struct.pack_into('<I', d, a - lo, v & 0xFFFFFFFF)

    def read(self, a, n):
        return bytes(self.r8(a + i) for i in range(n))

    def write(self, a, b):
        for i, v in enumerate(b):
            self.w8(a + i, v)


S32 = lambda v: v - 0x100000000 if v & 0x80000000 else v
SIMM = lambda w: (w & 0xFFFF) - 0x10000 if w & 0x8000 else w & 0xFFFF

# little-endian lwl/lwr/swl/swr, the usual four-entry tables
LWL_M = (0x00FFFFFF, 0x0000FFFF, 0x000000FF, 0)
LWL_S = (24, 16, 8, 0)
LWR_M = (0, 0xFF000000, 0xFFFF0000, 0xFFFFFF00)
LWR_S = (0, 8, 16, 24)
SWL_M = (0xFFFFFF00, 0xFFFF0000, 0xFF000000, 0)
SWL_S = (24, 16, 8, 0)
SWR_M = (0, 0x000000FF, 0x0000FFFF, 0x00FFFFFF)
SWR_S = (0, 8, 16, 24)


def run(mem, pc, args, resolve, limit=200000, regs=None, sp=SP):
    """@resolve(addr) hands back a stub for a called function, or None to let
    the interpreter run it.  Only addresses actually reached through jal/jalr
    are ever offered, so the routine's own code is never mistaken for one.

    @regs seeds registers the ABI does not cover - the code engine is entered
    with the BIOS function number in $t1 rather than with arguments.

    A register always holds an unsigned 32-bit value.  Everything that wants a
    signed one says so with S32(), which is only correct on that range, so a
    sign-extending load has to mask its result back into it - see `lb`/`lh`
    below.  Leaving a negative there does not stay contained: Python's `>>`
    keeps the sign, so `srl` of a loaded 0xFF would give 0xFFFFFFFF instead of
    0x7FFFFFFF, and S32() would subtract a second time and turn `sra` into a
    logical shift."""
    r = [0] * 32
    # Masked on the way in for the same reason `lb` masks on the way out: a
    # caller passing Python's -1 for 0xFFFFFFFF would otherwise seed a value no
    # instruction below can produce, and the first shift would give the wrong
    # answer with nothing to show for it.
    for i, v in enumerate(args):
        r[4 + i] = v & 0xFFFFFFFF       # $a0..$a3
    for i, v in (regs or {}).items():
        r[i] = v & 0xFFFFFFFF
    r[29], r[31] = sp & 0xFFFFFFFF, RET # $sp, $ra
    hi = lo = 0
    npc, called = pc + 4, set()
    for _ in range(limit):
        if pc == RET:
            return r
        if pc in called:
            stub = resolve(pc)
            if stub is not None:
                stub(mem, r)
                pc, npc = r[31], r[31] + 4
                continue
        w = mem.r32(pc)
        pc, npc = npc, npc + 4
        op, rs, rt, rd = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
        sa, fn, imm = (w >> 6) & 31, w & 63, SIMM(w)
        a, b = r[rs], r[rt]

        if op == 0:
            if fn == 0x00:   r[rd] = (b << sa) & 0xFFFFFFFF
            elif fn == 0x02: r[rd] = b >> sa
            elif fn == 0x03: r[rd] = (S32(b) >> sa) & 0xFFFFFFFF
            elif fn == 0x04: r[rd] = (b << (a & 31)) & 0xFFFFFFFF
            elif fn == 0x06: r[rd] = b >> (a & 31)
            elif fn == 0x07: r[rd] = (S32(b) >> (a & 31)) & 0xFFFFFFFF
            elif fn == 0x08: npc = a
            elif fn == 0x09: r[rd], npc = npc, a; called.add(a)
            elif fn == 0x10: r[rd] = hi
            elif fn == 0x11: hi = a
            elif fn == 0x12: r[rd] = lo
            elif fn == 0x13: lo = a
            elif fn in (0x18, 0x19):
                p = (S32(a) * S32(b)) if fn == 0x18 else (a * b)
                hi, lo = (p >> 32) & 0xFFFFFFFF, p & 0xFFFFFFFF
            elif fn in (0x1A, 0x1B):
                x, y = (S32(a), S32(b)) if fn == 0x1A else (a, b)
                if y:
                    q = abs(x) // abs(y)
                    if (x < 0) != (y < 0): q = -q
                    lo, hi = q & 0xFFFFFFFF, (x - q * y) & 0xFFFFFFFF
            elif fn in (0x20, 0x21): r[rd] = (a + b) & 0xFFFFFFFF
            elif fn in (0x22, 0x23): r[rd] = (a - b) & 0xFFFFFFFF
            elif fn == 0x24: r[rd] = a & b
            elif fn == 0x25: r[rd] = a | b
            elif fn == 0x26: r[rd] = a ^ b
            elif fn == 0x27: r[rd] = ~(a | b) & 0xFFFFFFFF
            elif fn == 0x2A: r[rd] = int(S32(a) < S32(b))
            elif fn == 0x2B: r[rd] = int(a < b)
            else: raise NotImplementedError('special fn 0x%02X at %08X' % (fn, pc - 8))
        elif op == 0x01:
            if rt == 0 and S32(a) < 0: npc = pc + (imm << 2)
            elif rt == 1 and S32(a) >= 0: npc = pc + (imm << 2)
        elif op in (0x02, 0x03):
            if op == 0x03:
                r[31] = npc
                called.add((pc & 0xF0000000) | ((w & 0x03FFFFFF) << 2))
            npc = (pc & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
        elif op == 0x04:
            if a == b: npc = pc + (imm << 2)
        elif op == 0x05:
            if a != b: npc = pc + (imm << 2)
        elif op == 0x06:
            if S32(a) <= 0: npc = pc + (imm << 2)
        elif op == 0x07:
            if S32(a) > 0: npc = pc + (imm << 2)
        elif op in (0x08, 0x09): r[rt] = (a + imm) & 0xFFFFFFFF
        elif op == 0x0A: r[rt] = int(S32(a) < imm)
        elif op == 0x0B: r[rt] = int(a < (imm & 0xFFFFFFFF))
        elif op == 0x0C: r[rt] = a & (w & 0xFFFF)
        elif op == 0x0D: r[rt] = a | (w & 0xFFFF)
        elif op == 0x0E: r[rt] = a ^ (w & 0xFFFF)
        elif op == 0x0F: r[rt] = (w & 0xFFFF) << 16
        elif op == 0x10:                                # cop0
            if rs == 0: r[rt] = mem.cop0[rd]            #   mfc0
            elif rs == 4: mem.cop0[rd] = b              #   mtc0
            else: raise NotImplementedError('cop0 rs=%d at %08X' % (rs, pc - 8))
        elif op == 0x20: v = mem.r8(a + imm); r[rt] = (v | 0xFFFFFF00) if v & 0x80 else v
        elif op == 0x24: r[rt] = mem.r8(a + imm)
        elif op == 0x21: v = mem.r16(a + imm); r[rt] = (v | 0xFFFF0000) if v & 0x8000 else v
        elif op == 0x25: r[rt] = mem.r16(a + imm)
        elif op == 0x23: r[rt] = mem.r32(a + imm)
        elif op == 0x28: mem.w8(a + imm, b)
        elif op == 0x29: mem.w16(a + imm, b)
        elif op == 0x2B: mem.w32(a + imm, b)
        elif op == 0x22:
            ad = a + imm; s = ad & 3
            r[rt] = (b & LWL_M[s]) | ((mem.r32(ad & ~3) << LWL_S[s]) & 0xFFFFFFFF)
        elif op == 0x26:
            ad = a + imm; s = ad & 3
            r[rt] = (b & LWR_M[s]) | (mem.r32(ad & ~3) >> LWR_S[s])
        elif op == 0x2A:
            ad = a + imm; s = ad & 3
            mem.w32(ad & ~3, (b >> SWL_S[s]) | (mem.r32(ad & ~3) & SWL_M[s]))
        elif op == 0x2E:
            ad = a + imm; s = ad & 3
            mem.w32(ad & ~3, (b << SWR_S[s]) | (mem.r32(ad & ~3) & SWR_M[s]))
        else:
            raise NotImplementedError('op 0x%02X at %08X' % (op, pc - 8))
        r[0] = 0
    raise RuntimeError('runaway at %08X' % pc)


def strncpy(mem, r):
    for i in range(r[6]):
        mem.w8(r[4] + i, mem.r8(r[5] + i))
    mem.w8(r[4] + r[6], 0)


def nop_stub(mem, r):
    pass


class Firmware:
    """The decrypt routine of one ROM, callable."""

    def __init__(self, path):
        img, base = fwimage.load(path)
        self.mem = Mem()
        self.mem.map(base, img)
        self.mem.map(RAM, bytes(0x100000))

        self.ins = mipscan.dis(img, base)
        self.idx = {x.address: i for i, x in enumerate(self.ins)}
        t = img.find(b' WB123')
        self.table = [struct.unpack_from('<I', img, t + 24 + 4 * i)[0]
                      for i in range(244)]
        # the dispatcher masks the first code byte with 0xF7; the routine starts
        # at the nearest stack frame above it.  Its routes are reached through
        # the jump table and need not sit next to it, so no attempt is made to
        # guess where the routine ends.
        disp = next(i for i, x in enumerate(self.ins)
                    if x.mnemonic == 'andi' and x.op_str.endswith('0xf7'))
        self.entry = self.ins[next(i for i in range(disp, 0, -1)
                                   if self.ins[i].mnemonic == 'addiu'
                                   and self.ins[i].op_str.startswith('$sp, $sp, -'))].address
        self.stubs = {}
        self.keyed = sum(1 << n for n in range(16)
                         if self.table[(((n << 4) | 4) & 0xF7) - 4] == self.table[0])

    def resolve(self, addr):
        """Classify a function the routine calls, the first time it is reached."""
        if addr not in self.stubs:
            self.stubs[addr] = (strncpy if self.is_strncpy(self.ins, self.idx, addr)
                                else nop_stub)
        return self.stubs[addr]

    def skipped(self):
        return sorted(a for a, f in self.stubs.items() if f is nop_stub)

    @staticmethod
    def is_strncpy(ins, idx, addr):
        """A BIOS A(0x1A) trampoline, or a function with a byte-copy loop in
        it.  The routine's other callee copies nothing - in the Pro firmware it
        is `jr $ra; nop`, an empty function."""
        head = ins[idx[addr]:idx[addr] + 3]
        if ([x.mnemonic for x in head] == ['addiu', 'jr', 'addiu']
                and head[0].op_str.endswith('0xa0')):
            return head[2].op_str.endswith('0x1a')          # A(0x1A) = strncpy
        body = []
        for x in ins[idx[addr]:idx[addr] + 24]:
            body.append(x.mnemonic)
            if x.mnemonic == 'jr' and x.op_str == '$ra':
                break
        return 'lbu' in body and 'sb' in body

    def decrypt(self, code, key=-1, dst=bytes(6)):
        """@dst is the destination buffer as the caller leaves it. The routine
        clears only bytes 1 to 5 of it, so a prefill other than zero shows which
        routes never write byte 0 - pass one to test that, as fxtest.py does."""
        self.mem.write(SRC, bytes(code))
        self.mem.write(DST, bytes(dst))
        run(self.mem, self.entry, (SRC, DST, key & 0xFFFFFFFF), self.resolve)
        return list(self.mem.read(DST, 6))
