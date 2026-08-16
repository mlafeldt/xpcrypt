#!/usr/bin/env python3
"""Word-aligned MIPS disassembler + constant scanner for Xplorer ROMs."""
import sys, re
from capstone import *

BASE = 0x1F000000

def load(path):
    return open(path, 'rb').read()

class Ins:
    __slots__ = ('address', 'mnemonic', 'op_str', 'imms')

def dis(data, base=BASE, start=0, end=None):
    """Decode every 4-byte word on its own so alignment is never lost."""
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    end = len(data) if end is None else end
    end -= (end - start) % 4
    out = []
    for off in range(start, end, 4):
        w = data[off:off + 4]
        i = Ins()
        i.address = base + off
        try:
            d = next(md.disasm(w, i.address))
            i.mnemonic, i.op_str = d.mnemonic, d.op_str
        except StopIteration:
            i.mnemonic, i.op_str = '.word', '0x%08x' % int.from_bytes(w, 'little')
        i.imms = set()
        for t in re.findall(r'-?0x[0-9a-f]+|(?<![\w$])-?\d+', i.op_str):
            try:
                i.imms.add(int(t, 0) & 0xFFFF)
            except ValueError:
                pass
        out.append(i)
    return out

def scan(ins, consts, window=40):
    hits = []
    n = len(ins)
    for a in range(n):
        seen = set()
        for b in range(a, min(a + window, n)):
            seen |= ins[b].imms
        if all(c in seen for c in consts):
            hits.append(a)
    out = []
    for h in hits:
        if not out or h - out[-1] > window:
            out.append(h)
    return out

def show(ins, idx, n=48, pre=4):
    for i in ins[max(0, idx - pre):idx + n]:
        print('%08X  %-8s %s' % (i.address, i.mnemonic, i.op_str))

if __name__ == '__main__':
    path = sys.argv[1]
    consts = [int(x, 0) for x in sys.argv[2].split(',')]
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 48
    base = int(sys.argv[4], 0) if len(sys.argv) > 4 else BASE
    ins = dis(load(path), base)
    hits = scan(ins, consts)
    print('# %s: %d hit(s) for %s' % (path, len(hits), [hex(c) for c in consts]))
    for h in hits:
        print('\n=== hit at %08X (file 0x%X)' % (ins[h].address, ins[h].address - base))
        if n:
            show(ins, h, n)
