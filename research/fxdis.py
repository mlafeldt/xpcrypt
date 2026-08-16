#!/usr/bin/env python3
"""Dump a word-aligned MIPS range.  fxdis.py <rom> <fileoff> <count> [base]"""
import sys
import mipscan

path, off, n = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0)
base = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x9F000000
data = mipscan.load(path)
for i in mipscan.dis(data, base, off, off + n * 4):
    w = int.from_bytes(data[i.address - base:i.address - base + 4], 'little')
    print('%08X %08X  %-9s %s' % (i.address, w, i.mnemonic, i.op_str))
