#!/usr/bin/env python3
"""COMP01 unpacker for Xplorer/Xploder PSX ROMs.

Reimplementation of the loader stub at 0x1F0001DC..0x1F00055C (xteng.dec).
Header: "COMP01" + 4 escape bytes + 4-byte big-endian output size.
The first 10 header bytes are XORed with the string at 0x1F000560,
"Wayne Hughes Beckett!" - so the four escape codes are masked with "Hugh".
"""
import sys

MASK = b'Wayne Hugh'   # first 10 bytes of the credit string


def note(stats, op, uses, saved):
    if stats is not None:
        e = stats.setdefault(op, [0, 0])
        e[0] += uses
        e[1] += saved


def unpack(data, off=0, verbose=False, stats=None):
    """@stats, if given, is filled in with {opcode: [uses, bytes saved]}."""
    hdr = bytes(b ^ m for b, m in zip(data[off:off + 10], MASK))
    esc_rle8, esc_rle16, esc_seq, esc_lz = hdr[6:10]
    size = int.from_bytes(data[off + 0xA:off + 0xE], 'big')
    if verbose:
        print('# esc rle8=%02X rle16=%02X seq=%02X lz=%02X size=0x%X'
              % (esc_rle8, esc_rle16, esc_seq, esc_lz, size), file=sys.stderr)

    out = bytearray()
    ip = off + 0xE
    escapes = (esc_rle8, esc_rle16, esc_seq, esc_lz)

    while len(out) < size:
        b = data[ip]; ip += 1
        # escape byte followed by 0x00 -> the escape byte itself
        was = len(out)
        if b in escapes and data[ip] == 0:
            out.append(b); ip += 1
            note(stats, 'literal-escape', 1, -1)
            continue
        if b == esc_rle8:                       # [count][byte]
            count, val = data[ip], data[ip + 1]
            out += bytes([val]) * count
            ip += 2
            note(stats, 'rle8', 1, len(out) - was - 3)
        elif b == esc_rle16:                    # [count][b1][b2]
            count, b1, b2 = data[ip], data[ip + 1], data[ip + 2]
            out += bytes([b1, b2]) * count
            ip += 3
            note(stats, 'rle16', 1, len(out) - was - 4)
        elif b == esc_seq:                      # [count][step][start]
            count, step, start = data[ip], data[ip + 1], data[ip + 2]
            out += bytes(((start + step * i) & 0xFF) for i in range(count))
            ip += 3
            note(stats, 'arith-run', 1, len(out) - was - 4)
        elif b == esc_lz:                       # [count][dist_lo][dist_hi]
            count = data[ip]
            dist = data[ip + 1] | (data[ip + 2] << 8)
            src = len(out) - dist
            for i in range(count):
                out.append(out[src + i])
            ip += 3
            note(stats, 'lz-match', 1, len(out) - was - 4)
        else:
            out.append(b)
            note(stats, 'literal', 1, 0)

    return bytes(out[:size]), ip - off


if __name__ == '__main__':
    data = open(sys.argv[1], 'rb').read()
    off = int(sys.argv[2], 0) if len(sys.argv) > 2 else data.find(b'COMP01')
    out, used = unpack(data, off, verbose=True)
    print('# 0x%X: %d packed -> %d bytes' % (off, used, len(out)), file=sys.stderr)
    sys.stdout.buffer.write(out)
