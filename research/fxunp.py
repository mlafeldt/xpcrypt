#!/usr/bin/env python3
"""Descramble + unpack the firmware image of an Xplorer FX ROM.

The FX boot stub (0x9F000100) hands three pointers to the descrambler at
0x9F00C0E0: the packed blob, the RAM address it belongs at, and the end of the
blob.  The descrambler skips four bytes, then walks the blob a byte at a time:

    out[i] = rol8(src[i] ^ key_i, (8 - (state_i & 7)) & 7)
    key_{i+1}   = key_i + 5                 (only the low 8 bits ever matter)
    state_{i+1} = (state_i ^ key_{i+1}) + 1

starting at key = 0x99, state = 6.  What falls out is a plain COMP01 stream,
the same container the Xplorer V2 ROMs use unscrambled - see comp01.py.

fwimage.load() is the usual entry point; this module is the FX-specific half.
"""
import sys

import comp01


def descramble(data, start, end):
    out = bytearray()
    key, state = 0x99, 6
    for i in range(start + 4, end):
        rot = (8 - (state & 7)) & 7
        v = (data[i] ^ key) & 0xFF
        v = ((v << rot) | (v >> (8 - rot))) & 0xFF if rot else v
        out.append(v)
        key = (key + 5) & 0xFFFFFFFF
        state = ((state ^ key) + 1) & 0xFFFFFFFF
    return bytes(out)


def blob_start(raw):
    """Offset of the scrambled COMP01 stream, or None if this is a V2 ROM.

    The descrambler's first output byte is rol8(raw[s + 4] ^ 0x99, 2) and the
    stream starts "COMP01", so almost every offset is rejected on one byte."""
    for s in range(len(raw) - 24):
        v = (raw[s + 4] ^ 0x99) & 0xFF
        if ((v << 2) | (v >> 6)) & 0xFF != ord('C'):
            continue
        if descramble(raw, s, s + 10)[:6] == b'COMP01':
            return s
    return None


if __name__ == '__main__':
    raw = open(sys.argv[1], 'rb').read()
    s = blob_start(raw)
    if s is None:
        sys.exit('%s: no scrambled COMP01 stream' % sys.argv[1])
    out, _ = comp01.unpack(descramble(raw, s, len(raw)))
    print('# %s: blob at 0x%X -> %d bytes' % (sys.argv[1], s, len(out)),
          file=sys.stderr)
    sys.stdout.buffer.write(out)
