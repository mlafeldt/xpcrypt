#!/usr/bin/env python3
"""Faithful Python port of the Xplorer firmware decrypt at 0x801ABF94 (xteng.dec).

decrypt(code, key=-1) - key -1 = normal code, else Supercode/Megacode payload key.
Byte-for-byte transcription of the MIPS, including the route table.

The routine writes into a caller-supplied destination and clears only bytes 1
to 5 of it on entry, so the routes that never write byte 0 - Special32,
Special33 and every payload key it does not implement - leave whatever the
caller had there. Pass @dst to model that; the default of six zero bytes is
what a caller who clears its buffer first would see.
"""
M = 0xFF

KEY4 = list(b'WHBX')            # window init, 0x1BF29C
KEY5 = list(b' WB123')          # 0x1BF294 (index 1..5 used)
KEY7 = list(b'FCD!')            # 0x1BF2A4

ROUTES = {}
for hi in (0x0, 0x1, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xB, 0xD, 0xF):
    for k in (4, 5, 6, 7):
        ROUTES[(hi << 4) | k] = 'key%d' % k
ROUTES[0x32] = ROUTES[0x82] = 'fcd'
ROUTES[0x33] = ROUTES[0x83] = 'not'


def decrypt(c, key=-1, route=None, dst=None):
    """@route forces a route the jump table does not have - a test hook, used
    to ask what the firmware *would* do for the first bytes it passes through.
    @dst is the destination as the caller left it; only byte 0 of it can survive."""
    o = list(dst) if dst is not None else [0] * 6
    o[1:] = [0] * 5                                 # 0x801ABFB4, dst[1..5] only
    if key != -1:                                   # payload row
        if key == 0:                                # verbatim
            return list(c)
        if key == 6:                                # 0x801AC314
            o[1] = (c[0] - 0x34) & M
            o[0] = (~c[1]) & M
            o[5] = (c[2] - c[0]) & M
            o[3] = (c[3] ^ c[1]) & M
            o[2] = (c[4] - 0x1B) & M
            o[4] = (c[5] - 0x55) & M
            return o
        if key == 7:                                # 0x801AC380
            return [(c[5 - i] - 0x55) & M for i in range(6)]
        return o                                    # unknown key -> bytes 1..5 zeroed

    route = route or ROUTES.get(c[0] & 0xF7)
    if route is None:                               # 0x801AC2B0, verbatim
        return list(c)
    if route == 'fcd':                              # 0x801AC038
        o[1] = (c[1] + 0x46) & M                    # 'F'
        o[2] = (c[2] + 0x43) & M                    # 'C'
        o[3] = (c[3] + 0x44) & M                    # 'D'
        o[4], o[5] = c[4], c[5]
        return o                                    # o[0] left as the caller had it
    if route == 'not':                              # 0x801AC08C
        o[1], o[2], o[3] = (~c[1]) & M, (~c[2]) & M, (~c[3]) & M
        o[4], o[5] = c[4], c[5]
        return o
    if route == 'key4':                             # 0x801AC0D0
        w = KEY4[:]
        for i in range(1, 6):
            v = (w[0] + 0x38) + w[1] + (w[2] ^ 0x12) + (w[3] | 0xEE)
            o[i] = (c[i] ^ v) & M
            w = w[1:] + [o[i]]
    elif route == 'key5':                           # 0x801AC170
        for i in range(1, 6):
            o[i] = (c[i] + KEY5[i]) & M
    elif route == 'key6':                           # 0x801AC1B0
        for i in range(1, 6):
            o[i] = ((c[i] - 0x55) ^ i) & M
    elif route == 'key7':                           # 0x801AC1F4
        w = KEY7[:]
        for i in range(5, 0, -1):
            v = (w[0] + 0x76) + w[1] + (w[2] ^ 0xEF) + (w[3] & 0x73)
            o[i] = (c[i] + v) & M
            w = w[1:] + [o[i]]
    o[0] = c[0] & 0xF0                              # 0x801AC1E0 / 0x801AC28C
    return o
