#!/usr/bin/env python3
"""Find the .fcd cipher in the PC tools, and prove it by running it.

`fcdcrypt.py` hardcodes the three constants of the cipher. This script recovers
the routines from the tools instead, and then does better than reading them: it
executes each one under an x86 emulator and requires the output to equal
`fcdcrypt.py` byte for byte, and to turn a real `.fcd` into its known plaintext.
`FCD.md` sections 4 and 5 have where the files come from and how the routines
were found.

    uv run --with capstone --with unicorn python xlink.py [-s] [binary ...]

`-s` also disassembles each routine. With no file arguments it takes every
`pc/*.exe`; like `roms/`, `pc/` is not in the repo. Four binaries are expected
there, and the eight routines in them are asserted at the end:

    XLink.exe             DOS X-Link V1.091, DOS/4GW LE, Watcom register args
    Xlink95.exe           Xlink95 v1.1, 1999-08-04 build, Win32 PE, stdcall
    Xlink95-19990702.exe  ... and its 1999-07-02 build, same cipher bytes
    x-killer.exe          X-Killer v0.55, a third party's, cdecl and in place

Two container formats, hence two loaders. The Win32 one is ordinary. The DOS one
is a linear executable: a 32-bit MZ stub, `LE` at the offset in the stub's
`e_lfanew`, then a page map naming the physical pages of each object. Two objects
- code at 0x10000 and data at 0x40000 - and every address printed for that file
is linear in the loaded image, not a file offset.

Absolute addresses in LE code are patched at load time from the fixup section,
which this loader does not apply. It does not need to: an unfixed site still
holds the target's *offset within its object*, so a data reference can be found
by searching the code for that offset as a little-endian word. That is how the
upgrade path was found - `"ARE YOU SURE YOU WISH TO UPGRADE?"` sits at 0x408AA,
so the code that prints it holds `AA 08 00 00`.
"""
import glob
import os
import re
import struct
import sys

# and r8, 0x37  /  xor r8, 0x2c - the addend, in any 8-bit register. Every build
# spells this the same way; what varies is how the xor mask is built and which
# registers hold what, so this is the only pattern worth searching for.
SIG = rb'\x80[\xe0-\xe7]\x37'
SIG2 = rb'\x80[\xf0-\xf7]\x2c'

# Where the emulator puts things. Far away from any image we load.
STACK, SRC, DST, RETADDR = 0x70010000, 0x71000000, 0x72000000, 0x7FFF0000

# Calling conventions to try. 's' source, 'd' destination, 'n' length, 'b' a
# single buffer transformed in place. All three were in use; which one a routine
# wants is not asserted anywhere, it is discovered by running it, so a new build
# with a fourth convention would report "no convention worked" rather than lie.
CONV = {
    'watcom_regs': (('eax', 'edx', 'ebx'), 'sdn', ''),   # Watcom /3r, DOS build
    'stdcall_3':   ((), '', 'sdn'),                      # Xlink95
    'cdecl_2':     ((), '', 'bn'),                        # X-Killer, in place
}


# ------------------------------------------------------------------ loading

def load_le(path, raw):
    """Return {object base: flat bytes} for a DOS/4GW linear executable."""
    le = struct.unpack_from('<I', raw, 0x3C)[0]
    if raw[le:le + 2] != b'LE':
        raise ValueError('%s: no LE image at 0x%X' % (path, le))
    g = lambda o: struct.unpack_from('<I', raw, le + o)[0]
    npages, psize, lastsz = g(0x14), g(0x28), g(0x2C)
    objtab, nobj, pagemap, datapages = g(0x40), g(0x44), g(0x48), g(0x80)

    pages = []
    for i in range(npages):
        b = raw[le + pagemap + i * 4:le + pagemap + i * 4 + 4]
        pages.append(((b[0] << 16) | (b[1] << 8) | b[2], b[3]))  # number is big-endian

    objs = {}
    for i in range(nobj):
        size, base, flags, pgidx, npg, _ = struct.unpack_from(
            '<IIIIII', raw, le + objtab + i * 24)
        img = bytearray()
        for k in range(npg):
            pi = pgidx - 1 + k
            num, pflags = pages[pi]
            sz = lastsz if pi == npages - 1 else psize
            if pflags == 0:
                off = datapages + (num - 1) * psize
                img += raw[off:off + sz]
            elif pflags == 1:
                raise NotImplementedError('iterated page in object %d' % (i + 1))
            else:
                img += b'\0' * sz
        img += b'\0' * max(0, size - len(img))
        objs[base] = bytes(img[:size])
    return objs


def load_pe(path, raw):
    """Return {section virtual address: raw bytes} for a Win32 PE."""
    e = struct.unpack_from('<I', raw, 0x3C)[0]
    if raw[e:e + 4] != b'PE\0\0':
        raise ValueError('%s: no PE header at 0x%X' % (path, e))
    nsec, = struct.unpack_from('<H', raw, e + 6)
    optsz, = struct.unpack_from('<H', raw, e + 20)
    imgbase, = struct.unpack_from('<I', raw, e + 24 + 28)
    secs = {}
    for i in range(nsec):
        o = e + 24 + optsz + i * 40
        _vsize, va, rsize, roff = struct.unpack_from('<IIII', raw, o + 8)
        secs[imgbase + va] = raw[roff:roff + rsize]
    return secs


def load(path):
    """Return {base: bytes}, whichever of the two formats the file is."""
    raw = open(path, 'rb').read()
    e = struct.unpack_from('<I', raw, 0x3C)[0] if len(raw) > 0x40 else 0
    if raw[e:e + 4] == b'PE\0\0':
        return load_pe(path, raw)
    return load_le(path, raw)


# ------------------------------------------------------------------ finding

def call_targets(segs):
    """{target: [call site, ...]} over direct E8 calls landing inside a segment.

    Used to pin down where a routine begins. Walking backwards through variable
    length instructions guesses; a call site does not. LE fixups do not matter
    here because a call is relative and these calls stay inside their object.
    """
    out = {}
    for base, code in segs:
        for m in re.finditer(rb'\xe8', code):
            o = m.start()
            if o + 5 > len(code):
                continue
            rel, = struct.unpack_from('<i', code, o + 1)
            t = base + o + 5 + rel
            if base <= t < base + len(code):
                out.setdefault(t, []).append(base + o)
    return out


def find_ciphers(segs):
    """Every address that looks like the entry of an .fcd cipher routine."""
    calls = call_targets(segs)
    out = []
    for base, code in segs:
        for m in re.finditer(SIG, code):
            hit = base + m.start()
            if not re.search(SIG2, code[m.start():m.start() + 0x20]):
                continue                      # 0x37 without the 0x2c: not ours
            near = [t for t in calls if hit - 0x90 < t <= hit]
            if not near:
                raise ValueError('cipher at 0x%X is never called directly' % hit)
            out.append(max(near))
    if not out:
        raise ValueError('no cipher found')
    return sorted(set(out))


# ------------------------------------------------------------------ running

def run(segs, entry, conv, data):
    """Execute one routine over `data` and return what it wrote."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn import x86_const as X
    reg = {'eax': X.UC_X86_REG_EAX, 'edx': X.UC_X86_REG_EDX,
           'ebx': X.UC_X86_REG_EBX, 'ecx': X.UC_X86_REG_ECX}

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for base, blob in segs:
        page = base & ~0xFFF
        uc.mem_map(page, (len(blob) + (base - page) + 0xFFF) & ~0xFFF)
        uc.mem_write(base, blob)
    span = (len(data) + 0xFFFF) & ~0xFFFF
    for a, n in ((STACK - 0x10000, 0x10000), (SRC, span), (DST, span),
                 (RETADDR & ~0xFFF, 0x1000)):
        uc.mem_map(a, n)
    uc.mem_write(SRC, data)
    uc.mem_write(DST, b'\xCC' * len(data))

    regs, rkind, skind = CONV[conv]
    arg = {'s': SRC, 'd': DST, 'b': SRC, 'n': len(data)}
    for r, k in zip(regs, rkind):
        uc.reg_write(reg[r], arg[k])
    frame = b''.join(struct.pack('<I', arg[k]) for k in skind)
    sp = STACK - 4 - len(frame)
    uc.mem_write(sp, struct.pack('<I', RETADDR) + frame)
    uc.reg_write(X.UC_X86_REG_ESP, sp)
    uc.emu_start(entry, RETADDR, count=200_000_000)
    out = DST if 'd' in rkind + skind else SRC
    return bytes(uc.mem_read(out, len(data)))


def identify(segs, entry, n=512):
    """(convention, direction) of a routine, found by running it.

    One period of the keystream of pseudorandom bytes has to come out exactly
    equal to `fcdcrypt.py`, so a convention that is wrong for this routine
    cannot pass by accident; it faults or writes rubbish.
    """
    from unicorn import UcError
    import fcdcrypt
    plain = bytes((i * 37 + (i >> 3) * 11) & 0xFF for i in range(n))
    cipher = fcdcrypt.encrypt(plain)
    hits = []
    for conv in CONV:
        for way, feed, want in (('decrypt', cipher, plain),
                                ('encrypt', plain, cipher)):
            try:
                if run(segs, entry, conv, feed) == want:
                    hits.append((conv, way))
            except UcError:
                pass
    if len(hits) != 1:
        raise ValueError('0x%X: %d conventions worked, wanted 1: %s'
                         % (entry, len(hits), hits))
    return hits[0]


def show(segs, addr, n=0x60):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    base, code = max(((b, c) for b, c in segs if b <= addr < b + len(c)))
    for i in md.disasm(code[addr - base:addr - base + n], addr):
        print('    %08X  %-18s %s %s' % (i.address, i.bytes.hex(),
                                         i.mnemonic, i.op_str))
        if i.mnemonic.startswith('ret'):
            break


# --------------------------------------------------------------------- checks

# What is in pc/. A build not listed here is reported and checked like the rest;
# only the final tally is pinned, so this is a record, not a gate on discovery.
EXPECTED = {
    'XLink.exe':            [('watcom_regs', 'decrypt'), ('watcom_regs', 'encrypt')],
    'Xlink95.exe':          [('stdcall_3', 'decrypt'), ('stdcall_3', 'encrypt')],
    'Xlink95-19990702.exe': [('stdcall_3', 'decrypt'), ('stdcall_3', 'encrypt')],
    'x-killer.exe':         [('cdecl_2', 'decrypt'), ('cdecl_2', 'encrypt')],
}


def real_pair():
    """The smallest .fcd/.dec pair in roms/, as ground truth outside this rig."""
    best = None
    for enc in sorted(glob.glob('roms/*.fcd')):
        dec = enc[:-4] + '.dec'
        if os.path.exists(dec):
            e, d = open(enc, 'rb').read(), open(dec, 'rb').read()
            if len(e) == len(d) and (best is None or len(e) < len(best[2])):
                best = (os.path.basename(enc), d, e)
    return best


def check_shipped_image():
    """The .fcd the DOS tool ships must decrypt to working firmware.

    The one check here that does not lean on anything else in this directory.
    That image came with the tool, its plaintext is in no `roms/` pair, and
    nothing but the cipher says what is inside it - so what comes out has to
    stand up on its own. It does: the ROM header, the credit string, and a
    COMP01 stream that decompresses to a firmware image whose own link address
    reads back as the 0x001A0000 every other V2 firmware uses. Getting that far
    on a cipher that was wrong anywhere is not a thing that happens.
    """
    import tempfile

    import fcdcrypt
    import fwimage
    p = 'pc/ROMS/Xteng.fcd'
    if not os.path.exists(p):
        return
    enc = open(p, 'rb').read()
    dec = fcdcrypt.decrypt(enc)
    assert dec[:2] == b'\x00\x01', dec[:8].hex()
    assert b'FCD = WHB PJH DN MW IN R?' in dec[:0x400]
    assert fcdcrypt.encrypt(dec) == enc
    with tempfile.NamedTemporaryFile(suffix='.dec') as t:
        t.write(dec)
        t.flush()
        img, base = fwimage.load(t.name)
    assert base == 0x001A0000, hex(base)
    print('pc/ROMS/Xteng.fcd (shipped with the DOS tool, plaintext nowhere else): '
          'decrypts to a ROM whose firmware unpacks, %d bytes at %08X'
          % (len(img), base))


def main(argv):
    show_asm = '-s' in argv
    paths = [a for a in argv if not a.startswith('-')] or sorted(glob.glob('pc/*.exe'))
    if not paths:
        print('no pc/*.exe - skipped (see FCD.md section 4 for where to get them)')
        return 0

    pair = real_pair()
    found = {}
    for path in paths:
        segs = sorted(load(path).items())
        entries = find_ciphers(segs)
        kind = 'PE' if any(b >= 0x400000 for b, _ in segs) else 'LE'
        print('%s: %s, %d segments, %d routines' % (path, kind, len(segs), len(entries)))
        for entry in entries:
            conv, way = identify(segs, entry)
            line = '  %08X  %-7s %-12s' % (entry, way, conv)
            if pair:
                name, plain, cipher = pair
                feed, want = (cipher, plain) if way == 'decrypt' else (plain, cipher)
                assert run(segs, entry, conv, feed) == want, (path, entry)
                line += ' %s (%d bytes) exact' % (name, len(feed))
            print(line)
            if show_asm:
                show(segs, entry)
            found.setdefault(os.path.basename(path), []).append((conv, way))

    check_shipped_image()
    for name, got in found.items():
        if name in EXPECTED:
            assert sorted(got) == sorted(EXPECTED[name]), (name, got)
    missing = set(EXPECTED) - set(found)
    n = sum(len(v) for v in found.values())
    print('%d routines in %d binaries, every one of them reproduces fcdcrypt.py%s'
          % (n, len(found), '' if not missing else ' (absent: %s)' % ', '.join(sorted(missing))))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
