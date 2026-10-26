#!/usr/bin/env python3
"""The Xplorer .fcd image cipher, as the vendor's own tool implements it.

Not to be confused with `romcrypt.py`, which is the *code* cipher out of the
cartridge firmware. This one is the whole-image transform between a distributed
`.fcd` file and the plaintext ROM - what `xpcrypt -r` does. The cipher is a
twenty-two-instruction loop over two one-line functions of the file offset;
xpcrypt formerly stored 1 KB of values produced by those functions.

Transcribed from `XLink.exe` of the DOS X-Link distribution - the binary reports
itself as V1.091 - which is the vendor's own upgrade utility (`XLink.exe:0x2A4A0`,
linear addresses in the LE image). Watcom register convention, eax = src,
edx = dst, ebx = len; called in place:

    0002A4B6  mov edx, eax           ; edx = i
    0002A4B8  sar edx, 1             ;     = i >> 1
    0002A4BA  mov edi, eax
    0002A4BC  add edx, 0x45          ;     = (i >> 1) + 0x45
    0002A4BF  xor edi, edx           ; edi = i ^ ((i >> 1) + 0x45)
    0002A4C1  mov [esp], edi         ; the xor mask, low byte taken below
    0002A4CB  mov dl, al             ; dl = i
    0002A4CD  and dl, 0x37
    0002A4D0  xor dl, 0x2c           ;     = (i & 0x37) ^ 0x2C, the addend
    0002A4D7  mov dl, [ecx]          ; src[i]
    0002A4D9  xor dl, [esp + 8]      ;   ^ mask
    0002A4E3  add dl, dh             ;   + addend
    0002A4E6  mov [ebx - 1], dl      ; dst[i]
    0002A4E9  cmp eax, esi           ; i < len
    0002A4EB  jl 0x2a4b6

`FCD.md` has how it was found, why the cartridge firmware does not contain it,
and the other seven copies of it - the two Windows builds and a third party's
tool - all of which `xlink.py` executes and compares against this file.

Two notes on faithfulness. This one shifts arithmetically (`sar`), which differs
from a logical shift only past 2 GiB of input, so the mask below uses a plain
`>>`; the third party's tool writes `shr` there anyway. And the offset is the
absolute one - the cipher has no block structure at all;
the removed `XP_ROM_BLKSIZE` was a consequence, not a parameter, because the
mask depends on bits 0..8 of the offset and the addend on bits 0..5.
"""
M = 0xFF
ROM_SIGNATURE = b'Sony'
ROM_SIGNATURE_OFFSET = 0x10
ROM_MIN_SIZE = ROM_SIGNATURE_OFFSET + len(ROM_SIGNATURE)


def xor_mask(i):
    """The xor mask for absolute offset i."""
    return (i ^ ((i >> 1) + 0x45)) & M


def addend(i):
    """The addend for absolute offset i."""
    return (i & 0x37) ^ 0x2C


def decrypt(buf):
    """.fcd -> plaintext ROM image."""
    return bytes(((b ^ xor_mask(i)) + addend(i)) & M for i, b in enumerate(buf))


def encrypt(buf):
    """Plaintext ROM image -> .fcd."""
    return bytes(((b - addend(i)) ^ xor_mask(i)) & M for i, b in enumerate(buf))


# --------------------------------------------------------------------- checks

def check_xpcrypt():
    """The shipped implementation must match the closed form in both directions.

    Include lengths on both sides of the old 512-byte minimum. The automatic
    direction check needs the complete ROM signature, while the explicit library
    functions accept still shorter buffers.
    """
    import pathlib
    import subprocess
    import tempfile

    exe = pathlib.Path(__file__).resolve().parent.parent / 'xpcrypt'
    sizes = (ROM_MIN_SIZE, 31, 511, 512, 513, 4097)

    with tempfile.TemporaryDirectory() as tmp:
        src = pathlib.Path(tmp) / 'in.rom'
        dst = pathlib.Path(tmp) / 'out.rom'

        def convert(buf):
            src.write_bytes(buf)
            run = subprocess.run((exe, '-r', src, dst), capture_output=True)
            assert run.returncode == 0, run.stderr.decode(errors='replace')
            return dst.read_bytes()

        for size in sizes:
            plain = bytearray((i * 73 + 19) & M for i in range(size))
            plain[ROM_SIGNATURE_OFFSET:ROM_MIN_SIZE] = ROM_SIGNATURE
            plain = bytes(plain)
            encrypted = encrypt(plain)
            assert convert(plain) == encrypted, ('encrypt', size)
            assert convert(encrypted) == plain, ('decrypt', size)

    print('xpcrypt: encrypt and decrypt match at %d lengths (%d..%d bytes)'
          % (len(sizes), sizes[0], sizes[-1]))


def check_images():
    """Both directions over every .fcd/.dec pair in roms/.

    A smoke test, not evidence: the `.dec` files were made by running `xpcrypt -r`
    over the `.fcd` files, so agreeing with them is agreeing with the seed tables,
    which `check_tables()` already does on every input rather than just the ones
    these images happen to hit. `FCD.md` section 1 has why that distinction
    matters and section 5a has the check that does not depend on it.
    """
    import glob
    import os
    pairs = [(f, f[:-4] + '.dec') for f in sorted(glob.glob('roms/*.fcd'))]
    pairs = [(e, d) for e, d in pairs if os.path.exists(d)]
    if not pairs:
        print('no .fcd/.dec pairs in roms/ - skipped')
        return
    total = 0
    for e, d in pairs:
        enc, dec = open(e, 'rb').read(), open(d, 'rb').read()
        assert len(enc) == len(dec), (e, len(enc), len(dec))
        assert decrypt(enc) == dec, e
        assert encrypt(dec) == enc, e
        total += len(enc)
    assert len(pairs) == 7, len(pairs)
    assert total == 1868896, total
    print('%d image pairs, %d bytes, decrypt and encrypt both exact'
          % (len(pairs), total))


def check_period():
    """The periods the closed forms imply, measured rather than asserted by eye."""
    def period(f, cap=4096):
        return next(p for p in range(1, cap + 1)
                    if all(f(i) == f(i + p) for i in range(cap)))
    assert period(xor_mask) == 512, period(xor_mask)
    assert period(addend) == 64, period(addend)
    assert xor_mask(0) == 0x45 and addend(0) == 0x2C
    print('mask period 512, addend period 64, both start at 0x45 / 0x2C')


if __name__ == '__main__':
    check_period()
    check_xpcrypt()
    check_images()
    print('all good')
