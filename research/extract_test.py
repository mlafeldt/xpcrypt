#!/usr/bin/env python3
"""Regression tests for xpcrypt's ROM database extractor."""
from pathlib import Path
import subprocess
import sys
import tempfile

import fcdcrypt
import romcrypt


XPCRYPT = Path(sys.argv[1] if len(sys.argv) > 1 else '../xpcrypt').resolve()


def run(*args):
    return subprocess.run((XPCRYPT, *map(str, args)), capture_output=True)


def make_fixture():
    """A tiny ROM with abbreviations and every stateful extraction case."""
    rom = bytearray(b'\xff' * 0x1000)
    rom[fcdcrypt.ROM_SIGNATURE_OFFSET:fcdcrypt.ROM_MIN_SIZE] = \
        fcdcrypt.ROM_SIGNATURE

    records = bytearray()
    records += b'Test\x06Game\0\x03'
    records += b'\x02 \x07\0\x01' + bytes.fromhex('76621A3E5450')
    records += b'Block\0\x03' + bytes.fromhex(
        '55A936CF2ED9 34FB3457235D 34F734F4FB55')
    records += b'Inline\0\x02' + bytes.fromhex(
        'A00000000000 76621A3E5450')
    records += b'Empty\0\x00'  # empty game (zero cheats): skipped, not fatal
    records += b'Next\0\x01'
    records += b'Reset\0\x01' + bytes.fromhex('76621A3E5450')
    records += b'\xff\xff\xff\xff'
    rom[0x400:0x400 + len(records)] = records
    return bytes(rom)


EXPECTED = b'''"Test TimeGame"
Unlimited Money
700CC7EA FBFE
Block
50007800 600C
040008AC 0800
0800E003 0000
Inline
A0000000 0000
76621A3E 5450

//=====

"Next"
Reset
700CC7EA FBFE

//=====

'''


def check_fixture():
    plain = make_fixture()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        plain_path = root / 'fixture.rom'
        encrypted_path = root / 'fixture.fcd'
        plain_path.write_bytes(plain)
        encrypted_path.write_bytes(fcdcrypt.encrypt(plain))

        for option, path in (('-x', plain_path),
                             ('--extract', encrypted_path),
                             ('--extract-codes', encrypted_path)):
            got = run(option, path)
            assert got.returncode == 0, got.stderr.decode(errors='replace')
            assert got.stdout == EXPECTED, (option, got.stdout, EXPECTED)
            assert got.stderr == b'', (option, got.stderr)

        no_db = bytearray(b'\0' * 128)
        no_db[fcdcrypt.ROM_SIGNATURE_OFFSET:fcdcrypt.ROM_MIN_SIZE] = \
            fcdcrypt.ROM_SIGNATURE
        no_db_path = root / 'no-db.rom'
        no_db_path.write_bytes(no_db)
        got = run('-x', no_db_path)
        assert got.returncode != 0
        assert b'no cheat database' in got.stderr

    print('synthetic plaintext/encrypted ROM extraction: all good')


def decrypt_code(raw):
    """The normal-code behavior xpcrypt intentionally promises."""
    route = romcrypt.ROUTES.get(raw[0] & 0xF7)
    if route and route.startswith('key'):
        dec = bytes(romcrypt.decrypt(list(raw)))
        return bytes([dec[0] | (raw[0] & 0x08)]) + dec[1:]
    if raw[0] >> 4 in (0x2, 0xA, 0xC, 0xE) and raw[0] & 7 >= 4:
        return raw
    if route in ('fcd', 'not'):
        return raw
    return bytes(romcrypt.decrypt(list(raw)))


def decrypt_cheat(lines):
    """Decrypt one database entry, including its bounded block payloads."""
    out = []
    index = rows = -1
    payload_key = 0
    inline = False
    for raw in map(bytes, lines):
        if index >= 0:
            if payload_key in (6, 7):
                dec = bytes(romcrypt.decrypt(list(raw), payload_key))
            else:
                dec = raw
            out.append(dec)
            index += 1
            if not inline and index >= rows:
                index = -1
            continue

        dec = decrypt_code(raw)
        out.append(dec)
        if dec[0] & 7 and dec[0] >> 4 != 0xA:
            continue
        if dec[0] >> 4 == 5:
            nbytes = ((dec[4] & 0xF) << 8) | dec[5]
            if nbytes:
                payload_key = dec[4] >> 4
                rows = (nbytes + 5) // 6
                index, inline = 0, False
        elif dec[0] >> 4 == 6:
            payload_key = dec[3] & 0xF
            rows = (((dec[4] << 8) | dec[5]) + 10 + 5) // 6
            index, inline = 0, False
        elif dec[0] >> 4 == 0xA:
            payload_key = 0
            index, inline = 0, True
    return out


def code_text(code):
    return ('%02X%02X%02X%02X %02X%02X' % tuple(code)).encode()


def check_images():
    """Exercise all complete databases when the private ROM corpus exists."""
    import db2

    rom_dir = Path('roms')
    paths = [rom_dir / name for name, _ in __import__('dbtypes').ROMS]
    if not all(path.exists() for path in paths):
        print('real ROM database extraction: skipped (no roms/)')
        return

    total_lines = total_cheats = 0
    for path in paths:
        _, db = db2.find_db(path.read_bytes())
        assert db is not None, path
        expected = [code_text(code) for _, _, lines in db
                    for code in decrypt_cheat(lines)]
        got = run('-x', path)
        assert got.returncode == 0, (path, got.stderr.decode(errors='replace'))

        # Names can themselves look like a code line, so compare the expected
        # code sequence as an ordered subsequence of the human-readable dump.
        output = iter(got.stdout.splitlines())
        for want in expected:
            assert any(line == want for line in output), (path, want)

        encrypted = path.with_suffix('.fcd')
        if encrypted.exists():
            from_fcd = run('-x', encrypted)
            assert from_fcd.returncode == 0, encrypted
            assert from_fcd.stdout == got.stdout, encrypted

        total_lines += len(expected)
        total_cheats += len(db)

    assert (total_lines, total_cheats) == (15349, 11718), \
        (total_lines, total_cheats)
    print('real ROM database extraction: %d lines in %d cheats, all good'
          % (total_lines, total_cheats))


if __name__ == '__main__':
    if not XPCRYPT.exists():
        sys.exit('no xpcrypt at %s - build it first' % XPCRYPT)
    check_fixture()
    check_images()
