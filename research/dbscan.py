#!/usr/bin/env python3
"""Extract the Xploder/Xplorer ROM code database and audit type 5/6 blocks.

The reader here is the first, strict one: it takes only printable names, so the
abbreviation bytes 1-7 (FINDINGS.md 4.1) make it reject xteng.dec, xtger.dec
and the USA ROM outright.  db2.py is the reader the notes rely on; what the
other scripts still import from here is decrypt_line(), xpcrypt's own code
decryption as a model."""
import sys

def decrypt_line(b):
    """xpcrypt's per-code decryption. Returns (bytes, ok)."""
    c = list(b)
    key = c[0] & 0x07
    if key == 4:
        c[1] ^= 0x25
        c[2] ^= ((c[1] & 0x11) + 0xFA) & 0xFF
        c[3] ^= ((c[2] & 0x11) + (c[1] ^ 0x12) - 0x40) & 0xFF
        c[4] ^= ((c[3] & 0x11) + (c[2] ^ 0x12) - 0x82 + c[1]) & 0xFF
        c[5] ^= ((c[4] & 0x11) + (c[3] ^ 0x12) - 0xDA + c[2] + c[1]) & 0xFF
    elif key == 5:
        for i, k in enumerate((0x57, 0x42, 0x31, 0x32, 0x33), start=1):
            c[i] = (c[i] + k) & 0xFF
    elif key == 6:
        for i in range(1, 6):
            c[i] = ((c[i] + 0xAB) & 0xFF) ^ i
    elif key == 7:
        c[5] = (c[5] - 0x35) & 0xFF
        c[4] = (c[4] + (c[5] & 0x73) - 0x35) & 0xFF
        c[3] = (c[3] + (c[4] & 0x73) - (c[5] ^ 0x90) + 0x5A) & 0xFF
        c[2] = (c[2] + (c[3] & 0x73) - (c[4] ^ 0x90) + 0x16 + c[5]) & 0xFF
        c[1] = (c[1] + (c[2] & 0x73) - (c[3] ^ 0x90) + 0xF5 + c[4] + c[5]) & 0xFF
    else:
        return bytes(c), False
    c[0] ^= key
    return bytes(x & 0xFF for x in c), True

def cstr_end(rom, pos, maxlen):
    end = rom.find(b'\0', pos, min(len(rom), pos + maxlen + 1))
    return end if end >= 0 else -1

def plausible(rom, a, b):
    return b > a and all(0x20 <= x != 0x7F for x in rom[a:b])

def parse_db(rom, start):
    """Yields (game, cheat, [lines]). Raises ValueError on a bad structure."""
    pos, games, out = start, 0, []
    while pos + 4 <= len(rom):
        if rom[pos:pos+4] == b'\xff\xff\xff\xff':
            if games == 0:
                raise ValueError("no games")
            return out
        end = cstr_end(rom, pos, 127)
        if end < 0 or not plausible(rom, pos, end):
            raise ValueError(f"bad game name at {pos:#x}")
        game = rom[pos:end].decode('latin-1')
        pos = end + 1
        ncheats = rom[pos]; pos += 1
        if ncheats > 200:
            raise ValueError("cheat count")
        games += 1
        for _ in range(ncheats):
            end = cstr_end(rom, pos, 255)
            if end < 0 or not plausible(rom, pos, end):
                raise ValueError(f"bad cheat name at {pos:#x}")
            name = rom[pos:end].decode('latin-1')
            pos = end + 1
            nlines = rom[pos]; pos += 1
            if nlines > 200 or pos + nlines * 6 > len(rom):
                raise ValueError("line count")
            lines = [rom[pos+6*i:pos+6*i+6] for i in range(nlines)]
            pos += nlines * 6
            out.append((game, name, lines))
    raise ValueError("ran off the end")

def find_db(rom):
    for start in [0x25000] + list(range(0, len(rom) - 0x400, 0x100)):
        try:
            db = parse_db(rom, start)
        except (ValueError, IndexError):
            continue
        if len(db) > 20:
            return start, db
    return None, None

def hexcode(b):
    return b[:4].hex().upper() + ' ' + b[4:].hex().upper()

def rows_type5(size, variant):
    n = size if variant == 'direct' else size + 6
    return (n + 5) // 6

def rows_type6(size, variant):
    n = size + (0x0A if variant == 'direct' else 0x12)
    return (n + 5) // 6

def main():
    for path in sys.argv[1:]:
        rom = open(path, 'rb').read()
        start, db = find_db(rom)
        print(f"=== {path}  ({len(rom)} bytes)")
        if db is None:
            print("   no database found\n")
            continue
        nlines = sum(len(c[2]) for c in db)
        print(f"   database at {start:#x}: {len(set(g for g,_,_ in db))} games, "
              f"{len(db)} cheats, {nlines} code lines")
        hits = 0
        for game, name, lines in db:
            for i, raw in enumerate(lines):
                dec, ok = decrypt_line(raw)
                if not ok or (dec[0] & 0xF0) not in (0x50, 0x60):
                    continue
                hits += 1
                mega = (dec[0] & 0xF0) == 0x60
                if mega:
                    pkey, size = dec[3] & 0x0F, (dec[4] << 8) | dec[5]
                    r_direct, r_old = rows_type6(size, 'direct'), rows_type6(size, 'old')
                else:
                    pkey, size = dec[4] >> 4, ((dec[4] & 0x0F) << 8) | dec[5]
                    r_direct, r_old = rows_type5(size, 'direct'), rows_type5(size, 'old')
                after = len(lines) - i - 1
                print(f"   [{game} / {name}] line {i+1}/{len(lines)}")
                print(f"     enc {hexcode(raw)} -> dec {hexcode(dec)}"
                      f"  type {'6' if mega else '5'} pkey={pkey} size={size:#05x}")
                print(f"     payload rows available={after}"
                      f"  direct={r_direct}{' FITS' if r_direct == after else ''}"
                      f"  old(+{18 if mega else 6})={r_old}"
                      f"{' FITS' if r_old == after else ''}")
        print(f"   type 5/6 headers found: {hits}\n")

if __name__ == "__main__":
    main()
