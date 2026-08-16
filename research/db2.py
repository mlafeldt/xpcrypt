#!/usr/bin/env python3
"""Xploder/Xplorer ROM database reader, including abbreviated names."""
import sys
from dbscan import decrypt_line

def cstr_end(rom, pos, maxlen):
    end = rom.find(b'\0', pos, min(len(rom), pos + maxlen + 1))
    return end if end >= 0 else -1

def ok_name(rom, a, b):
    if b <= a:
        return False
    body = rom[a:b]
    # Bytes 1..7 expand to common words (Infinite, Unlimited, and so on)
    # in both game and cheat names. High bytes are Shift-JIS in the Japanese
    # database. DEL and erased flash are not name bytes.
    return all(1 <= x <= 7 or 0x20 <= x < 0x7F or 0x80 <= x < 0xFF
               for x in body)

def parse_db(rom, start):
    pos, out = start, []
    while pos + 4 <= len(rom):
        if rom[pos:pos+4] == b'\xff\xff\xff\xff':
            if not out:
                raise ValueError("empty")
            return out
        end = cstr_end(rom, pos, 127)
        if end < 0 or not ok_name(rom, pos, end):
            raise ValueError(f"game name at {pos:#x}")
        game = rom[pos:end].decode('latin-1')
        pos = end + 1
        ncheats = rom[pos]; pos += 1
        if not 1 <= ncheats <= 200:
            raise ValueError("cheat count")
        for _ in range(ncheats):
            end = cstr_end(rom, pos, 255)
            if end < 0 or not ok_name(rom, pos, end):
                raise ValueError(f"cheat name at {pos:#x}")
            name = rom[pos:end].decode('latin-1')
            pos = end + 1
            nlines = rom[pos]; pos += 1
            if nlines > 200 or pos + nlines * 6 > len(rom):
                raise ValueError("line count")
            out.append((game, name,
                        [rom[pos+6*i:pos+6*i+6] for i in range(nlines)]))
            pos += nlines * 6
    raise ValueError("ran off the end")

def find_db(rom):
    """Locate the complete record chain after its erased-flash boundary.

    Looking for a printable game name found valid suffixes of three databases:
    abbreviation bytes in an earlier game made the parser reject the real
    start and resynchronize later. The complete chain begins after erased
    flash in every image, so only try offsets preceded by four 0xFF bytes and
    keep the largest valid chain.
    """
    candidates = []
    for start in range(4, len(rom)):
        if rom[start-4:start] != b'\xff' * 4:
            continue
        try:
            db = parse_db(rom, start)
        except (ValueError, IndexError):
            continue
        if len(db) > 50:
            candidates.append((len(set(g for g, _, _ in db)), len(db),
                               sum(len(c[2]) for c in db), -start, db))
    if not candidates:
        return None, None
    _, _, _, neg_start, db = max(candidates, key=lambda c: c[:4])
    return -neg_start, db

if __name__ == '__main__':
    for path in sys.argv[1:]:
        rom = open(path, 'rb').read()
        start, db = find_db(rom)
        if db is None:
            print(f"{path}: no database"); continue
        print(f"{path}: db at {start:#x} games={len(set(g for g,_,_ in db))} "
              f"cheats={len(db)} lines={sum(len(c[2]) for c in db)}")
