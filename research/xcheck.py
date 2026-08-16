from dbscan import decrypt_line
from db2 import find_db

def load(path):
    _, db = find_db(open(path,'rb').read())
    return db

enc = load('roms/xteng.dec')        # payload key 6 blocks
clr = load('roms/xtepro.dec')       # same cheats, payload in the clear

def blocks(db):
    """yield (game, name, header_dec, payload_rows_raw, pkey, size)"""
    for game, name, lines in db:
        pending = 0
        for i, raw in enumerate(lines):
            if pending: pending -= 1; continue
            dec, _ = decrypt_line(raw)
            t = dec[0] & 0xF0
            if t not in (0x50, 0x60): continue
            mega = t == 0x60
            size = ((dec[4]<<8)|dec[5]) if mega else (((dec[4]&0x0F)<<8)|dec[5])
            if not mega and size < 1: continue
            pkey = (dec[3] & 0x0F) if mega else (dec[4] >> 4)
            n = ((size + (0x0A if mega else 0)) + 5)//6
            rows = lines[i+1:i+1+n]
            pending = min(n, len(lines)-i-1)
            yield game, name, dec, rows, pkey, size, mega

def key(g, n):
    return g.lower().split(' - ')[0].strip(), n.lower().strip()

clear_blocks = {}
for g, n, dec, rows, pkey, size, mega in blocks(clr):
    if pkey == 0:
        clear_blocks.setdefault((key(g,n)[0], size, mega), []).append((g, n, rows))

def chunk6(b):
    c = list(b)
    return bytes(((c[3]^c[1])&0xFF, (c[4]-0x1B)&0xFF, (c[0]-0x34)&0xFF,
                  (~c[1])&0xFF, (c[2]-c[0])&0xFF, (c[5]-0x55)&0xFF))

def swap(b):
    return bytes((b[3],b[2],b[1],b[0],b[5],b[4]))

def hx(b): return b[:4].hex().upper()+' '+b[4:].hex().upper()

matched = swapped_ok = plain_ok = 0
for g, n, dec, rows, pkey, size, mega in blocks(enc):
    if pkey != 6: continue
    cands = clear_blocks.get((key(g,n)[0], size, mega), [])
    for cg, cn, crows in cands:
        if len(crows) != len(rows): continue
        dec_swap  = [swap(chunk6(r)) for r in rows]
        dec_plain = [chunk6(r) for r in rows]
        if dec_swap == crows or dec_plain == crows:
            matched += 1
            hit = "SWAPPED" if dec_swap == crows else "NOT swapped"
            swapped_ok += dec_swap == crows
            plain_ok += dec_plain == crows
            print(f"MATCH [{g} / {n}]  size={size:#x} rows={len(rows)}  -> payload matches {hit}")
            print(f"   enc row0 {hx(rows[0])}  chunk6 {hx(dec_plain[0])}  swap {hx(dec_swap[0])}"
                  f"  clear {hx(crows[0])}")
            break
    else:
        if cands:
            print(f"no match [{g} / {n}] size={size:#x} rows={len(rows)}; "
                  f"candidate rows {[len(c[2]) for c in cands]}")
print(f"\nblocks cross-checked: {matched}   swapped matches: {swapped_ok}   unswapped matches: {plain_ok}")
assert (matched, swapped_ok, plain_ok) == (16, 16, 0), \
       (matched, swapped_ok, plain_ok)
