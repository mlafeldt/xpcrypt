import sys
from dbscan import decrypt_line
from db2 import find_db
_, db = find_db(open(sys.argv[1],'rb').read())
want_game, want_size = sys.argv[2].lower(), int(sys.argv[3],16)
for game, name, lines in db:
    if want_game not in game.lower(): continue
    pending = 0
    for i, raw in enumerate(lines):
        if pending: pending -= 1; continue
        dec,_ = decrypt_line(raw)
        t = dec[0] & 0xF0
        if t not in (0x50,0x60): continue
        mega = t == 0x60
        size = ((dec[4]<<8)|dec[5]) if mega else (((dec[4]&0x0F)<<8)|dec[5])
        if not mega and size < 1: continue
        n = ((size + (0x0A if mega else 0)) + 5)//6
        pending = min(n, len(lines)-i-1)
        if size != want_size: continue
        for b in lines[i:i+1+n]:
            print(b[:4].hex().upper() + ' ' + b[4:].hex().upper())
        sys.exit(0)
