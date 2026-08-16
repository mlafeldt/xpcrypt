from dbscan import decrypt_line, find_db
rom = open('roms/xtepro.dec','rb').read()
_, db = find_db(rom)
def rows(mega,size): return ((size + (0x0A if mega else 0)) + 5)//6
for game,name,lines in db:
    pending=0
    for i,raw in enumerate(lines):
        if pending: pending-=1; continue
        dec,_=decrypt_line(raw)
        t=dec[0]&0xF0
        if t not in (0x50,0x60): continue
        mega=t==0x60
        size=((dec[4]<<8)|dec[5]) if mega else (((dec[4]&0x0F)<<8)|dec[5])
        if not mega and size<1: continue
        n=rows(mega,size); nxt=i+1+n
        if nxt < len(lines):
            b=lines[nxt]; d,_=decrypt_line(b)
            print(f"  block ends inside entry -> next line {b[:4].hex().upper()} {b[4:].hex().upper()}"
                  f" decrypts to {d[:4].hex().upper()} {d[4:].hex().upper()}"
                  f"  (type {d[0]>>4:X}, key {b[0]&7})   [{game} / {name}]")
        pending=min(n,len(lines)-i-1)
