import sys
from db2 import find_db
_, db = find_db(open(sys.argv[1],'rb').read())
for game, name, lines in db:
    print(f"; {game} / {name}".replace('\n',' '))
    for b in lines:
        print(b[:4].hex().upper() + ' ' + b[4:].hex().upper())
