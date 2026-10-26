#!/usr/bin/env python3
"""Hold xpcrypt's cartridge warnings to what the firmware research says.

xpcrypt converts codes faithfully, and since 1.2 it says on stderr when the
cartridge will do something the text does not show (README, "Warnings").  Each
warning rests on a finding, so each is checked against one:

  default-off    a keyless code with bit 3 set keeps the bit in its address
                 (ENGINE.md 7) - 120 rows of Pro 2.20, 112 each of FX 3.20/4.52
  no cipher      key bits 1-3 select no route, so they stay in the address, or
                 a header keeps its stored size (FINDINGS.md 6.5)
  Special32/33   the first bytes 32/82 and 33/83, routes xpcrypt leaves undone
  empty block    a block declaring no payload hangs every engine (ENGINE.md 7)
  cut short      a block whose payload ends before its length does
  decorated      a code line in "$" or hyphens, passed through as text
  copyright      -r on a ROM whose header fails its firmware's check
                 (FINDINGS.md 5.3b) - which a stock Pro 2.14 does on its own

Every case is checked both ways: the warning fires on its trigger, and a clean
neighbour stays silent.  With roms/ present, -x has to report exactly the counts
the research scripts measure, and -r has to warn on 2.14 and nothing else.

  uv run python warn_test.py [path/to/xpcrypt]
"""
from pathlib import Path
import subprocess
import sys
import tempfile

XPCRYPT = Path(sys.argv[1] if len(sys.argv) > 1 else '../xpcrypt').resolve()

# (arguments, code line(s), the phrase its warning must contain - or None for
# silence)
STREAM = [
    ([], ['8802A798 FFFF'], 'switched off by default'),     # keyless, bit 3
    (['-e', '4'], ['8802A798 FFFF'], None),     # encrypting it is the cure
    ([], ['8E1BDB3A 72C6'], None),              # default-off, but keyed
    ([], ['E8000000 0001'], 'switched off by default'),     # E has no key
    ([], ['B8000000 0001'], 'switched off by default'),     # a slide too
    ([], ['48000000 0001'], None),              # type 4 has no address
    ([], ['31001643 500F'], 'select no cipher'),    # the USA database's
    ([], ['82000000 0001'], 'Special32 route'),
    ([], ['33000000 0001'], 'Special33 route'),
    ([], ['50000000 0000'], 'empty payload'),
    ([], ['60000000 0000', '801FAB92 EA80', 'FFFFFFFF 0000'], 'empty payload'),
    ([], ['50000000 0012', '11111111 1111'], 'ends after 1 of the 3'),
    ([], ['50000000 0006', '11111111 1111'], None),     # exactly complete
    ([], ['$60000000 003F'], 'looks like a code'),
    ([], ['00123456-0012'], 'looks like a code'),
    ([], ['-00123456 0012'], None),             # not the narrow shape
    ([], ['Game name'], None),
    ([], ['80024292 3C00'], None),
]

# image -> what -x has to report for its database: phrase -> count
DATABASES = {
    'xteng.dec': {},
    'xtepro.dec': {'switched off by default': 120},
    'xtger.dec': {'select no cipher': 1, 'empty payload': 2,
                  'before the payload': 1},
    'xtjpro.dec': {},
    'Xploder V2 (USA) r2.004 1998-11-13 [!].rom': {'select no cipher': 1},
    'english.dec': {'switched off by default': 112},
    'english-452.dec': {'switched off by default': 112},
    'v452d.rom': {'switched off by default': 112},
    'german-450.dec': {'switched off by default': 1, 'select no cipher': 1,
                       'empty payload': 2, 'before the payload': 1},
}
PHRASES = ('switched off by default', 'select no cipher', 'Special32/33',
           'empty payload', 'before the payload')

# encrypted image -> must -r warn about its copyright header?
COPYRIGHT = {
    'xteng.fcd': False, 'xtepro.fcd': False, 'xtger.fcd': False,
    'xtjpro.fcd': True, 'english.fcd': False, 'english-452.fcd': False,
    'german-450.fcd': False,
}


def stderr_of(args, stdin=b''):
    return subprocess.run([XPCRYPT] + args, input=stdin,
                          capture_output=True).stderr.decode()


def check_stream(problems):
    for args, lines, phrase in STREAM:
        err = stderr_of(args, ('\n'.join(lines) + '\n').encode())
        if phrase is None and 'Warning' in err:
            problems.append('%s %s: unexpected %r' % (args, lines, err))
        elif phrase is not None and phrase not in err:
            problems.append('%s %s: no %r in %r' % (args, lines, phrase, err))
    print('stream warnings: %d cases' % len(STREAM))


def check_databases(problems):
    rom_dir = Path('roms')
    have = [n for n in DATABASES if (rom_dir / n).exists()]
    if not have:
        print('-x warning counts: skipped (no roms/)')
        return
    for name in have:
        err = stderr_of(['-x', str(rom_dir / name)])
        got = {}
        for line in err.splitlines():
            for phrase in PHRASES:
                if phrase in line:
                    got[phrase] = int(line.split()[1])
        if got != DATABASES[name]:
            problems.append('-x %s: %s, expected %s' % (name, got,
                                                        DATABASES[name]))
    print('-x warning counts: %d database(s)' % len(have))


def check_copyright(problems):
    rom_dir = Path('roms')
    have = [n for n in COPYRIGHT if (rom_dir / n).exists()]
    if not have:
        print('-r copyright check: skipped (no roms/)')
        return
    with tempfile.TemporaryDirectory() as tmp:
        for name in have:
            out = Path(tmp) / 'out.dec'
            err = stderr_of(['-r', str(rom_dir / name), str(out)])
            warned = 'copyright' in err
            if warned != COPYRIGHT[name]:
                problems.append('-r %s: warned %s, expected %s (%r)'
                                % (name, warned, COPYRIGHT[name], err))
            if name == 'xtjpro.fcd' and 'stock Xplorer Pro 2.14' not in err:
                problems.append('-r xtjpro.fcd: not named as stock 2.14')

            # One changed character the firmware compares, and it must warn
            # in both directions; one it does not compare, and it must not.
            if name in ('xteng.fcd', 'english.fcd'):
                plain = bytearray(out.read_bytes())
                module = int.from_bytes(plain[0x7C:0x80], 'little') & 0xFFFFFF
                for pos, should in ((8, name == 'xteng.fcd'), (12, True)):
                    edited = bytearray(plain)
                    edited[module + pos] ^= 0x01
                    src = Path(tmp) / 'edited.dec'
                    src.write_bytes(edited)
                    err = stderr_of(['-r', str(src), str(Path(tmp) / 'e.fcd')])
                    back = stderr_of(['-r', str(Path(tmp) / 'e.fcd'),
                                      str(Path(tmp) / 'e.dec')])
                    for what, e in (('encrypting', err), ('decrypting', back)):
                        if ('copyright' in e) != should:
                            problems.append('%s %s with header byte %d '
                                            'changed: warned %s, expected %s'
                                            % (what, name, pos,
                                               'copyright' in e, should))
    print('-r copyright check: %d image(s)' % len(have))


def main():
    if not XPCRYPT.exists():
        sys.exit('no xpcrypt at %s - build it first' % XPCRYPT)
    problems = []
    check_stream(problems)
    check_databases(problems)
    check_copyright(problems)
    for p in problems:
        print('   ' + p)
    print('%s' % ('every warning fires where the research says, and only there'
                  if not problems else
                  '%d expectation(s) not met - not a pass' % len(problems)))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
