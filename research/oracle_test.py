#!/usr/bin/env python3
"""Test xpcrypt against the Xploder firmware.

romcrypt.py is a transcription of the decrypt routine at 0x801ABF94 of the
cartridge (see REVERSING.md). This uses it as an oracle:

  * every normal code decrypts like the firmware does, or differs in one of the
    documented ways, which are asserted too;
  * every code xpcrypt *encrypts* is one the firmware decrypts back - the only
    way to check the encrypt side at all, since the cartridge has none;
  * the same for the payload of Supercode and Megacode blocks, plus the number
    of payload codes the firmware expects to follow a header;
  * a code type A header takes every code below it as raw payload, so none of
    them may be transformed as a code of its own;
  * a block header stored with key bits 1-3 starts a block anyway, with its
    size as stored, the way the cartridge stages it - and says so on stderr.

No ROM needed: the codes are generated. If decrypted ROMs are lying around in
roms/, their databases are thrown in as well.

  python3 oracle_test.py [path/to/xpcrypt]
"""
import glob
import os
import random
import subprocess
import sys

import romcrypt

XPCRYPT = sys.argv[1] if len(sys.argv) > 1 else '../xpcrypt'
CODE_LEN = 6
DESC_LEN = 10           # breakpoint descriptor in front of a Megacode payload
EXPECT_DB_LINES = 15349
EXPECT_DB_CHEATS = 11718

# High nibbles the firmware's jump table gives no crypto route. Both the firmware
# and xpcrypt leave such a code alone - see REVERSING.md 6.2.
GAP_NIBBLES = (0x2, 0xA, 0xC, 0xE)
# High nibbles that start a block of payload codes. Kept out of the code-level
# tests, where they would start a block and swallow the codes that follow. Type
# A has no length field: its payload runs to the end of the cheat.
BLOCK_NIBBLES = (0x5, 0x6, 0xA)

random.seed(20090510)


def run(args, codes):
    """Feed 6-byte codes to xpcrypt, get 6-byte codes back.

    Every caller zips the result against its input, so a run that dies or is
    cut short would quietly test fewer codes instead of failing. Insist on a
    clean exit and one code back for every code in."""
    text = '\n'.join('%02X%02X%02X%02X %02X%02X' % tuple(c) for c in codes)
    out = subprocess.run([XPCRYPT] + args, input=text.encode(),
                         capture_output=True)
    if out.returncode != 0:
        sys.exit('%s %s exited %d\n%s' % (XPCRYPT, ' '.join(args),
                                          out.returncode,
                                          out.stderr.decode().strip()))
    words = out.stdout.decode().split()
    got = [bytes.fromhex(a + b) for a, b in zip(words[0::2], words[1::2])]
    if len(got) != len(codes):
        sys.exit('%s %s: %d codes in, %d out' % (XPCRYPT, ' '.join(args),
                                                 len(codes), len(got)))
    return got


def stderr_of(args, codes):
    """What xpcrypt says on stderr about @codes."""
    text = '\n'.join('%02X%02X%02X%02X %02X%02X' % tuple(c) for c in codes)
    return subprocess.run([XPCRYPT] + args, input=text.encode(),
                          capture_output=True).stderr


def route_of(first):
    return romcrypt.ROUTES.get(first & 0xF7)


def rand_code(first):
    return bytes([first] + [random.randrange(256) for _ in range(CODE_LEN - 1)])


class Test:
    def __init__(self, name):
        self.name = name
        self.fail = self.checks = self.known = 0

    def eq(self, got, want, what):
        self.checks += 1
        if got != want:
            self.fail += 1
            if self.fail <= 5:
                print('  FAIL %-30s got %s want %s'
                      % (what, got.hex().upper(), want.hex().upper()))

    def done(self, note=''):
        print('%-44s %6d checks, %d failed%s'
              % (self.name, self.checks, self.fail, note))
        return self.fail


def test_decrypt():
    """A normal code decrypts like the firmware, or differs by design."""
    t = Test('normal codes vs the firmware')
    gaps = specials = 0
    firsts = [b for b in range(256) if (b >> 4) not in BLOCK_NIBBLES]
    codes = [rand_code(b) for b in firsts for _ in range(8)]

    for raw, mine in zip(codes, run([], codes)):
        route, key = route_of(raw[0]), raw[0] & 7
        if route and route.startswith('key'):
            # By design: the firmware clears the whole low nibble, xpcrypt
            # keeps the default-off bit so that a code can be re-encrypted.
            rom = bytes(romcrypt.decrypt(list(raw)))
            t.eq(mine, bytes([rom[0] | (raw[0] & 0x08)]) + rom[1:],
                 'key %d' % key)
        elif (raw[0] >> 4) in GAP_NIBBLES and key >= 4:
            # Types the jump table gives no crypto route: both leave the
            # code alone, even though its key bits look like a key.
            gaps += 1
            t.eq(mine, raw, 'gap %02X' % raw[0])
        elif route in ('fcd', 'not'):
            # By design: xpcrypt does not implement these two routes.
            specials += 1
            t.eq(mine, raw, 'route %s %02X' % (route, raw[0]))
        else:
            t.eq(mine, bytes(romcrypt.decrypt(list(raw))), 'copy %02X' % raw[0])

    # Type A gets a run of its own, because the first one is a header and takes
    # every code below it as payload. Either way every one of them comes back
    # unchanged: as a header of a type the jump table gives no route for, and as
    # a payload row, which is raw data the Xploder never decrypts.
    codes = [rand_code(0xA0 | lo) for lo in range(16) for _ in range(8)]
    for raw, mine in zip(codes, run([], codes)):
        gaps += 1
        t.eq(mine, raw, 'type A %02X' % raw[0])

    return t.done(', %d in route-table gaps, %d fcd/not' % (gaps, specials))


def test_encrypt():
    """Whatever xpcrypt encrypts, the firmware has to decrypt back."""
    t = Test('the firmware reads back what xpcrypt writes')
    good = [n for n in range(16)
            if n not in GAP_NIBBLES and n not in BLOCK_NIBBLES]
    for key in (4, 5, 6, 7):
        plain = [rand_code((random.choice(good) << 4) | random.choice((0, 8)))
                 for _ in range(1000)]
        for p, enc in zip(plain, run(['-e', str(key)], plain)):
            t.eq(bytes([enc[0] & 7]), bytes([key]), 'key nibble')
            t.eq(bytes(romcrypt.decrypt(list(enc))),
                 bytes([p[0] & 0xF0]) + p[1:], 'key %d' % key)

    # A code of a type the firmware never routes must come out unencrypted,
    # otherwise the cartridge would read the ciphertext as the code.
    plain = [rand_code((n << 4) | random.choice((0, 8)))
             for n in GAP_NIBBLES for _ in range(50)]
    for p, enc in zip(plain, run(['-e', '6'], plain)):
        t.eq(enc, p, 'gap %02X left in the clear' % p[0])

    return t.done(', %d unencryptable types left alone' % len(plain))


def make_block(mega, payload_key, nbytes):
    """A plaintext block header plus a random payload of the right length."""
    if mega:
        head = bytes([0x60, random.randrange(256), random.randrange(256),
                      payload_key, nbytes >> 8, nbytes & 0xFF])
        rows = (nbytes + DESC_LEN + CODE_LEN - 1) // CODE_LEN
    else:
        head = bytes([0x50, random.randrange(256), random.randrange(256),
                      random.randrange(256),
                      (payload_key << 4) | (nbytes >> 8), nbytes & 0xFF])
        rows = (nbytes + CODE_LEN - 1) // CODE_LEN
    return head, [rand_code(random.randrange(256)) for _ in range(rows)], rows


def test_blocks():
    """Block payloads: row count and per-row crypto against the firmware."""
    t = Test('block payloads vs the firmware')
    for mega in (0, 1):
        for payload_key in (0, 6, 7):
            for _ in range(60):
                nbytes = random.randrange(1, 0x400 if mega else 0x100)
                head, payload, rows = make_block(mega, payload_key, nbytes)

                enc = run(['-e', '6'], [head] + payload)
                t.eq(bytes([len(enc) - 1]), bytes([rows]), 'row count')
                t.eq(bytes(romcrypt.decrypt(list(enc[0])))[1:], head[1:],
                     'header')
                for got, want in zip(enc[1:], payload):
                    t.eq(bytes(romcrypt.decrypt(list(got), payload_key)), want,
                         'mega%d key%d row' % (mega, payload_key))

                t.eq(b''.join(run([], enc)[1:]), b''.join(payload),
                     'mega%d key%d round trip' % (mega, payload_key))
    return t.done()


def test_empty_blocks():
    """Blocks whose length field is zero - the boundary make_block() misses.

    The two types do not mean the same thing by it. A Supercode saying zero
    bytes has no payload at all, so the code below it is an ordinary code and
    has to be encrypted as one. A Megacode cannot say it: its length counts the
    bytes *after* the breakpoint descriptor, so zero still means the two codes
    the descriptor occupies, and the firmware's stager reads rows 0 and 1
    unconditionally before it ever looks at the length (REVERSING.md 7).
    """
    t = Test('blocks with a zero length field')
    good = [n for n in range(16)
            if n not in GAP_NIBBLES and n not in BLOCK_NIBBLES]

    def ordinary(first):
        return rand_code((random.choice(good) << 4) | first)

    for payload_key in (0, 6, 7):
        for off in (0x00, 0x08):
            # Supercode: nothing below it is payload.
            head = bytes([0x50 | off, random.randrange(256),
                          random.randrange(256), random.randrange(256),
                          payload_key << 4, 0x00])
            below = [ordinary(0) for _ in range(3)]
            enc = run(['-e', '6'], [head] + below)
            t.eq(bytes([len(enc)]), bytes([1 + len(below)]), 'super row count')
            for got, want in zip(enc, [head] + below):
                t.eq(bytes(romcrypt.decrypt(list(got)))[1:], want[1:],
                     'super key%d as an ordinary code' % payload_key)

            # Megacode: exactly the two descriptor rows, and no more.
            head = bytes([0x60 | off, random.randrange(256),
                          random.randrange(256), payload_key, 0x00, 0x00])
            rows = [rand_code(random.randrange(256)) for _ in range(2)]
            after = ordinary(0)
            enc = run(['-e', '6'], [head] + rows + [after])
            t.eq(bytes([len(enc)]), bytes([4]), 'mega row count')
            for got, want in zip(enc[1:3], rows):
                t.eq(bytes(romcrypt.decrypt(list(got), payload_key)), want,
                     'mega key%d descriptor row' % payload_key)
            t.eq(bytes(romcrypt.decrypt(list(enc[3])))[1:], after[1:],
                 'mega key%d code after the block' % payload_key)

            # ... and the whole thing has to come back out again.
            t.eq(b''.join(run([], enc)[1:]), b''.join(rows + [after]),
                 'mega key%d round trip' % payload_key)

    return t.done()


def test_unkeyed_headers():
    """Block headers stored with key bits 1-3, staged the cartridge's way.

    The jump table has no route for a low nibble of 1-3, so the firmware copies
    such a header and stages it by its *stored* type nibble - both stagers test
    byte 0 & 0xF0 before decrypting (0x1ACCEC, 0x1AD08C in xteng.dec) - with its
    size and payload key taken verbatim.  xpcrypt does the same since 95b85ec
    (it used to start no block, FINDINGS.md 6.5): the header comes back as it
    is, the rows below are payload under its payload key, and a warning names
    the key bits.  No shipped header is stored this way.  `differ` counts the
    rows that an ordinary-code reading - the old rule - would have got wrong."""
    t = Test('headers with key bits 1-3')
    good = [n for n in range(16)
            if n not in GAP_NIBBLES and n not in BLOCK_NIBBLES]
    differ = 0
    for key in (1, 2, 3):
        for off in (0x00, 0x08):
            for payload_key in (0, 6, 7):
                for mega in (False, True):
                    size = random.randrange(1, 24)
                    if mega:
                        head = [0x60 | off | key, random.randrange(256),
                                random.randrange(256), payload_key,
                                size >> 8, size & 0xFF]
                        rows = (size + DESC_LEN + 5) // CODE_LEN
                    else:
                        head = [0x50 | off | key, random.randrange(256),
                                random.randrange(256), random.randrange(256),
                                payload_key << 4, size]
                        rows = (size + 5) // CODE_LEN
                    below = [rand_code((random.choice(good) << 4) | 6)
                             for _ in range(rows)]
                    got = run([], [bytes(head)] + below)
                    t.eq(got[0], bytes(head), 'header left as it is')
                    for raw, mine in zip(below, got[1:]):
                        t.eq(mine, bytes(romcrypt.decrypt(list(raw),
                                                          payload_key)),
                             'row below as payload')
                        if mine != bytes(romcrypt.decrypt(list(raw))):
                            differ += 1
                    t.eq(bytes([b'select no cipher' in stderr_of(
                        [], [bytes(head)] + below)]), b'\x01', 'warning')
    return t.done(', %d row(s) an ordinary-code reading would get wrong'
                  % differ)


def test_inline_blocks():
    """Type A: raw payload, no length field, no payload key.

    The Xploder copies the six bytes of every code below the header into the
    payload buffer without decrypting or classifying them, so xpcrypt has to
    leave them alone in both directions. Nothing in the header says how many
    there are - the payload ends where the cheat does."""
    t = Test('inline data blocks (type A)')
    for flag in (0x0, 0x8, 0x6):        # including key bits, which mean nothing
        for _ in range(40):
            head = bytes([0xA0 | flag] + [random.randrange(256)
                                          for _ in range(CODE_LEN - 1)])
            # rows a stream reader would happily mangle: keyed normal codes and
            # a Supercode header of its own, which here is data like the rest
            payload = [rand_code(random.randrange(0x10, 0xF0) | 6)
                       for _ in range(random.randrange(1, 12))]
            payload.insert(random.randrange(len(payload) + 1),
                           bytes([0x50, 0, 0, 0, 0x60, 0x30]))

            for args in ([], ['-e', '6'], ['-e', '4']):
                got = run(args, [head] + payload)
                t.eq(bytes([len(got)]), bytes([1 + len(payload)]), 'row count')
                t.eq(got[0], head, 'header %s' % (args or ['-d'])[0])
                t.eq(b''.join(got[1:]), b''.join(payload),
                     'payload left alone %s' % (args or ['-d'])[0])
    return t.done()


def check_cheat(t, name, lines):
    """One cheat entry: the codes of one cheat, in order, as the cartridge
    reads them. Returns how many were of a type the jump table gives no route
    for."""
    gaps, index, rows, pkey = 0, -1, 0, 0
    for raw, got in zip(lines, run([], lines)):
        if index >= 0:
            t.eq(got, bytes(romcrypt.decrypt(list(raw), pkey)),
                 '%s payload' % name)
            index += 1
            if index >= rows:
                index = -1
            continue

        route, key = route_of(raw[0]), raw[0] & 7
        if (raw[0] >> 4) in GAP_NIBBLES and key >= 4:
            gaps += 1
        rom = bytes(romcrypt.decrypt(list(raw)))
        if route and route.startswith('key'):
            rom = bytes([rom[0] | (raw[0] & 0x08)]) + rom[1:]
        t.eq(got, rom, name)

        if got[0] & 0xF0 == 0x50:
            pkey = got[4] >> 4
            rows = ((((got[4] & 0xF) << 8) | got[5]) + 5) // CODE_LEN
            # A Supercode of size 0 has no payload, so it does not start a
            # block - the next code is an ordinary one. Two cheats in the
            # German database are written that way. (The cartridge stages one
            # anyway, and its engine then runs away - see ENGINE.md 7.)
            index = 0 if rows else -1
        elif got[0] & 0xF0 == 0x60:
            pkey = got[3] & 0xF
            rows = ((((got[4] << 8) | got[5]) + DESC_LEN + 5) // CODE_LEN)
            index = 0
        elif got[0] & 0xF0 == 0xA0:
            # No length: the rest of the cheat is payload, and raw
            pkey, rows, index = 0, len(lines), 0
    return gaps


def test_databases():
    """If decrypted ROMs are around, run every real code through both.

    One cheat at a time, one xpcrypt run each: a cheat entry is where the
    cartridge starts reading, so a block header at the end of one cheat must
    not swallow the codes of the next. Feeding a whole database as one stream
    does exactly that - in xtger.dec a one-line cheat decrypts to something
    that looks like a type 6 header declaring 9,212 rows, and the rest of the
    database is then never tested as ordinary codes."""
    roms = sorted(glob.glob('roms/*.dec') + glob.glob('roms/*.rom'))
    if not roms:
        print('%-44s skipped (no roms/)' % 'real databases vs the firmware')
        return 0
    try:
        import db2
    except ImportError:
        print('%-44s skipped (no db2.py)' % 'real databases vs the firmware')
        return 0

    t = Test('real databases vs the firmware')
    gaps = cheats = 0
    for path in roms:
        _, db = db2.find_db(open(path, 'rb').read())
        if db is None:
            continue
        for _, _, cheat in db:
            cheats += 1
            gaps += check_cheat(t, os.path.basename(path),
                                [bytes(l) for l in cheat])

    bad = t.done(', %d cheats, %d in route-table gaps' % (cheats, gaps))
    if (t.checks, cheats) != (EXPECT_DB_LINES, EXPECT_DB_CHEATS):
        print('  expected %d lines in %d cheats'
              % (EXPECT_DB_LINES, EXPECT_DB_CHEATS))
        bad += 1
    return bad


if __name__ == '__main__':
    if not os.path.exists(XPCRYPT):
        sys.exit('no xpcrypt at %s - build it first, or pass its path' % XPCRYPT)
    bad = (test_decrypt() + test_encrypt() + test_blocks()
           + test_empty_blocks() + test_unkeyed_headers() + test_inline_blocks()
           + test_databases())
    print('\n%s' % ('FAILED' if bad else 'all good'))
    sys.exit(1 if bad else 0)
