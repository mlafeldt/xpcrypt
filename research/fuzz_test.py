#!/usr/bin/env python3
"""Fuzz `xpcrypt -x` against malformed ROMs under ASan/UBSan.

The database reader is the only part of xpcrypt that walks attacker-shaped
input: `-d` and `-e` read fixed six-byte codes, but `-x` follows a record chain
of embedded lengths and NUL-terminated names through a buffer whose contents
are whatever was in the ROM.  Every bound in it is checked by hand.  This
generates images that stress those bounds and reports any that trip a
sanitizer.

Two things make a fuzzer that prints "0 crashes" worth believing, and this
asserts both rather than leaving the reader to notice:

  * the binary under test really is instrumented.  A plain build cannot report
    an overread, so it would pass this suite no matter what it did.
  * the cases really do reach the reader.  Random bytes are rejected by the
    name check almost every time and never get near the record walk, so a
    generator that has drifted would report a clean run while testing nothing.
    `reached` counts the images that came out as a database, and the run fails
    if too few did.

The cases are grown from extract_test.py's fixture - imported, not copied, so
the two cannot drift apart - by truncating it, corrupting it, and rebuilding
it with edge-value counts.  Anything that trips a sanitizer is kept under
fuzz-crashes/ with the seed that produced it in its name.

  uv run python fuzz_test.py [path/to/xpcrypt] [--cases N] [--seed N]
"""
import os
import random
import subprocess
import sys
import tempfile
from multiprocessing import Pool
from pathlib import Path

import fcdcrypt
from extract_test import make_fixture

XPCRYPT = Path('../xpcrypt')
CRASH_DIR = Path('fuzz-crashes')

# exitcode has to be distinct from xpcrypt's own 0 and 1, or a sanitizer report
# reads as an ordinary "not a ROM" refusal.
ENV = dict(os.environ,
           ASAN_OPTIONS='exitcode=99:detect_stack_use_after_return=1',
           UBSAN_OPTIONS='halt_on_error=1:exitcode=99:print_stacktrace=1')

SIG_OFF = fcdcrypt.ROM_SIGNATURE_OFFSET
SIG = fcdcrypt.ROM_SIGNATURE
MIN = fcdcrypt.ROM_MIN_SIZE

def fixture_db_offset(rom):
    """Where the fixture's record chain starts: past the erased run in front of
    it.  Located rather than hardcoded, so moving it in extract_test.py cannot
    quietly leave this corrupting empty flash instead of records."""
    i = MIN
    while i < len(rom) and rom[i] == 0xFF:
        i += 1
    return i


def name_bytes(rng, maxlen=12):
    """A plausible name: abbreviations, ASCII, and the Shift-JIS high range."""
    pool = (list(range(1, 8)) + list(range(0x20, 0x7F)) +
            list(range(0x80, 0xFF)))
    return bytes(rng.choice(pool) for _ in range(rng.randint(1, maxlen)))


def record_chain(rng):
    """A structurally plausible chain, biased to the counts that bound loops."""
    rec = bytearray()
    for _ in range(rng.randint(1, 4)):
        rec += name_bytes(rng) + b'\0'
        ncheats = rng.choice([1, 1, 1, 2, 3, 4, 200, 255])
        rec.append(ncheats)
        for _ in range(ncheats):
            rec += name_bytes(rng) + b'\0'
            nlines = rng.choice([0, 1, 2, 3, 200, 255]) \
                if rng.random() < 0.2 else rng.randint(0, 4)
            rec.append(nlines)
            rec += bytes(rng.randrange(256) for _ in range(6 * nlines))
    # Most chains terminate; the rest run off the end or stop mid-terminator.
    roll = rng.random()
    if roll < 0.9:
        rec += b'\xff\xff\xff\xff'
    elif roll < 0.95:
        rec += b'\xff' * rng.randint(1, 3)
    return bytes(rec)


def with_signature(body):
    rom = bytearray(body)
    if len(rom) < MIN:
        rom += b'\xff' * (MIN - len(rom))
    rom[SIG_OFF:SIG_OFF + len(SIG)] = SIG
    return bytes(rom)


def make_case(rng, kind):
    """One image. The families cover a different way to sit on a bound."""
    if kind == 0:                       # the fixture, cut at a random byte
        rom = make_fixture()
        return rom[:rng.randint(MIN, len(rom))]

    if kind == 1:                       # the fixture, corrupted in its records
        rom = bytearray(make_fixture())
        db = fixture_db_offset(rom)
        for _ in range(rng.randint(1, 6)):
            rom[rng.randrange(db - 8, min(db + 0x80, len(rom)))] = \
                rng.randrange(256)
        return bytes(rom)

    if kind == 2:                       # chain ending exactly at end of file
        return with_signature(b'\xff' * 0x20 + record_chain(rng))

    if kind == 3:                       # chain, then cut at a random byte
        rom = with_signature(b'\xff' * 0x20 + record_chain(rng) +
                             bytes(rng.randrange(256)
                                   for _ in range(rng.randint(0, 16))))
        return rom[:rng.randint(MIN, len(rom))]

    if kind == 4:                       # at offset 0: no erased run in front
        return with_signature(record_chain(rng))

    if kind == 5:                       # two candidates for the locator to rank
        return with_signature(b'\xff' * 0x20 + record_chain(rng) +
                              b'\xff' * rng.choice([4, 6, 8]) +
                              record_chain(rng))

    if kind == 6:                       # the encrypted path: decrypt, then walk
        return fcdcrypt.encrypt(
            with_signature(b'\xff' * 0x20 + record_chain(rng)))

    n = rng.randint(MIN, 0x400)         # noise, half of it sprayed with 0xFF
    rom = bytearray(rng.randrange(256) for _ in range(n))
    if rng.random() < 0.5:
        for i in range(0, n, rng.randint(2, 9)):
            rom[i] = 0xFF
    return with_signature(bytes(rom))


KINDS = 8


def keep_crash(seed, data, why):
    CRASH_DIR.mkdir(exist_ok=True)
    path = CRASH_DIR / ('crash-%d.rom' % seed)
    path.write_bytes(data)
    return (str(path), why, seed)


def run_case(args):
    """One image. Returns (crash, extracted) - @crash is None when it behaved,
    and @extracted says a database came out, which is what proves the case got
    as far as the record walk."""
    binary, seed = args
    rng = random.Random(seed)
    data = make_case(rng, seed % KINDS)

    with tempfile.NamedTemporaryFile(suffix='.rom', delete=False) as f:
        f.write(data)
        path = f.name
    try:
        p = subprocess.run([binary, '-x', path], capture_output=True,
                           timeout=60, env=ENV)
    except subprocess.TimeoutExpired:
        # A reader that never finishes is as much a bug as one that overruns,
        # and the images here are a few kilobytes at most.
        return keep_crash(seed, data, 'no exit within 60s'), False
    finally:
        os.unlink(path)

    if (p.returncode not in (0, 1) or b'AddressSanitizer' in p.stderr
            or b'runtime error' in p.stderr or b'SEGV' in p.stderr):
        return keep_crash(seed, data, 'rc=%d\n%s' % (
            p.returncode, p.stderr[:1500].decode(errors='replace'))), False

    return None, p.returncode == 0


def instrumented(binary):
    """Does this binary carry the sanitizer runtime that would catch a bug?"""
    p = subprocess.run([binary, '-V'], capture_output=True,
                       env=dict(os.environ, ASAN_OPTIONS='help=1'))
    return b'AddressSanitizer' in p.stderr


def main(argv):
    cases, seed, path = 4000, 1000, None
    argv = list(argv)
    while argv:
        arg = argv.pop(0)
        if arg == '--cases':
            cases = int(argv.pop(0))
        elif arg == '--seed':
            seed = int(argv.pop(0))
        else:
            path = arg

    binary = Path(path or XPCRYPT).resolve()
    if not binary.exists():
        sys.exit('no xpcrypt at %s - build it first' % binary)
    assert instrumented(binary), \
        ('%s is not an ASan build, so it cannot report an overread and this '
         'suite would pass whatever the reader did - build it with '
         '-fsanitize=address,undefined' % binary)

    work = [(str(binary), seed + n) for n in range(cases)]
    crashes, reached = [], 0
    with Pool() as pool:
        for crash, extracted in pool.imap_unordered(run_case, work, 64):
            if crash:
                path, why, bad_seed = crash
                crashes.append(path)
                print('CRASH: %s (--cases 1 --seed %d to repeat)\n%s'
                      % (path, bad_seed, why))
            reached += extracted

    # A clean run only means something if the images were getting through to
    # the record walk. Well under a third would say the generator has drifted
    # away from the format, not that the reader is sound.
    floor = cases // 3
    assert reached >= floor, \
        ('only %d of %d cases produced a database - the generator is no longer '
         'reaching the reader, so "no crashes" proves nothing' %
         (reached, cases))
    assert not crashes, '%d crash(es): %s' % (len(crashes), crashes)

    print('%d fuzzed ROMs, %d reached the database reader, no ASan/UBSan '
          'reports' % (cases, reached))


if __name__ == '__main__':
    main(sys.argv[1:])
