# What to do with xpcrypt next

Everything the firmware-reversing work suggests for the shipped tool, ranked — plus
the things that were considered and rejected, with the reason, so they do not get
re-derived.

Evidence lives in `FINDINGS.md` (conclusions) and `REVERSING.md` (method and
annotated listings). What the code types *do* is in `ENGINE.md`. Cite section
numbers rather than restating them.

Where the code stands. `main` is xpcrypt 1.2: `xpcrypt.c`, `crypto.c`/`crypto.h`
and `lzw.c`/`lzw.h`. `research` is `main` plus this directory, and its gate (`make`
here) is the regression check for every change to `main`; the tests stay here for
now. The module split exists only on the unmerged `module-split` branch (`fed8a70`,
forked from `854c1e1`). It renames `xp_crypto.*` the way `main` now has, but its
`db.c` predates the empty-game fix and everything since.

---

## Done in 1.2

The plan the ninth pass of `AUDIT.md` produced, as it landed on `main`:

* **`8f9b90b`** - `xp_crypto.c`/`.h` became `crypto.c`/`.h`. The identifiers keep
  their `xp_`.
* **`5ded6f1`** - the comments keep invariants, not history.
* **`87362e3`** - `-x` reads the Xplorer FX: the module's pointer at
  `*(rom + 0x7C) + 0xB8`, the container, and Nelson's 14-bit LZW in `lzw.c`
  (`FINDINGS.md` §6.3). V2 still goes through the framing scan, unchanged.
  `rom_module()` tells the generations apart, and `locate_database()` owns the
  FX-vs-V2 choice. `extract_test.py` has an FX fixture, four damaged containers
  and the four FX images; `fuzz_test.py` has two FX families.
* **`72384f1`** - empty games are printed, and a chain needs at least one cheat to
  count as a database (`TENTH.md` §3).
* **`58e825e`** - a block starts on the header's *stored* type, as on the cartridge.
  Key bits 1-3 keep the header as stored, size and all, with a warning
  (`FINDINGS.md` §6.5). `oracle_test.py` asserts the cart's side.
* **`b500462`** - the first code byte is described in one place: `xp_code_route()`,
  a table of the sixteen types, and the declared length from `xp_parse_block()`.
* **`9451311`** - warnings for codes the cartridge runs differently: the default-off
  bit on a keyless code (the slide code, type B, among the addressed types), key
  bits that select no cipher (or the Special32/33 routes), empty blocks, and blocks
  cut short. The stream returns them as events and does no I/O: the text filter
  prints them, and `-x` gives one line per kind for the whole database, an unknown
  payload key among them.
* **`bc3cadc`** - `-r` models the anti-tamper check on the plaintext side and warns,
  stock Pro 2.14 included. It still writes the output.
* **`8c08daf`** - a code line dressed in `$` or hyphens gets a warning and still
  passes through untouched.
* **`d86ba7c`** - release 1.2, with the README history and a Warnings section.

`warn_test.py` (`make warnings`) holds every warning to the finding it rests on, both
on the stream and in the `-x` counts per database.

Earlier, before the ninth pass: Supercode/Megacode and type A blocks, the route
table (`XP_KEYED_TYPES`), the closed-form ROM cipher, and `-x` itself.

---

## Still open

### 1. An optional runtime-lint mode

The FAQ comparison makes the seam explicit: xpcrypt validates and transforms the
stored format, but a syntactically valid decrypted code can still be inert,
target-specific or dangerous when the cartridge executes it. An opt-in
`--check`/`--lint` mode would report what the corpus establishes. The ninth pass
changed several of these facts, so build on `ENGINE.md` as it now reads:

* `CD`/`C6`/`C8` lines are inert. `C0` and an unhoisted `D0` become type 7 guards;
* a lone D becomes a global type F anchor, hoisted to the head of the list;
* type 4 works on V2/Pro and is inert on FX;
* a second Megacode in one selection wrecks the whole list;
* staging rewrites odd addresses:
  * a byte or halfword write at an odd address becomes a type E write of the low
    byte only;
  * a misaligned word write becomes a halfword write;
  * a slide's odd step is rounded down;
* an encrypted F anchor whose stored byte 3 is odd never matches after hoisting.
  Three shipped USA anchors are like that.

Keep it separate from encryption and decryption, and never rewrite the input. Some
facts need more context than a text stream has: D and the Megacode limit are
properties of the selection, type B consumes a second line, and FX differences need
a firmware family. The first version should say when it lacks that context rather
than infer it.

### Optional: `--unpack`

COMP01 plus the FX descrambler in C, about 120 lines; `comp01.py` and `fxunp.py` are
the references. With `lzw.c` in place, xpcrypt could open every layer
of either generation. Useless for converting codes, so whether to do it depends on
whether xpcrypt should be a cheat tool or a cartridge tool.

---

### Is a keyless default-off Supercode addressed?

The default-off warning covers the types the engine stores to or compares at:
0 3 7 8 9 B E F. Type 5 is left out, although the engine copies a Supercode's
payload to its address. Staging builds that list word as `0x50aaaaaa`, which may
drop bit 3 before the engine ever sees it. Read pass 2's emit before adding the
type.

### The module split, again

The code-quality review of 1.2 asked for `MODULE_SPLIT.md`'s split before the
push. That was set aside: `xpcrypt.c` is about 1,350 lines. The event-returning
stream is the seam `MODULE_SPLIT.md` wanted for it.

### Tests on `main`

Deferred by choice: the differential tests stay in `research/`. If `main` gets its
own `make check` later, the plan was golden vectors written and verified by
`romcrypt.py` here, so the release build needs no Python.

### The module split

`MODULE_SPLIT.md`, on its own branch. Reviving it now means rebasing it over 1.2,
which rewrote much of what it moved.

## Considered and rejected

### A COMP01 packer — feasible, just not needed

You do not need FCD's compressor; any stream their decompressor accepts is valid
(`FINDINGS.md` §5.1b). The constraint is size:

* store-only (every byte a literal, escape bytes doubled) runs +33% over the
  original on `xteng.dec`, `0x2BFC8` against `0x210CB`, and does not fit before the
  database;
* the LZ opcode alone accounts for 96-97% of what FCD's encoder saved on eight of
  the nine images, and 70% on `english-452.dec`. That 70% reflects FCD's encoder
  run, not the data, which compresses like `v452d.rom`'s.

Nothing needs a rebuilt ROM, and anyone who builds one is a single edited copyright
string away from bricking a cartridge, which `-r` now warns about.

### Code keys 2 and 3 (`Special32` / `Special33`)

The exact firmware constants are known (`FINDINGS.md` §6.4) and were implemented
once and reverted. Still no:

* no database uses them;
* none of the vendor's four PC tools implements them;
* `Special32` is one of the two V2 routes that run the self-destruct check.

### Re-litigating the route table

`XP_KEYED_TYPES = 0xABFB` holds in all ten firmwares, both generations, three
languages, and the vendor's encrypters agree. Settled.

## Housekeeping

* ~~The `Makefile` passes `-s`, which clang rejects under `-Werror`~~ — done; the
  binary is stripped by `install -s` now (`FINDINGS.md` §1).
* ~~The repo has a plain `TODO` with two lines~~ — removed in `dc66a3b`.
* ~~`crypto.h` (then `xp_crypto.h`) guards itself with `_XP_CRYPTO_H_`~~ — done,
  `XP_CRYPTO_H`.
* ~~Version bump and a README history entry~~ — done, 1.2.
* The root `Makefile` has no `check` target; the gate lives here (see "Tests on
  `main`").

---

## Verifying the current state

```sh
make            # everything below, in order, from research/
```

`research/Makefile` drives the suites the notes lean on — not every script here —
and ends in `all suites passed`. Its parts run on their own: `strict` and
`sanitize` for the two C builds, `fuzz` for `-x` against generated malformed
ROMs, `crypto` for the seven `oracle_test.py` suites,
`extract` for plaintext/encrypted database extraction, V2 and FX, `warnings` for
the cartridge warnings, `roundtrip` for `-e K | -d`
over every database code, `fxdb` for the FX databases, `firmware` for the nine-way
cipher agreement, `engine` for the executed engine, `tables` and `analyses` for
the published tables and counts. Targets that need the firmware dumps skip with a
note when `roms/` is empty rather than failing, so the crypto and block suites
still run on a fresh checkout.

It is meant to be usable as a gate, so a failing suite has to fail the build.
Every filtered suite pipeline runs under `set -o pipefail` (make 3.81 has no
`.SHELLFLAGS`), and **every** script asserts its expected values rather than
printing them and leaving the reader to notice — a producer that exits 0 while
emitting one line the Makefile's `grep` likes would otherwise pass with the wrong
numbers in it. What each one requires: `engineemu.py`, that the two differing
cases are the two type 4 ones, that they group as *those* five V2/Pro images
against *those* four FX ones, and that every case's traces still hash to its
recorded digest; `fxtest.py`, nine images, `XP_KEYED_TYPES = 0xABFB` in each, and
a known plaintext whose two halves are the same length before they are compared;
`engine.py`, the two dispatch chains and 13-15 `andi` sites with 9 read and the
same seven types; `dbtypes.py`, the published totals column; `packstats.py`, the
opcode use and saving ranges; `fxcmp.py`, four routines identical to the baseline
and four FX routes differing; `audit2.py`, exactly one overrunning block;
`escrank.py`, nine images with the rarest byte first and none worse than 13;
`defaultoff.py`, its counts for both pools; `roundtrip.py`, its 15,349 lines;
`extract_test.py`, the 15,349 lines in 11,718 cheats; `fuzz_test.py`, that the
binary under test carries the sanitizer runtime and that at least a third of its
images came out as a database.

That last pair is the point of it rather than a detail. A fuzzer reports the
absence of something, so both ways of getting a vacuous pass have to be closed:
a binary built without `-fsanitize` cannot report an overread, and a generator
that has drifted away from the record format produces images the name check
rejects before the walk ever starts. Either would print "no crashes" forever.
`fuzz_test.py` grows its cases from `extract_test.py`'s fixture by importing it,
so the two cannot drift apart in the first place.

Counting is not naming and naming is not membership: a count of two differing
cases accepts two *different* cases differing, and a 5/4 split accepts the wrong
five. `engineemu.py --record` regenerates the digest table, and is only for after
you have established that a change is intended.

The gate is serial (`.NOTPARALLEL`). Every C target rebuilds the same objects in
the parent directory with different flags, so under `-j` they trip over each
other; `make -j4 check` used to fail with a missing `../xpcrypt` or a
half-sanitized link.

Each producer replaced with `false` must fail its target:

```sh
make strict CC1=false CC2=false ; make sanitize CC2=false ; make fuzz PY=false
make oracle PY=false            ; make extract PY=false ; make roundtrip PY=false
make firmware PYCS=false        ; make engine PYCS=false
make tables PYCS=false          ; make analyses PYCS=false
```

If any of those exits 0, nothing below is a test.

The individual commands, for when a target needs picking apart:

```sh
cd .. && make && cd research
uv run python oracle_test.py ../xpcrypt      # 7 suites, expect "all good"
uv run python extract_test.py                # synthetic plus all available ROMs
uv run python warn_test.py                   # every warning against its finding
uv run python fuzz_test.py ../xpcrypt        # needs an ASan build; --cases N
uv run python roundtrip.py                   # expect "15349 code lines x 4 keys, 0"
uv run python fcdcrypt.py                    # the .fcd image cipher; "all good"
uv run --with capstone --with unicorn python xlink.py   # ... run out of the 4 PC tools
uv run --with capstone python fxtest.py      # expect "all 9 firmwares agree"
uv run --with capstone python fxprot.py      # the anti-tamper check, per ROM
uv run --with capstone python packstats.py   # what COMP01 spends its opcodes on
uv run python escrank.py                     # how rare COMP01's escape bytes are
uv run --with capstone python engineemu.py   # expect "2 of 26 cases differ"
uv run --with capstone python engine.py      # the type dispatch of all nine
uv run python dbtypes.py                     # code types used by the databases
uv run python defaultoff.py                  # expect 133 / 121 / 120 / 121
```

`uv` for all Python; capstone comes from `--with capstone`, never a system
install. Scripts import each other, so run them from `research/`.
