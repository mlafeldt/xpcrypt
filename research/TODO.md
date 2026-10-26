# What to do with xpcrypt next

Everything the firmware-reversing work suggests, ranked — plus the things that
were considered and rejected, with the reason, so they do not get re-derived.

Evidence lives in `FINDINGS.md` (conclusions) and `REVERSING.md` (method and
annotated listings). Cite section numbers rather than restating them. What the
code types *do* is in `ENGINE.md`.

The repo is ahead of `17e31fc` (squashed from 18); everything below `research/` is
notes and rigs, not shipped source. The corrections from all six `AUDIT.md` passes are
applied to this directory and, where they reached the source, to `crypto.c`,
`crypto.h` and `xpcrypt.c`. Items 1a, 1c, 2, 4 and 5 below are done, and item
1 has a research-only gate; the rest is not started.

The compatibility review of the historical `Advanced Xplorer Codes` FAQ in
`ADVANCED_EXPLORER_CODES.md` reinforces items 1, 1b and 1d, and adds the
runtime-lint and decorated-input diagnostics in 1e and 1f.

---

## Worth doing

### 1. Wire `oracle_test.py` into `make check`

xpcrypt now has focused C tests for the four extracted module interfaces, but
its firmware differential tests remain research-only. The differential test
runs with **no ROMs at all** — 1792 + 8200 + 20590 + 1080 checks against
`romcrypt.py` — and widens automatically to 15,349 real database codes in
11,718 cheats when `roms/` is populated. That means moving `romcrypt.py` and
`oracle_test.py` out of this directory into the shipped source, and adding a
`check` target.

Highest leverage of anything on this list: it turns "verified once" into "stays
verified", and makes everything below safer to attempt.

Half-done: the root `Makefile` has a `test` target for the focused C tests, and
`research/Makefile` runs the wider suites, extraction checks, strict builds and
sanitizers with one `make`. The root still has no `check` target, and the wider
gate needs `research/` and `uv` present. What is left is to move the
self-contained differential tests into the release source and add the root
target. `oracle_test.py` and `extract_test.py` widen over `roms/` when the
private corpus is present, so shipping them also means preserving a useful
no-ROM baseline.

### ~~1a. Replace the ROM seed tables with the six operations they spell out~~ — done

New; `FCD.md` has the evidence. The `.fcd` image cipher is

```
dec[i] = (enc[i] ^ (u8)(i ^ ((i >> 1) + 0x45))) + (u8)((i & 0x37) ^ 0x2C)
```

read out of four PC tools, both directions in each, all eight routines executed
under an emulator, and equal to xpcrypt's former
`seeds1`/`seeds2` on all 512 x 256 (offset, byte) inputs. Equal as a transform,
not byte for byte: the tables differ from `mask`/`addend` at 256 of the 512
offsets, by a `^ 0x80` and a `+ 0x80` that cancel mod 256. Every offset has
exactly two seed pairs that spell the same function — `(a, b)` and
`(a ^ 0x80, b + 0x80)`, and no others — and the deleted `xp_bf_rom()` scanned
`a` upward from 0, so it recorded the lower one each time. The 1 KB of tables in
`crypto.c` became `rom_mask()` and `rom_addend()`, each of
`xp_encrypt_rom()` / `xp_decrypt_rom()` became a one-line loop over the pair,
and the comment above them says where the six operations were read.

Also fixed: `XP_ROM_BLKSIZE` and the "encrypted in ECB mode" comment described a
block cipher that does not exist — 512 is just the period of the mask — and both
functions rejected buffers under 512 bytes for no reason the routine shares.
The `Sony` marker moved behind `xp_rom_is_plain()`, rather than three exported
macros that the CLI went on to re-implement twice, and the bound on its compare
is derived from the layout it guards. This removes the last thing in the source
that was guessed rather than read.

### 1b. Warn when `-d` produces a code the cartridge will mis-apply

Falls out of the engine work (`ENGINE.md` §7). The default-off bit survives
decryption for any code stored with key nibble 0 — `(code[0] & 0xF7) - 4` sends
`0x80` and `0x88` to the same verbatim-copy route — and the engine's
`& 0x0FFFFFFF` then keeps it, adding `0x08000000` to the address. Executed on
both halves; 120 lines of the Xplorer Pro 2.20 database store or compare at the
wrong address because of it, out of 133 that carry the bit.

xpcrypt deliberately preserves that bit so codes round-trip, which is right. But
it means `xpcrypt -d` can hand back a code that no cartridge will apply where the
user expects. A one-line warning when bit 3 survives on a keyed type whose
address the engine dereferences (3, 7, 8, 9, 0, B, E, F) would say so. Cheap, and
together with 1d it is what is left of the *user-visible* consequences of
`ENGINE.md`.

### ~~1c. Type A payloads~~ — done

Second audit, item 1. A type A header takes every code below it as raw payload
to the end of the cheat, and `crypt_codes()` only entered payload mode for types
5 and 6 — so it transformed those rows as codes of their own and silently
corrupted them. `xp_parse_block()` now reports a type A block as `unbounded`,
`xp_in_payload()` decides where a payload ends, and the CLI warns that it is
taking every following code. Covered by a new `oracle_test.py` suite (1080
checks) that fails against the pre-fix binary.

### 1d. Warn on a block that declares no payload

Second audit, item 2, and the other user-visible consequence. Both engine block
handlers copy one unit before they decrement and test, so a Supercode or
Megacode declaring zero bytes hangs the console — all nine firmwares, executed
(`ENGINE.md` §7). The German database ships two (`War Games`).

xpcrypt is right to treat a size-0 type 5 as "not a block" — the line below it
really is an ordinary code — but it could say that the cartridge disagrees. Same
shape of fix as 1b, same place.

### 1e. Add an optional runtime-lint mode

The FAQ comparison makes the seam explicit: xpcrypt validates and transforms
the stored format, but a syntactically valid decrypted code can still be inert,
target-specific or dangerous when the cartridge executes it. Add an opt-in
`--check`/`--lint` mode that reports the facts the firmware corpus establishes:

* ~~type C has no handler in any of the nine recovered engines~~ - ninth pass: staging
  rewrites `C0` (and an unhoisted `D0`) into type 7, so only `CD`/`C6`/`C8` are inert;
* type 4 works on V2/Pro and is inert on FX, when the user supplies a target;
* type D is promoted to a global type F anchor only when exactly one is selected;
* a type B slide performs halfword stores, so an odd start address or address
  step is not safely aligned;
* the default-off and zero-length hazards already described in 1b and 1d.

Keep this separate from encryption/decryption and do not rewrite the input. Some
checks need more context than the current unbounded text stream has: type D is a
property of the enabled selection, type B consumes a second line, and target
differences require an explicit firmware family. The first version should state
when it lacks that context rather than infer it.

### 1f. Warn when a code-looking line was passed through unchanged

`parse_code()` deliberately accepts only twelve hex digits and whitespace.
Historical documents commonly decorate records as `$60000000 003F` or
`00xxxxxx-yyyy`; those lines currently pass through as ordinary text, making a
conversion appear successful even though xpcrypt did nothing.

Recognize only narrow, unambiguous code-shaped failures — for example a leading
`$` before exactly twelve hex digits, or twelve hex digits split by the common
hyphen separator — and warn on stderr that the line was not processed. Do not
silently strip punctuation by default: preserving non-code text is an existing
interface guarantee, and automatic normalization could turn documentation into
input. An explicit normalization option can be considered separately if users
need batch import from old FAQs.

### ~~2. `-x/--extract` - dump cheat codes from a ROM~~ - done

Was line 2 of the repo's `TODO`, before that file was removed. The format is
proven across five databases and 15,349 code lines; `db2.py` is the corrected
reference implementation.

```
repeating:  gameName\0, cheatCount,
            per cheat: cheatName\0, lineCount, lineCount * 6 bytes
terminated by FF FF FF FF
```

Implemented with both gotchas fixed (`FINDINGS.md` §4.1): abbreviation bytes 1-7
are valid in game *and* cheat names, and a database starts after erased flash,
which distinguishes the complete chain from valid suffixes inside it. `-x`
accepts a plaintext ROM or encrypted `.fcd`, expands the name abbreviations and
decrypts each cheat independently so Supercode, Megacode and type A payloads end
at the entry boundary the ROM actually stores. `extract_test.py` covers a
synthetic image without ROMs and all five complete chains when they are present.

### 3. Warn before someone bricks a cartridge

`-r` writes ROMs back out. Eight of the nine firmwares compare the cheat-database
header against a hidden copyright string *while decrypting an ordinary code*, and
program 96 KB over their own flash if it does not match (`FINDINGS.md` §5.3b,
`REVERSING.md` §11; `fxprot.py` locates it in any ROM).

Read `*(u32 *)(rom + 0x7C)`, compare the target bytes against the masked string,
warn loudly on mismatch. About 30 lines. Mind that a stock Pro 2.14 image already
mismatches (its header says `1997-9`, its checker `1997/8`; ninth pass), and that the
V2 checker compares 14 characters, not 13. Rank it above 2 if anyone actually
reflashes carts — the downside it prevents is destroyed hardware.

### ~~4. Header guard in `crypt_codes()`~~ — done, `7d15818`

A header that failed to decrypt still started a block and swallowed the following
lines as payload. Fixed; `FINDINGS.md` §6.5 has the detail.

### ~~5. Split `xpcrypt.c` by behavior~~ - done

> **Ninth pass (`AUDIT.md`): done on the `module-split` branch only (`fed8a70`).**
> That branch is not merged into `main` or `research`. Here `xpcrypt.c` is still the
> 873-line monolith beside `xp_crypto.c`/`xp_crypto.h`, the root `Makefile` has no
> `test` target, and there are no C tests. The branch forks from `854c1e1`, before
> the empty-game fix (`7070614`), and its `db.c` still returns −1 on a zero-cheat
> game. Merging it as it stands would bring back the 2.005 regression in `TENTH.md`.

`xpcrypt.c` is now the 165-line composition root for CLI policy and dispatch.
The behavior it formerly combined lives behind the four interfaces proposed in
`MODULE_SPLIT.md`:

* `code_stream.c/h` owns the I/O-free, block-aware row transformer shared by
  text conversion and database extraction;
* `text.c/h` owns the exact stdin/stdout grammar, pass-through behavior and
  code diagnostics;
* `db.c/h` owns locating, validating, decoding and visiting database records
  behind one traversal interface; and
* `rom_file.c/h` owns ROM buffer ownership, extraction presentation, a fresh
  code stream per cheat and transaction-safe file conversion.

`crypto.c/h` stayed intact. The root `make test` target covers stream reset
and payload sequencing, byte-preserving text input, database selection and name
decoding, in-place ROM conversion, destination preservation on input failure,
and extraction through the new interfaces. The firmware oracle, sanitizer,
database extraction and image-cipher suites still pass through the CLI.

### Optional: `--unpack`

COMP01 plus the FX descrambler in C, ~120 lines; `comp01.py` and `fxunp.py` are
the references. Would make xpcrypt open any Xplorer ROM of either generation.
Useless for converting codes, so it turns on whether xpcrypt should be a cheat
tool or a cartridge tool.

---

## Considered and rejected

### A COMP01 packer — feasible, just not needed

The earlier note here said a rebuilt ROM "cannot be produced without the
compressor". **That was wrong.** You do not need FCD's compressor; any stream
their decompressor accepts is valid, and the format is trivial to emit
(`FINDINGS.md` §5.1b).

The real constraint is size. Measured with `packstats.py`:

* **store-only** — every byte a literal, escape bytes doubled — is valid but runs
  +33% over the original packed size on `xteng.dec` (`0x2BFAE` vs `0x210CB`, both
  with the 14-byte header). The blob region ends where the database starts, so it
  does not fit.
* **the LZ opcode alone** accounts for 96-97% of what FCD's compressor saved on
  eight of the nine images, 70% on `english-452.dec`. That measures their matcher,
  not a new one, so it says what the prize is worth and nothing about the effort.

Skip it because **nothing needs a rebuilt ROM** — and anyone who does build one is
a single edited copyright string away from bricking a cartridge (see 3 above).

### Code keys 2 and 3 (`Special32` / `Special33`)

The exact firmware constants are known (`FINDINGS.md` §6.4) and were implemented
once and reverted. Still no: no database uses them, no image here has an encrypt
side to check a round trip against, and `Special32` is one of the two routes that
triggers the self-destruct check on V2 firmware.

### FX flash-region / database tooling

> **Ninth pass: the premise is gone.** The shipped FX databases are in the four FX
> dumps, LZW-packed behind `*(ROM+0x7C)+0xB8` (`FINDINGS.md` §6.3). So `-x` for FX
> is feasible: one container header plus a 14-bit LZW decoder in front of the existing
> record walker. Both Xlink95 builds also read the full 512 KB into `ROMS\BackUp.FCD`
> during an upgrade, so FCD's own tool made full 512 KB dumps.

The FX keeps codes in flash above the firmware, in a region ending at
`0x1F080000`. No dump we have or could find reaches it (`FINDINGS.md` §6.3) —
that covers the four FX images here and everything downloadable we looked at, not
every dump that exists — and the Wayback CDX has six `.fcd` captures of the
vendor's own download page, none of them a full image. Nothing to work against
until someone produces a full 512 KB dump.

### Re-litigating the route table

`XP_KEYED_TYPES = 0xABFB` is confirmed across all nine firmwares, both
generations, three languages. Settled.

---

## Housekeeping

* ~~Version bump and a `README` history entry~~ - done with `-x`. **Not on this
  branch (ninth pass):** `APP_VERSION` is still `"1.1"` and the README history ends
  at v1.1 (2009), as `FINDINGS.md` §6.7 says.
* ~~The `Makefile` passes `-s`, which clang rejects under `-Werror`~~ — done; the
  binary is stripped by `install -s` now (`FINDINGS.md` §1).
* ~~The repo has a plain `TODO` with two lines~~ — removed in `dc66a3b`. Its
  `-x/--extract` entry is recorded here.
* ~~`crypto.h` guards itself with `_XP_CRYPTO_H_`~~ — done; a leading underscore
  followed by a capital is reserved to the implementation, so it is `XP_CRYPTO_H`.
* The root `Makefile` still has no `check` target; see item 1.

---

## Verifying the current state

```sh
make            # everything below, in order, from research/
```

`research/Makefile` drives the suites the notes lean on — not every script here —
and ends in `all suites passed`. Its parts run on their own: `strict` and
`sanitize` for the two C builds, `fuzz` for `-x` against generated malformed
ROMs, `crypto` for the six `oracle_test.py` suites,
`extract` for plaintext/encrypted database extraction, `roundtrip` for `-e K | -d`
over every database code, `firmware` for the nine-way
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
uv run python oracle_test.py ../xpcrypt      # 6 suites, expect "all good"
uv run python extract_test.py                # synthetic plus all available ROMs
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
