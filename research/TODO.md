# What to do with xpcrypt next

Everything the firmware-reversing work suggests for the shipped tool, ranked — plus
the things that were considered and rejected, with the reason, so they do not get
re-derived.

Evidence lives in `FINDINGS.md` (conclusions) and `REVERSING.md` (method and
annotated listings). What the code types *do* is in `ENGINE.md`. Cite section
numbers rather than restating them. The ninth pass of `AUDIT.md` (2026-10-26)
re-derived all of it against the binaries and reshaped this list: it found the FX
databases, the staging normaliser, and a header guard that disagrees with the cart.

Where the code stands. The shipped source is `xpcrypt.c` plus `xp_crypto.c`/
`xp_crypto.h` on `main`, and `research` is `main` plus this directory. Done there:
Supercode/Megacode and type A blocks, the route table, the ROM cipher as a closed
form (1a), and `-x` for V2 images, empty games included. The module split (old item
5) exists only on the unmerged `module-split` branch (`fed8a70`, forked from
`854c1e1`). Its `db.c` predates the empty-game fix (`7070614`), and it renames
`xp_crypto.c`/`.h` to `crypto.c`/`.h`. The version is still 1.1, and the README
history ends in 2009.

Code fixes land on `main`; `research` is rebased onto it afterwards, and its gate
(`make` here) is the regression check for each step until item 1 gives the root one.

---

## Plan for `main`

### 0. Decide the module split first

Everything below touches the database reader, the code stream or the text
diagnostics. Those are exactly the seams `MODULE_SPLIT.md` cut. Doing the work in
the monolith and then re-splitting does it twice, so settle the branch first:

* **Recommended: rebase `fed8a70` onto `main` and merge it.** Port the empty-game
  loop of `7070614` (`db_cursor_next()`'s `do ... while (ncheats == 0)`) into
  `db.c`'s cursor, and drop the `xp_crypto` → `crypto` rename while rebasing. The
  rename buys nothing, and the notes here name `xp_crypto.c`. Gate: `make` here,
  plus the branch's own `tests/`.
* Otherwise delete the branch and mark `MODULE_SPLIT.md` as not pursued.

### 1. A root `make check`

The firmware differential test runs with **no ROMs at all** (1792 + 8200 + 20590 +
60 + 150 + 1080 checks against `romcrypt.py`), but only from this directory, and it
needs `uv`. Give the root a `check` target that needs neither:

* the module-split `tests/` (stream reset, text pass-through, database selection,
  transaction-safe ROM files);
* golden vectors generated once by `romcrypt.py` and committed as a fixture: normal
  codes per key, payload rows per payload key, block row counts and the zero-length
  cases. A C test or a `diff` checks them, and `research/` keeps the generator, so the
  release build stays free of Python;
* `fixture.codes`/`fixture.expect` and the README samples, decrypted and diffed.

Highest leverage of anything here: it turns "verified once" into "stays verified"
for every item below.

### 2. `-x` for FX images

Found in the ninth pass (`FINDINGS.md` 4.1, 6.3); `fxdb.py` is the reference and
oracle. All four FX dumps carry their database, LZW-packed:

* **locate:** `*(u32 *)(rom + 0x7C)` is the support module (`0x9F001500` on FX,
  `0x1F023000`/`0x1F025000` on V2). Its word at `+0xB8` is the database address, and
  the address's low 20 bits are the file offset. Bounds-check both reads;
* **unpack (FX):** an 8-byte little-endian header (packed size, unpacked size),
  then 14-bit codes MSB first:
  * first free code 256, no clear code, end code `0x3FFF`;
  * the dictionary fills inside every shipped stream (`0x90C7` packed bytes is
    about 21,000 codes), so copy `fxdb.py`'s table-full rule exactly; the
    firmware's own decompressor agrees with it byte for byte;
  * require the output to be exactly the declared size and to end in
    `FF FF FF FF`;
* **walk:** the existing record walker, unchanged, over the unpacked buffer.

Tests:

* `extract_test.py` gains the FX figures, with `.fcd`/`.dec` identical:

  | build | cheats | lines |
  |---|---|---|
  | 3.20 | 1922 | 2825 |
  | 4.50 | 2071 | 2957 |
  | 4.52 | 1921 | 2823 |

* `fuzz_test.py` gains malformed containers: lying sizes, codes past the next
  free one, truncation;
* a synthetic FX image built by a small LZW encoder in the test covers the no-ROM
  path.

About 120 lines of C. The FX 3.20 and 4.52 databases carry 112 keyless default-off
rows each, so item 4a matters on FX too.

### 3. Harden the V2 locator

* Use the `+0xB8` pointer first on V2 as well. It names the framed start in all six
  V2 databases, 2.005 included. Keep the erased-flash framing as the fallback and
  as a cross-check.
* `find_database()` no longer enforces "at least one game": a chain made only of
  empty games is accepted, and `-x` exits 0 with no output. `db2.py` rejects it.
  Require at least one non-empty game (`TENTH.md` §3), with an `extract_test.py`
  fixture.

### 4. Make the cartridge's behaviour visible

xpcrypt converts the stored format faithfully. These are the places where a
faithful conversion still hands back something the cart will do differently:

* **a. Default-off bit on a keyless code** (old 1b; `ENGINE.md` §7). Warn when a
  code stored with key nibble 0 has bit 3 set and its type's address is
  dereferenced (0 3 7 8 9 B E F): the engine adds `0x08000000` to the address. This
  affects 120 rows of Pro 2.20, 112 of FX 3.20 and 112 of FX 4.52.
* **b. A block that declares no payload** (old 1d). Every engine hangs on it, all
  ten, executed; German `War Games` ships two.
* **c. A block cut short.** Input, or a cheat, that ends inside a declared payload
  currently passes silently.
* **d. Address bits in the key nibble of a keyless type**, e.g. `31001643` landing
  at `0x01001643`, or 2.0081's `F21EAB7C` becoming an anchor that aborts the list.
  The same warning family as a.

All of them go in the row events `crypt_code()` already produces, printed on stderr.
Under `-x`, give one summary per database rather than per row (Pro 2.20 alone would
print 120).

### 5. The header guard: follow the cart, and warn

`7d15818` starts a block only when the header's key bits are clear after
decryption. The cart does the opposite (`FINDINGS.md` §6.5). Its stagers classify
by the *stored* type nibble before decrypting, and key bits 1-3 take the copy route,
so the cart stages `51123456 6006` as a Supercode with the size as stored.
`oracle_test.py`'s "headers with key bits 1-3" suite counts 114 rows where xpcrypt
and the cart now disagree. No shipped database has such a header.

Recommended: classify like the cart, so that `-d` output is what the cart runs, and
warn that the header's key bits select no cipher. Then flip that suite to assert the
cart's side. The alternative, keeping the guard and only warning, leaves `-d` and
the cart disagreeing about which lines are payload.

### 6. Warn before someone bricks a cartridge (old 3)

`-r` writes ROMs. Before writing a plaintext image, model the check
(`FINDINGS.md` §5.3b, `selfdestruct.py`):

* **V2:** compare all 14 characters of `"(C) 1997/8 FCD"` against the header at
  `*(rom + 0x7C)`;
* **FX:** compare positions 0, 1, 2, 11, 12, 13 of `"(C) 1997-9 FCD  "`;
* **generation:** tell V2 from FX by the module pointer's region (`0x1F…`/`0x9F…`);
* **Pro 2.20:** recognise it by the release string at header `+0x10`; it has no
  check.

On a mismatch, warn loudly that the cart will program 96 KB over itself the first
time a code with one of the trigger first bytes of `FINDINGS.md` §5.3b is activated
(28 on V2, 24 on FX), or, on V2, two Megacodes at once. A stock 2.14
image must trigger the warning, because its own header fails its own check. Test:
the nine images (only 2.14 warns), a patched header, and 2.20. About 40 lines.

### 7. Release 1.2

Bump `APP_VERSION` and write the README history entry deferred since `-x`
(`FINDINGS.md` §6.7). It covers Supercode/Megacode, type A, the closed-form ROM
cipher, `-x` for V2 and FX, and the warnings. Also update the README's `-x` text to
match what it reads.

### 8. An optional runtime-lint mode (old 1e, corrected)

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

### 9. Warn when a code-looking line was passed through unchanged (old 1f)

`parse_code()` deliberately accepts only twelve hex digits and whitespace.
Historical documents commonly decorate records as `$60000000 003F` or
`00xxxxxx-yyyy`; those lines currently pass through as ordinary text, making a
conversion appear successful even though xpcrypt did nothing. Recognise only
narrow, unambiguous code-shaped failures and warn on stderr. Do not strip
punctuation by default: preserving non-code text is an interface guarantee.

### Optional: `--unpack`

COMP01 plus the FX descrambler in C, about 120 lines; `comp01.py` and `fxunp.py` are
the references. With item 2's LZW decoder in place, xpcrypt could open every layer
of either generation. Useless for converting codes, so whether to do it depends on
whether xpcrypt should be a cheat tool or a cartridge tool.

---

## Done

* **1a, the ROM seed tables.** The tables are now the two expressions read out of
  the PC tools (`FCD.md`):
  `dec[i] = (enc[i] ^ (u8)(i ^ ((i >> 1) + 0x45))) + (u8)((i & 0x37) ^ 0x2C)`.
  They equal the old tables as a transform: the two spellings differ by a `^ 0x80`
  and a `+ 0x80` at 256 offsets, which cancel. The 512-byte minimum and the block
  cipher comment are gone.
* **1c, type A payloads.** Every code below a type A header is payload to the end
  of the cheat; covered by an `oracle_test.py` suite.
* **2, `-x/--extract`.** For V2 images, plaintext or `.fcd`, from the erased-flash
  boundary, with abbreviations expanded and a fresh block state per cheat. Since
  `7070614` it skips empty games, which recovers 2.005's database.
* **4, the header guard (`7d15818`).** Done as specified, but the ninth pass found
  it diverges from the cart; see item 5 of the plan.
* **5, the module split.** Done on `module-split` only; see item 0 of the plan.

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
string away from bricking a cartridge (item 6).

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
* ~~`xp_crypto.h` guards itself with `_XP_CRYPTO_H_`~~ — done, `XP_CRYPTO_H`.
* The version bump and README history entry are item 7; the root `check` target is
  item 1.

---

## Verifying the current state

```sh
make            # everything below, in order, from research/
```

`research/Makefile` drives the suites the notes lean on — not every script here —
and ends in `all suites passed`. Its parts run on their own: `strict` and
`sanitize` for the two C builds, `fuzz` for `-x` against generated malformed
ROMs, `crypto` for the seven `oracle_test.py` suites,
`extract` for plaintext/encrypted database extraction, `roundtrip` for `-e K | -d`
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
