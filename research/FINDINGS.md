# What we know about the Xploder PSX code crypto

Everything learned while adding the code types 5 (Supercode) and 6 (Megacode), and
while reading the crypto out of the cartridge firmware afterwards. `REVERSING.md` is
the companion: how the firmware was cracked open, step by step.

xpcrypt has a second, unrelated cipher in it: the whole-image transform between a
`.fcd` file and a plaintext ROM, which `-r` once applied with two brute-forced
512-byte seed tables (replaced by the closed form in `82f50b6`). That one is **not**
in the firmware and never was - it belongs to the PC-side tools, where it is a
loop of about twenty instructions (22 in the DOS tool) and no tables, in four binaries
and both directions, all eight of them executed under an emulator to prove it.
`FCD.md` is that hunt, and it stands apart from everything below.

Lives in `research/` of the xpcrypt repo, kept apart from the shipped source —
none of this belongs in it. Issue: https://github.com/mlafeldt/xpcrypt/issues/1

Nine review passes are in `AUDIT.md`: the first covers this note, `REVERSING.md`,
`TODO.md` and the scripts that existed then; the second, `ENGINE.md` and the engine
tools, and it reaches into the root C source as well; the third and fourth re-read
what the ones before them changed, which is where most of the sharper corrections
came from; the fifth went at the C implementation and the verification rig, and
found four defects in the CLI and one in the MIPS interpreter; the sixth re-audited
the fifth's own fixes and found the gates were still accepting results that were
wrong but well-formed; the eighth validates extraction and the complete database
chains. Those eight have been applied, so read them as the record of what was wrong.
The ninth (2026-10-26) is different: it checks everything against the binaries with
independent tools, overturns §6.3 and the type C/D/E reading of §7, and is applied
here only as marked callouts - its script and source findings are still open. Read
its section first.

Note: the ROM images these scripts work on are cartridge firmware dumps. Keep them out
of the repo — `research/.gitignore` names `roms/` for that reason. The line was missing
at first, and a `git add -A` promptly staged 4 MB of firmware dumps.

> ⚠ **If you ever write a modified image back to a real cartridge, read 5.3b first.**
> Nine of the ten firmwares check the cheat database against a hidden copyright
> string while decrypting an ordinary code, and overwrite 96 KB of their own flash if
> it does not match. Nothing in this repo can trigger it — xpcrypt only ever touches
> files — but a rebuilt ROM with the header edited will. And one needs no edit at
> all: Pro 2.14's check string (`1997/8`) predates its own header (`1997-9`), so on
> a stock 2.14 cart the first key-7 or Special32 code a user activates programs the
> 96 KB. So does activating two Megacodes at once, with neither among them.
> No row of its shipped database takes any of those routes, which is presumably why
> it went out like that. FCD's own DOS X-Link has a key-7 encrypt routine
> (`ENCRYPT.md`), so users could make such codes with the vendor's own tool. 5.3b
> lists every trigger.

The feature is **implemented, committed and validated against real cartridge ROMs**.
This document captures what the shipped source does not: the format knowledge, the
evidence behind each decision, the test rig, and what is still unproven.

---

## 1. State of the work

The feature landed in `17e31fc..HEAD`.
Read `git log -p 17e31fc..HEAD` for the code; the format itself is documented in
`crypto.c` (block comment above `known_payload_key()`) and in `README` (sections
"Supercode/Megacode" and "Inline data blocks"). Do not re-derive from this doc — the
source is authoritative.

Public API added in `crypto.h`: `struct xp_block`, `xp_parse_block()`,
`xp_in_payload()`, `xp_decrypt_block_line()`, `xp_encrypt_block_line()`. The block
state machine is shared by `crypt_codes()` and the ROM extractor through
`crypt_code()` in `xpcrypt.c`.

Three pre-existing bugs were fixed along the way (see the commit messages):
key nibble derivation dropped the default-off bit; unsupported keys mangled `code[0]`;
`-e` silently corrupted codes whose key nibble is occupied.

**Build gotchas (macOS), both fixed:** the `Makefile` used to pass `-s` in `CFLAGS`, so
every compile got a linker flag; gcc ignores it, clang calls it an unused argument and
`-Werror` fails the build. Stripping now happens in `install -s`, where it belongs —
putting `-s` on the link line instead works too, but Apple's `ld` then warns "-s is
obsolete" on every build. The link rule also used `$?` (only the prerequisites newer
than the target) instead of `$^`, so a rebuild of one object linked that object alone
and failed - a no-op build did nothing and touching the header rebuilt both, which is
why it went unnoticed. Fixed while writing the tests.

---

## 2. Format knowledge (the part that took the work)

### Block layout

```
Supercode header  5?aaaaaa Knnn      K = payload key, nnn  = payload bytes (12 bit, >= 1)
Megacode  header  6?aaaaaK nnnn      K = payload key, nnnn = payload bytes (16 bit, >= 0)

rows_type5 = ceil(nnn / 6)
rows_type6 = ceil((nnnn + 10) / 6)      10 = breakpoint descriptor: 6 addr/type + 4 mask
```

`?` is the type-nibble's low half: bit 3 = "switched off by default", bits 0-2 = the
normal code key. The header is an ordinary encrypted code line; the payload rows are
**not** — they are data and must never be re-classified by their first nibble.

Megacode row roles: row 0 = breakpoint descriptor, row 1 = 4-byte mask + first 2 payload
bytes, rows >= 2 = payload. The engine installs the payload at `0x80000040` and rounds
the byte count up to whole words at runtime (irrelevant for crypto — keep whole rows).

### Payload keys

* `0` — payload stored in the clear. **This is the common case in real ROMs.**
* `6`, `7` — the only two ciphers the cartridge implements (see
  `decrypt_payload()`/`encrypt_payload()` in `crypto.c`).
* anything else — **does not exist**: the firmware zeroes bytes 1 to 5 of the row and
  never writes byte 0 at all, so such a block is dead on the cart whatever the caller
  had in that byte (5.2). xpcrypt preserves the rows and warns instead, which is the
  friendlier tool behaviour.

Every row of a payload is treated the same way, whatever its first nibble looks like,
and that includes the breakpoint descriptor of a Megacode.

> **Superseded.** Until the firmware was read, this section claimed that type 5 payload
> rows need an extra byte swap that type 6 rows do not, and that a keyless Megacode has
> two rows encrypted as ordinary code lines (the descriptor, and rows escaped to protect
> a leading `0x08`). All three claims are wrong — the swap is simply part of the key-6
> routine, for both types. That was the bug fixed in `7d15818`; 5.2 and 5.3 have the
> firmware's own version.

### Two claims that were wrong in the source material

1. The docx attached to the issue says the type 5 size field needs `+6`; the type 6
   `+0x12` rule is not in the docx at all but in the older engine in the attached zip
   (`XploderMemoryCryptEngine.hpp:305`). Both are the **loader's internal staged
   count**, which includes the header row. The external size field is the direct payload
   byte count. Disproved on real data (see 4.2).
2. The same docx prints the decrypted payload record *unswapped*
   (`AC080004 0008`). The swapped form (`040008AC 0800`) is what the ROM actually
   stores. Disproved on real data (see 4.3).

The newest version of SkillerCMP's repo is right about both; the zip attached to the
issue is an older engine that still has the `+6`/`+0x12` model. Prefer the repo.

---

## 3. Source material

* https://github.com/SkillerCMP/PSX-Xploder — the reference implementation.
  Only `src/XploderMemoryCryptEngine.hpp` maps onto xpcrypt. `XploderCmpConverter.hpp`
  has the text-level block flow, `XploderCodeTypes.hpp` the semantics,
  **`LegacyDatabaseImport.hpp` the ROM database reader** (used in section 4).
* Issue attachments: `Xploder_PSX_CodeTypes.docx` (their lab notes — runtime branch map,
  the memory-dump method) and `PSX-Xploder.zip` (older engine).
* How *they* reversed it, reconstructed from those: PSX RAM dump with the cart active →
  interpreter at `0x80037B00`, per-type dispatch branches (`…C40` type 5, `…C74` type 6)
  → staged/decrypted code list at `0x8000FF00` gives known plaintext for encrypted
  database codes → payload routines read out of the dump (that is why key 7 exists with
  no samples) → round-trip against a German Xploder ROM database, which surfaced the
  descriptor/escape special cases.

---

## 4. The test rig (this is the reusable part)

Scripts are in this directory. They import each other, so run them from here.
They need decrypted ROM images; regenerate with:

```sh
mkdir -p roms && cd roms            # the scripts expect the images under ./roms/
for f in xplorer-eng-rom xplorer-pro-eng-rom xplorer-fx-eng-rom \
         xplorer-fx-eng-v452-rom xploder-v2-usa-r2.004-1998-11-13; do
    curl -sSLO "https://www.murraymoffatt.com/xplorer/$f.zip" && unzip -o -q "$f.zip"
done

# four more from the vendor's own site, via the Wayback Machine.  Its CDX index
# lists six .fcd captures in all - these four plus xteng and xtepro, which the
# mirror above already has.  The remaining links on that page are not in it.
A=https://web.archive.org/web/20000229200703if_/http://www.x-plorer.co.uk/roms
for f in xtger xtjpro english german; do curl -sSLO "$A/$f.fcd"; done
mv english.fcd english-452.fcd      # this one is a V4.52, not the V3.20 above
mv german.fcd german-450.fcd

for f in xteng xtepro english english-452 german-450 xtger xtjpro; do
    xpcrypt -r $f.fcd $f.dec        # .fcd = encrypted flash image, .rom = decrypted
done                                # xpcrypt -r auto-detects the direction
```

Nine firmwares, and none of the tooling is keyed on a file name — `fwimage.load()`
detects the generation and recovers the load address from the image itself:

| image | release | family |
|---|---|---|
| `xteng.dec` | 2.008 | Xplorer UK |
| `xtger.dec` | 2.0081 | Xplorer German |
| `xtjpro.dec` | 2.14 | Xplorer Pro Japanese |
| `xtepro.dec` | 2.20 | Xplorer Pro UK |
| `Xploder V2 (USA)…rom` | 2.004 | Xploder V2 USA |
| `english.dec` | 3.20 | Xplorer FX |
| `german-450.dec` | 4.50 | Xplorer FX German |
| `english-452.dec` / `v452d.rom` | 4.52 | Xplorer FX |

`make` in this directory runs the suites the notes lean on — not every script in
the inventory below, several of which answered one question and were kept for the
record. The two that matter on their own:

```sh
uv run python oracle_test.py ../xpcrypt   # xpcrypt vs the firmware, six suites
uv run --with capstone python fxtest.py   # all nine firmwares against each other
```

| script | what it is |
|---|---|
| `Makefile` | runs the suites the notes lean on, plus the strict and sanitizer C builds; `make` from `research/`. Serial by design — every C target rebuilds the same objects in the parent. Fails if any suite does, and every suite asserts its published values rather than printing them — check with `make firmware PYCS=false` |
| `fixture.codes` / `fixture.expect` | the sanitizer input and its expected decryption: four ordinary codes, a Supercode, a Megacode and an inline data block, so the run walks the payload state machine and not just the stateless path. Generated once and verified row by row against `romcrypt.py`, not against xpcrypt |
| `romcrypt.py` | hand transcription of the decrypt routine; the model xpcrypt is checked against |
| `oracle_test.py` | xpcrypt vs `romcrypt.py`, generated codes plus every real database, one cheat at a time |
| `roundtrip.py` | `xpcrypt -e K \| xpcrypt -d` over every recovered database code, for all four keys |
| `fwimage.py` | unpacks the firmware out of any of the ten ROMs (V2 or FX) |
| `fxunp.py` | the FX descrambler that sits in front of COMP01 (5.4) |
| `comp01.py` | the COMP01 container both generations use |
| `fwemu.py` | MIPS I interpreter — runs the decrypt routine, and the code engine, straight out of an image |
| `fxtest.py` | executes all nine firmwares over the same codes and diffs the results |
| `fxcmp.py` | static per-route diff of the nine firmwares |
| `packstats.py` | what COMP01 spends its opcodes on; the re-pack budget (5.1b) |
| `escrank.py` | how rare COMP01's four escape bytes are in the stream that chose them (5.1b) |
| `defaultoff.py` | the four default-off counts, with the matching rule behind the fourth (7) |
| `fxprot.py` | the self-bricking copyright check hidden in the decrypt routine (5.3b) |
| `fxdb.py` | where each firmware keeps its codes: the V2 chain, or the FX LZW container, decoded and counted (4.1, 6.3) |
| `engine.py` | finds the in-game code engine in any of the nine ROMs and dumps its type dispatch (7) |
| `engineemu.py` | executes that engine over a synthetic patch list and records what it touches (7) |
| `dbtypes.py` | block-aware survey of the recovered databases: which code types are actually used (7) |
| `fcdcrypt.py` | the *image* cipher — the `.fcd` transform, as the vendor's tool implements it, checked against the xpcrypt binary and every image pair (`FCD.md`) |
| `xlink.py` | LE and PE loaders for the PC-side tools; finds both directions of that cipher in all four of them and executes all eight routines under an emulator (`FCD.md` §5, §5a) |
| `xcode.py` | the *code* cipher in those same four tools, found by executing all 3,920 call-target candidates in them rather than by searching: the vendor's DOS tool holds the encrypt side the cartridge never had, and it agrees with `xpcrypt -e` byte for byte (`ENCRYPT.md`) |
| `mipscan.py` / `fxdis.py` | word-aligned disassembler, constant scanner, range dumper |
| `fwscan.py` | the same two operations over the *unpacked* firmware, so the addresses match the ones the notes quote |
| `db2.py` / `dbscan.py` | ROM database readers (4.1) |
| `extract_test.py` | `xpcrypt -x` against a synthetic plaintext/encrypted ROM and all five complete database chains (4.5) |
| `audit2.py` / `boundary.py` / `xcheck.py` | the row-count and round-trip oracles (4.2, 4.3) — `audit.py` is its superseded first version and says so |
| `fuzz_test.py` | malformed ROMs through `-x` under ASan/UBSan, generated from `extract_test.py`'s fixture |
| `prechain.py` | what lies between the packed firmware and the record chains: pad, erased flash, the support module, and the FX database container |
| `rom2005.py` | the tenth image, release 2.005 from `pc/ROMS/Xteng.fcd`, placed against the corpus (`TENTH.md`) |
| `payloads.py` | the shipped Supercode/Megacode/type-A payloads disassembled, and the ten that ship corrupt |
| `selfdestruct.py` | the copyright check of 5.3b executed, under a model of the flash part |
| `plugin.py` | the `FCDEXE1138` memory-card upgrade loader, per image (`PLUGIN.md`) |
| `comms.py` | the X-Link parallel-port protocol, PC and cartridge ends |
| `typecx.py` | what types 2 and C are, across the databases, the firmware and `XLink.exe` (`ENGINE.md` §16) |

### 4.1 ROM database layout

Repeating `gameName\0`, `cheatCount`, then per cheat `cheatName\0`, `lineCount`,
`lineCount * 6` bytes of code. Terminated by `FF FF FF FF`; the complete chain
begins after an erased run of `FF` bytes.

**Gotcha that cost time twice:** bytes 1 through 7 are abbreviations in *both*
game and cheat names (`Infinite`, `Unlimited`, ` Lives`, `Player`, ` Energy`,
` Time`, `Money`). Requiring printable names rejected three databases. The
first repair allowed them in cheat names only, so `db2.py` still resynchronized
partway through a name - inside `"Duke Nukem:\x06 To Kill"`, at `0x27F69` in the UK
image and `0x2C8EC` in the USA one - and parsed a valid suffix from there. Requiring the erased-flash
boundary and accepting the seven bytes in either name recovers the real start.
High bytes are retained for the Japanese database's Shift-JIS names; `0x7F` and
`0xFF` are not accepted as name bytes.

| image | database at | games / cheats / code lines |
|---|---|---|
| `xteng.dec` (Xplorer V2.008 UK) | `0x25000` | 285 / 2130 / 3060 |
| `xtepro.dec` (Xplorer Pro V2.20 UK) | `0x2b000` | 285 / 2134 / 3082 |
| `Xploder V2 (USA) r2.004…rom` | `0x25000` | 250 / 4048 / 4905 |
| `xtger.dec` (Xplorer German 2.0081) | `0x25000` | 240 / 1787 / 2476 |
| `xtjpro.dec` (Xplorer Pro Japanese 2.14) | `0x2b000` | 61 / 1619 / 1826 |
| `pc/ROMS/Xteng.fcd` (Xplorer V2.005 UK, `TENTH.md`) | `0x25000` | 233 / 1668 / 2365 |
| `english.dec` (FX V3.20) | `0x44400`, LZW-packed (6.3) | 264 / 1922 / 2825 |
| `german-450.dec` (FX V4.50) | `0x41200`, LZW-packed | 264 / 2071 / 2957 |
| `english-452.dec` / `v452d.rom` (FX V4.52) | `0x4FA00` / `0x40300`, LZW-packed | 263 / 1921 / 2823 |

The V2 chains are found by their framing alone, but the firmware also points at
them: `*(u32 *)(ROM + 0x7C)` is the support module, and its slot at `+0xB8` holds
the database address in all ten images. On FX that address is a container (6.3),
not a chain.

"Games" counts distinct names. The USA chain has 252 game records, because `Bio
Freaks` and `Casper` each appear twice, and `-x` prints all 252. 2.005 has 234
records, one of them the empty `Moto Racer 2`. The FX chains hold 265 (3.20), 269
(4.50) and 264 (4.52) records. Five of the German ones are deliberate zero-cheat
legend entries (`"Abkuerzungen"`, `"ENG = Energie"`, …). A cheat may declare zero lines too, and the USA chain has 249
such cheats.

The correction adds 1,633 cheats and 2,144 code lines: 679 lines from the UK
prefix and 1,465 from the USA prefix. Across the five original V2 images the
complete chains hold 1,121 distinct games (1,123 records), 11,718 cheats and
15,349 code lines; every count and gate below is over those five unless it says
otherwise.

### 4.2 Row-count oracle

Each cheat entry declares its own line count, so a block must fit inside it. Run
`audit2.py` for all five databases at once, or `audit2.py <rom>` for one with the
per-block listing:

* direct formula: **44/44 blocks fit** across the first three databases (21 + 21 + 2);
  the majority end exactly on the entry's last line, the rest are followed by a clean
  code (`boundary.py` prints those — e.g. `90007690 0018`, `80060818 000A`).
* old `+6`/`+0x12`: overruns the entry in most cases (fits 6/21, 6/21, 1/2).
* the German database adds 9 more, of which 8 fit. The ninth,
  `Metal Gear Solid - Jp / Verliere Chaff` in `xtger.dec`, declares 0xD7DD payload
  bytes at the very end of its entry with nothing following — a corrupt record,
  not a formula error. `audit2.py` expects exactly that one and fails on any other.

### 4.3 Payload-cipher oracle (the good one)

The *same cheats* appear in `xteng.dec` encrypted with payload key 6 and in
`xtepro.dec` stored in the clear. `xcheck.py` decrypts the former and compares:

```
blocks cross-checked: 16   swapped matches: 16   unswapped matches: 0
```

Including a 176-byte / 30-row payload. Example (Puzzle Bobble 4 / Bust-A-Move 3DX):

```
xteng  (key 6)  34FB3457 235D
chunk decrypt   AC080004 0008     <- what the docx calls "active payload bytes"
+ swap          040008AC 0800
xtepro (clear)  040008AC 0800     <- what the ROM stores
```

Nice sanity check: Rayman "FCD Pause" decrypts to `7475662F 7275` = "tuf/ru", which only
becomes `/futur` after the swap. The block is the string `/future/console/design/`.

### 4.4 Specimens kept here

* `ray.txt` — Rayman "Rayman can fly", a complete 14-line **keyless Megacode**:
  header `60000000 003F`, descriptor `801FAB92 EA80`, mask `FFFFFFFF` + inline `F4FF`,
  MIPS body, escaped row `08004003 0C00`, `size 0x3F -> 13 rows` exactly.
* `pb.enc` / `pb.clear` — the 0xB0-byte Supercode, key 6 vs. clear. `xpcrypt < pb.enc`
  must reproduce `pb.clear` from line 2 on (the header differs by the retained key
  nibble: `60B0` vs `00B0`).
* `br.txt` — Bloody Roar, a 10-line keyless Megacode whose descriptor row `1F800198
  EA80` has key bits set. The regression case for "row 0 is payload, not a code".
* Also useful: `31001643 500F` (Xploder USA, *Spider / Poison (On Pickup)*) — the code
  that has no room for a key.

### 4.5 Regression checks worth keeping

`oracle_test.py` now runs most of this automatically, using `romcrypt.py` (the
firmware transcription, see section 5) as the oracle: normal codes, the encrypt
side checked by having the firmware read back what xpcrypt writes, block payloads
and row counts, and - if `roms/` is populated - every code of the five databases
(15,349 lines in 11,718 cheats). It needs no ROM to be useful and asserts the two by-design
divergences instead of ignoring them.

The database suite runs **one cheat entry per xpcrypt invocation**, because a cheat
entry is where the cartridge starts reading. Feeding a whole database as one stream
looks equivalent and is not: in `xtger.dec` a one-line cheat decrypts to something that
reads as a type 6 header declaring 9212 rows, which swallows the remaining 1266 lines
into a payload that is never checked as ordinary code. Two cheats found that way are
worth keeping in mind - `War Games` has Supercode headers of size 0, which start no
block at all.

```sh
cd research && uv run python oracle_test.py [path/to/xpcrypt]
```

`extract_test.py` adds a synthetic database with normal, Supercode and type A
entries, checks plaintext and encrypted-ROM input, then widens to all five real
databases when `roms/` is present. `make -C research extract` runs it. The checks
below are the ones `oracle_test.py` does not cover.

* `55A936CF 2E49` decrypts to `50007800 607C` (the docx's confirmed header).
* `0E569755 5D5A` <-> `08004003 0C00` with key 6 (documented escape row).
* `xpcrypt -e K | xpcrypt` reproduces the input for K = 4,5,6,7 on all five
  databases - 15,349 code lines, 0 not reproduced (`roundtrip.py`). The three
  images used by the first differential comparison now contribute 11,047 lines;
  the old suffix-only scan saw 8,903. One cheat entry at a time wherever a block is
  involved, because a header at the end of a cheat would otherwise take the next
  cheat's codes as its payload.
* `SAMPLE` in the repo round-trips (ignore its CRLF line endings).
* Compare against the pre-feature binary by building `git archive 17e31fc` in a temp
  dir; it differs on 281 / 263 / 350 lines of the three complete databases (239 / 263 /
  97 was the suffix-only count; ninth pass).

---

## 5. The firmware, disassembled

The crypto was located in the cartridge firmware and read instruction by instruction.
This section supersedes every guess above it; `romcrypt.py` here is a faithful Python
port of the routine and reproduces the 30 payload rows of `pb.clear` exactly.

### 5.1 Getting at the code

The ROM body is packed. `comp01.py` unpacks it:

```sh
python3 comp01.py roms/xteng.dec 0x580 > xteng.unp     # 179992 bytes, loads at 0x801A0000
uv run --with capstone python3 mipscan.py xteng.unp 0xffab,0x1,0x2 40 0x801A0000
```

The loader stub sits unpacked at `0x1F0001DC..0x1F00055C`. Format: `"COMP01"`, four
escape bytes, 4-byte big-endian output size; the first ten header bytes are XORed with
the credit string at `0x1F000560` (`"Wayne Hugh"`), so only the escape bytes are really
masked. Escapes: `[c][b]` RLE8, `[c][b1][b2]` RLE16, `[c][step][start]` arithmetic run,
`[c][dist_lo][dist_hi]` LZ back-reference, and `esc 00` for a literal escape byte.
Nested COMP01 blocks hold the resources.

The FX ROMs use the very same container, one scrambling pass further in — see 5.4. An
earlier note here called it a different format ("LZ"); that was wrong, and it is why the
FX firmware went unread for a session.

`fwimage.load()` hides the difference: give it any of the nine ROMs and it hands back
the unpacked firmware plus the base address its jump table is written against.

**`mipscan.py` decodes one word at a time** rather than linear-sweeping with capstone's
`skipdata`. An earlier note here blamed `skipdata` for resyncing on byte boundaries; it
does not — capstone 5.0.7 skips four bytes at a time on MIPS. Word-at-a-time decoding is
still the right call, because it keeps the undecodable words visible as data and does not
rest on a per-architecture constant inside capstone, but the alignment argument was wrong.

### 5.1b COMP01 looks hand-rolled

It matches no standard algorithm we could identify, and four things point at a format
written for this firmware rather than taken off a shelf. `packstats.py` measures the
last one; the first three are structural readings, and none of them is a document from
FCD saying so:

1. **No entropy coding of any kind.** No Huffman, no arithmetic or range coder. The
   three contemporary formats we read do have one: DEFLATE
   ([RFC 1951](https://www.rfc-editor.org/rfc/rfc1951.html)), the LHA/LZH methods in
   [`jca02266/lha`](https://github.com/jca02266/lha), and Microsoft's LZXD as documented
   in [MS-PATCH](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/687e0350-b236-4b80-8b43-2c85c5bf078d)
   — that last is the Cabinet-family LZX, not the unrelated Amiga archiver of the same
   name, which has no public original specification we could read. The ratio is ~0.75,
   which is what plain LZ77 gets on mixed code and data.
2. **The four escape bytes are chosen per stream, from the data.** `xteng.dec` uses
   `9D 8B 99 DB`, the USA ROM `7B D1 F3 F2`, `english.dec` `EB EF FB FD`, and they are
   the rare bytes of the stream they escape: in all nine images the first escape is the
   *rarest* byte of the unpacked output, and all four sit among the 14 rarest of 256
   (`escrank.py`). That the encoder arrived at them by counting byte frequencies is the
   obvious reading of that, but it is a reading — the decoder only reads the four out of
   the header, and no encoder survives to check. The contrast with the three formats
   above is in the *grammar*, not in the tags: what a token means is fixed by the format
   in all three, and none of them picks four byte values per stream to act as opcode
   sentinels. Their token *codes* are not fixed — DEFLATE can carry a per-block Huffman
   codebook (RFC 1951 §3.2.3-3.2.7), LHA/LZH has adaptive and per-block Huffman methods,
   and LZXD Huffman-codes its literal/match tokens — so "a fixed tag byte or bit flags",
   which this note used to say, was the wrong contrast to draw.
3. **The arithmetic-run opcode** (`[count][step][start]`, emit `start`, `start+step`, …)
   has no counterpart in DEFLATE, in the LHA/LZH methods we read, or in LZXD: none of
   the three has an opcode that emits `start + n*step`. That is a statement about those
   three, not a survey of every compressor of the era. That
   it was *aimed* at the pointer and index tables this firmware is full of is a guess
   about intent and follows from neither the decoder nor the corpus. What the corpus
   shows is that it fires 9-14 times per image and saves 58-73 bytes.
4. **Two of the four opcodes barely pay for themselves.** Across all nine images
   `rle16` fires 4-19 times and `arith-run` 9-14, saving 56-108 and 58-73 bytes
   respectively, against a total saving of 23 KB to 86 KB per image. That is the whole
   of the evidence here. How the format came to be — designed on intuition, never
   profiled, written in-house rather than licensed — is a guess laid over it. The
   numbers show two opcodes this data barely exercises; they do not show who wrote
   them or why.

```
xteng.dec       escapes 9D 8B 99 DB   0x210CB -> 0x2BF18  ratio 0.75
   literal          102736 uses        +0 bytes
   lz-match           7883 uses    +43583 bytes
   rle8                251 uses     +1063 bytes
   rle16                 4 uses       +56 bytes
   arith-run            12 uses       +70 bytes
   literal-escape      136 uses      -136 bytes
```

**Re-packing is feasible** — worth knowing, because the earlier claim that a rebuilt ROM
was impossible without FCD's compressor was wrong. Any stream their decompressor accepts
is valid, so an encoder need not match theirs. The constraint is size:

* **store-only** (every byte a literal, escape bytes doubled) is valid but +33% over the
  original packed size on `xteng.dec` — `0x2BFC8` against `0x210CB`, both counted with
  the 14-byte header (ninth pass: `0x2BFAE` counted the stream's 136 escape tokens, not
  the image's 162 escape-byte occurrences) — and the blob region ends where the
  database begins, so it does not fit;
* **the LZ opcode alone** accounts for 96-97% of everything FCD's compressor saved on
  eight of the nine images (70% on `english-452.dec`). Ninth pass: not because that data
  is less compressible. It compresses exactly like `v452d.rom`'s (zlib 0.563 vs 0.562),
  but FCD's encoder emitted 3,373 LZ tokens for it against 16,240.

That last number is what *their* matcher found, not what a new one would find, so it
bounds the prize rather than the effort: a greedy matcher is the obvious way to go after
it, but nothing here measures how close one would land or how long it would take.
`TODO.md` explains why it is not worth doing either way.

### 5.2 The routine

One function, `0x001ABF94` in `xteng.dec` (`0x001AD85C` in xtepro, `0x001ABA78` in the
USA ROM - all five V2 ROMs are identical here; V2 addresses here are the `0x001Axxxx`
form every absolute pointer in those images uses, although the loader enters through
`0x801A0008`), `decrypt(src, dst, key)` with `key = -1`
for a normal code and the payload key for a Supercode/Megacode row. **No image here
contains an encrypt routine** - a scan of all nine for the shapes of the four ciphers
finds only the decrypt sites. The cart only ever decrypts, which is all a cart needs to
do; that FCD's authoring tools are where the encrypt side lived is the obvious reading,
not something these images prove.

Normal codes dispatch through a 244-entry jump table indexed by `(src[0] & 0xF7) - 4`,
i.e. the default-off bit is masked out before routing. Constants live in a table at
`+0x18` before it: `" WB123"`, `"WHBX"`, `"FCD!"` - the key-5 addends and the initial
sliding windows of the key-4 and key-7 chains.

| first byte `& 0xF7` | route |
|---|---|
| `x4` for x in 0,1,3,4,5,6,7,8,9,B,D,F | key 4 |
| same 12 for `x5`, `x6`, `x7` | key 5 / 6 / 7 |
| `32`, `82` | `dst[1] += 'F'; dst[2] += 'C'; dst[3] += 'D'` |
| `33`, `83` | complement `dst[1..3]` |
| everything else (192 values) | copy verbatim |

Keys 4-7 end with `dst[0] = src[0] & 0xF0`. Payload rows: key 0 copies, key 6 is the
six-equation form, key 7 reverses the byte order and subtracts `0x55`, **every other key
returns zeros in bytes 1 to 5 and leaves byte 0 as the caller had it** - so keys 1-5 and
8-15 do not exist, they are dead codes. (The routine clears only `dst[1..5]` on entry;
Special32 and Special33 never write `dst[0]` either. Prefill the destination with `0xAA`
and the firmware answers `AA0000000000` for an unknown payload key and `AA474547 0405`
for `32010203 0405` - `fxtest.py` runs every case that way.)

Block handling (`0x001ACC74`, which is both the list walker and the Megacode stager,
and the Supercode stager at `0x001AD010`) confirms the layout:
type 5 rows `= (nnn + 5) / 6` with the key from `hdr[4] >> 4`; type 6 rows `= 2 +
ceil((nnnn - 2) / 6)` with the key from `hdr[3] & 0x0F`, the descriptor reversed into the
engine control block at `+0x782`, the payload rounded up to whole words. Both stagers
decrypt **every** row with the payload key and copy the result in order.
(Footnote: the list walker computes `((hi & 0xF) << 8) | (lo + 5)` - an `or` where the
stager uses `add`, so it miscounts rows when `lo >= 0xFB` and `hi` is **odd**. An even
`hi`, zero included, leaves nothing for the carry to collide with and the two agree.
See `ENGINE.md` §7.)

### 5.3 Differences to xpcrypt (as first measured)

Measured over 8903 real codes when the ROM was first read: 199 lines decrypted
differently. Items 2-5 have since been fixed, leaving only item 1.

1. **178 lines - default-off bit.** Firmware `& 0xF0`, xpcrypt `^= key`. Deliberate:
   the tool has to round-trip. Not a bug, and the only difference that remains.
2. **20 lines - route gaps.** High nibbles `2, A, C, E` get no crypto route from the
   jump table - their entries copy;
   the firmware copies them. All 20 are `CD`/`C6` lines used as comment rows
   (`"***** ISLAND STRIKE *****"`) plus Wipeout's `C6671C0E 505A`. xpcrypt used to
   decrypt them into garbage; it now follows the table and refuses to encrypt
   those types. `XP_KEYED_TYPES` in `crypto.c` is *not* that table - it is
   what remains of it once the redundant parts are taken out. Of the 244
   entries, 120 are unreachable (the index masks bit 3 away, so no index with
   that bit set is ever formed), 48 select a key that `code[0] & 0x07` already
   gives us, 4 are the fcd/not routes we do not implement, and the rest are
   copy. What is left is which of the 16 type nibbles are keyed: 16 bits. **SkillerCMP's route table is a literal transcription of
   this jump table and is correct**; an earlier note in this file claimed otherwise
   on the strength of the Wipeout pair - that was wrong.
3. **1 line - Megacode descriptor.** The firmware decrypts row 0 with the *payload*
   key like any other row; xpcrypt decrypts it as a normal code. Bloody Roar /
   *Infinite Energy Player 1* stores `1F800198 EA80` (the break address `0x1F800198`,
   which also appears as `lui $k0,0x1F80 / ori $k0,0x0198` inside the payload) and
   xpcrypt turns it into `1812FD87 F84B`. Same applies to the `0x08` escape rule for
   rows >= 2: no basis in the firmware. Both rules are inherited from SkillerCMP.
4. **Type 6 with payload key 6/7** (no sample exists): the firmware uses the *same*
   routine for both block types, so the byte permutation that xpcrypt applies through
   `swap_payload()` (since removed) for type 5 belongs to type 6 as well.
5. **Payload key 7** (no sample exists): firmware subtracts `0x55`, xpcrypt subtracts
   `0xAB`, and xpcrypt additionally swaps for type 5. Both inherited from the reference,
   which marks the route "forced" - it was never observed either.

Everything else matches exactly. Keys 4, 5, 6, 7 were verified algebraically against
the MIPS, including the folded forms: `x | 0xEE == (x & 0x11) + 0xEE` and
`(x ^ 0xEF) + k == 0x7F - (x ^ 0x90) + k`.

### 5.3b The other call: a self-bricking copyright check

The decrypt routine calls exactly two functions in every firmware. One is `strncpy`.
The other — `f(0x1F000000, 0x18000)` — was written off as inert while the FX work was
going on. It is not. Run `fxprot.py`.

```c
/* V2, 0x1A4620 in xteng.dec */
sig = *(u32 *)(ROM + 0x7C);                  /* -> 0x1F023000, the database header */
for (i = 0; i < strlen(masked) - 1; i++)     /* all 14: this strlen counts the NUL */
    if ((~masked[i] & 0xFF) != sig[i])
        flash_write(0x3E8, 0x1F000000, 0x18000);   /* on the *first* mismatch */
```

**It does not run on every decrypt.** V2 wires it into two routes, FX into one,
which is presumably the point — a check that fired on every code would be trivial to
notice and to correlate with the punishment:

| firmware | fires while decrypting |
|---|---|
| Xploder V2 2.004, Xplorer 2.008 / 2.0081 / 2.14 | a **key-7** code, or a **Special32** code (`32`/`82`) |
| Xplorer FX 3.20 / 4.50 / 4.52 | a **key-4** code |
| Xplorer Pro 2.20 | never |

Never on the payload path of a Supercode/Megacode, never on an unencrypted code, and
never on the copy route for a type the cart does not encrypt.

By first byte, measured by decrypting all 256 in every image (`selfdestruct.py`
asserts the lists): bit 3, the default-off flag, does not matter, and key 7 on
types 2, A, C and E takes no route, so V2 has 28 trigger bytes and FX 24:

```
V2  07 0F 17 1F 37 3F 47 4F 57 5F 67 6F 77 7F 87 8F 97 9F B7 BF D7 DF F7 FF
    32 3A 82 8A
FX  04 0C 14 1C 34 3C 44 4C 54 5C 64 6C 74 7C 84 8C 94 9C B4 BC D4 DC F4 FC
```

On V2 staging reaches it too, with no trigger code selected. Two Megacodes in one
selection make pass 3 hoist the second one's mask row as a type F anchor, and the
shipped specimen's mask, `FFFFFFFC`, decrypts down the key-7 route on the way
(`ENGINE.md` §13). Executed in all six V2 builds: the checker is called twice with
`(0x1F000000, 0x18000)` (on 2.20 the callee is empty). One Megacode does not call
it. On FX that row takes key 7, which is not FX's trigger.

The string is `"(C) 1997/8 FCD"`, stored **bitwise NOTed** so `strings` never shows it.
(The firmware also carries a plaintext banner - `"(C) 1998 Future Console Design
Ltd."` in most V2 builds, `1998/9` in Pro 2.20, `1997-99` on FX - which is what the
menu prints, not what the checker reads.)

`flash_write(src, dst, len)` is the cart's own flash programmer — the same routine that
saves settings elsewhere as `flash_write(buf, 0x1F022600, 0x10)`. JEDEC unlock (`0xAA`
to `0x5555`, `0x55` to `0x2AAA`, then `0xA0`), a page at a time, skipping bytes that
already match. Aimed at `0x1F000000` for `0x18000` bytes it programs 96 KB over the boot
stub and the packed firmware, sourced from `0x3E8` — PSX kernel RAM, not a staged image.
**Strip FCD's copyright from the code database and the cartridge destroys itself.**

The FX builds do the same thing and work harder to hide it:

* the masked string (`"(C) 1997-9 FCD  "`, XOR `0xEB`) is staged onto the stack with
  `lwl`/`lwr` together with a function pointer, rather than read in place;
* only six characters are compared — positions `0, 1, 2, 12, 11, 13`, i.e. `"(C)"` and
  `"FCD"` — driven by an index list stored after the string and walked out of order, so
  no contiguous compare loop appears anywhere. Mismatches are *counted* and the
  punishment comes after the whole list, rather than on the first one;
* the punisher is reached indirectly, through the staged pointer plus `0x66`, so the
  call site cross-references nothing. It lands on `0x8001EE24`, which masks its
  destination with `0x7FF80` and programs the same `0x18000` bytes from the same `0x3E8`.

| firmware | checker | string |
|---|---|---|
| Xploder V2 2.004, Xplorer 2.005 / 2.008 / 2.0081 / 2.14 | live | NOT, all 14 chars (2.14: its own header fails it, see the ⚠ note at the top) |
| **Xplorer Pro 2.20** | **`jr $ra; nop`** | **absent from the image** |
| Xplorer FX 3.20 / 4.50 / 4.52 | live | XOR `0xEB`, 6 chars by index |

Pro 2.20 is the odd one out: the callee is empty *and* the masked string is not in the
image at all, so the check was removed from that build rather than merely disabled — and
it is back in every later one. Why is unknown; a self-destruct that fires on a false
positive is an expensive support incident, which would be a reason to pull it and a
reason to make the FX version check six characters instead of thirteen.

This is also the answer to "did they hide the FX code storage at `0x1F07FFF8` to be
clever?" — no. When FCD wanted protection they wrote this. The flash layout is just an
allocator.

### 5.4 The Xplorer FX firmware — same crypto, exactly

The FX ROMs (V3.20 `english.dec`, V4.52 `v452d.rom`) hide their firmware behind one
extra pass. The boot stub is plain MIPS at ROM `0x100` and gives the whole thing away:

```
9F000158  lui $a0,0x9f01 ; addiu $a0,-0x2d30    src  = 0x9F00D2D0
9F000164  lui $a1,0x8001                        dst  = 0x80010000
9F000168  lui $a2,0x9f04 ; addiu $a2,0x4378     end  = 0x9F044378
9F000170  jal 0x9F00C0E0                        descramble
9F000178  lui $v0,0x8001 ; jalr $v0             and run it
```

`0x9F00C0E0` skips four bytes and walks the blob a byte at a time (`fxunp.descramble`):

```
out[i]      = rol8(src[i] ^ key_i, (8 - (state_i & 7)) & 7)
key_{i+1}   = key_i + 5                 only the low 8 bits ever matter
state_{i+1} = (state_i ^ key_{i+1}) + 1
```

from `key = 0x99`, `state = 6`. Out falls a plain `COMP01` stream — masked with the same
`"Wayne Hughes Beckett!"` at `0x9F000544`, unpacked by the same escape machinery at
`0x9F00028C`, loaded at `0x80010000`.

Inside, everything is where 5.2 says it is: `" WB123"`, `"WHBX"`, `"FCD!"` byte for byte
identical, the 244-entry jump table right behind them, the dispatcher indexing it with
`(src[0] & 0xF7) - 4` under the same unsigned `0xF4` bound. Same constants throughout —
`0x38/0x12/0xEE`, `-0x55 ^ i`, `0x76/0xEF/0x73` — same `dst[0] = src[0] & 0xF0` tail,
same `+'F'/+'C'/+'D'` and `~` special routes, same six payload-key-6 equations.

**`XP_KEYED_TYPES` is `0xABFB` in all nine firmwares** — five V2 (2.004 … 2.20, three
languages) and four FX (3.20, 4.50, 4.52 twice). The same four nibbles — 2, A, C, E —
have no route in either generation. Adopting the route table (`318d776`) was therefore
right for both families, not just the one we could check; the caveat recorded when it
was adopted is withdrawn.

`fxcmp.py` shows the static picture and `fxtest.py` the behavioural one. All five V2
firmwares give the same normalized instruction sequence — the routines and their tables
are relocated per build, so `fxcmp.py` drops absolute addresses before comparing and the
raw operands do differ; the FX routes *are* scheduled
differently — the shared tail is a `j` away (V2 also jumps to it from keys 4 and 5
and inlines it only in key 7), and the
one call the routine makes sits at the top rather than the bottom — so a static diff
flags four routes. It changes nothing:

```
$ uv run --with capstone python fxtest.py
   1536 codes x 17 key settings
   romcrypt.py (the model) 0 disagreement(s)
   english-452 (4.52)      0 disagreement(s) vs Xploder V2 USA (2.004)
   english (3.20)          0 disagreement(s) vs Xploder V2 USA (2.004)
   german-450 (4.50)       0 disagreement(s) vs Xploder V2 USA (2.004)
   ... and the rest
all 9 firmwares agree
```

That is not a re-reading — `fwemu.py` is a small MIPS I interpreter that *executes* the
routine out of each image, so the comparison is of behaviour, not of my transcription.
It also decrypts the known-plaintext Bust-A-Move 3DX Supercode (`pb.enc`, once misnamed
"Punky Bear") 30/30 on all nine, which is
what proves the FX descrambler and unpacker right end to end.

Two calls are stubbed. One is `strncpy` loading a 4-byte constant table (V2 reaches BIOS
`A(0x1A)`, FX has its own copy - `0x80012AA8` in 3.20, `0x80012B28` in 4.50 and
4.52). The other is the copyright check of
5.3b — it takes no pointer to either buffer, the ABI preserves `$s0`/`$s1`, and the
known-plaintext check confirms it cannot touch a decrypted code, so stubbing it is safe
for this purpose. It is emphatically *not* inert on real hardware. Every one of the nine
firmwares calls exactly two functions, one of each kind; `fxtest.py` prints both
addresses per firmware so the assumption stays visible rather than buried.

### 5.5 The author's name, and where it stops being vanity

Wayne Hughes Beckett wrote the original firmware, and his name or initials occur **59
times across the nine images** — but three of the seven occurrences per image are
load-bearing, so this is not only signature-in-the-corner:

```
                                                            V2   FX
boot stub, ROM 0x544-0x5A8    "Wayne Hughes Beckett!"         1    1
stub header, two copies       "FCD = WHB PJH DN MW IN R?"     2    2
constant table (5.2)          "WHBX"    key-4 window          1    1
                              " WB123"  key-5 addends         1    1
firmware credit               "Wayne Hughes Beckett!"         1    -
                              "WHB & PJH"                     1    -
                              "Original Version by
                               Wayne H Beckett"               -    1
                                                  per image   7    6

                              5 V2 x 7  +  4 FX x 6  =  59
```

The three that carry weight:

* the COMP01 header is XORed with the first ten bytes of the stub credit, `"Wayne Hugh"`
  (5.1) — no image unpacks without it;
* the key-4 sliding window starts as `"WHBX"` and key 5 adds the characters of
  `" WB123"` (5.2) — decrypting an ordinary code means adding up his initials.

Not to be confused with the string the self-destruct compares (5.3b): that one is
`"(C) 1997/8 FCD"` / `"(C) 1997-9 FCD  "`, the company rather than the person.

The credits differ by generation. V2 stores `"Wayne Hughes Beckett!"` followed by
`" .. Paul :)"` — surname and exclamation mark for one author, a smiley for the other —
plus a separate `"WHB & PJH"`. FX splits it properly: *Original Version by Wayne H
Beckett*, *Version 2 and Version 3 by Paul J Herbert*. The header list
`"FCD = WHB PJH DN MW IN R?"` (FX: `"WHB *PJH DN MW IN RM SM"`) names six or seven
people and puts WHB first in all nine.

```sh
uv run --with capstone python - <<'EOF'
import pathlib, fwimage
for f in sorted(pathlib.Path('roms').glob('*')):
    if f.suffix == '.fcd':
        continue
    raw = f.read_bytes()                       # stub only: the rest is packed
    img, _ = fwimage.load(str(f))              # and would double-count
    print(f.name, sum(raw[:0x1000].count(p) for p in (b'Wayne', b'WHB '))
                + sum(img.count(p) for p in (b'Wayne', b'WHB ', b'WHBX', b' WB123')))
EOF
```

This is a count of byte strings and nothing more. It shows the name is in the binary and
in the cipher; it says nothing about why it is there. A four-byte window has to be seeded
with something, and initials are as good as any other four bytes.

---

## 6. Still unproven / open

0. **The self-destruct of 5.3b has been executed, but only under emulation.**
   `selfdestruct.py` runs each image's real decrypt routine with the checker live and
   the flash modelled. The ninth pass repeated that independently, with the flash as
   plain RAM: a mismatching header programs cart `0x0-0x17FFF` from `0x3E8` in all nine
   live images, and Pro 2.14 does it from a stock header (the ⚠ note at the top). No
   cartridge has been watched destroying itself and none should be.

   Not recoverable by re-flashing over the damage. The flash parts the firmware
   identifies write a page at a time, and each page write erases the page first. So the
   96 KB are replaced, boot stub included, not merely dirtied. An earlier note here
   assumed programming only clears bits, which holds only for the byte-programmed
   "type 3" part that 4.50 alone also accepts.

   No accepted part is known to be safe. `selfdestruct.py` reports that on chip
   type 2 (manufacturer `0xDA`) nothing reaches the array, but that is its model
   talking. The V2 programmer sends `0x90` instead of `0xA0` for that type (`0x1A41A8`
   in 2.14), and the model only knows `0x90` as autoselect. The same routine is the
   cart's only programmer: in 2.14 it also writes the patch list (`0x900` bytes to
   `0x1F024600`) each time cheats are activated, and the cheat database at
   `0x1F02B000`. A type-2 part that did not program on `0x90` would never run a cheat.

   What gets written is not all kernel RAM either. `0x3E8-0xFFFF` is; on FX,
   `0x10000` onwards is the running firmware itself. Still open: why Pro 2.20 shipped
   without the check while every later build has it. **Anyone experimenting with a real
   cart should assume it is one-way.**
1. **Payload key 7 and type 6 with payload key 6/7 still have no real-world sample.**
   The firmware now settles what the hardware *does* (5.2, 5.3) — but nothing confirms
   that any database in the wild uses them.
2. ~~Payload keys other than 0/6/7~~ — **settled: they do not exist.** For keys 1-5 and
   8-15 the firmware zeroes bytes 1 to 5 of the row and writes nothing to byte 0, so
   such a block is dead on the cart. xpcrypt preserves the rows and warns, which is the
   friendlier tool behaviour.
3. ~~**FX databases** (V3.20, V4.52) not located~~ — **found: they are in the dumps,
   LZW-packed.** Until the ninth pass (`AUDIT.md`) this item said the opposite - "not
   in these dumps, a dumping problem" - and the misreading is recorded below because
   the same trap is easy to fall into again. Run `fxdb.py`.

   The support module's database slot, `*(u32 *)(ROM + 0x7C) + 0xB8`, names the chain
   directly on V2 (`0x1F025000`, `0x1F02B000`). On FX it names a container:
   `english.dec` `0x9F044400`, `german-450.dec` `0x9F041200`, `english-452.dec`
   `0x9F04FA00`, `v452d.rom` `0x9F040300`. The container is an 8-byte little-endian
   header - packed size, unpacked size - followed by an LZW stream:
   * fixed 14-bit codes, MSB first;
   * first free code 256;
   * no clear code;
   * end code `0x3FFF`.

   The decompressor (`0x80025E80` in `english.dec`) allocates tables of 4 x 18041,
   18041 and 4000 bytes, which are the sizes in Mark Nelson's 1989 14-bit LZW. The save
   path (`0x80030C38`) appends `FF FF FF FF` before compressing, so what comes out is
   the ordinary record chain of 4.1, codes and all, with the counts in the 4.1 table.
   Executed: the firmware's own decompressor, run under an emulator, and two
   independent decoders agree byte for byte and stop at exactly the declared size. The
   two 4.52 dumps are different builds but carry the same database.

   The encoder is Nelson's too. Re-packing each decoded chain with his `compress()` at
   14 bits reproduces the stored stream byte for byte, all four of them (`fxdb.py`
   asserts it). That is greedy longest match, a code per new string until `0x3FFE`,
   then the end code and one code 0 to flush. Since 1.2, `xpcrypt -x` reads these
   databases (`lzw.c`), plain or `.fcd`.

   How it was misread. The FX firmware also keeps an 8-byte descriptor at `0x1F07FFF8`
   (a 16-bit field at +6). `0x8003BEEC` in `v452d.rom` sizes a region as
   `0x80000 - (p + 0x100 + n)`; `0x8003C7CC` writes the descriptor and `0x8003C7F8`
   reads it back. All four FX firmwares name `0x1F07FFF8` that way and no V2 firmware
   does. That was taken to mean "the codes live at the top of the 512 KB flash, above
   what these dumps cover". In fact `p` is the container pointer and `n` its packed
   size, so the region is the *free* flash above the shipped database. `0x1F07FFF8` is
   a logical flash offset, not a bus address. The accessors (`0x8001EF3C`,
   `0x8001F230`) reach offsets at or above `0x60000` through the
   `0x1F040000-0x1F05FFFF` window after writing `0x21` to `0x1F060001`, so the bus
   shows 384 KB, and `v452d.rom` is exactly `0x60000` bytes. The constant search of
   `REVERSING.md` §10.5 could not see the database, because it is reached through a
   pointer slot, not a `lui`. The tails were misread too. The last `0x915E` bytes of
   `english.dec` are `0x8F` bytes of Shift-JIS UI text and the alphabet table, and
   then the container from `0x44400` to the end of the file. In `v452d.rom` the
   packed data ends at `0x493A5`, followed by zero pad to `0x49400` and erased flash
   after.

   Still true from the earlier search: there is exactly one `COMP01` blob per ROM, the
   firmware; and the `ABCDEFGHIJKLM\r\n…` table at image `0x333DA` is the on-screen
   keyboard grid for the code-entry screen, 13 characters per row, not a name index.
   Full 512 KB dumps were not rare either. Both Xlink95 builds read `0x1F000000` for
   `0x80000` bytes into `ROMS\BackUp.FCD` during an upgrade (`comms.py`, `FCD.md`).
4. **The `Special32`/`Special33` routes are deliberately not ported.** They are the
   keys 2 and 3, and per 5.2 the firmware really does route `32`/`82` and `33`/`83`
   there — but only those four first bytes, and **the reference's key-2 constants are
   wrong**: the firmware adds `'F'`,`'C'`,`'D'` to bytes 1, 2, 3, not `'C'`,`'D'` to
   bytes 1, 2. Implemented once from the reference and reverted, which turned out to be
   the right call. Still no evidence any database uses them: every `32`/`33`/`82`/`83`
   line in the three databases is a type 5/6 payload row, and the cart has no encrypt
   side at all. If ported, mind that the firmware leaves `dst[0]` untouched here.
5. ~~**A header whose key bits select no cipher - xpcrypt and the cart disagree.**~~
   **Settled in 1.2 (`95b85ec`): xpcrypt follows the cart.** `7d15818` made xpcrypt
   start a block only when the header's key bits are clear after decryption: either it
   decrypted, or it never carried a key. The motivation was that `51123456 6006`
   turned the following line into `4476D366 AA22`, and that a header reading `6FFF`
   swallowed the next 683 codes. The ninth pass (`AUDIT.md`) found that the cart does
   the opposite. Both stagers (`0x1ACCEC` / `0x1AD08C` in `xteng`) classify a header
   by the *stored* byte 0 high nibble, before decrypting it with key −1, and key bits
   1-3 send byte 0 to the copy route. So the cart stages `51123456 6006` as a
   Supercode with the size as stored, and it would swallow those 683 codes too. That
   made the guard a divergence, not a fix. xpcrypt now classifies the same way and
   warns that the header's key bits select no cipher. `oracle_test.py` holds it to the
   cart's side. No shipped database has such a header.
6. ~~**Extract cheat codes from ROMs.**~~ - **implemented.** `-x`
   accepts either a plaintext ROM or its encrypted `.fcd`, locates the complete
   database - after the erased-flash boundary on V2, through the module's pointer and
   the LZW container on FX (since 1.2) - expands name abbreviations and decrypts every
   entry with a fresh block state at its real cheat boundary. Empty games are printed,
   and since 1.2 it says on stderr what the cartridge will run differently (README,
   "Warnings"; `warn_test.py`).
7. ~~**Version bump / `README` history entry remains deferred.**~~ - done: 1.2.

---

## 7. What the code types do

Everything above is about the cipher. What the *decrypted* codes mean is a
separate body of work, written up in `ENGINE.md`: Part I is what the engine is
and what each code type does, Part II is how it was found and what stays open.

The short version, because it changes how to read the rest of this file:

* The cartridge menu firmware never runs while a game does. Codes are applied by
  a 0x24C-byte blob (V2; the Pro and FX installers copy 0x250) copied into PSX
  kernel RAM at `0x00000A00`. It hooks the BIOS B-function trampoline at
  `0x000000B0` and fires on `B(17h) ReturnFromException`, so on every interrupt.
  Four of the ten images keep that blob inside the packed firmware and the other six
  keep it unpacked in the ROM, which is why an image-only search finds it in a third
  of the corpus.
* It implements eleven of the sixteen types - `0 3 4 5 6 7 8 9 B E F` - as a
  fall-through `bne` chain, not a table. Types 1 and 2 have no handler and
  nothing touches them. Type 1 is *used* for that: 134 times in the databases, as
  the inert second line of a type B slide code. Types A, C and D have no handler
  either, but staging rewrites them before the engine sees them: A into a 5, a lone
  D into an F hoisted to the head of the list, and every `C0` and every other `D0`
  into a type 7 guard. Only `CD`/`C6`/`C8`-style lines, whose flag nibble survived,
  reach the engine as type C and do nothing. Every shipped filler or disabled line
  is one of those.
* **The last staging pass normalises every code** (executed in all ten images).
  After decrypting a line, pass 4 makes every address the engine reads as a
  halfword even:
  * a byte write at an odd address becomes a type E write one byte down;
  * a halfword write at an odd address does too, keeping only its low byte;
  * a misaligned word write becomes a halfword write;
  * a conditional's address and a slide's step are forced even.

  None of the 15,349 shipped lines is stored as type E, but 1,156 of the 14,939
  codes among them are type E by the time the console sees them.
* **All ten firmwares agree except on type 4** (slow motion), which is present
  in the six V2/Pro builds and missing from all four FX builds. The other ten
  handlers give the same normalized instruction sequence across three languages
  and two hardware generations, as does the order of the chain. Not the same
  bytes: the blob is three byte-distinct groups (§7), and what differs between
  them is where each build keeps its patch list and support vectors. The FX
  engines also clear the breakpoint control register (DCIC) on *every* B() call;
  that is not about a code type and is checked on its own.
* Type 6 is the interesting one: it programs the R3000's COP0 breakpoint
  registers from the Megacode descriptor and installs the payload at
  `0x80000040` (written through its uncached alias `0xA0000040`) - the breakpoint
  exception vector. The payload is not data being poked into the game, it is the
  handler. Only one Megacode fits a selection: pass 1 stops after the first, and a
  second one's mask row is hoisted as a type F anchor that almost certainly
  mismatches, so nothing runs. Hoisting decrypts that row, as key 7 for an `F7` or
  `FF` mask, which on V2 runs the copyright check: on a stock 2.14 cart, two Megacodes
  overwrite the firmware (5.3b).
* Three of the four types the cipher gives no route to (2, A, C, E) are staging's:
  A and C are rewritten and E is generated. Only 2 plays no part anywhere. D, which
  staging also rewrites, does have a route, so the table is not simply "the staging
  types" either. The overlap is what the corpus shows, not the reason for it
  (`ENGINE.md` §7). An earlier version of this note called the two mechanisms
  independent, before pass 4 had been read.

The **runtime** half is executed, not only read. `engineemu.py` runs each
firmware's engine out of the image over a synthetic patch list and records every
access: 10 firmwares x 26 cases, one per-type difference (type 4, seen in two
cases). It also runs the menu firmware's own four staging passes over real
selections in all ten images, and the normaliser over 29 codes. What is left a
reading is the extent of type A and what the R3000 does about an odd address
(`ENGINE.md` §13, §16).

Two new defects. The first, in `ENGINE.md` §7: the default-off bit survives
decryption for any code stored with key nibble 0, because `(src[0] & 0xF7) - 4`
sends `0x80` and `0x88` to the same verbatim-copy route. The engine's
`& 0x0FFFFFFF` then keeps it, adding `0x08000000` to the address. Both halves
executed:

```
decrypt routine  8802A798FFFF -> 8802A798FFFF          byte 0 survives
engine           lh 0802A798 | lh 0802A798 | sh 0802A798=FFFF
                    all three outside the console's 2 MB of RAM
```

Of the 133 lines in the Xplorer Pro 2.20 database with the bit set, all 133 keep it
through decryption (12 are `CD` filler rows, which the copy route passes untouched).
121 of them carry no key, and **120 of those then use the wrong address**; all 121 also ship in
another database, identical apart from that bit (117 distinct rows). Earlier
counts of 101 and 118 came from suffix-only record chains. Under the saved rule -
clear bit 3, look for the same six bytes as a dispatched code row elsewhere -
the result is 121 whether all four other databases or only the three that ship
encrypted are searched. `defaultoff.py` states the rule and re-measures all four
counts. The engine is
not really where the bug is - it strips the type nibble and trusts the flag nibble
is already gone, which the four cipher routes guarantee and the copy route does
not. What exposed it was not "the first database in the clear" — Pro 2.14 was
already in the clear — but the first database to set the default-off bit on rows
that carry no key - among the V2 databases. The FX 3.20 and 4.52 databases (6.3)
carry 112 keyless default-off rows each at an addressed type. Not run on hardware,
so what an R3000 does about the bad address is still open.

The second is a boundary: both block handlers copy one unit before they decrement
and test the count, so a Supercode or Megacode declaring zero payload bytes loops
forever. All ten engines hang on it, and the German database ships two such
Supercodes (`War Games`).
