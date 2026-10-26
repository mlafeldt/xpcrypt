# Audit of the Xploder research notes

Audit dates: 2026-07-28 through 2026-07-30, and 2026-10-26.

> **Current status:** nine passes. The ninth (2026-10-26) is the first to cover the
> material added after the eighth: `TENTH.md`, `PLUGIN.md`, `N64.md`, `ENCRYPT.md`,
> `FCD.md` and the later scripts. It is also the first to re-derive the firmware
> claims with independent tooling rather than the repo's own. It overturns three
> headline conclusions (FX databases, type C/D/E, the N64 ciphers). Every research-side
> finding is now fixed in the notes and the scripts (see its Disposition). The "Open"
> markers in its findings record the state after the first round. What remains open is
> the C source, planned in `TODO.md`. The older sections are history.

## Ninth pass: deep review against the binaries - 2026-10-26

### Scope and standard of evidence

> **Two rounds.** The first round recorded the findings below and applied the doc
> corrections as callouts (`337cb0c`). The second fixed everything in `research/`:
> the callouts are folded into the bodies, the scripts are corrected, and new
> assertions back the new results. Items marked "Open" below were open after the
> first round; the Disposition at the end lists what the second round did and the
> little that is left.

Every note in this directory, re-checked against the ten images (the nine in `roms/`
plus 2.005 from `pc/ROMS/Xteng.fcd`), the four PC binaries and, for `N64.md`/
`ADVANCED_EXPLORER_CODES.md`, the cited public sources. The rule was independence. The
repo's scripts were re-run only as a reproducibility check, and every conclusion below
rests on one of these:

* **Own decoders.** COMP01, the FX descrambler, the LE loader (6,030 fixups), a
  database reader and a 14-bit LZW decoder, all written from the disassembly. The
  COMP01 decoder and descrambler reproduce all ten unpacked images byte for byte.
* **Decompilation.** Ghidra 12.1.4 headless on the raw MIPS images, and REA's Ghidra
  provider on the PE/LE tools.
* **Disassembly.** rizin and capstone.
* **Execution.** Unicorn harnesses, not `fwemu.py`. Each image's real decrypt routine
  ran 9,216 cases with key −1 and payload keys 0-15. The checker ran live. The FX
  LZW decompressor ran out of the firmware. The vendor's encrypters ran against
  `xpcrypt -e`. The staging passes ran in Ghidra's emulator, and the pass-4
  normaliser ran in all ten images.

Findings that change a published conclusion were spot-checked a second time by hand
before being written in.

### Bottom line

The cipher work stands. The decrypt routine, the route table (`0xABFB` in all ten
images), the payload keys, the image cipher and the vendor's encrypter all agree
with xpcrypt case for case:

* 9,216 decrypts per image;
* 8,000 codes plus 1,000 payload rows through the DOS encrypter;
* 4,000 runs through X-Killer;
* all eight image-cipher routines at lengths 20-4099.

Three headline conclusions do not stand:

1. **The FX databases are in the dumps.** `FINDINGS.md` §6.3 is wrong. Each FX image
   points at an LZW-packed record chain from `*(ROM+0x7C)+0xB8`. The format is an
   8-byte header (packed and unpacked size), then 14-bit MSB-first codes starting at
   256, with end code `0x3FFF` and no clear code. The firmware's own decompressor at
   `0x80025E80` (executed) and two independent decoders give byte-identical output of
   exactly the declared size, ending `FF FF FF FF`. The counts are:
   * 3.20: 265 records / 1,922 cheats / 2,825 lines;
   * 4.52: 264 / 1,921 / 2,823, the same database in both dumps;
   * 4.50: 269 records (5 of them empty) / 2,071 / 2,957.

   The `0x1F07FFF8` region is free flash above that database, reached through a bank
   switch (`0x21` to `0x1F060001`, offsets ≥ `0x60000` read via
   `0x1F040000-0x1F05FFFF`). It is not where the shipped codes live. The §6.3
   formula's "firmware_end" is the container pointer, and its `n` is the packed size.
   §10.5's `lui`-page method missed it because the database is reached through a
   pointer slot.
2. **Types C, D and E are shaped by staging.** `ENGINE.md` finding 2, the type C/D/E
   sections, §13 and `FINDINGS.md` §7 are wrong. Pass 4 calls a normaliser after
   every decrypt (`xteng` `0x1AA9F8` → `0x1A835C`, its only caller, present in all
   ten images):
   * `C0`, `D0` and `70` become `70`, with the address forced even;
   * odd-address `30` and `80` become `E0`;
   * misaligned `00` becomes `80`;
   * `B0` gets bit 0 of byte 3 cleared.

   So `C0` is a live equality guard and only `CD`/`C6`/`C8` are inert. An unhoisted
   `D0` becomes type 7. E is generated 1,156 times for the five databases. "Designed
   independently" fails: three of the four routeless types are exactly staging's.
3. **The N64 shares both ciphers.** `N64.md` is wrong on two counts:
   * the published N64 code cipher (hammerhead/kodewerx `DecryptCodeMethod2`) is PSX
     key 6 on bytes 1-5, and `Method1` is the same function;
   * X-Killer handles an "FCD N64 ROM - Encrypted" format with the PSX image cipher.

   The "byte-identical" COMP01 block is the PSX block word-swapped.

`make check` **fails at HEAD.** `rom2005.py` asserts the pre-fix behaviour that
`7070614` removed: that `-x` fails on 2.005 and that `db2` rejects it. Make stops at
the first failure, so `payloads`, `typecx` and `selfdestruct` never run under the gate.
Run on their own, all three pass, and every other target passes. Each target still
fails when its producer is replaced by `false`.

### Firmware cipher, container, protection (`FINDINGS.md` §5, `REVERSING.md`)

Confirmed independently:

* COMP01 format, escapes and the `"Wayne Hugh"` header mask;
* FX descrambler formula and seeds;
* every decrypt route, including the `0xAA`-prefill answers;
* the 120/48/4/72 split of the 244 entries;
* the folded identities;
* no encrypt routine in any image;
* exactly two callees per decrypt;
* the or-vs-add row-count bug in all ten (FX has two such sites);
* the 59 name occurrences;
* `romcrypt.py` over 87,040 cases;
* `xp_crypto.c`, which departs from the firmware only by design (bit 3 kept;
  Special32/33 copied).

Not as published:

* **Pro 2.14 bricks with no modification.** Its checker (`0x1A4E54`) compares
  `"(C) 1997/8 FCD"` against its own header `"(C) 1997-9 FCD  "` and mismatches at
  index 8. Executed: the first key-7 or Special32 code a user activates programs cart
  `0x0-0x17FFF`. No row of the stock 2.14 database takes either route: all 1,826 rows
  have low nibble 0. Only the Makefile and `selfdestruct.py` said so, and the Makefile
  overstates it ("on a stock cartridge" without the trigger). *Callout applied:*
  `FINDINGS.md` ⚠ note and §5.3b table.
* **The V2 checker compares 14 characters, not 13.** Its `strlen` (`0x1A4410`) counts
  the NUL. *Applied* in `FINDINGS.md` §5.3b and `TENTH.md` §1. Still open in
  `REVERSING.md:1043`, the `fxprot.py:16` docstring, and `selfdestruct.py:331`
  (`range(len-1)`).
* **"Exactly one route" contradicts its own table.** V2 uses two (key 7 and
  Special32), FX one (key 4). *Applied.*
* **"Eight of the nine" is now nine of ten.** *Applied* in the ⚠ note.
* **The recoverability premise was wrong.** FINDINGS said programming "only clears
  bits", but the identified parts are page-write parts that erase first. *Applied.*
  Open: `selfdestruct.py:100`'s "accepts exactly `0xD5`/`0xDA`/`0xA4`". After the
  Atmel ID check the V2 probe (`0x1A3444`) also runs SST's alternate ID entry
  (AA/55/80/AA/55/60). FX 4.50 and 4.52 accept a device `0xBA` too, and 4.50 a
  byte-programmed Intel-style part. Chip names come from memory; no datasheet was
  checked.
* **The overwrite source.** `0x3E8-0x183E7` is kernel RAM only up to `0xFFFF`. On FX
  the rest is the running firmware. `selfdestruct.py:46`'s "first 90-odd KB of the
  packed firmware" holds for V2 only.
* **The store-only re-pack is `0x2BFC8`, not `0x2BFAE`.** `packstats.py:66` counts the
  136 escape tokens instead of the 162 escape-byte occurrences. The fix recorded in
  the first audit did not hold. +33% stands. *Applied* in `FINDINGS.md`. Open:
  `REVERSING.md:354`, `TODO.md:224`, `packstats.py`.
* **english-452 is not "far less compressible".** zlib gives 0.563 against v452d's
  0.562; FCD's encoder simply emitted 3,373 LZ tokens against 16,240. *Applied* in
  `FINDINGS.md`. Open: `packstats.py:13`, `TODO.md:228`.
* **english-452 and v452d are two 4.52 builds.** Their headers are dated
  22/11/1999 and 05/11/1999, the unpacked sizes are `0x48284` and `0x4825C`, and the
  code is relocated. They behave identically, and their databases are identical.
  german-450's header carries a 1997 date.
* **No German 0x1000 gap.** At the right base, the German routes follow the
  dispatcher as in 2.008. The "second table set" is `lui`/`addiu` pairs naming debug
  strings `0x1000` below the tables. *Applied* in `REVERSING.md` §10.6. Open: the
  `fwemu.py:22`/`:250` comments and `fwimage.py:54`.
* **Small slips** (open unless noted):
  * "Punky Bear" is the Bust-A-Move 3DX Supercode (*applied* in `FINDINGS.md`; open
    in `fxtest.py` and in AUDIT history);
  * the USA decrypt entry is `0x801ABA78`;
  * `0x1ACCC0`/`0x1ACD30`/`0x1ACE0C` are inside one function, `0x1ACC74`, which is
    both the list walker and the Megacode stager;
  * V2 inlines the shared tail only in key 7;
  * fwemu is 294 lines, not "about 120";
  * the descrambler needs only the low 3 bits of state, not all 32;
  * the FX strncpy at `0x80012AA8` is 3.20's only;
  * on Pro 2.20 the checker callee is emptied, not "compiled out";
  * the notes mix the `0x801A…` and `0x001A…` bases. The loader enters
    `0x801A0008`, but every absolute pointer is `0x001Axxxx`. Pick one convention
    and say so.

### Code engine (`ENGINE.md`, `FINDINGS.md` §7)

Confirmed:

* blob locations in all ten (2.005 is a fourth packed one, so 4 of 10);
* the three SHA groups;
* every handler body and the chain order;
* type 4 absent on FX;
* type 6's COP0 programming;
* copy-before-test hangs on zero-length blocks;
* the 0x80/0x88 shared copy route;
* the 133/121/120/117 counts;
* type 1 always the second line of a slide (134/134);
* type C's 17/4/6 split.

Not as published:

* **The pass-4 normaliser** (Bottom line 2). *Callout applied* at the top of
  `ENGINE.md`, in `FINDINGS.md` §7, in `ADVANCED_EXPLORER_CODES.md` (the FAQ's
  type C claim is *right*) and in `TODO.md` 1e. Still open inside `ENGINE.md`:
  * the type C section (748-750, 1730-1733);
  * the type D section (808-811, 1584-1586);
  * the type E section (834-837);
  * 1268-1272;
  * the §13 classifier scans (1559-1573);
  * `typecx.py:17-20` and `:708-717`.
* **A second enabled Megacode wrecks the list** (executed on 2.008). Pass 1 stops
  after the first type 6. The second's mask row is hoisted as an F anchor
  (`F01FE3C9 120F`) and decrypted as key 7, which runs the copyright check. The
  second header goes in raw. "Room for exactly one Megacode" understates this.
* **The malformed MGS record is worse than "malformed".** Executed: it takes the next
  enabled cheat. That cheat's name line and first code become its descriptor and
  mask, and the rest of the cheat becomes payload. It builds a 13,816-word copy over
  kernel RAM from `0xA0000040`, the engine included. (The first round said "the three
  cheats enabled after it". That came from a test selection without cheat-name
  lines.)
* **Overrunning Supercode rows are handled three ways.** V2 2.004-2.0081 and Pro 2.14
  hang (`j .`, `xteng` `0x1AD270`). Pro 2.20 returns length `0x18`, because it
  branches one instruction past `move v0,t2`. FX handles it. No shipped code
  triggers it.
* **"One difference" holds only by construction.** FX clears DCIC on *every* B()
  call (`mtc0 $zero,$7` in the delay slot at `0xA04`, nop-ed by the installer when
  `0x8000002F` is non-zero). `engineemu.py:263-267` deletes that write from its
  traces.
* **Stale counts.** The §4 "Uses:" counts predate the complete chains:
  * type 1: 114, now 134;
  * type 3: 2,681, now 2,988;
  * type 5: 42, now 44;
  * type 6: 9, now 11;
  * type 7: 491, now 589;
  * type 8: 9,062, now 10,689;
  * type 9: 36, now 43;
  * type B: 136, now 159;
  * type F: 231, now 245.

  The key-nibble table at 1229-1235 is stale for 2.008 (key 6 2,767, key 6 + off 121)
  and USA (key 6 4,007, key 4 552, key 6 + off 311). The table's own 116 contradicts
  its "all 121 carry key 6".
* **"133 … 121 keep it through decryption"** (`FINDINGS.md` §7). All 133 keep the
  bit; 121 is the keyless subset, and the other 12 are `CD` rows.
* **Smaller items:**
  * Pro and FX installers copy `0x250` bytes, not `0x24C`;
  * only V2 makes the `0x700`/`0x9F0` installer writes;
  * the payload goes through the uncached `0xA0000040`;
  * the flag nibble leaks beyond bit 3: `31001643` lands at `0x01001643`, and
    2.0081's `F21EAB7C` becomes an anchor at `0x021EAB7C`;
  * "fifty-odd instructions" is about 101;
  * the 37-entry table has 7 distinct targets, not 6.
* **B(17h) fires "on every interrupt."** Unverifiable without a BIOS image.

### Databases and extraction (`FINDINGS.md` §1-4, §6, `TENTH.md`)

Confirmed:

* all five V2 chain offsets and counts;
* 11,718 cheats and 15,349 lines;
* 44/44 and 8/9 block fits;
* 16/16 vs 0/16 for the payload swap;
* the specimens;
* the 1,266-line trap;
* 2.005's header, territory byte and chain;
* the support-module slot `+0x38` equal to the framed start in all six V2 databases;
* `payloads.py`'s 65 blocks, 10 of them corrupt (3 hand-checked: code-cipher
  re-encryption);
* no payload key 7 anywhere, FX included.

Not as published:

* **The FX databases** (Bottom line 1). *Callouts applied* in `FINDINGS.md` §4.1 and
  §6.3 and in `TODO.md`. Open: `REVERSING.md` §10.5 (915-947), the `fxdb.py`
  docstring, `comms.py:63`/`:395`, and the "past `0x493A3` is erased" detail.
  `0x493A4-0x493FF` is zero pad, and `0xFF` starts at `0x49400`.
* **The header guard is the cart's opposite.** Both stagers classify a header by its
  *stored* byte 0 nibble (`xteng` `0x1ACCEC`/`0x1AD08C`, checked by hand). Key bits 1-3
  route byte 0 to copy, so the cart stages `51123456 6006` as a Supercode with the
  stored size. xpcrypt's `7d15818` guard makes it diverge. No shipped header is
  affected. *Callout applied* in `FINDINGS.md` §6.5. The `crypt_code()` comment and
  `TODO.md` §4 are open.
* **2.005 vs 2.008.** 208 of the 223 shared game names have identical codes and 15
  differ; the doc said "byte-identical". The `Moto Racer 2` offsets were one too high.
  2.005's default-off rows are all keyed (119 rows), which settles the TENTH §4
  question against the suspicion. The FX databases keep bit 3 on 113 rows (3.20), 112
  (4.52) and 4 (4.50). 113, 112 and 1 of them are keyless, and 112, 112 and 1 sit at
  an addressed type (3, 7, 8), so they land at the wrong address. *All applied* in
  `TENTH.md`.
* **`rom2005.py`'s "six times larger oracle"** compares 7 blocks / 95 rows against
  16 / 141, so it is smaller. It is not independent either: the 7 are among the 16.
  Open.
* **The 17e31fc comparison** gives 281 / 263 / 350 over complete chains, not
  239 / 263 / 97. *Applied.*
* **"Games" counts distinct names, not records.** USA has 252 records (Bio Freaks and
  Casper twice) and `-x` prints 252. The corpus has 1,123 records against 1,121
  distinct names, and 2.005 has 234 records including the empty one. Open:
  `FINDINGS.md` §4.1, the eighth-pass table, `TENTH.md` §2.
* **The old parser restarted *inside* a name.** It resynchronised in
  `"Duke Nukem:\x06 To Kill"` at `0x27F69`/`0x2C8EC`, not at "a later printable
  game". The 1,633 / 2,144 figures reproduce exactly.
* **C edge case (open).** `find_database()` no longer enforces "at least one game".
  A chain of only empty games is accepted and `-x` exits 0 with no output, where
  `db2.py` rejects it. So `TENTH.md` §3's "two mirrored places" is not exact. No real
  image is affected.
* **Minor:**
  * MGS "Verliere Chaff" stores the intended `865FAA06 5A5A` shifted one hex digit
    left; the same bytes ship again in German FX 4.50;
  * two Mortal Kombat Trilogy cheat names parse as codes;
  * zero-line cheats are common (249 in USA);
  * `prechain.py`'s "10,054 distinct names" is a per-chain sum, and the union is
    8,307;
  * xpcrypt gives no warning when input ends inside a declared block;
  * `swap_payload()` (`FINDINGS.md` §4.3, §5.3) no longer exists.

### PC tools (`FCD.md`, `ENCRYPT.md`, `comms.py`)

Confirmed:

* the image-cipher closed form, by all eight routines in an own harness at 20-4099
  bytes, 511/512/513 included;
* the §1 seed-table statistics;
* no image-cipher code in any firmware;
* the §4 file identities;
* the DOS encrypter and X-Killer against `xpcrypt -e` (0 differences);
* no Special32/33 anywhere;
* the joypad table and the joker generator;
* the payload templates.

Not as published:

* **Xlink95 reads the full 512 KB.** Both builds call `'G'` for `0x1F000000`,
  `0x80000` (`push 0x80000; push 0x1F000000` at file `0x10998` in both, found again
  by hand). They encrypt the result to `ROMS\BackUp.FCD`, and their upload has a
  512 KB mode. `comms.py`'s "the vendor tool simply never asks" holds for DOS XLink
  only. FCD's own Windows tool made full FX dumps. Open in `comms.py`.
* **Cart command `'X'` uploads and executes.** It receives to a wire-given address
  and `jalr`s into it (`0x1A1B2C`), a second unauthenticated code path. `comms.py`
  calls it "program flash, as U". Open in `comms.py`. *Noted* in `PLUGIN.md`.
* **The command set is not "the same" across images.** 0x10/0x11 exist in 2.005,
  2.008, 2.0081, 2.14 and 2.20. FX and Pro add opcodes, and FX drops `'P'`. DOS also
  sends in-game `'A'`/`'D'`. Open in `comms.py`.
* **`FCD.md` §2 misclassified a flash-programmer caller.** `0x1A4698` is the
  self-destruct, not a page read-modify-write. *Applied.*
* **`ENCRYPT.md` slips.** The jump table is not "eight zeros" on disk; each entry is
  its target's in-object offset. The cart's clear loop is at `0x1ABFE0`, not
  `0x801ABFB4`. *Both applied.* The `xcode.py` docstring is open.
* **A latent vendor defect.** XLink's walker (`0x29550`) sizes a Megacode as
  `2 + ceil(nnnn/6)`, one row too many when `nnnn % 6` is 1 or 2. With payload key
  6/7 it would encipher the next code. No keyed Megacode exists.
* **Wording** (open):
  * the DOS loop is 22 instructions, not 21;
  * X-Killer's body is 15;
  * the Windows builds are stdcall;
  * X-Killer's third candidate `0x4050AC` is a false positive;
  * the dates and versions are off (binary "Released : 19/10/98"; version resource
    1.07);
  * the "3,920 functions" are call-target-shaped byte patterns, not functions;
  * `FINDINGS.md`'s "seed tables" wording is stale (*applied*).

### `PLUGIN.md`, `N64.md`, `ADVANCED_EXPLORER_CODES.md`

* **`PLUGIN.md`.** It is FCD's advertised memory-card upgrade, with menu strings on
  both generations, and it is not silent on FX. The finding that stands is that it is
  unauthenticated. The "seek/rewind" is `FileSeek(fd, 0x200)`, so the payload does
  start at `0x200`. The listing omits a close, a memset, and a malloc/free pair. A
  failed `FileRead` (−1) passes the `beqz` check. The "one-shot flag" gates only the
  card BIOS init. The routine is not structurally identical across builds. `0x03` as
  "standard block count" is uncertain per psx-spx. THX-1138 is a guess. *Callout
  applied.* Open: `plugin.py` derives the header slot rather than checking it, does not
  check the seek, and `find_string_addr()` references an undefined `path` on its error
  path.
* **`N64.md`.** Both ciphers carry over, and the shared block is word-swapped
  (Bottom line 3). At least eight other streams are byte-identical PSX ↔ N64, and
  `comp01.py` decodes all N64 streams. *Callouts applied.* Open source details:
  * sharkdumps has six builds, five of them scrambled;
  * the chips are byte-interleaved;
  * writes need the address transform too;
  * the team string differs per build.
* **`ADVANCED_EXPLORER_CODES.md`.** Its type C and D verdicts are *applied*. The FAQ
  is FCD's own, signed "Wayne" and credited to Herbert and Beckett, not a third-party
  description. The `../crypto.c` link is stale.

### Notes vs this branch

* **`TODO.md` §5 and `MODULE_SPLIT.md` call the module split "done".** It is only on
  the unmerged `module-split` branch (`fed8a70`, forked from `854c1e1`). That
  branch's `db.c` still rejects a zero-cheat game, so merging it would revert
  `7070614`. *Callout applied* in `TODO.md`. Open in `MODULE_SPLIT.md`.
* **About 45 mentions of `crypto.c`/`crypto.h`** across the notes name files that
  exist only on `module-split`. Here they are `xp_crypto.c`/`xp_crypto.h`. Left
  as is: which name is right depends on whether that branch is merged.
* **`TODO.md`'s "version bump done" contradicts `FINDINGS.md` §6.7.** Still 1.1, no
  README entry. *Applied.*
* **No pass before this one covered** `FCD.md`, `ENCRYPT.md`, `PLUGIN.md`, `N64.md`,
  `TENTH.md`, `comms.py`, `xlink.py`, `xcode.py`, `payloads.py`, `prechain.py`,
  `selfdestruct.py`, `typecx.py` or `rom2005.py`.

### Disposition

**First round** (`337cb0c`). The doc corrections were applied as "Ninth pass"
callouts. The script and C findings were recorded but not fixed.

**Second round: everything in `research/` is fixed.**

* **The gate is whole again.** `rom2005.py` asserts the post-`7070614` behaviour,
  so `make check` runs every target, `payloads`, `typecx` and `selfdestruct`
  included. A new `fxdb` target gates the FX databases.
* **Notes.** The callouts are folded into the bodies of `ENGINE.md` (findings 2, 3
  and 5; types C, D and E; §§6, 7, 13 and 16; the §4 counts; the key-nibble table),
  `PLUGIN.md`, `N64.md`, `REVERSING.md` (§10.5 and the slips), `FINDINGS.md` (§4.1
  with the FX and 2.005 rows, §6.0, §6.3, §6.5, §7), `TENTH.md`, `ENCRYPT.md`,
  `FCD.md`, `ADVANCED_EXPLORER_CODES.md` and `MODULE_SPLIT.md`. `TODO.md` is
  rewritten as a plan for `main`. The notes now name `xp_crypto.c`/`.h`, as on this
  branch. `MODULE_SPLIT.md` keeps the branch's names and says so.
* **Scripts.**
  * `fxdb.py` decodes the FX containers twice, with its own LZW decoder and by running
    the firmware's decompressor, and asserts every count.
  * `engineemu.py` runs all four staging passes in all ten images. It asserts the
    normaliser and ten real selections, and it asserts the FX DCIC clear on its own
    instead of filtering it out.
  * `engine.py` locates the normaliser.
  * `typecx.py` asserts that the `C0` jokers become type 7.
  * `selfdestruct.py` compares 14 characters, models SST's ID entry, and asserts
    that no stock 2.14 row reaches the check.
  * `packstats.py` counts escape-byte occurrences.
  * `comms.py` asserts both Xlink95 builds' 512 KB read and `'X'`'s shared receive
    routine, and keys the command set by release.
  * `plugin.py` finds the header buffer from the 0x200-byte read and asserts the
    seek.
  * `oracle_test.py` gains a suite for headers with key bits 1-3, which counts 114
    rows where xpcrypt and the cart disagree.
  * `rom2005.py`, `prechain.py`, `db2.py`, `xcheck.py`, `defaultoff.py` and
    `xcode.py`: wording, plus the corrected or extra assertions.
* **Found while fixing.**
  * The list walker's row-count bug needs an odd high nibble, so it fires at 507-511
    payload bytes, 1,019-1,023 and so on, not at 251-255. It is now reproduced.
  * Pass 3 clears bit 0 of a hoisted F's *stored* byte 3 before decrypting it, so
    three shipped USA key-4 anchors (Diablo twice, Golden Nugget) can never match.
    Executed in all ten images.
  * FX drops an overrunning block together with its guard and carries on.
  * The N64 cheat database at `0x30000` uses the PSX layout. Under the key-6 cipher,
    3,598 of its 3,630 `E8` rows become RAM-range writes; the raw rows give none.
    That is evidence for `N64.md`'s code-cipher finding that does not rest on
    hammerhead.
* **Still open (C source, planned in `TODO.md`):**
  * FX `-x`;
  * the empty-only-chain case in `find_database()`;
  * the header-guard divergence;
  * the warnings for cart behaviour;
  * the brick check;
  * the release.
* **Still open (research).** These were not established:
  * what disarms the `0x700` poke table on Pro/FX;
  * whether the menu caps the selection size;
  * the extent of type A;
  * what the R3000 does about an odd address;
  * the N64 firmware's own decrypt routine;
  * the flash chip names, which come from memory rather than datasheets;
  * the bank-switched FX read, which was decompiled, not executed.

  Widening the five-database gates to 2.005 and the FX databases was left out on
  purpose, because it changes every published count. A one-off run over them (10,970
  more lines in 7,582 cheats) found no failures in the oracle or the round trip.

## Extraction implementation audit - 2026-07-30

### Bottom line

`-x/--extract` is implemented and the former database-scope limitation is
resolved. The old locator accepted abbreviation bytes 1-7 in cheat names but
still required printable game names, so it rejected an early UK or USA game and
returned a later suffix that happened to parse. All figures below that cite
13,205 lines or a start at `0x27F69`/`0x2C8EC` are historical audit records and
are superseded by this section.

The format supplies a stronger frame: each complete chain begins immediately
after erased flash. Accepting the abbreviation bytes in both name positions,
rejecting `0x7F`/`0xFF` as name data, and requiring four preceding `0xFF` bytes
finds these complete chains:

| image | start | games | cheats | lines |
|---|---:|---:|---:|---:|
| Xplorer 2.008 UK | `0x25000` | 285 | 2,130 | 3,060 |
| Xplorer 2.0081 DE | `0x25000` | 240 | 1,787 | 2,476 |
| Xplorer Pro 2.14 JP | `0x2B000` | 61 | 1,619 | 1,826 |
| Xplorer Pro 2.20 UK | `0x2B000` | 285 | 2,134 | 3,082 |
| Xploder V2 2.004 US | `0x25000` | 250 | 4,048 | 4,905 |

Total: 1,121 games, 11,718 cheats and 15,349 lines. This adds 2,144
previously skipped lines: 679 UK and 1,465 USA.

### Implementation checks

1) `extract_test.py` builds a ROM with abbreviation bytes in a game and cheat
name, an ordinary encrypted code, a Supercode, an inline type A block and a
following cheat that proves block state resets at the entry boundary. Plaintext,
encrypted `.fcd`, `--extract` and the compatibility spelling `--extract-codes`
all produce the exact expected output. A plaintext ROM without a database fails.

2) With `roms/` present, the same test checks all 15,349 extracted/decrypted
lines in order across all 11,718 cheats. Every `.fcd`/`.dec` pair produces
byte-identical output.

3) `oracle_test.py` passes 1,792 + 8,200 + 20,590 + 60 + 1,080 generated
checks and all 15,349 real lines. `roundtrip.py` reproduces all 15,349 lines
under each of four encryption keys. `audit2.py` still finds exactly one corrupt
overrunning block.

4) The expanded corpus changes the published type totals to
`[1, 134, 0, 2988, 6, 44, 11, 589, 10689, 43, 0, 159, 27, 3, 0, 245]`.
It holds 14,939 dispatched code rows and 410 payload rows. The direct block-size
formula fits 44/44 blocks in the UK 2.008, Pro 2.20 and USA databases; the
German corpus still contributes the one corrupt type 6 header.

5) The complete comparison pool changes the default-off cross-database result:
all 121 keyless flagged Pro 2.20 rows have an unflagged counterpart in either
comparison pool (117 distinct), not 118. The core 133 flagged / 121 keyless /
120 wrong-address counts are unchanged.

### Disposition

Applied in the extractor implementation and the following research update.
`FINDINGS.md` sections
4.1-4.5, `ENGINE.md` sections 8 and 14, `REVERSING.md` section 10.6, `TODO.md`,
and the executable assertions now use the complete-chain figures.

## Independent validation - 2026-07-29

### Bottom line

The central results hold for the recovered corpus. This pass independently
reproduced the firmware and database provenance, cipher route table, Type 5 byte
swap, database counts, block-boundary audit, COMP01 measurements, V2/FX route
equivalence, engine handler set, and the nine-firmware execution results. No
documented cipher equation or main code-engine semantic was disproved.

The root C implementation is correct for the subset it documents: normal-code
crypto, Type A handling, Type 5/6 block layout and payload crypto, and whole-ROM
scrambling. It is not a literal emulator of every recovered firmware route. No
cipher equation, payload transform, block-boundary, or ROM-transform mismatch
was found.

### Open C implementation findings

1) **Medium - option parsing can overwrite the stack with short enums.**
`xpcrypt.c:278-292` passes `enum xp_key *` to `sscanf("%i", ...)`, although
`%i` requires `int *`. The default ABI happens to give the enum `int` size, but
an LLVM 22 build with `-fshort-enums` makes it one byte and AddressSanitizer
reports a four-byte stack-buffer overflow for `xpcrypt -e 7`. Parse into an
`int`, validate the entire argument, and then convert to the enum.

2) **Medium - accepted whitespace can silently change code bytes.**
`is_code()` at `xpcrypt.c:74-101` accepts whitespace at any position among the
12 hex digits, while the six fixed-width conversions at `xpcrypt.c:153-155`
consume whitespace between conversions rather than removing it from the digit
stream. For example, `1 23456789 ABC` is accepted and parsed as
`01234567 89AB`, silently dropping the final `C`. Restrict input to the
documented `XXXXXXXX XXXX` form or normalize it before exact parsing, and check
the conversion count and trailing input.

3) **Medium - some I/O failures still return success.** `crypt_codes()` does
not check `ferror(stdin)`, output calls, or final flushing, and `main()` ignores
its return value. A read-erroring stdin and a closed stdout both reproduced exit
status zero. ROM mode also ignores `fseek()` and final `fclose()` failures, so a
late write error can be reported as success.

4) **Medium as a fidelity qualification - four real firmware routes are
deliberately omitted.** `crypto.c:58-70` documents that first bytes `32/82`
and `33/83` have Special32/Special33 firmware transforms but are preserved by
the C implementation. No recovered database uses them and there is no firmware
encrypt side, so preservation is a reasonable product choice; it still means
the implementation is not fully firmware-faithful for every possible six-byte
input.

The other deliberate differences are also defensible but must be included in
any fidelity claim: the C library preserves the default-off bit for round trips,
preserves unknown payload-key rows instead of zeroing them, treats zero-size
block headers as ordinary stream rows instead of reproducing the firmware hang,
and carries Type A to end-of-input because the CLI has no cheat-record boundary.
It does not implement the unrelated code-engine, database, COMP01, or
anti-tamper behavior researched in this directory.

Lower-severity CLI/build issues are that `-e 4junk` is accepted, `-d` does not
reset a previous `-e` or `-r` selection, the public header uses the reserved
guard `_XP_CRYPTO_H_`, and the root Makefile exposes no `check` target even
though the research Makefile contains the effective test suite.

### Open research findings

1) **Medium - `fwemu.py` mishandles signed values followed by shifts.**
`fwemu.py:186-188` stores `lb` and `lh` results as negative Python integers.
The logical right-shift implementations then shift those unbounded negative
integers without first converting them to 32-bit register values. `S32()` also
assumes a non-negative 32-bit input, so it double-adjusts an already negative
value. A focused instruction test gives:

```text
lb  $t0, 0($a0)       # memory byte FF
srl $v0, $t0, 1       # emulator: FFFFFFFF; expected: 7FFFFFFF
sra $v0, $t0, 1       # emulator: 7FFFFFFF; expected: FFFFFFFF
```

Unicorn differential testing found all 14 focused signed-shift/arithmetic cases
differed. An impact audit found no change to the published results: the exact
`fxtest.py` population executed 705,024 signed byte loads, all below `0x80`, and
the current engine cases had no external-log or instruction-path difference
after normalizing loads. Engine Supercode copies do load negative bytes, but
they flow directly into `sb`, which masks them back to eight bits.

2) **Medium - the verification target does not enforce all facts it
advertises.** `fxtest.py` calculates known-plaintext failures but only prints
them; its exit status is based on model/cross-firmware differences. It does not
assert that nine ROMs were loaded or that every `XP_KEYED_TYPES` value is
`0xABFB`. A fake-firmware run with one image, `XP_KEYED_TYPES = 0`, and 0/30
known-plaintext rows still printed `all 1 firmwares agree` and exited zero.

`engineemu.py` asserts only that two cases differ, not that they are the two
Type 4 cases or that the expected V2/FX grouping and traces remain intact.
Several other Makefile checks grep or print output. The present outputs are
correct, but `all suites passed` does not mean that every published number and
identity is regression-gated.

3) **Medium - the round-trip population is mislabeled.** `FINDINGS.md:301-302`
says the cipher round-trip covers `all three exported databases (13205 codes)`.
The value 13,205 is the sum of all five recovered database chains; the three
databases used by the historical comparison contain 8,903 rows. There is also
no saved per-cheat round-trip script for this exact claim. That boundary matters
because flattening a database can turn an accidental Type 5/6 header into a
block spanning later cheats.

4) **Low - the engine-location headline contradicts the later evidence.**
`REVERSING.md:19-22` and `ENGINE.md:40-43` say the engine is not in the firmware
image, while the later evidence establishes that it is inside the packed
firmware for three images and stored raw elsewhere in the ROM for six. The
supported statement is that it is not always in the unpacked firmware image.

5) **Low - the COMP01 measurements hold, but some origin claims do not.** The
stream layout, output sizes, escape bytes, opcode counts, and compression ratios
reproduce. Claims that the compressor scans for rare bytes, that standard
formats never use data-dependent escapes, and that the arithmetic-run opcode
was aimed specifically at firmware tables do not follow from the decoder or
corpus. They are hypotheses, not recovered implementation facts.

6) **Low - `instruction-for-instruction identical` means normalized
identity.** `fxcmp.py` canonicalizes absolute addresses before reaching this
result. Raw operands differ because the routines and tables are relocated.
`FINDINGS.md:578-582` should say `the same normalized instruction sequence` or
`behaviorally identical`.

7) **Low - one exact default-off cross-database count is not reproducible as
stated.** The reported 133 flagged Pro 2.20 rows, 121 key-zero rows, and 120 rows
that reach the wrong address all reproduce. The claim that exactly 101 also
appear in encrypted V2 databases has no saved script or matching rule.
Reasonable exact matching criteria produce nearby but different totals. The
examples and defect are sound; the normalization procedure behind 101 must be
preserved before the value is independently repeatable.

### Independent verification

1) An independent C differential harness completed 2,214,854 assertions. It
covered every first-byte route, systematic single-byte perturbations, 100,000
random normal codes, all 65,536 Supercode size encodings, all 65,536 Megacode
size encodings, every payload key at block boundaries, inverse and preservation
properties, the Punky Bear fixture, and CLI block streams. It found no
supported-path mismatch.

2) The repository oracle completed 44,867 checks over normal codes, firmware
reads, firmware writes, blocks, Type A, and all five recovered databases with
zero failures. Its separately reported 320 unimplemented-route gaps, 64
`fcd/not` cases, 200 unencryptable firmware types, and 21 database gaps are
modeled coverage boundaries, not failed equations.

3) Across all nine ROMs, `fxtest.py` reproduced `XP_KEYED_TYPES = 0xABFB`, all
30 Punky Bear payload rows with payload key 6, and zero disagreements for 1,536
inputs under 17 key settings. `fxcmp.py` reproduced normalized identity for all
five V2 routes and the four documented FX scheduling differences.

4) `engineemu.py` reproduced nine firmwares by 26 cases, the two Type 4-only
V2/FX differences, both zero-length Type 5/6 runaways, and the
conditional-at-list-end tail dispatch. These are observations of extracted
engine blobs; staging behavior remains a static/model result as disclosed.

5) Seven `.fcd`/decrypted-image pairs and two raw ROMs round-tripped
byte-for-byte through the C ROM transform. Strict C99 builds passed with Apple
Clang 17 and Homebrew LLVM 22. Ordinary, Type 5, Type 6, and Type A fixtures
passed under AddressSanitizer and UndefinedBehaviorSanitizer; the
`-fshort-enums` run in C finding 1 is the portability exception.

6) Parsing the five database chains reproduced 13,205 rows, 10,085 cheats, and
all per-image game/cheat/row totals. `audit2.py` reproduced 49 apparent blocks,
48 fitting their cheat boundary, 34 with the exact declared size, and the one
documented overrun. `boundary.py` reproduced the documented clean
headers/codes after inside-entry boundaries.

7) The 14 known Type 5 examples matched only with the documented payload byte
swap: 14/14 swapped and 0/14 unswapped. The direct Type 5/6 size formulas and
route table are independently visible in the pinned upstream implementation,
which still retains the documented Special32 and payload-key-7 differences.

8) COMP01 output sizes, offsets, per-opcode use, repack budgets, and FX outer
descrambling reproduced. The stronger historical-intent claims in research
finding 5 did not.

### Scope limits that remain valid

1) No real shipped payload-key-7 Type 5 block or payload-key-6/7 Type 6 block
was found. Those paths are supported by firmware static analysis and modeled
tests, not a known-plaintext corpus specimen.

2) The FX self-destruct behavior is established statically. It was not
triggered on hardware.

3) The recovered database corpus is incomplete in places, including missing
early records in at least one chain. Claims about shipped databases apply to
the five recovered chains, not every database ever distributed.

### Disposition of the fifth pass

Applied 2026-07-29. All eleven findings and all four lower-severity items were
reproduced before being acted on; none turned out to be wrong. Two of the
audit's own numbers did not survive re-measurement and are noted below.

C findings:

| # | correction | what was done |
|---|---|---|
| 1 | `%i` into a short enum | reproduced exactly - Homebrew LLVM 22 with `-fshort-enums` gives ASan a 4-byte write into a 1-byte `key` for `xpcrypt -e 7`. `-e` now parses with `strtol()` into a `long`, requires the whole argument to be consumed, and converts to the enum after the range check. That closes the `-e 4junk` item with it |
| 2 | whitespace changes the bytes | reproduced: `1 23456789 ABC` came out `01234567 89AB`, dropping the last digit, because `is_code()` allowed a gap anywhere and each fixed-width `%02hhx` then ate it. `is_code()` and the `sscanf()` are replaced by one `parse_code()` that collects the twelve digits and converts from those, so the accepted set and the parse agree by construction - whitespace is a separator and cannot move a byte. Nothing that parsed before parses differently, only `1 23456789 ABC`-shaped input, which now reads as its digits do |
| 3 | I/O failures exit 0 | reproduced both: `xpcrypt -d < .` and a closed stdout each exited 0. `crypt_codes()` now checks every `printf`, `ferror(stdin)` and the final `fflush`/`ferror(stdout)`, and `main()` uses its return value; `crypt_rom()` checks both `fseek()`s and closes the output file explicitly so a buffered write error is reported |
| 4 | fidelity qualification | a block comment at the top of `crypto.c` lists all six deliberate departures - Special32/33, the surviving default-off bit, unknown payload keys left alone, size-0 headers treated as ordinary codes, type A running to end of input, and the engine/database/COMP01/anti-tamper behaviour not implemented at all - and points at the notes for each |
| low | `-d`, header guard, `check` | `-d` resets an earlier `-e`/`-r` (reproduced: `-e 4 -d` used to encrypt); the guard is `XP_CRYPTO_H`, since a leading underscore before a capital is reserved; the root `Makefile` gained a `check` target. It delegates to `research/`, because that is where the oracle and the dumps are - `TODO.md` item 1 still owns the move |

Research findings:

| # | correction | what was done |
|---|---|---|
| 1 | `fwemu.py` signed loads | reproduced with a focused two-instruction test: `lb` of `0xFF` then `srl` gave `FFFFFFFF` for `7FFFFFFF`, and `sra` gave `7FFFFFFF` for `FFFFFFFF`. `lb`/`lh` now mask back to 32 bits, which is the invariant the rest of the interpreter already assumed; `run()`'s docstring states it. The impact claim was checked rather than taken: `fxtest.py` and `engineemu.py -v` produce byte-identical output before and after |
| 2 | gates do not assert | reproduced - a one-image `roms/` still printed `all 1 firmwares agree` and exited 0. `fxtest.py` now requires nine images, `XP_KEYED_TYPES = 0xABFB` on every one, and a clean 30-row known plaintext at payload key 6; `engineemu.py` requires nine images and that the differing cases are *the two type 4 ones* splitting 5 V2/Pro against 4 FX, not merely that two of them differ. Both verified to fail on the one-image corpus and to pass on the real one |
| 3 | round-trip population | correct: 13205 is the five chains, and the three databases hold 8903 of it. Rather than narrow the claim to an unreproducible 8903, the missing script is now `roundtrip.py` - `-e K \| -d` over **all five** databases, one cheat entry at a time wherever a block is involved so a header cannot reach into the next cheat. 13205 lines x 4 keys, 0 not reproduced, and it is in `make check` |
| 4 | engine-location headline | `ENGINE.md` §"four findings" and `REVERSING.md`'s pointer both said the engine is not in the firmware image; they now say three of the nine keep it inside the packed firmware and six keep it raw elsewhere, which is what §12 already showed |
| 5 | COMP01 origin claims | the "scans for rare bytes" half turned out to be measurable, so it was measured: `escrank.py` shows the first escape is the *rarest* byte of the unpacked stream in all nine images, and all four are among the 14 rarest of 256. That makes the encoder inference evidenced rather than asserted, and it is now labelled as an inference either way. "Standard formats never use data-dependent escapes" is scoped to the ones we looked at, and the arithmetic-run opcode's purpose is marked a guess about intent with the measured 9-14 uses beside it |
| 6 | normalized identity | `fxcmp.py` drops absolute addresses before comparing, so `FINDINGS.md` now says "the same normalized instruction sequence" in both places and says why the raw operands differ. The engine-handler sentence got the same treatment, plus a pointer to the three byte-distinct blobs |
| 7 | the 101 | **the audit understated this.** 133, 121 and 120 all reproduce exactly. 101 does not reproduce under any rule tried: a search over every subset of the other four databases crossed with all three base populations found no 101 anywhere. `defaultoff.py` states a rule - clear bit 3, look for the same six bytes as a dispatched code row elsewhere - and gets 118 of the 121, the same 118 whether all four other databases or only the three that ship encrypted are searched. The notes carry 118 and name the rule |

Also from this pass: `roundtrip.py`, `escrank.py` and `defaultoff.py` are in
`make check`, each asserting its own expected result, and all nine producer
substitutions still exit 2:

```
make strict CC1=false CC2=false ; make sanitize CC2=false
make oracle PY=false            ; make roundtrip PY=false
make firmware PYCS=false        ; make engine PYCS=false
make tables PYCS=false          ; make analyses PYCS=false
make analyses PY=false
```

## Follow-up re-audit of the fifth-pass fixes - 2026-07-29

### Bottom line

The repaired research results hold against the current primary artifacts. The
signed-load interpreter fix gives the correct MIPS results; all nine firmware
decryptors and engine blobs still produce the published behavior; the
per-cheat database round trip reproduces all 13,205 rows under all four keys;
and the revised COMP01 and default-off counts reproduce from the ROM corpus.

The root C fixes also reproduce. Short-enum sanitizer builds are clean, the
malformed-whitespace example is parsed from all twelve digits, code-stream and
late ROM-output failures are propagated, and the 44,867-check firmware oracle
still has zero failures. The remaining C points below are edge handling and an
explicit product-scope boundary, not a cipher regression.

Five of the seven previously open research findings are therefore fully
resolved. Finding 2 is partly fixed, not closed: the gate now checks
substantially more than it did, but the counterexamples below still exit
successfully. Finding 5's corpus measurements and inference labels are fixed,
but one comparison of outside formats remains too broad. Neither issue is
evidence that a currently published cipher or engine result is false.

### C implementation follow-up

| fifth-pass item | follow-up status | primary evidence |
|---|---|---|
| enum `%i` overwrite and `-e` suffixes | **Resolved** | `xpcrypt.c:350-370` parses with `strtol()` into a `long`, validates complete consumption and range, then casts. Strict and ASan/UBSan builds with `-fshort-enums` pass; `4junk`, `7.5`, and an overflowing value exit nonzero. |
| whitespace-dependent parsing | **Resolved** | `xpcrypt.c:82-135` collects exactly twelve hex digits and pairs those digits itself. `1 23456789 ABC` now produces `12345678 9ABC`; no final digit is dropped. |
| code/ROM I/O failures | **Resolved for the data paths; low-risk edges remain** | `crypt_codes()` checks reads, writes, and final flushing, and `main()` propagates its result. ROM seeks and the final output close are checked. Directory stdin, closed code-output stdout, and a simulated late ROM-output failure now exit nonzero. `-h` and `-V` still ignore `printf`/flush failure (`xpcrypt.c:376-381`), so `xpcrypt -h 1>&-` exits zero; the already-read input ROM's `fclose()` at line 299 is also unchecked. |
| Special32/Special33 fidelity | **Documented scope, not implemented** | `crypto.c:27-49,83-90` now states this and the five other deliberate cartridge differences. First bytes `32/82` and `33/83` still pass through, so the implementation is faithful only to its documented converter subset, not every firmware route. |
| `-d`, header guard, root check target | **Resolved** | `-d` resets mode/key, the guard is `XP_CRYPTO_H`, and root `make check` runs the differential oracle. The root target is intentionally narrower than `research/Makefile`'s strict, sanitizer, firmware, engine, and analysis gates. |
| extra positional operands | **Low - still open** | Code mode ignores every positional operand, and ROM mode ignores operands after input/output. Both `xpcrypt unexpected-code-arg` and `xpcrypt -r in out extra` exit zero. Reject extras if silently accepting a mistyped invocation is not intended CLI behavior. |

### Status of every fifth-pass research finding

| # | follow-up status | primary evidence |
|---|---|---|
| 1 | **Resolved** | A focused `lb 0xFF; srl`/`sra` execution now returns `7FFFFFFF` and `FFFFFFFF`. The nine-ROM `fxtest.py` and `engineemu.py` runs also pass with the corrected unsigned-register invariant. |
| 2 | **Still open, partially resolved** | Nine-image count, keyed mask, named differing cases, and a 5/4 split are now checked. Exact group membership, exact engine traces, fixture completeness, and several published analysis values are not; see remaining finding 1. |
| 3 | **Resolved** | `roundtrip.py` parses all five recovered chains and runs each stateful cheat separately. It reports `13205 code lines x 4 keys, 0 not reproduced` and exits zero; changing the corpus total or any returned row makes it nonzero. |
| 4 | **Resolved** | `ENGINE.md` now says three blobs are in packed firmware and six are raw elsewhere in ROM; `REVERSING.md` uses the same qualified statement. This matches `engine.py`/`fwimage.py` over the nine dumps. |
| 5 | **Partially resolved** | `escrank.py` reproduces first-escape rank 0 in 9/9 images and worst rank 13. The notes now label encoder frequency selection and opcode intent as inferences rather than recovered facts. The script's weaker gate remains under finding 2, and the outside-format wording remains under finding 3 below. |
| 6 | **Resolved** | Both affected passages now say "normalized instruction sequence" and explain the relocated absolute operands. This matches what `fxcmp.py` actually compares. |
| 7 | **Resolved as a research claim** | `defaultoff.py` reproduces 133 flagged rows, 121 keyless rows, 120 wrong-address rows, and 118 rows also shipped without the bit under the now-stated dispatched-row rule. The second-pool assertion gap remains under finding 2. |

### Re-run commands and results

The following commands were run from `research/` against the current nine ROM
artifacts. Python bytecode writes were disabled during the follow-up.

```sh
uv run --with capstone python fxtest.py
# all 9 firmwares agree; ABFB in all 9; key 6; 30/30 rows in all 9;
# 1536 codes x 17 settings; zero model or cross-firmware differences

uv run --with capstone python engineemu.py
# 9 firmwares x 26 cases; only "4 slow motion" and
# "4 + default-off" differ, in the observed five-V2/four-FX groups

uv run python escrank.py
# first escape rank 0 in 9/9; worst of the four ranks is 13

uv run python defaultoff.py
# 133 flagged; 121 keyless; 120 wrong address; 118 also shipped

uv run python roundtrip.py /tmp/xpcrypt-research-audit-20260729
# 13205 code lines x 4 keys, 0 not reproduced
```

The temporary `xpcrypt` used by the last command was compiled directly from the
current `xpcrypt.c` and `crypto.c`; no repository output was needed. A
focused interpreter program separately produced:

```text
lb 0xFF; srl by 1 -> 7FFFFFFF
lb 0xFF; sra by 1 -> FFFFFFFF
```

The full `make check` also passes in the current worktree, and every listed
`false` producer substitution in the fifth-pass disposition returns status 2.
Those controls establish pipeline failure propagation; they do not establish
that a producer returning zero asserted the right detailed result.

### Remaining findings

1) **Medium - research finding 2's gate still accepts materially wrong
results.** The real outputs above are correct, but six assertion gaps remain:

   * `engineemu.py:299-304,384-390` checks the two case names and group sizes
     `[4, 5]`, not which ROMs are in each group. It also has no expected trace
     for any case. A focused fake-engine run put one FX name in the five-ROM
     group, one V2 name in the four-ROM group, and replaced every otherwise
     agreed trace with `x group=0`; `engineemu.main()` still returned 0:

     ```text
     2 of 26 cases differ between firmwares
     wrong-membership gate rc=0
     ```

     Assert the exact V2/Pro and FX filename sets for both Type 4 cases and
     preserve expected signatures, at least for the traces the notes quote.

   * `fxtest.py:61-66` compares known plaintext with `zip()` and reports the row
     count from `pb.enc` alone. Removing the last row from `pb.clear` still
     returns `(payload key 6, 30 rows, 0 bad)` and satisfies the checks at
     `fxtest.py:85-92`. Assert equal fixture lengths before comparing them.

   * `defaultoff.py:89-102` stores the first pool's 118 with `setdefault()`, so
     the separately printed claim that the three encrypted databases also give
     118 cannot affect the exit status. Store and assert both named pool results.

   * `escrank.py:24-25,28-62` does not require nine images and allows a worst
     rank of 32, while the published claim is nine images and all four escapes
     among the 14 rarest bytes (worst rank 13). Restricting it to
     `english.dec` alone produced the expected rank 13 and `one-image gate
     rc=0`. Assert nine and `worst <= 13`, or change the published bound to the
     intentionally gated one.

   * The older display-only gaps remain. `Makefile:147-163` greps or prints
     `engine.py -s`, `dbtypes.py`, `packstats.py`, and `fxcmp.py`; those scripts
     do not assert the exact published classifier set, type histogram, COMP01
     ranges, route identities, or route count. `pipefail` catches a crashing or
     false producer, but a zero-exit producer emitting one matching line can
     still report wrong values and pass. Give each producer explicit expected
     values and a nonzero mismatch exit, then let the Makefile filter its
     already-validated output.

   * The aggregate gate is not parallel-safe. `check` exposes `strict`,
     `sanitize`, `oracle`, and the other suites as independent prerequisites,
     while the first two repeatedly clean and rebuild the same root objects and
     binary (`Makefile:62,68-95`). `make -j4 -C research check` reproducibly
     failed with missing `../xpcrypt` errors and a mixed sanitizer/non-sanitizer
     link; `-j1` passes. Serialize the shared-build prerequisites, mark the gate
     non-parallel, or give each target isolated build outputs.

   `FINDINGS.md:10-17` consequently overstates the disposition when it says all
   fifth-pass findings have been applied and that `AUDIT.md` has no outstanding
   work. The research conclusions are current, but this gate finding remains
   open until the assertions above are made or the advertised gate scope is
   narrowed.

2) **Low - `fwemu.run()` does not enforce its unsigned-register invariant at
the API boundary.** The signed `lb`/`lh` results are now canonical 32-bit values,
so the original finding and every current firmware/engine caller are fixed.
However, `args`, `regs`, and `sp` are copied into the register file without a
32-bit mask at `fwemu.py:113-118`. Seeding `$a0` with Python `-1` and executing
`srl $v0,$a0,1` still returns `-1`/`FFFFFFFF` instead of `7FFFFFFF`. Mask seeded
values, or explicitly require and validate canonical unsigned inputs.

3) **Low - the revised outside-format comparison still uses an inaccurate
blanket description.** `FINDINGS.md:369-374` and `REVERSING.md:319-323` say the
formats examined use a fixed tag byte or bit flags and refer only to unnamed
"general-purpose compressors." The supported narrower result is that the
DEFLATE, inspected LHA/LZH methods, and inspected LZX variants have fixed token
meanings, no four byte values selected per stream as opcode sentinels, and no
opcode that emits `start + n*step` output. Their token *codes* are not always
fixed tags or flags: DEFLATE can transmit a per-block Huffman codebook
([RFC 1951 sections 3.2.3-3.2.7](https://www.rfc-editor.org/rfc/rfc1951.html#section-3.2.3));
LHA/LZH includes adaptive and per-block Huffman methods
([`dhuf.c`](https://github.com/jca02266/lha/blob/16619b066b189ef289bb8b07b37d1c38d550da99/src/dhuf.c#L267-L291),
[`huf.c`](https://github.com/jca02266/lha/blob/16619b066b189ef289bb8b07b37d1c38d550da99/src/huf.c#L405-L460));
and Microsoft's documented LZXD variant uses Huffman-coded literal/match tokens
([MS-PATCH section 2.6](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/687e0350-b236-4b80-8b43-2c85c5bf078d)).
Name the exact families/variants and say "fixed bitstream grammar and token
meanings" rather than "fixed tag byte or bit flags." If `LZX` means the Amiga
format rather than Microsoft's LZXD/Cabinet family, say so separately; they are
different formats and the former has no public original specification in this
evidence set.

### Disposition of the sixth pass

Applied 2026-07-29. Every finding was reproduced before it was acted on; none
turned out to be wrong. The theme is the one the pass names: a gate that runs
is not the same as a gate that checks, and several of the fifth pass's gates
were the former.

| # | correction | what was done |
|---|---|---|
| 1a | engine gate ignores membership and traces | reproduced with the audit's own counterexample - a fake engine that puts `english.dec` in the V2 group and `xtjpro.dec` in the FX group and flattens every trace used to exit 0. `engineemu.py` now names both image sets and requires the two type 4 cases to group as *those* five against *those* four, and every case carries a recorded digest over its traces *and* their group membership (`--record` regenerates the table). The fake now exits 1 and says which case moved |
| 1b | known plaintext compared with `zip()` | reproduced: `pb.clear` one row short still reported `30/30 rows match` and exited 0, because the row count came from `pb.enc` alone. The two halves are length-checked before they are compared |
| 1c | only one `defaultoff.py` pool gated | `setdefault()` meant the second pool's number could not fail. Both pools are named constants now and both are in `EXPECT`; "118 either way" is the published claim, so both have to be 118 |
| 1d | `escrank.py` gate weaker than the claim | it accepted one image and a worst rank of 32 while the note says nine images and 13. Reproduced on a one-image `roms/`, which passed. Now nine and 13, and the one-image run exits 1 |
| 1e | four producers assert nothing | `engine.py` checks the dispatch chain against the V2/Pro and FX orders and the staging scan against 13-15 sites, 9 read, types `5 6 7 9 A D F`; `dbtypes.py` checks the published totals column; `packstats.py` checks the rle16 and arith-run use and saving ranges, the store-only overshoot and the LZ share; `fxcmp.py` checks nine images, `0xABFB` in each, four routines identical to the baseline and the four FX routes that differ. Each verified to fail when its expectation is perturbed |
| 1f | `make -j4 check` races | reproduced three times out of three: every C target rebuilds the same objects in the parent with different flags, so `-j` gave a missing `../xpcrypt` and a half-sanitized link. `.NOTPARALLEL` with the reason written down; `-j4 check` now passes |
| 2 | `fwemu.run()` seeds unmasked | reproduced through both `args` and `regs`: `$a0 = -1` then `srl` returned `-1`. Masked at the boundary, the same invariant `lb`/`lh` restore on the way out |
| 3 | outside-format comparison too broad | the three formats actually read are now named - DEFLATE (RFC 1951), the LHA/LZH methods in `jca02266/lha`, and Microsoft's LZXD, explicitly not the Amiga LZX - and the contrast is drawn where it holds: fixed bitstream grammar and token meanings, no per-stream opcode sentinels, no `start + n*step` opcode. The claim that their token *codes* are fixed tags or bit flags is withdrawn, since all three Huffman-code them |
| 4 | CLI edges | reproduced all three: `xpcrypt -h 1>&-` and `-V` exited 0, and both `xpcrypt stray-arg` and `xpcrypt -r in out extra` exited 0 while ignoring the operand. `-h`/`-V` go through a checked `print_out()`; a stray operand is an error naming what it should have been; the input ROM's `fclose()` is checked and warns, since by then the image is already in memory and refusing to write the output would be the worse answer |

Separately, the committed root files and the tip commit message referred to
`research/` as though it were part of the repository. It is not. The root
`check` target keeps a `TESTDIR` variable but says in the comment that the suite
lives with these notes, and fails plainly when the directory is absent instead
of reporting a run that did not happen as a pass; `crypto.c` points at the
issue tracker rather than at `research/*.md`; and the commit was amended so its
message says the same.

## Seventh-pass re-audit of the sixth-pass fixes - 2026-07-29

### Bottom line

The real nine-ROM corpus still produces every published cipher, engine,
default-off, escape-rank, type-total, and COMP01 result checked in this pass.
The exact engine traces and family membership are now gated, the focused bad
fixtures are rejected, `fwemu.run()` canonicalizes all seeded registers, and
the aggregate is serial even when invoked with `-j4`.

Sixth-pass items 1a-1d, 1f, and 2 are resolved. Item 1e is partial: its new
checks validate real output, but four producers still accept wrong results that
preserve a count, total, or inclusive bound. Item 3 is resolved for the named
compression grammars, but the adjacent claim about a generic LZ77 compression
ratio has no supporting comparator. These are verification/prose findings, not
contradictions in the recovered Xploder algorithms.

### C implementation follow-up

The committed CLI follow-on in `fc52dae` resolves the remaining operational C
findings without changing the supported crypto results:

| item | status | exact follow-up evidence |
|---|---|---|
| help/version output errors | **Resolved** | `print_out()` checks `printf()` and `fflush()` (`xpcrypt.c:244-256`), and `-h`/`-V` propagate failure (`xpcrypt.c:397-400`). Both commands return 1 with closed stdout and print `Error: could not write to stdout`; normal output still returns 0. |
| extra positional operands | **Resolved** | Code mode rejects any operand and ROM mode rejects a third one (`xpcrypt.c:407-434`). Both focused invocations return 1 before doing unintended input or file work. |
| input-ROM close | **Resolved under the stated policy** | `xpcrypt.c:313-320` checks `fclose()` and warns, then continues because the complete ROM is already in memory. This pass source-verified that branch; unlike the other I/O paths, close failure is intentionally a warning rather than command failure. |
| compiler and regression checks | **Passed** | The isolated 44,867-case oracle and full nine-ROM gate pass. Direct strict C99 compilation passes under Apple Clang 17 and Homebrew LLVM 22.1.8; the `-fshort-enums` ASan/UBSan key probe is clean. |
| fidelity/build scope | **Unchanged qualification** | Special32/Special33 remain documented pass-through exclusions, so this is not a literal implementation of every firmware route. Root `make check` deliberately delegates only to the oracle; the full strict/sanitizer/firmware/engine/analysis aggregate remains `research/Makefile`. |

### Status of every sixth-pass research item

| item | status | exact follow-up evidence |
|---|---|---|
| 1a - engine membership and traces | **Resolved** | The nine real images match all 26 recorded trace/group digests. A fake engine with `english.dec` in the V2 group, `xtjpro.dec` in the FX group, and every trace replaced by `x group=0` now returns 1 and reports both membership and digest changes. |
| 1b - truncated known plaintext | **Resolved** | The real fixture is 31 rows per half and gives 30/30 payload matches in all nine firmwares. Removing the last `pb.clear` row now stops with `pb.enc has 31 rows, pb.clear 30`. |
| 1c - second default-off pool | **Resolved** | Both pools reproduce 118. Perturbing only the expected encrypted-three result to 117 makes `defaultoff.py` return 1 and name that pool. |
| 1d - escape-rank corpus/bound | **Resolved** | The real result is 9/9 first escapes at rank 0 and worst rank 13. Restricting the script to `english.dec` now returns 1 because one image is not the published corpus. |
| 1e - display-only producers | **Partial** | The real `engine.py`, `dbtypes.py`, `packstats.py`, and `fxcmp.py` runs return 0 with their published output. Their new assertions catch many perturbations, but the focused counterexamples under remaining finding 1 still return 0. `fxprot.py` was not covered by the fix at all. |
| 1f - parallel aggregate | **Resolved** | An isolated `rtk make -j4 -C research check` under GNU Make 3.81 returned 0 and ended in `all suites passed`. `.NOTPARALLEL` serializes the shared parent build outputs. No build was run concurrently with another audit agent. |
| 2 - unmasked interpreter seeds | **Resolved** | Focused `srl` programs seeded with Python `-1` through `args`, `regs`, and `sp` now return `7FFFFFFF` in all three cases. `fwemu.py:118-122` masks each API input to 32 bits. |
| 3 - outside-format comparison | **Resolved for the cited grammars; adjacent ratio claim open** | The named primary sources support Huffman-coded literal/match grammars and no arithmetic-progression token. The remaining unsupported ratio sentence is finding 2 below. |

### Positive re-runs

The following current commands returned 0 against the primary ROM/database
artifacts:

```sh
uv run --with capstone python fxtest.py
# 9 images; ABFB throughout; 30/30 known rows; 1536 x 17; no differences

uv run --with capstone python engineemu.py
# all 26 recorded digests; exact V2/Pro-vs-FX membership; two Type 4 cases

uv run --with capstone python engine.py
uv run --with capstone python engine.py -s
# the two observed chains; 13-15 sites; 9 read; 5 6 7 9 A D F

uv run python defaultoff.py
uv run python escrank.py
uv run python dbtypes.py
uv run --with capstone python packstats.py
uv run --with capstone python fxcmp.py
uv run --with capstone python fxprot.py
```

The last command reproduced eight live copyright checkers and the Pro 2.20
stub. V2/Pro live checkers are reached from Special32 and key 7; all four FX
checkers are reached from key 4. This is the published result, but `fxprot.py`
does not yet assert it.

### Primary compression-source check

The revised narrow comparison holds:

1) DEFLATE defines stored blocks or literal/length and backward-distance
symbols under fixed or per-block dynamic Huffman codes. Its grammar contains no
per-stream byte sentinel and no arithmetic-progression output token
([RFC 1951 sections 3.2.3-3.2.7](https://www.rfc-editor.org/rfc/rfc1951.html#section-3.2.3)).

2) At pinned commit `16619b0`, LHA maps `lh1` through `lh7` to their adaptive or
block Huffman decoders
([`slide.c:59-73`](https://github.com/jca02266/lha/blob/16619b066b189ef289bb8b07b37d1c38d550da99/src/slide.c#L59-L73)).
Its common output loop has only a literal arm and an LZSS match-copy arm
([`slide.c:423-472`](https://github.com/jca02266/lha/blob/16619b066b189ef289bb8b07b37d1c38d550da99/src/slide.c#L423-L472));
the adaptive and block decoders are visible in
[`dhuf.c:267-291`](https://github.com/jca02266/lha/blob/16619b066b189ef289bb8b07b37d1c38d550da99/src/dhuf.c#L267-L291)
and
[`huf.c:405-460`](https://github.com/jca02266/lha/blob/16619b066b189ef289bb8b07b37d1c38d550da99/src/huf.c#L405-L460).

3) Microsoft's LZXD specifies Huffman-encoded literal and match tokens, with
the trees carried by the block header
([MS-PATCH section 2.6](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/687e0350-b236-4b80-8b43-2c85c5bf078d)).
That supports the notes' now-scoped contrast with COMP01's four byte-valued
opcode sentinels and arithmetic-run operation. It does not describe the
unrelated Amiga LZX archive format, which the notes now explicitly exclude.

### Remaining findings

1) **Medium - the analysis gate still accepts wrong semantic assignments.**
Five focused controls demonstrate the remaining surface:

   * `fxprot.py:113-137` has no corpus, route, live/stub, signature, or exit
     assertion. With an empty corpus `main()` returns `None` (process success),
     and `Makefile:131-132` only greps for at least one `live`. A producer with
     one live line satisfies that pipeline although the published result is the
     exact eight-live/one-stub assignment and exact V2/FX routes.

   * `fxcmp.py:113-159` requires four routines identical and four with the
     expected difference list, but never binds either result to filenames. A
     fake corpus swapping one V2 and one FX classification returned 0 with the
     same 4/4 counts. Assert the exact four V2/Pro names and four FX names.

   * `engine.py:158-163,207-215` similarly allows either dispatch chain for
     every image. Assigning the FX chain to all five V2 names and the V2 chain
     to all four FX names satisfies its predicate. `engineemu.py` would catch
     that runtime change in the aggregate, but `engine.py` does not assert the
     static per-file claim it prints.

   * `dbtypes.py:93-125` asserts only the totals column of the published
     per-database table. Moving every row to the first database while preserving
     all 16 totals made `counts()` return 0. Record and compare the five columns
     as well as their sums, or explicitly narrow the advertised gate to totals.

   * `packstats.py:27-32,75-89` checks that every image falls inside the
     published global ranges, not that the corpus actually attains both stated
     extrema. A nine-image fake corpus with every RLE16 and arithmetic-run value
     in the middle of the intervals returned 0. If `4-19`, `9-14`, and the
     percentage ranges are observed minima/maxima rather than safety bounds,
     assert `min()` and `max()` (or the exact per-image values).

   The real outputs remain correct. These controls show why the banner must not
   yet say every published value is regression-gated.

2) **Low - the generic LZ77 ratio comparison remains unsupported.**
`FINDINGS.md:367-368` says ratio 0.75 is "what plain LZ77 gets on mixed code and
data"; `REVERSING.md:312-314` says it is "exactly" what plain LZ77 gives. None
of the cited specifications defines a plain-LZ77 encoder, a mixed-code/data
corpus, or an expected ratio, and no local script performs that comparison.
The measured COMP01 ratio is valid. Remove the comparator or label it as an
informal expectation tied to a named encoder and reproducible corpus.

3) **Low - repository-state wording contradicts the current index.**
`git ls-files research` and the cached diff each contain 37 research paths, all
staged as additions. Three newer scripts (`defaultoff.py`, `escrank.py`, and
`roundtrip.py`) remain untracked, while the current `HEAD` tree contains no
`research/` paths. Thus "not part of this repository" describes the committed
`HEAD` only; it does not describe the current index/worktree or the tree that
the staged additions would create.

`FINDINGS.md:7-8` makes the coherent distinction: the research lives in the
xpcrypt repository but is kept apart from the shipped source. In contrast,
root `Makefile:17-20,25-27` says unqualifiedly that the transcription and
differential suite are "not part of this repository", and the historical
sixth-pass disposition above says "It is not." No tracked `.gitattributes` or
`export-ignore` rule defines a separate release/archive scope, so those
statements conflict with the staged index as written. If release scope is
intended, they should instead say that the material is not part of the shipped
xpcrypt source or release archive and implement that exclusion.

## Post-fix review - 2026-07-29

### Bottom line

Commit `4ec59c8` faithfully implements the type A stream convention documented
by the firmware research. Its message matches its four-file diff and stays
within the repository's 80-column commit-message convention. The configured
strict builds and Clang sanitizer build pass, the sample runs cleanly under
ASan/UBSan, and the full oracle passes 44,867 checks:

```
 1,792  normal codes
 8,200  encryption read-backs
20,590  generated type 5/6 block checks
 1,080  type A block checks
13,205  recovered database lines
```

The nine firmware crypto routines still agree across 1,536 codes and 17 key
settings. The engine harness executes 26 cases across all nine images and
reproduces the single type 4 family difference in two cases, both zero-length
runaways, and the conditional-at-list-end defect. The database and COMP01
scripts reproduce their published scoped results.

Six prose defects remained. The recheck below marks three resolved and narrows
the remaining three to the exact sentences that still need work.

### Findings from the review

> **Historical:** these are the six findings as originally reported. Their
> current status is under "Disposition of the latest re-audit" and "Final
> verification" below; do not read the old line references as current defects.

1) **`FINDINGS.md` still gives the wrong trigger for the Supercode row-count
bug.** `FINDINGS.md:424-425` says the list walker miscounts whenever
`lo >= 0xFB` and `hi != 0`. The corrected derivation in `ENGINE.md:1178-1193`
and `REVERSING.md:684-688` is narrower: the carry is lost only when `hi` is
odd. A nonzero even high nibble gives the same result under `or` and `add`.

Follow-up item 8 was therefore only partly applied. Replace `hi != 0` in
`FINDINGS.md` with the odd-high-nibble condition.

2) **The repository-state correction was not applied and now contradicts the
index.** The research notes and scripts are currently staged as new tracked
files, the root `.gitignore` does not ignore `research/`, and only
`research/.gitignore` excludes `roms/`. These current claims are false:

- `ENGINE.md:3-4`: `research/` is untracked on purpose;
- `FINDINGS.md:7-8` and `FINDINGS.md:33-39`: the directory is untracked and
  stays that way;
- `TODO.md:10-12` and `TODO.md:25`: the directory is untracked;
- the follow-up disposition for item 12 below: `research/` stays untracked.

Decide whether the staged research is meant to be committed. If it is, describe
it as tracked research while keeping only `research/roms/` excluded. If it is
not, unstage it and retain the existing prose. The current mix cannot be true in
either state.

3) **`engineemu.py` asserts hardware behavior that the research explicitly
leaves open.** `engineemu.py:74-80` says an access outside its modelled map is a
bus error on real hardware. The emulator does not model the PlayStation bus; it
records the access, returns zero for a load, and discards a store. Accordingly,
`ENGINE.md:1173-1176` and follow-up item 4 correctly say that the effect of an
access such as `0x0802A798` on an R3000/PlayStation remains unestablished.

Remove the bus-error assertion or qualify it as a hypothesis. The executed
evidence establishes the address the engine presents to the memory interface,
not the console's response.

4) **The three engine blobs do not differ only in how they name the patch list
and enable flag.** `ENGINE.md:975-979` and `ENGINE.md:1324-1326` give that as the
complete explanation for the V2, Pro, and FX byte groups. A word-by-word diff of
the extracted `xteng` and `xtepro` blobs finds three changes:

| blob offset | V2 instruction | Pro instruction | purpose |
|---|---|---|---|
| `0x50` | `ori $t0,$t0,0x30B0` | `ori $t0,$t0,0x50B0` | per-pass callback |
| `0x60` | `ori $a0,$a0,0x2600` | `ori $a0,$a0,0x4600` | patch-list base |
| `0xB8` | `ori $v1,$v1,0x30A0` | `ori $v1,$v1,0x50A0` | type 4 helper |

The V2 and Pro enable gate is unchanged. The SHA-256 grouping and normalized
handler conclusion still hold, but the stated reason for the byte differences
must include the support-vector addresses.

5) **The staging-classifier scan does not prove that it found every
classification site.** `ENGINE.md:981-984`, `ENGINE.md:1463-1487`, and
`engine.py:101-111` say every type-nibble classifier must contain
`andi rX,rY,0xf0`, hence enumerating that instruction is exhaustive. That is one
compiler idiom, not a necessary property: a classifier could use a shift, a
different mask, a range test, or a table without that instruction.

The scan does establish that all seven V2/Pro and eight FX sites using this
idiom collectively mention `5 6 7 9 A D F`. Narrow the claim to that measured
result unless an independent exhaustive search or control-flow analysis rules
out other classifier shapes.

6) **The FX patch-list expression names the pointer slot, not the loaded list
base.** The FX row at `ENGINE.md:120-124` gives
`*(u32*)0x1F00007C + 0xBC` as the list base. The blob actually performs:

```
lw  $a3, 0x7C($a3)   # a3 = support-module pointer
lw  $a0, 0xBC($a3)   # a0 = list base loaded from the slot
```

Thus `*(u32*)0x1F00007C + 0xBC` is the address of the pointer slot; the list
base is `*(u32 *)(*(u32 *)0x1F00007C + 0xBC)`. Use the double dereference in the
table and make the same distinction unambiguous at `ENGINE.md:967-970`.

### Recheck findings

> **Historical:** these were the findings before the disposition below was
> applied. All seven have since been fixed; the final two were closed in the
> disposition of the latest re-audit.

Rechecked against the current index, an exhaustive evaluation of all 4,096
`hi`/`lo` pairs, and fresh extraction and disassembly of all nine engine blobs.
Items 1, 3 and 4 are resolved. The other three remain, followed by four new
findings about the scan, latest commit, and verification Makefile:

1) **The tracking-status correction still leaves a soon-to-be-stale history
claim.** `FINDINGS.md:27-28` still calls the research material something "not
in the repo," and `FINDINGS.md:34` says that none of `research/` is in
`17e31fc..HEAD`. Those are true only while the staged research files have not
been committed; they become false in the commit that adds them. They also
contradict the disposition's claim that repository-state assertions were
"dropped, not restated." Replace them with timeless scope statements, as
`ENGINE.md` and `TODO.md` now do.

2) **The classifier caveat still follows an exhaustive premise.**
`ENGINE.md:1493-1495` says that the compiler isolates a type nibble this way
"everywhere it does so," `ENGINE.md:1684-1686` says every classifier must
contain the instruction, and `engine.py:103-104` says this is the idiom emitted
"wherever this firmware classifies a code." Neither assertion is established by
enumerating the instruction. The later caveats at `ENGINE.md:1513-1519` and
`engine.py:105-108` are correct, but do not undo those premises. Describe this
as a scan of sites that use the `andi ..., 0xF0` idiom, without claiming that
every classifier uses it.

There is a second, independent problem with the same result: the script does
not enumerate every site that uses its chosen idiom. `engine.py:138-139` drops
an `andi` occurrence whenever its heuristic finds no nearby comparison
constant. The images contain 13 to 15 raw `andi ...,0xF0` occurrences while the
script prints seven V2/Pro or eight FX "sites." Not every raw occurrence need be
a classifier, but clear classifiers are omitted because their constants fall
before the six-instruction backward window:

```
xteng.dec   0x1A9A04  addiu $t6,$zero,0xF0
             ...
             0x1A9A48  andi  $v0,$v0,0xF0
             0x1A9A4C  bne   $v0,$t6,...

xteng.dec   0x1BA234  addiu $s3,$zero,0xA0
             ...
             0x1BA254  andi  $v0,$v0,0xF0
             0x1BA258  bne   $v0,$s3,...

english.dec 0x800331B0 addiu $t9,$zero,0xF0
             ...
             0x800331FC andi  $v0,$v0,0xF0
             0x80033200 bne   $v0,$t9,...
```

These omissions repeat types F and A, so the printed union happens to stay
`5 6 7 9 A D F`. The union is consistent with the inspected examples, but the
seven/eight site counts and the claim that the script establishes it are not.

3) **The FX summary still calls the pointer slot the list base.** The table and
two-load listing at `ENGINE.md:120-135` are now correct, but
`ENGINE.md:997-1000` says FX forms the "list base at `+0xBC`" from the support
pointer. Fresh disassembly again gives `lw $a3,0x7C($a3)` followed by
`lw $a0,0xBC($a3)`: support `+0xBC` is the slot, and its loaded value is the
list base. Say "list base loaded from the slot at `+0xBC`" there and make the
same distinction in the compressed summary at `ENGINE.md:1352-1354`.

4) **The latest commit message gives a compiler result that does not
reproduce.** Commit `14a428a` adds explicit `u8` casts around two complements.
The subject matches the two-line diff, the casts are behavior-preserving, and
the message is correctly wrapped. Its rationale says Clang rejects the parent
under `-Wconversion` while GCC accepts it. On this host, `/usr/bin/gcc` and
`/usr/bin/clang` are both Apple Clang 17.0.0, and both compile
`HEAD^:crypto.c` cleanly with the exact strict flags from the Makefile,
including `-Wconversion`, `-Wsign-conversion`, and `-Werror`. Keep the useful
explicit casts, but do not attribute them to a reproduced Clang error.

The same aliasing means `research/Makefile:49-55` runs Apple Clang twice while
printing "gcc" and "clang." It does not establish the GCC-and-Clang portability
claim. Use an actual GNU GCC binary when available, detect and report the
compiler family, or narrow the claim to the compiler that was run.

5) **The firmware and engine targets mask failed producers.** The recipes pipe
`fxtest.py` through `tail`, `fxprot.py` through `grep` and `sed`, and
`engineemu.py` through `tail` without pipefail. The shell therefore returns the
last filter's status instead of the Python program's. Reproduction:

```
$ make firmware PYCS=false
== the nine firmwares against each other ==
  copyright checkers found: 0
$ echo $?
0
```

This discards the nonzero status that `fxtest.py` deliberately returns on a
disagreement. `engineemu.py` has a separate enforcement gap: it prints the
number of differing cases but always exits zero, so an unexpected result is not
a test failure even without the pipeline. Consequently `make check` can reach
"all suites passed" without running or passing the advertised checks. Preserve
producer status through the filters and make the engine harness assert its two
expected type 4 differences.

6) **The advertised aggregate does not reproduce every published result.** The
Makefile and `FINDINGS.md` say that `make` runs the whole verification rig, but
the `tables` target runs only `engine.py -s` and `dbtypes.py`. It omits at least
the previously audited `audit2.py`, `fxcmp.py`, and `packstats.py` results. Add
those checks, or narrow "everything," "the lot," and "every suite" in the
Makefile, `FINDINGS.md`, and `TODO.md` to the subset actually run.

7) **The sanitizer sample does not exercise the block state machine.** The four
input rows at `research/Makefile:66-69` decrypt to types 7, 8, 9 and 8; none is a
type 5, 6, or A header. The comment at lines 58-60 therefore cannot promise that
a block-state walk-off will be detected. Add block fixtures under ASan/UBSan or
narrow the comment to the ordinary-code sample it runs.

### Disposition of the recheck (historical)

At this point on 2026-07-29, all seven original findings had reproduced. Items 1
to 3, 5, and 7 were resolved. Items 4 and 6 still needed the smaller corrections
that the latest re-audit and its disposition record below.

| # | correction | what was done |
|---|---|---|
| 1 | repository-state claim | `FINDINGS.md` no longer says what is or is not in the repo: the intro says the notes capture what the shipped source does not, and §1 says the feature landed in `17e31fc..HEAD` without asserting what did not. Nothing left to go stale on the next commit |
| 2 | scan omits its own idiom's sites | reproduced and worse than reported: `staging()` dropped 5 to 8 of the 13-15 `andi` occurrences per image, so "7 sites" was a filtered count presented as a complete one. It now returns *every* occurrence, prints unresolved ones as `(constant not resolved)`, and widens the backward window from 6 to 32 instructions - 13-15 sites, 9 read, in every image. `ENGINE.md` §6, §13 and §17 give the new numbers and stop claiming every classifier must use the idiom. The union is unchanged, and holds at four window sizes (67 to 81 of 124 occurrences resolved), which is now stated as the reason to believe it |
| 3 | slot versus base | `ENGINE.md` §6 says the base is *loaded from* the slot at `+0xBC`; §10 says "the patch list twice removed, in a slot at `+0xBC`". The table and listing at §2 were already right |
| 4 | commit rationale | **closed by the amend to `c5c1fca`** - see the disposition of the latest re-audit. In this task environment `cc` and `clang` both resolve to Apple Clang 17 and both accept `HEAD^:crypto.c` under the exact strict flags. Explicit `/opt/homebrew/opt/llvm/bin/clang` is Homebrew LLVM 22.1.8 and does reject it with two `-Wimplicit-int-conversion` errors. The diagnostic is real; the commit's generic "clang rejects, gcc accepts" was not. The Makefile side calls the legs `CC1`/`CC2` and prints each compiler's own version, so it no longer assumes two command names mean two implementations |
| 5 | pipelines mask failures | **resolved.** The Makefile uses bash and prefixes every filtered suite pipeline with `set -o pipefail`; `engineemu.py` and `audit2.py` assert their expected results (2 differing cases and 1 known-corrupt block). Direct fault injection makes `strict`, `sanitize`, `oracle`, `firmware`, `engine`, `tables`, and `analyses` each exit 2 when its producer is replaced with `false` |
| 6 | aggregate omits analyses | **resolved.** The new `analyses` target runs `packstats.py`, `fxcmp.py`, and `audit2.py`; `audit2.py` gained a no-argument mode over all five recoverable databases. The Makefile, `TODO.md` and - after the latest re-audit - `FINDINGS.md` all narrow the aggregate to the suites the notes lean on |
| 7 | sanitizer fixture misses blocks | `fixture.codes` / `fixture.expect` replace the inline sample: four ordinary codes, a Supercode with a key 6 payload, a Megacode with a key 7 payload and an inline data block whose rows include one that looks like a keyed code and one that looks like a Supercode header. The target also asserts the type A warning reaches stderr. Generated once and checked row by row against `romcrypt.py`, so it is not xpcrypt marking its own homework |

### Latest re-audit

The scanner now returns exactly the raw `andi ...,0xF0` addresses found by an
independent Capstone pass: 13 to 15 per image, 124 in total. With backward
windows of 6, 16, 32, and 64 instructions it resolves 67, 72, 81, and 81 of
them, respectively, while every image retains the union `5 6 7 9 A D F`.
Fresh disassembly of all four FX blobs confirms the two loads and the corrected
slot-versus-value wording. The 14 sanitizer rows independently match
`romcrypt.py`, and the real sanitizer target covers types 5, 6, and A.

The seven producer substitutions below all return make status 2, as required:

```
make strict   CC1=false CC2=false
make sanitize CC2=false
make oracle   PY=false
make firmware PYCS=false
make engine   PYCS=false
make tables   PYCS=false
make analyses PYCS=false
```

> **Historical:** at this point the following three corrections remained. The
> disposition immediately below records how all three were closed.

1) **Commit `14a428a` named the compiler result too broadly.** Apple Clang 17
accepts the parent with the exact strict flags; Homebrew LLVM 22.1.8 rejects it
with the two documented conversion diagnostics. The casts and no-behavior-change
claim held, but the message needed to identify those compiler families and
versions rather than say Clang rejected what GCC accepted.

2) **The aggregate-coverage wording was not fully narrowed.**
`FINDINGS.md:171` said `make` ran "every suite below," but the following table
also listed one-off tools such as `fxdb.py`, `boundary.py`, and `xcheck.py` that
the Makefile intentionally did not run. This also contradicted the correctly
narrowed Makefile row at `FINDINGS.md:180`. It needed to say that `make` ran the
core suites or the suites the notes lean on.

3) **The audit-pass count and completion status disagreed.** This file described
four passes and retained the commit-message exception. `FINDINGS.md:10-14` and
`TODO.md:10-13` described three passes and said all their corrections were
applied. The count needed to be made consistent and the completion claim scoped
to exclude the outstanding commit-message correction until it was amended.

### Disposition of the latest re-audit

Applied 2026-07-29. All three reproduced; nothing left open.

| # | correction | what was done |
|---|---|---|
| 1 | commit names the compiler too broadly | `14a428a` amended to `c5c1fca`, message rewritten to name Homebrew LLVM 22 as the compiler that diagnoses the parent and Apple Clang 17 as the one that accepts it. Message only - the tree is byte-identical (`7748c4f`), and the amend used `--only` so the staged research files stayed out of it |
| 2 | aggregate-coverage wording | `FINDINGS.md` §5.1 now says `make` runs the suites the notes lean on, not every script in the inventory that follows, and says why several of them are there at all. The Makefile header and `TODO.md` already said this |
| 3 | pass count and completion status | `FINDINGS.md` and `TODO.md` say four passes; with item 1 closed, "all of them have been applied" is now true without an exception to scope. The status header at the top of this file says the same |

### Final verification

The amended tip holds up against its exact diff and both named compilers:

- `c5c1fca` changes only the two implicit complement assignments to explicit
  `u8` casts, exactly as its subject and body say.
- Its tree is byte-identical to the pre-amend `14a428a` tree: both resolve to
  `7748c4f1fa33eb8e728b855493d710c586586220`.
- Apple Clang 17.0.0 compiles `HEAD^:crypto.c` with the exact strict flags;
  Homebrew LLVM 22.1.8 rejects it at the two assignments with
  `-Wimplicit-int-conversion`, as the amended message says.
- No commit-message line exceeds 80 columns.

`FINDINGS.md` and `TODO.md` now agree on four applied passes, and both narrow
the aggregate to the suites the notes lean on.

> **Historical:** one documentation defect remained at this point and was
> closed immediately below.

1) **The Makefile's pipefail explanation scoped itself to every suite.**
`research/Makefile:22-26` said "Every suite below is a Python program piped
through a filter." The strict and sanitizer targets were C builds, and
`oracle_test.py` was invoked directly. The pipefail fix itself was correct; the
subject needed to be narrowed to the filtered commands or pipelines it actually
governed.

**Applied 2026-07-29.** The comment now says *most* suites are a Python program
piped through a filter, and names the three exceptions: `strict` and `sanitize`
are C builds and `oracle` prints its own five lines unfiltered. `$(P)` appears on
all seven filtered suite pipelines and nowhere else; the only other `|` is the
`$$($$cc --version | head -1)` used to print a compiler's identity, which is
display-only and cannot mask a build failure - `make strict CC2=false` still
fails.

> **Historical:** one final prose correction remained at this point and was
> closed immediately below.

1) **"Every pipeline" includes a deliberate exception.**
`research/Makefile:26` says `$(P)` appears on every pipeline, while line 71 pipes
the compiler version through `head` without it. That display-only pipeline
cannot mask the compiler build at lines 72-74, so behavior is correct. Say
"every filtered suite pipeline" or "every test-output pipeline," or name the
compiler-version display as a fourth exception.

**Applied 2026-07-29.** The comment now says `$(P)` appears on every filtered
suite pipeline, which accurately excludes the display-only compiler-version
pipeline.

## Follow-up audit - 2026-07-29

### Scope and standard of evidence

This pass covers the new engine research in `ENGINE.md`, `engine.py`,
`engineemu.py`, and `dbtypes.py`, then checks the consequences against the root
C implementation. It also re-runs the earlier crypto and database evidence so
that the engine work cannot silently invalidate it.

Primary evidence used:

- The engine and staging routines extracted from all nine local firmware
  images. The runtime engine was executed from each image over the documented
  21 cases, plus new zero-length and default-off boundary cases.
- The five database chains returned by `db2.find_db()`, inspected in their
  stored and decrypted forms with block boundaries preserved per cheat entry.
- Direct disassembly of the type 5 and 6 staging paths, including the order in
  which list entries, control blocks, and row-count guards are emitted.
- Strict C99 builds with `-Wall -Wextra -Wpedantic -Wconversion
  -Wsign-conversion -Werror`, an ASan/UBSan build, `oracle_test.py`,
  `fxtest.py`, `engineemu.py`, `dbtypes.py`, `audit2.py`, `fxprot.py`,
  `fxcmp.py`, and `packstats.py`.

### Bottom line

The core crypto work still holds. Keys 4 through 7, `XP_KEYED_TYPES = 0xABFB`,
the normal-code route behavior, the type 5/6 row-count formulas used by the
crypto tool, payload keys 6 and 7, ROM crypto, COMP01, and the V2/FX crypto
equivalence all reproduce.

The engine research is not yet reliable as an authoritative description. Two
runtime boundary defects were missed, several headline claims mix different
populations or overstate what was executed, and the root CLI corrupts type A
payloads because it does not model their block boundary.

### Corrections required

1) **The root CLI silently corrupts type A payload rows.** `ENGINE.md:560-597`
establishes that a type A header consumes every following code row through the
end of the cheat entry as literal bytes. Those rows are neither decrypted nor
classified by the cartridge.

`crypt_codes()` only enters payload mode when `xp_parse_block()` recognizes a
header, and `xp_parse_block()` recognizes only types 5 and 6. A payload row that
looks like a keyed code is therefore transformed as an independent code:

```
input to xpcrypt -d:
    A0001000 0000
    84010203 0405

current output:
    A0001000 0000
    8024F805 895F

firmware staging payload:
    00 00 84 01 02 03 04 05
```

The second row must remain literal. The CLI has no explicit cheat-entry model,
so support needs either a documented boundary convention or an explicit refusal
that prevents silent corruption. `oracle_test.py` does not catch this: its
normal-code suite treats type A rows independently, and its block suite covers
only types 5 and 6.

2) **A zero-length Supercode makes the real engine run away, and two shipped
cheats contain one.** The type 5 handler loads the count, copies one byte, then
decrements and tests it. Count zero therefore becomes `0xFFFFFFFF` after the
first byte and continues copying. Executing a zero-count staged block runs away
in all nine firmware engines.

This is not only a generated boundary case. Both German `War Games` cheats
named `Oeffnet alle Levels fuer NORAD` and `Oeffnet alle Levels fuer WOPR`
contain:

```
stored       56565A56 595A
decrypted    50000702 0000
next line    800AA370 0101       (NORAD)
             800AA3A0 0101       (WOPR)
```

The stager emits the type 5 list entry and its zero-count block before the
`blez` at `0x1AD230`; the guard only skips the payload-row loop. The next line
is still staged as an ordinary code, but the runtime engine never reaches it.

`xp_parse_block()`, `dbtypes.py`, and the first audit call a size-zero type 5
line "not a block". That is a useful crypto-stream rule because zero payload
rows must not swallow the next line, but it is not the cartridge's runtime
behavior. Keep the framing rule, but document the engine defect and consider a
warning.

A Megacode with `nnnn == 0` has the same boundary defect: staging writes a
payload word count of zero, while the type 6 handler copies a word before
decrementing. `ENGINE.md:432-436` currently omits the decrement and `bnez`
instructions at `0xC00..0xC08`, hiding this case. No shipped zero-length type 6
specimen was found.

3) **The database usage survey is an extracted-subset survey, not a complete
five-database census.** `dbtypes.py` obtains each database through
`db2.find_db()`. The first audit already established that this returns the
`xteng.dec` chain at `0x27F69` even though apparent database data starts around
`0x25000`; the exact number and contents of the omitted early records remain
unknown.

Consequently the type-use table and claims derived from it must be scoped to
the recovered 13,205-line corpus. In particular, the evidence does not support
absolute claims that every type 1 occurrence in the shipped databases is a
slide row, that types 2/A/E were never shipped, or that no additional specimens
exist in the unparsed `xteng` prefix.

The headline block counts are syntactic type-nibble counts too. The reported 42
type 5 entries include the two zero-length `War Games` headers above, and the
reported nine type 6 entries include `Metal Gear Solid - Jp / Verliere Chaff`,
whose one-line cheat decrypts to a header declaring 9,212 following rows. The
recovered corpus contains 40 positive-length type 5 blocks and eight type 6
blocks that fit inside their cheat entry, plus those three malformed entries.

4) **The default-off discussion conflates 133 flagged rows, 121 keyless flagged
rows, and 120 wrong-address operations.** In the parsed Xplorer Pro 2.20 data:

```
133 rows have bit 3 set
121 of those have normal key bits 0
120 of those 121 are types 3, 7, or 8
  1 of those 121 is type 4
 12 of the 133 are type C route-gap rows with low nibble D
```

Thus `ENGINE.md`'s "broke 121 codes", its later 133/120 split,
`FINDINGS.md`'s "bit set on 121 lines", and `TODO.md`'s 120 affected lines
are not interchangeable statements. The safe conclusions are:

- 120 lines perform their intended store or comparison at the wrong address;
- all 133 flagged rows make out-of-range reads in the dispatcher;
- what those reads do on real hardware remains untested.

The release-history explanation is also wrong. Pro 2.20 is not stored entirely
in the clear: 84 ordinary code rows carry key 6. More importantly, the earlier
Pro 2.14 database has all 1,826 parsed code rows keyless and no default-off
rows. The distinguishing change was using the default-off bit on keyless
routed codes, not shipping the first clear database after four encrypted
releases.

5) **The engine does not read every entry's target exactly twice.** The real
counts are:

| type/path | reads of the entry's masked field |
|---|---:|
| F | 1 |
| B header | 1 |
| 9 | 3 |
| 4 | 2 |
| the remaining types | 2 |

The second type 4 read occurs after its cartridge helper returns, despite the
helper itself ignoring the address. A type B read targets its count/step field,
not a game-memory address. The embedded trace already shows one read for the B
header and one for a failing F. `engineemu.py` hid the two type 4 target reads
in the published trace because its type 4 test uses address zero, inside a
quiet region.

This also changes the default-off wording: the flagged type 4 and type C rows
are not memory-access-neutral merely because their handlers ignore the address
or do nothing.

6) **The notes overstate which semantics were executed.** `engineemu.py` writes
already-staged word pairs and manually constructed type 5/6 control blocks
directly into the patch list. It does not run any of the four staging passes.
The emulator therefore observes the runtime handlers, but the following remain
static disassembly conclusions:

- type A rewriting and end-of-cheat payload capture;
- type D rewriting, hoisting, and the multiple-D rule;
- moving conditionals with block entries;
- construction of type 5 and 6 control blocks;
- patch-list and payload-capacity enforcement.

The emulator's A and D cases prove only that the raw runtime nibbles are inert.
Also, `Trace.quiet` deliberately suppresses accesses in four mapped regions, so
"every memory access is recorded" is not literally true. Revise
`ENGINE.md:20-25`, `ENGINE.md:835`, and `ENGINE.md:1396` to distinguish executed
runtime behavior from static staging analysis.

7) **Part I gives the wrong absolute patch-list addresses for the two Pro
firmwares.** The correct layout is:

| family | patch-list base | Megacode control block |
|---|---:|---:|
| V2 2.004/2.008/2.0081 | `0x1F022600` | `0x1F022D80` |
| Pro 2.14/2.20 | `0x1F024600` | `0x1F024D80` |
| FX | loaded from the support-module pointer | base-relative `+0x780` |

`ENGINE.md:93-110`, the type 5 emitted pointer, and the type 6 fixed pointer use
the first row as though it covered every non-FX image. The later emulator notes
already acknowledge the Pro base. Express the format relative to the per-build
patch-list base and give all three locations once.

8) **The Supercode `or`/`add` bug triggers only for odd high size nibbles.** If
`lo >= 0xFB`, then `lo + 5` carries into bit 8:

```
OR high byte   = hi | 1
ADD high byte  = hi + 1
```

Those differ only for `hi = 1, 3, 5, 7, 9, B, D, F`. Even values, including
zero, give the same result. `ENGINE.md:1031` says every nonzero `hi`, while
`REVERSING.md:684` says every `lo >= 0xFB`; both are too broad. The conclusion
that no recovered database specimen triggers the defect still holds.

9) **The type 4 re-entry constant is miscomputed.** `4 | 0x1234` is `0x1234`,
not `0x1236` as annotated in `ENGINE.md:307`. The executed trace correctly
records `sw 00000C84=1234`.

10) **The Wipeout type C specimen supports a relationship, but not a one-nibble
comment-out claim.** The stored rows are:

```
type C row       C6671C0E 505A
active row       86671C0E 5061
active decrypted 8013C5BA FF09
```

The two stored rows share the ciphertext address bytes, but the final byte also
differs. Narrow `ENGINE.md:663` and `ENGINE.md:1352-1353` to the evidence rather
than calling them the same code with only its type changed.

11) **Several absolute or categorical descriptions need narrowing.** Fix these
while editing the substantive items:

- Types 1, 2, and C do reach the console's runtime list; they fall through
  without handlers. A type D can reach it too when the staging rules do not
  promote it. Replace "five types never reach the console" with "five types
  have no direct runtime handler" and describe the split.
- Type 6 is not the only type that is not a memory poke. Type 4, the
  conditionals, the anchor, and no-op types are counterexamples.
- A missing cipher route does not prove types A and E could only have been
  hand-entered. Clear databases and authoring tools can store route-gap types
  directly, as the type C specimens demonstrate.
- The raw engine blob is not identical across the corpus. SHA-256 groups it
  into three byte-distinct blobs: V2, Pro, and FX. The normalized relevant
  handlers agree except for type 4; say that instead.

12) **Repository-state and audit-scope descriptions are stale.** At this audit,
`17e31fc..HEAD` contains seven commits, not four; `research/` is staged rather
than untracked; and the root `TODO` mentioned in `research/TODO.md` has been
removed. The first audit also predates `ENGINE.md`, so statements that it is an
external review of everything in the current directory are no longer true.

### Verified findings

1) The strict C99 and ASan/UBSan builds pass. The published sample decrypts to
the expected four lines under the sanitizer build.

2) `oracle_test.py` exits successfully with 1,792 normal-code checks, 8,200
encryption read-back checks, 20,590 generated type 5/6 block checks, and 13,205
real extracted database lines. Its scope excludes type A block framing and the
runtime engine's zero-count behavior, as noted above.

3) `fxtest.py` finds `XP_KEYED_TYPES = 0xABFB` in all nine images, reproduces
all 30 known Punky Bear payload rows in each, and reports zero disagreements for
1,536 codes across 17 settings.

4) `engineemu.py` reproduces the documented handler behavior in all nine images
and still finds exactly one cross-family difference among its 21 standard
cases: type 4 is absent on FX. Added zero-count cases run away in all nine, and
added type 4/type C default-off cases record the out-of-range reads described
above.

5) `dbtypes.py`, `audit2.py`, `fxprot.py`, `fxcmp.py`, and `packstats.py`
reproduce their published output for the records and firmware regions they
actually inspect. The corrections above concern scope and interpretation, not
their ordinary-case output.

### Disposition

Applied 2026-07-29, then rechecked. Every finding was reproduced before it was
acted on; none turned out to be wrong. The post-fix review above found that item
8 was missed in one note, item 12 was not reconciled with the index, and the
revisions for items 4, 7 and 11 left four narrower precision issues. Item 5's
read counts, item 8's parity condition, item 11's three engine blobs and the
whole of items 2, 3 and 4 were re-measured here.

| # | correction | what was done |
|---|---|---|
| 1 | type A payloads corrupted | `xp_parse_block()` recognises `0xA0` and reports it as `unbounded`; new `xp_in_payload()` decides where a payload ends; `crypt_codes()` uses it and warns that every following code is being taken as payload; `README` gained an "Inline data blocks" section. New `oracle_test.py` suite, 1080 checks - 279 of them fail against the pre-fix binary |
| 2 | zero-length block runs away | two new emulator cases, `5 of length 0` and `6 of length 0`; both hang all nine engines. Written up in `ENGINE.md` §7 with the two `War Games` specimens and the `blez` that does not guard it, and in the type 5 and type 6 sections. The missing `0xC00..0xC08` instructions added to the type 6 listing. `TODO.md` item 1d proposes the warning |
| 3 | database survey is a subset | `ENGINE.md` §8 gained a scope paragraph, §14 and §16 say "recovered corpus", the type 5/6 rows are split into well-formed and malformed (40 of 42, 8 of 9), and `dbtypes.py`'s docstring says both. `TODO.md` item 2 now says to fix `db2.find_db()` first |
| 4 | 133 / 121 / 120 conflated | `ENGINE.md` §7 states all three with what each means; the headline finding and `FINDINGS.md` say 120; `TODO.md` says 120 of 133. The release-history claim replaced with the stored-key-nibble histogram: Pro 2.14 was already in the clear, and 84 Pro 2.20 rows still carry key 6 - what is new in 2.20 is the default-off bit on *keyless* rows. `engineemu.py` overstated what real hardware does with the resulting address - see post-fix item 3 |
| 5 | reads are not always two | measured: 9 reads three times, F and B once, the rest twice. Table in `ENGINE.md` §5, wording fixed in §4 (type 4), §7 and §15. The type 4 test case moved off address zero, which is what hid its two reads - and so was the type 6 case, which had the same problem for the same reason and was not in the audit. Two new cases, `4 + default-off` and `C + default-off`, show that neither type is spared |
| 6 | overstates what was executed | the intro, §5, §7, §13, §15 and §16 now separate the executed runtime from the read-only staging analysis, and `engineemu.py`'s docstring leads with it. "Every access" qualified with the four quiet regions |
| 7 | wrong list base for the Pro | `ENGINE.md` §2 gives all three families in a table and expresses the layout relative to the base; the type 5, type 6 and capacity paragraphs and the §3 listing follow. The FX row stopped at the pointer-slot address instead of dereferencing it - see post-fix item 6 |
| 8 | `or`/`add` needs an odd `hi` | corrected in `ENGINE.md` §7 and §16 and in `REVERSING.md` §7; missed in `FINDINGS.md` at the time - see post-fix item 1 |
| 9 | `4 \| 0x1234` is `0x1234` | annotation fixed in `ENGINE.md` §4; the guard word is a constant |
| 10 | the Wipeout type C pair | narrowed in `ENGINE.md` §4 and §14 to what the stored bytes show: three shared ciphertext address bytes, and a differing last byte |
| 11 | categorical descriptions | "never reach the console" → "no runtime handler", with the split spelled out in §13; type 6 is "the only type that uses the CPU's debug unit" (type 5 installs code too, when its payload is code); types A and E are no longer "hand-entered only"; §6 and §10 say the blob is three byte-distinct groups, not one. The explanation of what differs between those groups and the staging scan's exhaustiveness were still too broad - see post-fix items 4 and 5 |
| 12 | stale repo/audit state | the audit count and removed root `TODO` were corrected, but the untracked-directory claim conflicted with the staged index - see post-fix item 2 |

Two things were found while reproducing the above and fixed with them:

* `engineemu.py` mapped the patch list *after* the cartridge, and the first
  matching segment wins - so the list was shadowed by the shipped image and every
  word the harness had not written read as ROM. Now mapped first, along with the
  control port. Surfaced by a new case that walks off the end of the list.
* A conditional whose skip arm fires as the *last* entry steps over the zero
  terminator, and the engine dispatches whatever is behind it. Executed on all
  nine (`7 miss, list end`); `ENGINE.md` §7.

## First audit - 2026-07-28, resolved

### Scope and standard of evidence

At the time, this audit covered the three pre-engine research notes, all Python
tools then present, and the four checked-in text specimens under `research/`.
It checked binary-specific claims against the nine local firmware images,
source-material claims against the issue attachments and the current reference
source, and third-party-library claims against the library's own source. The
root C implementation was outside this first pass's scope.

Primary material used:

- The nine decrypted firmware images under `research/roms/`. Their SHA-256 hashes are:
  `73480a70...85f26` (Xploder USA 2.004), `21350db8...6a2` (xteng 2.008),
  `22f101df...f140` (xtepro 2.20), `695d09a1...38d6` (xtger 2.0081),
  `2ee0e989...b3a2d9` (xtjpro 2.14), `b085d617...c9c02` (english 3.20),
  `150932df...abbd` (german 4.50), `d65a675a...e8a5` (english 4.52), and
  `d60b801a...66c1` (v452d 4.52). The complete hashes are obtainable with
  `sha256sum research/roms/*`.
- The [xpcrypt issue and its original attachments](https://github.com/mlafeldt/xpcrypt/issues/1):
  `Xploder_PSX_CodeTypes.docx` SHA-256 `d0e78752...d9d886` and
  `PSX-Xploder.zip` SHA-256 `0a96585a...a3f`.
- SkillerCMP's current reference source at commit
  [`5bade9248d1f15feb2cc34e6e1a5f404d257acfd`](https://github.com/SkillerCMP/PSX-Xploder/tree/5bade9248d1f15feb2cc34e6e1a5f404d257acfd),
  especially
  [`XploderMemoryCryptEngine.hpp`](https://github.com/SkillerCMP/PSX-Xploder/blob/5bade9248d1f15feb2cc34e6e1a5f404d257acfd/src/XploderMemoryCryptEngine.hpp)
  and
  [`LegacyDatabaseImport.hpp`](https://github.com/SkillerCMP/PSX-Xploder/blob/5bade9248d1f15feb2cc34e6e1a5f404d257acfd/src/LegacyDatabaseImport.hpp).
- Capstone 5.0.7's own
  [`skipdata_size()` implementation](https://github.com/capstone-engine/capstone/blob/52c66920fc7bfa15fd9626dfd9f646c698aaa99b/cs.c#L637-L657).
- The Internet Archive's
  [CDX inventory for the original vendor ROM directory](https://web.archive.org/cdx/search/cdx?url=www.x-plorer.co.uk/roms/*&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&collapse=urlkey).

### Bottom line

The central technical result holds: the documented normal-code routes, block row-count
formulas, payload-key 6 and 7 transforms, payload byte order, FX descrambler, COMP01
decoder, and V2/FX behavioral equivalence all match the audited firmware corpus. The
real-data oracles reproduce their published results.

The notes are not fully reliable as written, however. The corrections below should be
made before treating the directory as an authoritative record.

### Corrections required

1) The Capstone `skipdata` warning is false for the version the documented `uv` command
installs. `REVERSING.md:79-83` and `FINDINGS.md:303-304` say MIPS skip-data advances by
one byte and loses alignment. Capstone 5.0.7 returns a four-byte skip size for MIPS, and
an executable check produced `.byte` at offset 0 followed by `nop` at offset 4. Decoding
one word at a time remains a reasonable defensive choice, but the stated reason is
wrong.

2) The COMP01 size printed in `REVERSING.md:309` and `FINDINGS.md:327` is off by one.
`comp01.unpack()` and `packstats.py` both produce `0x2BF18` (179,992), not `0x2BF19`,
for `xteng.dec`.

3) The store-only measurements in `FINDINGS.md:340-342` and `TODO.md:81-83` are
mislabelled. `0x2B794` versus `0x209E4` belongs to the Xploder USA image, not
`xteng.dec`. For `xteng.dec`, the script reports unpacked/store bytes `0x2BFA0` and
packed bytes `0x210CB`. In addition, `packstats.py:46-50` omits the 14-byte COMP01
header from the printed store-only total while including it in `used`; an apples-to-
apples store-only stream is therefore `0x2BFAE`. Neither defect changes the conclusion
that it overruns the available region.

4) The all-nine-image opcode ranges in `FINDINGS.md:321-323` and
`REVERSING.md:318-320` are stale. `xtjpro.dec` uses RLE16 19 times and saves 108 bytes;
the actual RLE16 range is 4-19 uses and 56-108 bytes, not 4-14 and 60-100.
`packstats.py:9-11` is also too broad in saying LZ alone recovers about 95 percent: the
per-image result falls to 70 percent for `english-452.dec`, a caveat the main note does
include.

5) The source attribution at `FINDINGS.md:89-90` is partly wrong. The DOCX gives the
Type 5 `+6` staged-size model, but contains no Type 6 `+0x12` rule. The latter is in the
older attached ZIP (`XploderMemoryCryptEngine.hpp:305`), as `FINDINGS.md:97-98` more
accurately implies.

6) The archive count at `FINDINGS.md:131-132` and `TODO.md:100-102` is outdated and
incorrect as an absolute claim. The Wayback CDX currently lists six successful `.fcd`
captures: `english`, `german`, `xteng`, `xtepro`, `xtger`, and `xtjpro`. Thus four were
additional to the two already obtained elsewhere, but it is not true that the other ten
of fourteen were never archived; at most eight are absent from the current CDX result.

7) A printable-only parser rejects three of the five V2 databases, not two as stated in
`FINDINGS.md:186-189` and `TODO.md:37-40`. Calling the strict parser at the known starts
fails on `xteng`, Xploder USA, and `xtger`, while `xtepro` and `xtjpro` parse. The tolerant
reader reports 221/1695/2381, 285/2134/3082, 172/2850/3440, 240/1787/2476, and
61/1619/1826 games/cheats/lines respectively. The table's dashes at
`FINDINGS.md:196-197` can therefore be filled with 240 and 61.

8) `romcrypt.py` is not a fully faithful function model despite its claim at
`romcrypt.py:2-5` and `REVERSING.md:671`. The real routine clears only `dst[1..5]` on
entry. Special32, Special33, and unsupported payload-key paths do not write `dst[0]`.
With destination byte 0 prefilled as `0xAA`, the xteng firmware returns
`AA4745470405` for input `32010203 0405`, while `romcrypt.py` returns
`00474547 0405`. Unsupported payload keys similarly return `AA0000000000`, not a fully
zeroed row. This contradicts `FINDINGS.md:73`, `FINDINGS.md:373`,
`FINDINGS.md:568-570`, and `REVERSING.md:582`; notably, the notes already acknowledge
the unwritten byte at `REVERSING.md:392` and `FINDINGS.md:604`.

`fwemu.Firmware.decrypt()` masks this difference by explicitly zeroing the destination
at `fwemu.py:240-243`, so `fxtest.py` cannot catch it. The practical conclusion that
unsupported payload keys make unusable rows still holds because bytes 1 through 5 are
zeroed, but "a zeroed row" is too strong without a pre-zeroed-destination precondition.

9) `fxprot.py:8` incorrectly says the V2 checker is reached from every keyed route.
Direct route tracing shows it is reached by key 7 and Special32 in V2 builds; FX reaches
it from key 4; Xplorer Pro 2.20 calls an empty stub. The tables in `FINDINGS.md:437-444`
and `REVERSING.md:1068-1074` are correct. `fxprot.py:30-31` also calls the source bytes
"garbage", although `FINDINGS.md:562-563` correctly says the contents of low RAM at
`0x3E8` are unknown.

10) Several script descriptions are stale even though their code runs across the current
nine-image corpus: `FINDINGS.md:168` says `fwimage.py` handles five ROMs;
`fxtest.py:4` says five images; `fxdb.py:4-19` says five images and two FX dumps.
`fxtest.py:43-45` also calls the Punky Bear specimen payload key 7; the header and its
own output show key 6. `oracle_test.py:31-32` says xpcrypt decrypts route-gap types even
though the current test correctly requires them to remain unchanged.

11) `audit.py` is a superseded/broken entry point but is not labelled as such. It imports
the strict `dbscan.find_db()` and crashes with `TypeError: 'NoneType' object is not
iterable` on the documented `xteng.dec` command. `audit2.py`, which imports the tolerant
reader, is the functioning row-count audit used by the notes.

12) `oracle_test.py:184-210` flattens all cheats in a database into one uninterrupted
code stream. In `xtger.dec`, the one-line cheat `Metal Gear Solid - Jp / Verliere
Chaff` decrypts from `65FAA065 A5AA` to `6051E296 D7DD`, which resembles a Type 6,
payload-key-6 header declaring 9,212 following rows even though the cheat has no rows
left. The test consequently treats the remaining 1,266 database lines as key-6 payload
instead of resetting at the cheat boundary. Those comparisons still show that xpcrypt
and the model make the same stream-state decision, but they do not exercise those lines
as normal database codes. The claim that every real database line is tested in its true
database context should be narrowed, and the database suite should process each cheat
separately.

13) `oracle_test.py:41-47` does not check the xpcrypt subprocess return code, stderr, or
the number of output records. A failed or truncated invocation can silently reduce the
number of comparisons because every caller uses `zip()`. This was reproduced with an
unsupported AddressSanitizer option: the first suites reported zero checks and zero
failures before a later block assertion happened to raise. `run()` should require a zero
exit status and exactly one output code for every input code.

### Verified findings

1) `oracle_test.py` passes all four suites: 1,792 normal-code checks, 8,200 encryption
read-back checks, 20,590 generated block checks, and 13,205 real database lines, with
zero failures.

2) `fxtest.py` locates `XP_KEYED_TYPES = 0xABFB` in all nine images, reproduces all 30
Punky Bear payload rows on each image, and finds zero disagreements across 1,536
generated codes times 17 normal/payload-key settings. This is strong differential
evidence, though not an exhaustive proof over all 48 payload bits.

3) The 244-entry jump table, normal keys 4-7, route gaps for high nibbles 2/A/C/E,
Special32 `+"FCD"`, Special33 complement, and the key-6/key-7 payload equations match
the annotated MIPS. The current SkillerCMP source independently agrees on the normal
route table but still contains the payload-key-7 `-0xAB` behavior that the notes
correctly identify as differing from the firmware's `-0x55` behavior.

4) The row-count evidence reproduces exactly: direct sizing fits 17/17, 21/21, and 2/2
blocks in the first three databases, whereas the older formulas fit only 5/17, 6/21,
and 1/2. `xcheck.py` reproduces 14/14 swapped payload matches and 0/14 unswapped
matches. `ray.txt`, `br.txt`, `pb.enc`, and `pb.clear` have the claimed row counts and
headers.

5) The COMP01 decoder produces 179,992 bytes from `xteng.dec`, and all nine images have
exactly one outer plain or scrambled COMP01 stream at the offsets reported by the tools.
The FX descrambler yields the declared COMP01 sizes and exposes the same constant and
route tables.

6) **Narrowed by follow-up item 3.** The database structure and the extracted
13,205-line corpus are supported by the five database-bearing V2/Pro images.
The claim that `db2.py` misses early `xteng` records is also well founded:
printable game data begins at `0x25000`, while `db2.py` only returns a later
chain at `0x27F69`. The exact number of omitted records remains unknown.

7) The anti-tamper claim is strongly supported as a static reading: eight images contain
a live masked-signature checker, the ninth has `jr $ra; nop`; the mismatch path supplies
`0x3E8`, `0x1F000000`, and `0x18000` to code containing the standard `AA/5555`,
`55/2AAA`, `A0` flash-program sequence. The notes correctly disclose that this has not
been executed on hardware, so "will brick" remains a safety-conservative inference, not
an experimentally observed result.

8) Within the audited files, all four FX dumps end below `0x80000`, name the region ending
at `0x1F080000`, and contain no second COMP01 stream or embedded database. The narrow
claim "these dumps do not contain the FX database" holds.

### Claims that remain unsupported or should be narrowed

1) `FINDINGS.md:306-324`, `REVERSING.md:291-322`, and `packstats.py:4-7` establish the
COMP01 structure and opcode-use statistics, but not that it was unlicensed, uniquely
house-written, designed "on intuition", or never profiled. Those are historical-intent
inferences. Likewise, the claim that no general-purpose compressor has an arithmetic-run
opcode is not established by the cited evidence.

2) `FINDINGS.md:343-347` and `TODO.md:84-87` do not demonstrate that a new greedy matcher
of roughly 200 lines would land within a few percent or take a weekend. `packstats.py`
only measures how much the original streams' already-selected LZ matches save.

3) `FINDINGS.md:355-356` and `REVERSING.md:344-347` find no encrypt routine matching the
known cipher shapes in these images. That supports "the cartridge only needs decrypt",
but not the absolute historical claim that encryption existed solely in FCD's authoring
tools.

4) `TODO.md:100-103` says no dump in existence reaches the FX database region. The local
and cited downloadable corpus does not, but a universal statement about every private or
public dump is not independently verifiable. Restrict it to the audited corpus.

5) The self-destruct mechanism, payload key 7 in a real database, and Type 6 with payload
key 6 or 7 remain unobserved on hardware/in real data, exactly as disclosed in
`FINDINGS.md:554-567`. Their firmware behavior is statically and differentially supported;
their real-world use is not.

### Disposition

Applied 2026-07-28. Every audit finding was reproduced before it was acted on; none
turned out to be wrong.

| # | correction | what was done |
|---|---|---|
| 1 | capstone `skipdata` | reason rewritten in both notes; word-at-a-time decoding kept, on its own merits |
| 2 | COMP01 size off by one | `0x2BF19` -> `0x2BF18` in `FINDINGS.md` and `REVERSING.md` |
| 3 | store-only figures | the xteng numbers replaced with `0x2BFAE` vs `0x210CB`; `packstats.py` now counts the 14-byte header on both sides |
| 4 | stale opcode ranges | re-measured over all nine images: 4-19 uses, 56-108 and 58-73 bytes; the "~95%" in `packstats.py` split into 96-97% and 70% |
| 5 | DOCX vs ZIP | the type 6 `+0x12` rule attributed to the zip's engine |
| 6 | archive count | six `.fcd` captures in the CDX, four of them new here |
| 7 | strict parser | three of five, named; the table's two dashes filled with 240 and 61 |
| 8 | `romcrypt.py` fidelity | `decrypt()` takes the destination, `fwemu` stopped zeroing it, `fxtest.py` prefills `0xAA` - all nine firmwares and the model still agree; the "zeroed row" wording fixed in the notes and in `crypto.c` |
| 9 | `fxprot.py` route claim | corrected, and the script now measures and prints the reaching routes; "garbage" replaced with what is actually known about `0x3E8` |
| 10 | stale descriptions | five images -> nine; Punky Bear is payload key 6; the `oracle_test.py` gap comment fixed |
| 11 | `audit.py` | replaced with a note pointing at `audit2.py`, saying why |
| 12 | flattened database stream | the suite runs one cheat entry per xpcrypt invocation now |
| 13 | unchecked subprocess | `run()` requires exit status 0 and one output code per input code |

The five "unsupported or narrow" items were applied as well: the COMP01 design
inferences, the packer estimate, where the encrypt side lived, and the FX-dump claim
are now marked as inference or restricted to the audited corpus. Item 5 needed no
change; it was already disclosed.

**Superseded in part by follow-up item 2.** Fixing #12 surfaced two `War Games`
cheats in `xtger.dec` with a Supercode header of size 0. Refusing to enter
payload mode is correct for the crypto stream because the next line is an
ordinary code, and `oracle_test.py` was fixed accordingly. The follow-up found
that the cartridge still stages the zero-count header and that the runtime
engine then runs away. All four original suites pass: 1792 + 8200 + 20590 +
13205 checks, 0 failures; none exercises that engine boundary.
