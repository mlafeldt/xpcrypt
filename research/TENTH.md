# A tenth firmware, and the empty game that hides it

Everything here is about one image the rest of the research treats as a footnote:
the `.fcd` that ships **inside the DOS X-Link tool**, `pc/ROMS/Xteng.fcd`. `FCD.md`
§5a decrypts it once, as an end-to-end check on the image cipher ("a build we did
not otherwise have, 179140 bytes"), and moves on. It is more than a cipher fixture.

Two findings:

1. It is a **tenth firmware** — Xplorer UK **2.005**, 24 Nov 1998 — a real build
   older than every image in `roms/` except the 2.004 USA one, with its own cheat
   database. The corpus is called "nine firmwares" throughout the notes; this is
   the tenth, and until this note it had not been run through the database,
   engine or anti-tamper suites (§4 lists the ones that take it now).
2. **`xpcrypt -x` extracted nothing from it (now fixed, §3).** Its database is
   complete and valid - 234 game records to a clean terminator, 233 of them with
   cheats - but one game carries a cheat count of zero, and both the shipped C
   reader and `db2.py` once treated that as a fatal error that discards the
   whole chain. No in-ROM chain in `roms/` has an empty game, so the hazard was
   never seen. (The German FX 4.50 database has five, but it ships LZW-packed
   and nothing read it until the ninth pass - `fxdb.py`.) The one-line tolerance
   in §3 recovers the whole database and changes nothing on the five corpus
   databases.

The evidence uses the tool's own shipped file, so it needs no `roms/`. Before the
fix in §3, the second command failed:

```sh
xpcrypt -r pc/ROMS/Xteng.fcd xteng-2005.dec    # 196458-byte .fcd -> plaintext
xpcrypt -x xteng-2005.dec                       # was: Error: no cheat database found
                                                # now: 233 games / 1668 cheats / 2365 lines
```

---

## 1. It is Xplorer 2.005

The database header (`*(u32 *)(ROM + 0x7C)` -> `0x1F023000`, the same header
`fxprot.py` reads) carries the version and build date in the clear, right after
the copyright the self-destruct checks:

```
00023000  28 43 29 20 31 39 39 37 2f 38 20 46 43 44 20 20  (C) 1997/8 FCD
00023010  72 65 6c 65 61 73 65 20 32 2e 30 30 35 00 00 00  release 2.005
00023020  32 34 2f 31 31 2f 31 39 39 38 2d 30 39 3a 35 30  24/11/1998-09:50
00023030  45 00 00 19 ...                                   'E' = English
```

`release 2.005`, dated 1998-11-24, territory `E`. That places it between the
oldest image in the corpus and the next:

```
2.004 USA   1998-11-13   roms/Xploder V2 (USA) ...
2.005 UK    1998-11-24   pc/ROMS/Xteng.fcd        <- this
2.008 UK    1999-03-03   roms/xteng.dec
```

The header layout is worth recording because nothing else here does. Byte `+0x30`
is a **territory code** — `E`/`G`/`J`/`U` for English/German/Japanese/USA across
the corpus — which is what `XLink.exe`'s "Cannot change cartridge territories!
(Use %s ROMS only)" enforces and what `RelNotes.txt` means by "you must upload an
equal territory". The self-destruct compares only the first 14 bytes,
`(C) 1997/8 FCD`, so it guards neither the version string nor the territory byte.

### Cipher and protection are the V2 build's, exactly

Dropped next to 2.004 and 2.008 and run through the existing rigs (the firmware
suites key on nothing but the bytes, so a fresh `roms/` with just these three
works):

```
fxtest.py    xteng-2005 (2.005)  0 disagreement(s) vs usa-2004 (2.004)
             ... and the code cipher agrees with romcrypt.py
fxprot.py    xteng-2005  checker 001A4338 live
             called from Special32, key7
             NOT  image 0x2B598  "(C) 1997/8 FCD"  checks all of it
```

Same code cipher, same route table, same self-bricking copyright check wired into
the same two routes as every other V2 image. Nothing new in the crypto — which is
the point: it is a genuine sibling of the corpus, not an oddball.

---

## 2. The database is complete — and was unreadable

Framed the way `db2.find_db` frames (first record after the erased-flash run), the
chain begins at `0x25000` and parses cleanly to its `FF FF FF FF` terminator at
`0x2FF66` — **except** that, before §3, the parser never got there. Game record
112 is:

```
0002A8C5  4d 6f 74 6f 20 52 61 63 65 72 20 32 00 00        "Moto Racer 2" 00 | 00
                                                 ^^ name    ^^ terminator  ^^ cheatCount = 0
0002A8D3  4d 6f 74 6f 20 52 61 63 65 72 00 04            "Moto Racer" 00 | 04  (the next game)
```

An empty game: a name, a cheat count of zero, and then the next game. The chain
continues normally after it and reaches the terminator. But both readers, as
they were before §3, stopped there:

* shipped C, `xpcrypt.c` `db_cursor_next()` before `7070614`:

  ```c
  if (ncheats == 0)
          return -1;
  ```

* reference, `db2.py` `parse_db()` before `6f42321`:
  `if not 1 <= ncheats <= 200: raise ValueError`

`find_database()` / `find_db()` treated that `-1`/exception as "this offset is not
a database" and dropped the **entire** chain. No other `FF FF FF FF`-preceded
offset frames a >50-record chain (the suffix after `Moto Racer 2` is not preceded
by erased flash), so the search ended with nothing and `-x` printed *no cheat
database found*. One empty game cost all 233.

### What is actually there

A zero-cheat-tolerant parser (skip the empty game, keep going) recovers the whole
chain, and the codes are real. Where 2.005 and 2.008 share a game the decrypted
codes are mostly identical: 208 of the 223 shared game names match exactly, and 15
differ (Nuclear Strike goes from 9 to 91 cheats, for example). Tekken 3 is one of
the 208 (ninth pass, `AUDIT.md`).

```
                     strict            tolerant
xteng-2005 (2.005)   none              234 game records (233 with cheats) / 1668 cheats / 2365 lines
                                       (empty: "Moto Racer 2")

Tekken 3:  2.005 44 cheats / 2.008 44 cheats;  identical decrypted set = True
  Infinite Health Player 1 -> 800A95E6 0082
  Infinite Health Player 2 -> 880AAE72 0082
```

The five corpus databases have no empty game, so the tolerant reader returns the
**same** records as the strict one on every one of them:

```
                strict                          tolerant
xteng.dec       285 / 2130 / 3060               285 / 2130 / 3060
xtepro.dec      285 / 2134 / 3082               285 / 2134 / 3082
xtger.dec       240 / 1787 / 2476               240 / 1787 / 2476
xtjpro.dec       61 / 1619 / 1826                61 / 1619 / 1826
USA 2.004       250 / 4048 / 4905               250 / 4048 / 4905
```

The first column of each is distinct game *names*, which is how `db2.py` counted
them. Records and names agree everywhere but in the USA chain: 252 game records
under 250 names (`Bio Freaks` and `Casper` appear twice), and `xpcrypt -x` prints
all 252. `db2.py` prints both figures now.

So tolerating an empty game is free on everything already tested and unlocks the
one image that needs it.

---

## 3. The fix

An empty game has no codes to extract, but it is a record, so the right behaviour
is to keep reading, not to reject the database. That took two steps in the C and
one in the reference reader:

* **`7070614`, `xpcrypt.c` `db_cursor_next()`.** Instead of `return -1` on
  `ncheats == 0`, it read past the game to the next one, so an empty game was
  skipped: not counted and not printed.
* **`72384f1` (1.2), the same function.** An empty game is now a record of its
  own, with no cheat name and no codes. `-x` prints it as a game name with nothing
  under it. That matters beyond 2.005: the German FX database opens with five
  empty games that make up a legend for its abbreviations. `find_database()` also
  requires a chain to hold at least one cheat now. Before, a chain of nothing but
  empty games validated, and `-x` exited 0 and printed nothing.
* **`db2.py`, `parse_db()`.** The `1 <= ncheats` lower bound became a `continue`
  on `ncheats == 0`, keeping the `<= 200` sanity cap. It already rejected a chain
  with no cheat in it, so on that edge the two readers now agree.

`extract_test.py` carries a fixture with an empty game between two real ones,
which `-x` has to print, and a chain of empty games only, which it has to refuse.
On the shipped `pc/ROMS/Xteng.fcd` the extractor recovers 234 game records (233
with cheats) / 1668 cheats / 2365 lines, and the five corpus databases still
extract their original 15349 lines / 11718 cheats. `rom2005.py` holds both readers
to it:
* `-x` has to print all 234 records, `Moto Racer 2` with nothing under it;
* `db2.find_db()` has to find the chain at `0x25000`;
* a walk that still rejects a zero count has to fail on `Moto Racer 2` and nowhere
  else.

---

## 4. Open

* **Is an empty game valid to the cartridge, or is it corruption XLink emitted?**
  It is official shipped data in FCD's own ROM, it parses end to end, and its
  codes largely match 2.008 (§2) — so a tool that drops 233 games over it is
  wrong regardless.
  Whether the cartridge *menu* lists an empty game or skips it was not read out of
  the firmware.
* **Default-off codes in 2.005.** A rough stored-nibble count suggests 2.005 has
  keyless default-off rows (the `ENGINE.md` §7 hazard) well before Pro 2.20, which
  the notes call the first to combine the two. This is *not* established: the
  audited count comes from `defaultoff.py`, which is block-aware and uses a
  cross-database matching rule, and it cannot see 2.005 until the extractor above
  is fixed. Re-run it over the six databases before believing any number.
  **Settled in the ninth pass (`AUDIT.md`): no.** 2.005 has 119 rows stored with
  bit 3, and all of them are keyed (stored `3E`/`4E`/`7E`/`8E`), so every one loses
  the bit on decryption. Pro 2.20 is still the first V2 database with keyless
  default-off rows. The hazard is not confined to it, though: the FX 3.20 and 4.52
  databases (`FINDINGS.md` §6.3) each carry 112 keyless default-off rows at an
  addressed type, which `fxdb.py` asserts.
* **Is an empty game deliberate?** Probably a placeholder. 2.008 fills `Moto Racer 2`
  with 7 cheats, and the German FX 4.50 database ships five zero-cheat records on
  purpose, as a legend ("Abkuerzungen", "ENG = Energie", …). How the menu shows
  them is still unread.
* **The image never entered the suites.** Partly stale: `payloads.py`, `plugin.py`,
  `typecx.py`, `selfdestruct.py`, `fxdb.py` and `rom2005.py` use it now, and
  `rom2005.py` asserts the fixed readers rather than the failure. `dbtypes.py`,
  `engine.py`, `engineemu.py`, `fxtest.py` and `fxprot.py` still do not, and
  `oracle_test.py`, `roundtrip.py` and `extract_test.py` keep to the five
  in-ROM chains on purpose, so that the 15,349-line / 11,718-cheat figures the
  notes cite stay the population they were measured on. A one-off run of the
  oracle and round-trip suites over 2.005 and the three distinct FX databases
  (ninth pass) passed: 10,970 more lines in 7,582 cheats, none failed and none
  not reproduced.

## 5. Reproducing

```sh
# the file is already in the tree, shipped with the DOS tool
xpcrypt -r pc/ROMS/Xteng.fcd /tmp/xteng-2005.dec
grep -a 'release' /tmp/xteng-2005.dec | head -1     # -> release 2.005
xpcrypt -x /tmp/xteng-2005.dec                        # -> 233 games (was: Error, before §3)
uv run --with capstone python rom2005.py              # the whole of this note, asserted

# the empty game
xxd -s 0x2a8c5 -l 24 /tmp/xteng-2005.dec             # "Moto Racer 2" 00 00 "Moto Racer" 00 04
```
