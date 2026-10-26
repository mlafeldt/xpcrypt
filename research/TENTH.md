# A tenth firmware, and the empty game that hides it

Everything here is about one image the rest of the research treats as a footnote:
the `.fcd` that ships **inside the DOS X-Link tool**, `pc/ROMS/Xteng.fcd`. `FCD.md`
§5a decrypts it once, as an end-to-end check on the image cipher ("a build we did
not otherwise have, 179140 bytes"), and moves on. It is more than a cipher fixture.

Two findings:

1. It is a **tenth firmware** — Xplorer UK **2.005**, 24 Nov 1998 — a real build
   older than every image in `roms/` except the 2.004 USA one, with its own cheat
   database. The corpus is called "nine firmwares" throughout the notes; this is
   the tenth, and it has never been run through the database, engine or
   anti-tamper suites.
2. **`xpcrypt -x` extracts nothing from it.** Its database is complete and valid,
   233 games to a clean terminator, but one game carries a cheat count of zero,
   and both the shipped C reader and `db2.py` treat that as a fatal error that
   discards the whole chain. No image in `roms/` has an empty game, so the hazard
   was never seen. A one-line tolerance recovers the whole database and changes
   nothing on the five corpus databases.

The evidence uses the tool's own shipped file, so it needs no `roms/`:

```sh
xpcrypt -r pc/ROMS/Xteng.fcd xteng-2005.dec    # 196458-byte .fcd -> plaintext
xpcrypt -x xteng-2005.dec                       # Error: no cheat database found
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
equal territory". The self-destruct compares only the first 13 bytes,
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

## 2. The database is complete — and unreadable

Framed the way `db2.find_db` frames (first record after the erased-flash run), the
chain begins at `0x25000` and parses cleanly to its `FF FF FF FF` terminator at
`0x2FF66` — **except** the parser never gets there. Game 112 is:

```
0002A8C6  4d 6f 74 6f 20 52 61 63 65 72 20 32 00 00        "Moto Racer 2" 00 | 00
                                                 ^^ name    ^^ terminator  ^^ cheatCount = 0
0002A8D4  4d 6f 74 6f 20 52 61 63 65 72 00 04            "Moto Racer" 00 | 04  (the next game)
```

An empty game: a name, a cheat count of zero, and then the next game. The chain
continues normally after it and reaches the terminator. But the readers stop:

* shipped C, `xpcrypt.c` `db_cursor_next()`:

  ```c
  if (ncheats == 0)
          return -1;            /* line 471 */
  ```

* reference, `db2.py` `parse_db()`: `if not 1 <= ncheats <= 200: raise ValueError`

`find_database()` / `find_db()` treat that `-1`/exception as "this offset is not a
database" and drop the **entire** chain. No other `FF FF FF FF`-preceded offset
frames a >50-record chain (the suffix after `Moto Racer 2` is not preceded by
erased flash), so the search ends with nothing and `-x` prints *no cheat database
found*. One empty game costs all 233.

### What is actually there

A zero-cheat-tolerant parser (skip the empty game, keep going) recovers the whole
chain, and the codes are real: where 2.005 and 2.008 share a game the decrypted
codes are byte-identical.

```
                     strict            tolerant
xteng-2005 (2.005)   none              233 games / 1668 cheats / 2365 lines   (empty: "Moto Racer 2")

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

So tolerating an empty game is free on everything already tested and unlocks the
one image that needs it.

---

## 3. The fix

An empty game has no codes to extract, so the right behaviour is to skip it, not
to reject the database. Two places, mirroring each other:

* **`xpcrypt.c`, `db_cursor_next()`.** Instead of `return -1` on `ncheats == 0`,
  read the next game name+count in a loop until one is non-empty or the
  terminator is reached. The empty game contributes no `db_record`, so
  `print_database()` and `find_database()`'s scoring need no other change (an
  empty game simply is not counted and is not printed).
* **`db2.py`, `parse_db()`.** Replace the `1 <= ncheats` lower bound with `continue`
  on `ncheats == 0`, keeping the `<= 200` sanity cap.

`extract_test.py` should grow a fixture with an empty game between two real ones,
and — once this file is in `roms/` under whatever name — the wider gate should
extract 233/1668/2365 from it.

Not done here; this note is the evidence, not the patch.

---

## 4. Open

* **Is an empty game valid to the cartridge, or is it corruption XLink emitted?**
  It is official shipped data in FCD's own ROM, it parses end to end, and its
  codes match 2.008 — so a tool that drops 233 games over it is wrong regardless.
  Whether the cartridge *menu* lists an empty game or skips it was not read out of
  the firmware.
* **Default-off codes in 2.005.** A rough stored-nibble count suggests 2.005 has
  keyless default-off rows (the `ENGINE.md` §7 hazard) well before Pro 2.20, which
  the notes call the first to combine the two. This is *not* established: the
  audited count comes from `defaultoff.py`, which is block-aware and uses a
  cross-database matching rule, and it cannot see 2.005 until the extractor above
  is fixed. Re-run it over the six databases before believing any number.
* **The image never entered the suites.** With the fix and a copy in `roms/`,
  `dbtypes.py`, `engine.py`, `engineemu.py`, `oracle_test.py` and `roundtrip.py`
  all have a tenth, earlier image to widen over.

## 5. Reproducing

```sh
# the file is already in the tree, shipped with the DOS tool
xpcrypt -r pc/ROMS/Xteng.fcd /tmp/xteng-2005.dec
grep -a 'release' /tmp/xteng-2005.dec | head -1     # -> release 2.005
xpcrypt -x /tmp/xteng-2005.dec                        # -> Error: no cheat database found

# the empty game
xxd -s 0x2a8c6 -l 24 /tmp/xteng-2005.dec             # "Moto Racer 2" 00 00 "Moto Racer" 00 04
```
