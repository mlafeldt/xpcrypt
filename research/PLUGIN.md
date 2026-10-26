# The FCDEXE1138 loader: the cartridge runs unsigned code from a memory card

Every Xplorer/Xploder PSX firmware in the corpus contains a routine that opens a
PlayStation memory-card save named `FCDEXE1138`, copies it into RAM, and jumps
into it. There is no signature, no checksum, no magic-byte test: the only thing
that has to be true for the cartridge to execute the file is that it exists on
the card under that name. It is a homebrew / arbitrary-code entry point wired
into the shipped firmware, and nothing else in this research had noticed it.

This stands apart from everything in `FINDINGS.md`, `ENGINE.md` and `FCD.md`,
which are about *codes* - the code cipher, the cheat database, the runtime code
engine, and the `.fcd` image cipher. This is not a code path at all. It is the
menu firmware, and it hands the console to whatever is on the card.

Reproduce it:  `uv run --with capstone python plugin.py`  (a `make plugin`
target runs it in the gate).

> **Ninth pass (`AUDIT.md`): it is FCD's advertised memory-card *upgrade*, not a
> hidden door.** V2 2.008's caller (`0x1B76E0`) draws a "CD & Memory Card Upgrade"
> screen with "Press @s to upgrade via Memory Card." and "Couldnt upgrade via
> MemoryCard!". FX has an "Upgrade Via Memory-Card" menu item, draws "Loading
> Upgrade", and fails with "Failed to find memorycard upgrade / Please use official
> FCD expansion memory-cards only". So it is not silent on FX, and "nothing else had
> noticed it" describes this research, not the product. The finding that stands is
> that the upgrade is **unauthenticated**. Corrections to the listing below:
> * the call labelled "seek/rewind" is `FileSeek(fd, 0x200, SEEK_SET)` in all ten
>   images, so the payload really does start at file offset `0x200`;
> * the first fd is closed (`0x1A08D4`) before the second open, so it is not leaked.
>   The listing also omits a `memset` and an unused `malloc(0x300)`/`free` pair;
> * "read failed ? bail" is a `beqz`, but `FileRead` returns −1 on error, so a
>   failed read goes on with an uninitialised header and jumps to whatever it holds;
> * the "one-shot re-entry flag" gates only the one-time card BIOS init (`InitCard`,
>   `StartCard`, `_bu_init`, `set_card_auto_format`). The loader runs on every
>   Square press;
> * the structure is not identical: Pro 2.14/2.20 hang (`j .`) on an empty header
>   read; FX has no `malloc`/`free` and masks interrupts (`I_MASK = 0`) if the
>   payload returns;
> * offset `0x03` as a "standard block count" is unsupported: psx-spx lists it as
>   uncertain. "1138 = THX-1138" and "FCDEXE = FCD executable" are guesses.
>
> The cart's X-Link command `'X'` is a second unauthenticated path: it receives a
> block to a wire-given address and jumps into it (`jalr $fp` at `0x1A1B2C` in
> `xteng`).

## The four findings that matter

1. **`bu00:FCDEXE1138` is loaded and executed with no validation.** The routine
   opens the file, reads a header, reads the body to an address the *file* names,
   and `jalr`s into it. The path from the final read to the jump is straight-line
   - not one branch inspects the loaded bytes (`plugin.py` asserts this). The
   name is the whole gate.

2. **The file names its own load address, and it is also the entry point.** The
   loader reads the first `0x200` bytes to a scratch buffer, takes the 32-bit
   word at **file offset `0x44`** as the destination, reads the rest of the file
   there, and jumps to that same address. A crafted save can place and run code
   anywhere in the address space.

3. **It is in all ten images, both hardware generations, every release.** V2
   (Xplorer 2.x / Xploder V2, base `0x001A0000`) and FX (Xplorer FX V3/V4, base
   `0x80010000`), English/German/Japanese, releases 2.004 (1998) through 4.52,
   including release 2.005 - the tenth image bundled with the vendor's own X-Link
   and never counted by the rest of this research. Exactly one reference to the
   filename string in each; identical structure in each.

4. **The on-card file is a well-formed PSX save.** The two fields the loader
   trusts live in bytes the console's own save format leaves to the application:
   the block count at title-frame offset `0x03` (a standard field) doubles as the
   size, and the load address sits at offset `0x44`, inside the title frame's
   reserved area between the 64-byte title and the icon palette. The payload
   begins at file offset `0x200` - immediately after the title frame and three
   icon frames - so an `FCDEXE1138` save looks like an ordinary save with an
   icon, with the executable packed behind the icon data.

## 1. The routine, annotated

From `xteng.dec` (release 2.008, V2, base `0x001A0000`); the string
`bu00:FCDEXE1138` is at image `0x1BE2D4` and is referenced from exactly one
place. The four memory-card calls are not named by their argument shapes but
pinned by disassembly: each is a PSX BIOS B-function thunk - `addiu $t0, 0xB0;
jr $t0; addiu $t1, N`, a jump to the BIOS `0xB0` dispatch table with the
function number in `$t1` - and reading `N` out of each fixes the file API
exactly:

```
0x1A3DB4  B(32h) FileOpen      0x1A3DC0  B(33h) FileSeek
0x1A3DCC  B(34h) FileRead      0x1A3DF0  B(36h) FileClose
```

```
001A0834  addiu $sp, $sp, -0x240
...       ; build "bu00:FCDEXE1138\0" on the stack at sp+0x210
001A08BC  jal   0x1a3db4          ; open(name, 1)            -> fd
001A08CC  beq   $s1, $s2, ...      ; fd == -1 ? bail          (error check 1)
001A08E0  jal   0x1a3db4          ; open again               -> fd
001A08EC  beq   $s1, $s2, ...      ; fd == -1 ? bail          (error check 2)
001A08F4  addiu $a1, $sp, 0x10     ; header scratch buffer
001A08F8  jal   0x1a3dcc          ; read(fd, sp+0x10, 0x200) ; title + icon frames
001A0900  beqz  $v0, ...           ; read failed ? bail       (error check 3)
001A090C  lw    $s0, 0x54($sp)     ; s0 = *(u32*)(header + 0x44)   the load address
001A0910  jal   0x1a3dc0          ; seek/rewind
001A091C  lbu   $a2, 0x13($sp)     ; a2 = header[0x03]              the block count
001A0920  move  $a1, $s0           ; dst = load address
001A0924  sll   $a2, $a2, 0xd      ; size = blocks * 0x2000
001A0928  jal   0x1a3dcc          ; read(fd, load_addr, size - 0x200)
001A092C  addiu $a2, $a2, -0x200
001A0930  jal   0x1a3df0          ; close(fd)
001A0940  lw    $v1, 0x54($sp)     ; v1 = the load address again
001A0948  jalr  $v1                ; *** run it ***
```

The only three conditional branches in the whole routine are the two open checks
and the one read check. None of them reads a byte of the loaded file. There is
no comparison of any header field against a constant - no `PS-X EXE`, no FCD
magic, nothing. `plugin.py` verifies, per image, that the load-address slot sits
`0x44` past the header buffer, the size byte `0x03` past it, and that the window
from the payload read to the `jalr` contains no branch at all.

The FX firmwares are the same routine at a different base. In `english.dec`
(V3.20) it ends:

```
8002DF9C  lw    $s0, 0x5c($sp)     ; header + 0x44
8002DFAC  lbu   $a2, 0x1b($sp)     ; header + 0x03
8002DFB4  sll   $a2, $a2, 0xd
8002DFB8  jal   0x80041408         ; read body to [header+0x44]
8002DFD8  lw    $v1, 0x5c($sp)
8002DFE0  jalr  $v1                ; run it
```

The Pro builds (2.14, 2.20) print `Loading Memory Card Plugin...` and
`Executing Memory Card Plugin...` around the jump; the plain V2 and FX builds run
it silently. Same code either way.

## 2. The file format

```
offset  size  meaning
0x00    2     "SC" - the PSX save-title magic (a normal save)
0x03    1     block count; loader uses (this << 13) as the total size
0x04    64    Shift-JIS title (shown by the console's save browser)
0x44    4     LOAD ADDRESS, little-endian == entry point         <-- FCD's field
0x60    32    icon palette
0x80    ...   icon frame(s)
0x200   ...   payload: loaded to [0x44], executed from [0x44]
```

Everything except offsets `0x03` and `0x44` is standard PSX save layout, and
even those two are fields the console never dereferences - `0x03` is the block
count it already respects, `0x44` is reserved title-frame space. So a working
`FCDEXE1138` is indistinguishable from an ordinary save until the cartridge
loads it.

`1138` is the THX-1138 in-joke; `FCDEXE` is "FCD executable" - Future Console
Design's own name for the format, the same FCD whose initials seed the code keys
(`FINDINGS.md` §5.5).

## 3. Where it sits, and how it is reached

The loader is called from the cartridge's front-end (in `xteng` from `0x1B7744`),
behind a menu/pad action and a one-shot re-entry flag. It is a feature, not a
bug - FCD built it deliberately, alongside the CD-plugin path (`Searching for
Xplorer Plugins` / `Launching Xplorer Plugin`) that loads plugins from a disc,
and the `cdrom:system.cnf;1` read that boots the game. The cartridge is, among
other things, a loader platform. What no one had written down is that its
memory-card door is unauthenticated: any card with an `FCDEXE1138` save runs
arbitrary MIPS code on the PlayStation, with the load address chosen by the file.

## 4. What this does and does not settle

Settled, by disassembly across all ten images and by `plugin.py`'s per-image
assertions: the loader is present everywhere, the header offsets are `0x44`
(address) and `0x03` (size), and nothing validates the payload before the jump.
An independent disassembler (rizin, not this repo's capstone-based `mipscan`)
reproduces the 2.008 routine instruction-for-instruction, including the four
BIOS thunks above and the branch-free window from the payload read to the
`jalr`, so the reading does not rest on one toolchain.

Not executed. Unlike the code engine (`ENGINE.md` §5, run under `fwemu.py`),
this routine has only been *read*. Driving it would need the PSX memory-card
BIOS calls modelled, which the emulator here does not have. The reading is
strong - the routine is short, straight-line, and identical across ten
independent images - but it is a reading. No `FCDEXE1138` file has been observed
in the wild, so the format above is inferred from the loader, not from a sample.

Out of scope for xpcrypt. This is firmware behaviour, like the anti-tamper
check (`FINDINGS.md` §5.3b) and the code engine - documented here because it is
part of what these ROMs *are*, not because the code/ROM converter should act on
it.
