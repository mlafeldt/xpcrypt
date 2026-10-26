# The FCDEXE1138 loader: the memory-card upgrade runs unsigned code

Every Xplorer/Xploder PSX firmware in the corpus can upgrade itself from a memory
card. The routine behind that menu entry opens a PlayStation memory-card save
named `FCDEXE1138`, copies it into RAM, and jumps into it. There is no signature,
no checksum and no magic-byte test. The only thing that has to be true for the
cartridge to execute the file is that it exists on the card in slot 1 under that
name. FCD advertises the feature on screen; what nobody had written down is that
it is **unauthenticated**: any card carrying an `FCDEXE1138` save runs arbitrary
MIPS code on the PlayStation, at an address the file chooses.

This stands apart from everything in `FINDINGS.md`, `ENGINE.md` and `FCD.md`,
which are about *codes* - the code cipher, the cheat database, the runtime code
engine, and the `.fcd` image cipher. This is not a code path at all. It is the
menu firmware, and it hands the console to whatever is on the card.

Reproduce it:  `uv run --with capstone python plugin.py`  (a `make plugin`
target runs it in the gate).

## The four findings that matter

1. **It is FCD's own memory-card upgrade, and the menu says so.** In V2 2.008 the
   caller draws a *CD & Memory Card Upgrade* screen: "Press @s to upgrade via
   Memory Card.", "Press @c to run Xplorer CD`s.", "Press START to go back to
   menu.", and on failure "Couldnt upgrade via MemoryCard!". FX 3.20 has an
   *Upgrade Via Memory-Card* menu entry. Its loader draws "Loading Upgrade", and
   its caller then prints "Failed to find memorycard upgrade / Please use official
   FCD expansion memory-cards only". The Pro builds call the same file a *Memory
   Card Plugin*. It is a deliberate, advertised feature, not a hidden door.

2. **`bu00:FCDEXE1138` is loaded and executed with no validation.** The routine
   opens the file, reads a header, reads the body to an address the *file* names,
   and `jalr`s into it. The path from the final read to the jump is straight-line
   - not one branch inspects the loaded bytes (`plugin.py` asserts this). The
   name is the whole gate. "Official FCD expansion memory-cards only" is a request
   to the user; nothing in the code enforces it.

3. **The file names its own load address, and it is also the entry point.** The
   loader reads the first `0x200` bytes to a scratch buffer, takes the 32-bit
   word at **file offset `0x44`** as the destination, seeks to file offset
   `0x200`, reads the rest of the file there, and jumps to that same address. A
   crafted save can place and run code anywhere the BIOS read can write.

4. **It is in all ten images, both hardware generations, every release.** V2
   (Xplorer 2.x / Xploder V2, base `0x001A0000`) and FX (Xplorer FX V3/V4, base
   `0x80010000`), English/German/Japanese, releases 2.004 (1998) through 4.52,
   including release 2.005 - the tenth image bundled with the vendor's own X-Link.
   Exactly one reference to the filename string in each, and the same core
   sequence in each. The code around that sequence differs by build (§1).

## 1. The routine, annotated

From `xteng.dec` (release 2.008, V2, base `0x001A0000`); the string
`bu00:FCDEXE1138` is at image `0x1BE2D4` and is referenced from exactly one
place. The memory-card calls are not named by their argument shapes but pinned
by disassembly: each is a PSX BIOS thunk - `addiu $t0, 0xB0; jr $t0; addiu $t1, N`,
a jump to the BIOS `0xB0` (or `0xA0`) dispatch table with the function number in
`$t1` - and reading `N` out of each fixes the API exactly. The names and return
conventions are psx-spx's
([BIOS file functions](https://problemkaputt.de/psxspx-bios-file-functions.htm)):

```
0x1A3DB4  B(32h) FileOpen      0x1A3DC0  B(33h) FileSeek
0x1A3DCC  B(34h) FileRead      0x1A3DF0  B(36h) FileClose
0x1A3E14  A(2Bh) memset
```

```
001A0834  addiu $sp, $sp, -0x240
...       ; build "bu00:FCDEXE1138\0" on the stack at sp+0x210
001A08A0  jal   0x1a3e14           ; memset(sp+0x220, 0, 4)   zero the 4 bytes after it
001A08A8  jal   0x1a40cc           ; s3 = malloc(0x300)       never used, see below
001A08BC  jal   0x1a3db4           ; open(name, 1)            -> fd
001A08CC  beq   $s1, $s2, ...      ; fd == -1 ? return -1     (error check 1)
001A08D4  jal   0x1a3df0           ; close(fd)                the first fd is closed
001A08E0  jal   0x1a3db4           ; open(name, 1) again      -> fd
001A08EC  beq   $s1, $s2, ...      ; fd == -1 ? return -1     (error check 2)
001A08F4  addiu $a1, $sp, 0x10     ; header scratch buffer
001A08F8  jal   0x1a3dcc           ; read(fd, sp+0x10, 0x200) title + three icon frames
001A0900  beqz  $v0, ...           ; read returned 0 ? return -1  (error check 3)
001A0908  addiu $a1, $zero, 0x200
001A090C  lw    $s0, 0x54($sp)     ; s0 = *(u32*)(header + 0x44)   the load address
001A0910  jal   0x1a3dc0           ; lseek(fd, 0x200, SEEK_SET)    the payload offset
001A0914  move  $a2, $zero
001A091C  lbu   $a2, 0x13($sp)     ; a2 = header[0x03]              the block count
001A0920  move  $a1, $s0           ; dst = load address
001A0924  sll   $a2, $a2, 0xd      ; size = blocks * 0x2000
001A0928  jal   0x1a3dcc           ; read(fd, load_addr, size - 0x200)
001A092C  addiu $a2, $a2, -0x200
001A0930  jal   0x1a3df0           ; close(fd)
001A0938  jal   0x1a4294           ; free(s3)
001A0940  lw    $v1, 0x54($sp)     ; v1 = the load address again
001A0948  jalr  $v1                ; *** run it ***
001A0950  j     ...                ; if it ever returns: return 0
```

`0x1A40CC` and `0x1A4294` are the firmware's own heap allocator and its free.
Its block headers carry the words `0x57484246` and `0x57484255` (`"WHBF"`,
`"WHBU"`) and the heap ends at `0x58585858` (`"XXXX"`). The 0x300-byte buffer is
allocated and freed, and nothing in between touches it.

The only three conditional branches in the whole routine are the two open checks
and the one read check. None of them reads a byte of the loaded file. There is
no comparison of any header field against a constant - no `PS-X EXE`, no FCD
magic, nothing. Between the payload read and the `jalr` there are only the two
calls to `close` and `free`. Ghidra's decompilation of the routine reads the
same way, as does an independent disassembler (rizin, not this repo's
capstone-based `mipscan`).

Three details the listing makes plain:

* **The first open is a probe.** Its fd is closed before the second open. Why the
  firmware opens twice is not visible in the code.
* **Error check 3 tests for zero only.** `FileRead` returns the byte count, or −1
  on failure (psx-spx). A −1 passes the `beqz`, and the routine then reads the
  load address and block count out of a header buffer the read never filled -
  stack contents - and jumps there.
* **The bail paths leak.** Error check 3 returns without closing the second fd,
  and every bail skips the `free`.

`plugin.py` checks the core of this per image, using the bytes and not the
names: it locates the header buffer from the `0x200`-byte read and asserts that
the load-address slot sits `0x44` past it and the size byte `0x03` past it. It
asserts that the seek is to file offset `0x200`, that the size is `blocks << 13`
less `0x200`, and that the window from the payload read to the `jalr` contains
no branch at all. The open, read and seek calls are identified by the BIOS
function number in their thunks. Calls inside that window are allowed, and their
callees are not checked.

### Where the builds differ

The core sequence above - open, close, open, read `0x200`, seek `0x200`, read the
body, close, `jalr` - is the same in all ten images. Around it:

* **Plain V2 (2.004, 2.005, 2.008, 2.0081)** are as listed. The routine itself
  draws nothing; the menu around it does (§3).
* **Pro (2.14, 2.20)**, `0x1A0730` in `xtepro.dec`. The routine draws `Loading
  Memory Card Plugin...` after the header read and `Executing Memory Card
  Plugin...` immediately before the `jalr`. Error check 3 does not return. It
  fills the screen with one colour and hangs in a one-instruction loop
  (`0x1A0824 j 0x1A0824`).
* **FX (3.20, 4.50, 4.52)**, `0x8002DEB4` in `english.dec`. No `malloc`/`free`
  pair. The routine draws "Loading Upgrade" after the header read. After the body
  read and the close it makes two further calls, `0x80018BA0()` and
  `0x80010484(2)`, which were not identified. If the payload returns, it writes
  0 to the interrupt mask register (`I_MASK`, `0x1F801074`) and redraws.

The FX core, in `english.dec` (V3.20):

```
8002DF68  jal   0x80041408         ; read(fd, sp+0x18, 0x200)
8002DF8C  jal   0x80018c00         ; draw "Loading Upgrade"
8002DF9C  lw    $s0, 0x5c($sp)     ; header + 0x44
8002DFA0  jal   0x800413fc         ; lseek(fd, 0x200, SEEK_SET)
8002DFAC  lbu   $a2, 0x1b($sp)     ; header + 0x03
8002DFB4  sll   $a2, $a2, 0xd
8002DFB8  jal   0x80041408         ; read body to [header+0x44]
8002DFD8  lw    $v1, 0x5c($sp)
8002DFE0  jalr  $v1                ; run it
```

## 2. The file format

What the loader reads, against the standard title frame as psx-spx documents it
([memory card data format](https://problemkaputt.de/psxspx-memory-card-data-format.htm)):

```
offset  size  psx-spx                                      the loader
0x00    2     "SC"                                         not checked
0x02    1     icon display flag, 11h-13h                   not checked
0x03    1     "Block Number (1-15) ... Uh?" - uncertain    block count: size = this << 13
0x04    64    Shift-JIS title                              not read
0x44    12    reserved (00h)                               LOAD ADDRESS, LE == entry point
0x50    16    reserved, used by the PocketStation          not read
0x60    32    icon palette                                 not read
0x80    384   icon frames 1-3                              not read
0x200   ...   data                                         payload: loaded to and run from [0x44]
```

Everything except offsets `0x03` and `0x44` is standard PSX save layout. `0x44`
falls in reserved title-frame space that psx-spx says is zero. `0x03` is less
settled: psx-spx lists it with a question mark, as "usually 01h or 02h" and
possibly a block number within a multi-block file. Treating it as the file's
block count is FCD's reading; the console itself sizes a file from the directory
frames and the block chain. So a working `FCDEXE1138` looks like an ordinary
save with an icon, the executable packed behind the icon frames, but whether the
console's own browser cares about byte 3 is not settled here.

Only `bu00:` is opened, so only the card in slot 1 is consulted.

The name is not explained anywhere in the firmware or the PC tools. That
`FCDEXE` means "FCD executable" is an inference from the letters. That `1138` is
a THX-1138 in-joke is a guess.

## 3. Where it sits, and how it is reached

In `xteng` the loader is called from one place, `0x1B7744`, inside the *CD &
Memory Card Upgrade* screen's loop at `0x1B76E0`:

```c
pad = FUN_1a3a80(1, 0x30);               /* a button mask, active low */
if (!(pad & 0x0080)) {                   /* Square, the "@s" of the prompt */
        if (!card_ready) {               /* once per session */
                InitCard(1);             /* B(4Ah) */
                StartCard();             /* B(4Bh) */
                _bu_init();              /* A(70h) */
                set_card_auto_format(1); /* A(ADh) */
                card_ready = 1;
        }
        if (fcdexe_loader() == -1)
                message("Couldnt upgrade via MemoryCard!");
}
if (!(pad & 0x0020)) ...                 /* Circle: run an Xplorer CD */
if (!(pad & 0x0800)) ...                 /* START: back to the menu */
```

The button names are inferred: the three bits are the standard pad positions of
Square, Circle and START, and they match the three prompts on the screen. The
BIOS calls are read from their thunks. The flag at `0x1CBBD0` makes the
memory-card BIOS initialisation happen once. It
does not guard the loader, which runs on every Square press. The FX caller is
the same shape: its flag is at `0x8005BD38`, the same four BIOS calls follow
"Please Wait...", and after the loader returns it prints "Failed to find
memorycard upgrade" without looking at the return value.

The other callers: `0x1B7254` (USA 2.004), `0x1B7424` (2.005), `0x1B7748`
(2.0081), `0x1B8C38` (Pro 2.14), `0x1B91B4` (Pro 2.20), `0x8002DD60` (FX 3.20),
`0x8002E500` (4.50), `0x8002E18C` (4.52, both dumps).

FCD built it deliberately, alongside the CD-plugin path (`Searching for Xplorer
Plugins` / `Launching Xplorer Plugin`) that loads plugins from a disc, and, in
`xteng`, the `cdrom:system.cnf;1` read that boots the game. The cartridge is,
among other things, a loader platform, and both of its upgrade doors take
whatever they are given.

## 4. A second door: the X-Link command `'X'`

The parallel-port protocol (`comms.py`) has the same property. In `xteng` the
cartridge's receive loop stores a block at an address the PC sends, compares a
16-bit additive checksum, and for command byte `0x58` (`'X'`)
answers `'O'`, `'K'` and calls the block's start address (`jalr $fp` at
`0x1A1B2C`). The checksum guards against line noise, not against the sender, so
a PC on the cable can run code on the console just as a memory card can. Only
the `xteng` site was read for this note; `comms.py` has the protocol.

## 5. What this does and does not settle

Settled, by disassembly across all ten images (capstone, rizin, Ghidra) and by
`plugin.py`'s per-image assertions:

* the loader is present everywhere and reached from the upgrade screen;
* the header offsets are `0x44` (address) and `0x03` (size);
* the payload is read from file offset `0x200`;
* nothing validates the payload before the jump.

Not executed. Unlike the code engine (`ENGINE.md` §5, run under `fwemu.py`),
this routine has only been *read*. Driving it would need the PSX memory-card
BIOS calls modelled, which the emulator here does not have. The reading is
strong - the routine is short and straight-line, and its core is the same in ten
independent images - but it is a reading.

No `FCDEXE1138` file has been observed in the wild, and a web search for the
name finds nothing. The format above is inferred from the loader, not from a
sample. FX's "official FCD expansion memory-cards" suggests FCD shipped such
cards. None has turned up.

Out of scope for xpcrypt. This is firmware behaviour, like the anti-tamper
check (`FINDINGS.md` §5.3b) and the code engine - documented here because it is
part of what these ROMs *are*, not because the code/ROM converter should act on
it.
