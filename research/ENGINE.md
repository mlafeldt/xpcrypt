# The Xploder PSX code engine

Research notes. Not a user-facing document - it lives here with the rest of
`research/`, away from the shipped source.

The cartridge firmware everyone reverses - the menu, the code editor, the
database browser - is not what applies cheats. It stops running the moment a
game boots. What applies cheats is a 0x24C-byte blob that the firmware copies
into PlayStation kernel RAM at `0x00000A00` on its way out, hooking a BIOS entry
point so that it runs on every interrupt for as long as the game does.

That blob is the code engine. Its instruction set is the sixteen Xploder code
types, and it implements eleven of them in about a hundred instructions - a
fall-through chain of `bne`s, two branch targets, no jump table.

**Part I** is what the engine is and what each code type does. **Part II** is how
it was found, including the dead ends. `REVERSING.md` is the companion for the
cipher; `FINDINGS.md` has the conclusions of that work.

Everything here was read out of the cartridge ROMs, and then **executed**. The
engine of each of the nine firmwares is run in a MIPS interpreter over a
synthetic patch list, and every memory access it makes outside its own code, its
stack and the cartridge is recorded (§5, §15). So what a code type does *on the
console* is an observation rather than a reading. What the cartridge does to a
code *before* the console sees it - the four staging passes, which rewrite types
A, C and D, normalise addresses and build the control blocks for 5 and 6 - is
executed too, out of all ten images, over a handful of selections (§13). What is
not executed is the menu that builds a selection: the passes are handed
descriptor and pointer arrays constructed by hand. Every semantic carries the
annotated disassembly behind it and, where the shipped cheat databases have
specimens, real codes to go with it.

Scripts: `engine.py` finds and reads the engine in any ROM, `engineemu.py` runs
it, `dbtypes.py` surveys the shipped databases, and `typecx.py` is the file about
the two types this document could not account for (§16). The corpus is the same
nine images as everything else here - five Xplorer/Xploder V2 generation, four
Xplorer FX - and the five code databases they carry (§10). `typecx.py` and
`rom2005.py` add a tenth, release 2.005 out of `pc/ROMS/Xteng.fcd`, with a sixth
database; nothing in it moves any result here.


## The five findings that matter

**1. The engine is not always in the firmware image.** Three of the nine images
keep the blob inside the packed firmware (four of ten, with 2.005); the other six
keep it unpacked elsewhere in the ROM, so an image-only search finds it in a
third of the corpus and the search has to cover both (§12).

**2. Five of the sixteen types have no runtime handler, and staging decides what
three of them mean.** Types 1 and 2 have no handler and nothing in staging
touches them: they reach the engine and are ignored. A, C and D have no handler
either, but the staging passes rewrite them before the engine sees them - A into
a 5, a lone D into an F at the head of the list, and every C0 and every other D0
into a type 7 guard. Only a C or D whose flag nibble survived decryption reaches
the engine as itself, and does nothing. Type 1's emptiness is *used*: 134 times
in the shipped databases, as the second line of a slide code (§4, §13).

**3. All nine firmwares implement the same eleven types, in the same order, with
the same instructions - except type 4.** Slow motion is present in the five
V2/Pro builds and missing from all four FX builds. Executing all nine over the
same 26 cases finds that one per-type difference (§5, §6). The FX engines also
disarm the hardware breakpoint on every BIOS B() call, which is not about any
code type and is checked on its own.

**4. Shipping default-off codes without a cipher broke 120 codes.** The
default-off bit survives decryption for any code stored with key nibble 0, and
the engine's address mask keeps it - so the address gains `0x08000000`. Executed
on both halves (§7).

**5. The last staging pass normalises every code, and type E is its output.**
After decrypting a line, pass 4 rewrites it so that every address the engine
reads as a halfword is even: a byte or halfword write at an odd address becomes a
type E one byte down, a misaligned word write a halfword write, and a
conditional's address or a slide's step is made even. None of the 15,349 shipped
lines is stored as type E; 1,156 of the 14,939 codes among them are type E by
the time the console sees them. This, and the C and D rewrites of finding 2, are
whole-byte compares that no type-nibble scan can see (§13).

> **Ninth pass (`AUDIT.md`).** Findings 2, 3 and 5, the type C, D and E sections,
> §6, §7, §13 and §16 are rewritten: staging pass 4 normalises codes - `C0` and
> unhoisted `D0` become type 7, odd-address byte writes type E - and staging is
> now executed (`engineemu.py`). Also corrected: the §4 "Uses" counts, §7's
> key-nibble table, the installer sizes and stores, the FX list layout, the FX
> breakpoint disarm on every B() call, and the `WHB.` listing in §12.


# Part I - what the engine is

## 1. The shape of a code

A code is six bytes, written as eight hex digits, a space, and four more:

```
   T k a a a a a a   v v v v
   | |     |            |
   | |     |            +-- 16-bit value
   | |     +--------------- 24-bit address
   | +--------------------- flag nibble: bit 3 = off by default, bits 0-2 = cipher key
   +----------------------- code type
```

Only the *first* hex digit selects behaviour. The second is not part of the
address: bits 0 to 2 hold the encryption key and bit 3 marks a code that the
cartridge lists as switched off until the user enables it. Each of the four
cipher routes ends with `dst[0] = src[0] & 0xF0`, so a code that carried a key
comes out of decryption with a second digit of `0` - or `8` out of xpcrypt, which
keeps the default-off bit so that codes survive a round trip. A code stored *in
the clear* keeps whatever was there, which has consequences (§7).

That leaves 24 address bits. The engine masks the first word with `0x0FFFFFFF`
before using it as a pointer, so the flag nibble lands in bits 24 to 27 of the
address. It is zero for any code that went through a cipher route; a code stored
in the clear keeps it, which is §7's defect. Addresses are therefore KUSEG -
`0x0009CAC8` means `0x8009CAC8`, the same physical RAM.

The 16-bit value field is what most types write. Type 0 writes it as a 32-bit
word, zero-extended; there is no code type that carries a full 32-bit constant.

## 2. The engine: installation and feeding

Knowing this is what makes the per-type semantics readable, because part of the
type system lives in the staging code and never runs on the console at all.

```
  cheat database in ROM  ->  user enables cheats  ->  four staging passes
        ->  patch list written to cartridge flash at the list base
        ->  console reset, game boots
        ->  engine copied into PSX kernel RAM, BIOS trampoline hooked
        ->  engine walks the patch list on every return from exception
```

**The patch list** is an array of word pairs at a per-build base, terminated by a
zero first word. Everything below is relative to that base:

```
  +0x000  u32 word0   code bytes 0..3, big-endian   (type nibble intact)
  +0x004  u32 word1   code bytes 4..5               (or a pointer, see types 5/6)
  ...
  +0x400  payload bytes for Supercodes and inline data blocks
  +0x780  Megacode control block
  +0x800  game title
```

The base is not the same in all three families, which is easy to get wrong
because the V2 value is the one that turns up in every listing:

| family | list base | Megacode control block |
|---|---|---|
| V2 2.004, 2.008, 2.0081 | `0x1F022600` | `0x1F022D80` |
| Pro 2.14, 2.20 | `0x1F024600` | `0x1F024D80` |
| FX 3.20, 4.50, 4.52 | `*(u32 *)(*(u32 *)0x1F00007C + 0xBC)` | base `+0x780` |

The V2 and Pro engines name their base inline, in a `lui`/`ori` pair. The FX
engines take two loads to get there:

```
lw  $a3, 0x7C($a3)        ; a3 = the cartridge's support module
lw  $a0, 0xBC($a3)        ; a0 = the list base, out of a slot in it
```

so `*(u32*)0x1F00007C + 0xBC` is the address of the *slot*, and the list base is
what that slot holds - two dereferences, not one. Hard-coding the V2 value made
the emulator read cartridge ROM as a code list on the Pro firmwares (§15).

Staging builds the image in a zeroed 0x1000-byte buffer, and the cartridge's own
flash writer programs it at the list base, so the engine reads it straight out of
the cartridge. V2 and Pro write the whole 0x900 bytes, title included. FX writes
the 0x800 bytes of list, payload and control block there and the 0x100-byte title
separately, so the `+0x800` row of the layout above is V2/Pro only. The listings
below are from `xteng.dec` and so say `0x1F022600`; read that as "the list base"
throughout.

**The four staging passes** run over the enabled lines before that
(`0x1ACC74`, `0x1AD010`, `0x1ACB48` and an inline loop at `0x1AA9BC`, in
`xteng.dec`). Between them they consume the types the engine has no handler for:

| pass | function | what it consumes |
|---|---|---|
| 1 | `0x1ACC74` | type 6 - builds the Megacode control block (the first one only); skips over type 5 payload rows |
| 2 | `0x1AD010` | type 5 and type A - copies payload bytes to the buffer, emits a pointer |
| 3 | `0x1ACB48` | type F and type D - hoists one of them to the front of the list |
| 4 | inline | everything else, in order - each line normalised first (`0x1A835C`, §13) |

**The engine** is a 0x24C-byte position-dependent blob. `0x1A00AC` in
`xteng.dec` installs it:

```
001A00B0  lui   $a0, 0x1a
001A00B4  addiu $a0, $a0, 0x3778     ; src  = engine body
001A00B8  lui   $v0, 0x1a
001A00BC  addiu $v0, $v0, 0x39c4     ; end
001A00D0  addiu $a1, $zero, 0xa00    ; dst  = PSX RAM 0x00000A00
001A00D4  lw    $v0, ($a0)           ; word copy loop
001A00E0  sw    $v0, ($a1)
001A00F4  addiu $a0, $a0, 0x3768     ; src  = the 4-word trampoline
001A0110  addiu $a1, $zero, 0xb0     ; dst  = the BIOS B-function entry point
001A0138  sw    $v0, 0x9f0($zero)    ; *(u32*)0x9F0 = 0x001A3F70
001A0140  sw    $v0, 0x700($zero)    ; *(u32*)0x700 = -1
```

That is the V2 installer, and it copies exactly the 0x24C bytes of the blob. The
Pro and FX installers sit in the raw ROM (Pro 2.20 at ROM `0x22474`, FX 3.20 at
ROM `0xC1A0`) and use an inclusive end bound, so they copy 0x250 - the blob and
the word after it. Only the four V2 installers (2.004, 2.005, 2.008, 2.0081)
make the last two stores, to `0x9F0` and `0x700` (§9). The FX installer instead
may patch the engine it has just copied: if the byte at `0x8000002F` is set, it
stores a zero over the instruction at `0xA08`, which is FX's breakpoint disarm
(§6).

`0xB0` is the PSX kernel's B-function trampoline. Four words - the whole stub -
are replaced with a jump to `0xA00`:

```
09F0  3C080000  lui   $t0, 0
09F4  25080A00  addiu $t0, $t0, 0xa00
09F8  01000008  jr    $t0
09FC  00000000  nop
```

and the engine screens the call by function number, passing everything else
straight to `0x5E0`, which is where the original stub went:

```
0A00  08000282  j     0xa08
0A08  24080017  addiu $t0, $zero, 0x17   ; B(17h) = ReturnFromException
0A0C  1528008C  bne   $t1, $t0, 0xc40    ; anything else -> straight to the BIOS
...
0C40  340805E0  ori   $t0, $zero, 0x5e0  ; the real B-function dispatcher
0C44  01000008  jr    $t0
```

`$t1` holds the BIOS function number by convention, so the codes run on every
`ReturnFromException` - which is to say on every interrupt, several times a
frame. (That the kernel reaches B(17h) through the `0xB0` entry on every
interrupt is the BIOS's behaviour; nothing in these images shows it.) That is the
whole timing model: there is no separate "apply once" pass, and a code that has to
be written repeatedly and a code that only has to be written once are the same
code.

## 3. The dispatcher

```
0A34  3C021F06  lui   $v0, 0x1f06
0A38  90440000  lbu   $a0, ($v0)         ; cartridge control port
0A44  30840001  andi  $a0, $a0, 1
0A48  10800075  beqz  $a0, 0xc20         ; codes switched off -> do nothing
0A4C  3C081F02  lui   $t0, 0x1f02
0A50  350830B0  ori   $t0, $t0, 0x30b0   ; cartridge vector table, entry 6
0A54  0100F809  jalr  $t0                ; per-pass cartridge callback
0A58  34040057  ori   $a0, $zero, 0x57   ; 'W'

0A5C  3C041F02  lui   $a0, 0x1f02
0A60  34842600  ori   $a0, $a0, 0x2600   ; a0 = the patch list (0x4600 on Pro;
                                         ;   FX loads a pointer instead)

0A64  8C850000  lw    $a1, ($a0)         ; <- loop head, word0
0A6C  10A0006C  beqz  $a1, 0xc20         ; zero word0 terminates the list
0A74  8C860004  lw    $a2, 4($a0)        ; a2 = word1: value, or a pointer
0A7C  3C030FFF  lui   $v1, 0xfff
0A80  3463FFFF  ori   $v1, $v1, 0xffff   ; v1 = 0x0FFFFFFF
0A84  00051702  srl   $v0, $a1, 0x1c     ; v0 = type
0A88  00A32824  and   $a1, $a1, $v1      ; a1 = address
...                                      ; one bne per type, in the order
                                         ; F 4 B 7 9 3 E 8 0 5 6
0C18  08000299  j     0xa64              ; "next code"
0C1C  24840008  addiu $a0, $a0, 8        ; delay slot: advance one entry
0C20  ...                                ; "stop": restore and leave
```

Four things follow from the shape of this loop and are worth having in mind
before reading the individual types.

* The chain is a **fall-through chain, not a jump table**. A type with no `bne`
  of its own simply falls off the end and reaches "next code" having done
  nothing. That is not an error path - it is how types 1 and 2, and a C or D
  that staging left alone, are disposed of, and type 1 is used deliberately for
  it (see type 1).
* Two labels do the work: `0xC18` advances by one entry and loops, `0xC20`
  abandons the rest of the list for this pass. Conditionals reach `0xC18` with
  an extra `addiu $a0, $a0, 8` in the delay slot, which is how they skip the
  line they guard.
* `$a2` is loaded once, before the type is known. For most types it is the
  16-bit value; for types 5 and 6 the staging pass put a *cartridge pointer*
  there instead.
* Every entry's address is read as a **halfword** before its type is known: the
  type F test's `lhu` sits in the delay slot of its `bne` (`0xA94`), and type 7's
  does too (§5). An odd address there is an address-error exception on an R3000
  - by the MIPS I rules, not observed here - inside the B(17h) hook. Staging's
  normaliser makes the addresses it can even, which is what type E is for (§13).

## 4. The instruction set

The sixteen code types, ordered by type nibble. "Uses" counts codes in the five
shipped databases, counting a block header once and not counting its payload
rows.

### Type 0 - 32-bit write

```
00aaaaaa vvvv       *(u32 *)addr = value;      /* value is zero-extended */
```

```
0B78  14020002  bne   $zero, $v0, 0xb84    ; only type 0 gets here with v0 == 0
0B7C  00000000  nop
0B80  ACA60000  sw    $a2, ($a1)
```

Uses: 1. The odd one out in the corpus - `002A79A0 3FF4` in the German
Command & Conquer 2 entry, and its address is past the end of a 2 MB PSX. The
type works; nobody used it. A 32-bit write of a value that can only be 16 bits
wide is not very useful, which is presumably why. A type 0 at an address that is
not a multiple of four never reaches the engine as one: staging turns it into a
16-bit write, or a byte write at an odd address (§13).

### Type 1 - nothing

No handler in any of the nine firmwares. A type 1 line falls through the whole
chain and advances to the next entry.

Uses: 134 - and every one of them is deliberate. Type 1 is the conventional
**second line of a type B slide code** (see type B): the slide handler reads that line
as data through `$a0`, but the loop still advances by only eight bytes, so the
second line is then dispatched on its own. Giving it a type with no handler is
what stops it from also being executed as a code.

```
Xplorer 2.008 UK | G-Police | All weapons
    B00D0004 0000
    100F60D4 0030     <- type 1: data for the line above, no-op on its own
    800F60F0 0000
```

### Type 2 - nothing

No handler, no route in the cipher's jump table, and no specimen in any of the
databases. Nothing in the corpus says what it was meant to be.

`typecx.py` is the attempt to close that (§16). It adds a **tenth image** -
`pc/ROMS/Xteng.fcd`, release 2.005, which ships with the DOS tool and carries a
sixth database of 1,668 cheats - and widens §13's classifier scan from one idiom
to three. Ten firmwares, 17,183 code lines: still no handler, still no site that
looks at the nibble, still not one specimen. `x-killer.exe`, a stranger's tool
from 1999 whose help dialog writes out all sixteen types, has `"2" : ??`.

### Type 3 - 8-bit write

```
30aaaaaa 00vv       *(u8 *)addr = value;       /* low byte of the value */
```

```
0B44  34080003  ori   $t0, $zero, 3
0B48  14480002  bne   $v0, $t0, 0xb54
0B4C  00000000  nop
0B50  A0A60000  sb    $a2, ($a1)
```

Note the missing branch after the store: type 3 falls into the type E test,
which cannot match because `$v0` is still 3. The chain is written throughout on
that assumption.

Uses: 2,988, second only to type 8. 1,093 of them have an odd address, and
staging hands those to the engine as type E one byte down (§13) - the same
store, by a handler whose dispatcher reads stay aligned.

```
Xplorer 2.008 UK | Everybody's Golf | Unlock All Courses
    30104918 0005
```

### Type 4 - slow motion

```
40000000 vvvv       busy-wait (value << 12) iterations, once per pass
```

The engine does not implement this itself; it calls entry 4 of the cartridge's
vector table.

```
0AA8  34080004  ori   $t0, $zero, 4
0AAC  15020005  bne   $t0, $v0, 0xac4
0AB4  3C031F02  lui   $v1, 0x1f02
0AB8  346330A0  ori   $v1, $v1, 0x30a0   ; 0x1F0230A0 (0x1F0250A0 on the Pro)
0ABC  0060F809  jalr  $v1
```

and on the other side of the call, in the cartridge's unpacked support module:

```
9F02334C  27BDFFEC  addiu $sp, $sp, -0x14
9F02335C  84030C84  lh    $v1, 0xc84($zero)   ; re-entry guard
9F023360  35081234  ori   $t0, $t0, 0x1234    ; t0 is still 4, and 4 | 0x1234
9F023364  11030006  beq   $t0, $v1, 0x9f023380  ; is 0x1234 - so the guard word
9F02336C  00061300  sll   $v0, $a2, 0xc       ; is a constant.  v0 = value << 12
9F023370  AC080C84  sw    $t0, 0xc84($zero)
9F023374  1C40FFFF  bgtz  $v0, 0x9f023374     ; the delay
9F023378  2442FFFF  addiu $v0, $v0, -1
9F02337C  AC000C84  sw    $zero, 0xc84($zero)
```

The helper ignores the address field; the value is the delay. The dispatcher does
not ignore the address, though - it dereferences it twice on the way past like
every other entry (§5). Since the list is walked on every return from exception,
burning cycles there slows the game down.

Uses: 6, all of them named "Slow Motion" or "SlowMo".

```
Xplorer 2.008 UK | International Track & Field | Slow Motion
    40000000 002A
Xplorer Pro 2.20 UK | Rayman | SlowMo
    48000000 5100        <- flag nibble 8: listed but switched off by default
```

**Not implemented on Xplorer FX.** All four FX firmwares are missing this one
branch and nothing else (§6). A slow-motion code on an FX cartridge falls
through the chain and does nothing.

### Type 5 - Supercode: copy a byte block into RAM

```
5?aaaaaa Knnn       header: nnn = payload bytes (12 bit), K = payload key
<ceil(nnn/6) payload rows>
```

Staging pass 2 walks the payload rows, decrypts each with the payload key, and
lays the block down in the flash buffer behind a four-byte header:

```
  +0  u16  nnn, little-endian
  +2  u16  0
  +4  ...  nnn payload bytes
```

The list entry it emits is `word0 = 0x50aaaaaa`, `word1 = list base + offset`
-  a pointer, not a value. The engine then copies:

```
0B84  34080005  ori   $t0, $zero, 5
0B88  1502000B  bne   $t0, $v0, 0xbb8
0B90  84C20000  lh    $v0, ($a2)         ; count from the block header
0B94  24C60004  addiu $a2, $a2, 4        ; skip the header
0B98  80C30000  lb    $v1, ($a2)         ; <- byte copy loop
0B9C  24C60001  addiu $a2, $a2, 1
0BA0  A0A30000  sb    $v1, ($a1)
0BA4  2442FFFF  addiu $v0, $v0, -1
0BA8  1440FFFB  bnez  $v0, 0xb98
0BAC  24A50001  addiu $a1, $a1, 1        ; delay slot
0BB0  10000019  b     0xc18
```

A byte-at-a-time copy, so the destination need not be aligned and the payload
length need not be a multiple of anything. Overlapping source and destination
would be well defined too, though the source is in flash.

The loop copies a byte *before* it decrements and tests, so a count of zero
becomes `0xFFFFFFFF` and the copy never ends. Two shipped cheats declare one
(§7).

Uses: 44 headers, of which 42 declare a payload. The payload is usually a patch
written in MIPS - which is what makes Supercodes worth the trouble.

```
Xplorer 2.008 UK | Future Cop LAPD | Ammo
    5006C268 6008        <- 8 payload bytes, payload key 6
    E8031124 8400        <- payload rows, decrypted
    71A40000 0000
```

The eight payload bytes `E8 03 11 24 84 00 71 A4` are two MIPS instructions:

```
    addiu $s1, $zero, 0x3e8
    sh    $s1, 0x84($v1)
```

1000 rounds of ammunition, stored by the game's own code, patched in over
whatever was there.

### Type 6 - Megacode: hardware breakpoint plus handler

```
6?aaaaaK nnnn       header: nnnn = payload bytes, K = payload key
<descriptor row>    break address (4 bytes, big-endian) + 2 bytes of DCIC
<mask row>          break mask (4 bytes, big-endian) + first 2 payload bytes
<payload rows>
```

The only type that uses the CPU's debug unit: it arms a hardware watchpoint and
installs an exception handler, instead of writing to an address of its own.
(Type 5 also installs code, when its payload happens to be code - but it does it
with a plain byte copy to the address in its header.) Staging pass 1 turns the
descriptor into a control block at list base `+0x780`, storing the rows
byte-reversed so that each big-endian field lands as a little-endian word:

```
  +0x00  u32  DCIC value        (descriptor bytes 4,5 in the high half)
  +0x04  u32  break address     (descriptor bytes 0..3)
  +0x08  u32  break mask        (mask row bytes 0..3)
  +0x0C  u32  payload word count = (nnnn + 3) / 4
  +0x10  ...  payload
```

and emits the fixed list entry `word0 = 0x60000000`, `word1 =` that address.
The engine programs the R3000's debug registers from it and installs the payload
at `0xA0000040`:

(COP0 registers are numbered here; capstone prints them with general-purpose
register names, so `mtc0 $zero, $a3` in a raw listing is `mtc0 $zero, $7`.)

```
0BB8  34080006  ori   $t0, $zero, 6
0BBC  15020016  bne   $t0, $v0, 0xc18
0BC4  40803800  mtc0  $zero, $7        ; DCIC = 0, breakpoints off while we work
0BC8  8CC30008  lw    $v1, 8($a2)      ; mask
0BCC  8CC20004  lw    $v0, 4($a2)      ; break address
0BD0  40835800  mtc0  $v1, $11         ; BPCM
0BD4  40834800  mtc0  $v1, $9          ; BDAM
0BD8  40821800  mtc0  $v0, $3          ; BPC
0BDC  40822800  mtc0  $v0, $5          ; BDA
0BE0  40823000  mtc0  $v0, $6          ; TAR
0BE4  8CC3000C  lw    $v1, 0xc($a2)    ; word count
0BE8  24C80010  addiu $t0, $a2, 0x10   ; payload
0BEC  3C05A000  lui   $a1, 0xa000
0BF0  24A50040  addiu $a1, $a1, 0x40   ; 0xA0000040 - the breakpoint vector
0BF4  8D020000  lw    $v0, ($t0)       ; <- word copy loop
0BF8  25080004  addiu $t0, $t0, 4
0BFC  ACA20000  sw    $v0, ($a1)
0C00  2463FFFF  addiu $v1, $v1, -1     ; copy first, then count down
0C04  1460FFFB  bnez  $v1, 0xbf4       ; ... so a count of 0 wraps and runs away
0C08  24A50004  addiu $a1, $a1, 4      ; delay slot
0C0C  8CC80000  lw    $t0, ($a2)       ; DCIC value from the control block
0C10  10000001  b     0xc18
0C14  40883800  mtc0  $t0, $7          ; delay slot: arm it
```

`0x80000040` is the R3000's **breakpoint exception vector** with `BEV` clear.
The payload is not data being written into the game - it is the exception
handler. The cartridge sets a hardware watchpoint on an address the game
touches, and the payload runs whenever it does. That is why a Megacode's payload
ends in `jr $k0` and why the descriptor's break address turns up as a literal
inside the payload:

```
Xplorer Pro 2.20 UK | Bloody Roar | Infinite Energy Player 1
    60000000 002C      <- 0x2C = 44 payload bytes, payload key 0
    1F800198 EA80      <- descriptor: break at 0x1F800198, DCIC 0xEA800000
    FFFFFFFC 0038      <- mask 0xFFFFFFFC, then payload bytes 00 38
    8040801F 1A3C
    98015A37 0000
    40A780EA 1A3C
    00389A40 0070
    1A400000 0000
    04005A27 0800
    40031000 0042
```

Ten lines, 44 payload bytes, and they disassemble into a complete exception
handler:

```
80000040  40803800  mtc0  $zero, $7        ; DCIC = 0 - disarm, we are inside it
80000044  3C1A1F80  lui   $k0, 0x1f80
80000048  375A0198  ori   $k0, $k0, 0x198  ; the watched address
8000004C  A7400000  sh    $zero, ($k0)     ; ... and the actual cheat
80000050  3C1AEA80  lui   $k0, 0xea80
80000054  409A3800  mtc0  $k0, $7          ; re-arm with the descriptor's DCIC
80000058  401A7000  mfc0  $k0, $14         ; EPC
8000005C  00000000  nop
80000060  275A0004  addiu $k0, $k0, 4      ; step past the faulting instruction
80000064  03400008  jr    $k0
80000068  42000010  rfe                    ; delay slot
```

`0x1F800198` is in the scratchpad, `0xFFFFFFFC` masks a whole word, and the
"cheat" is one `sh`. Everything else is breakpoint bookkeeping. The `$k0`/`$k1`
registers, the `mfc0 $14`, the `rfe` in the delay slot - this is an exception
handler written by someone who did it for a living.

The descriptor row is *payload*, not a code line: it is decrypted with the
payload key like every other row, and its first nibble means nothing. Reading it
as a code is what xpcrypt used to get wrong.

Uses: 11 headers, of which 10 declare a payload that fits inside their cheat
entry. The eleventh is malformed: `Metal Gear Solid - Jp / Verliere Chaff` in the
German database is a one-line cheat whose only line decrypts to a header
declaring 55,261 payload bytes - 9,212 rows that are not there. Enabled, it does
not fail quietly. Pass 1 takes its descriptor and mask from the next two selected
lines without looking at them - the next enabled cheat's name line and first
code - and the rest of that cheat as payload, so the next cheat is swallowed; and
the control block it writes tells the engine to copy 13,816 words to
`0xA0000040` upward, over the exception vectors and the engine itself. Executed
in all ten images (§13).

### Type 7 - execute next code if equal

```
70aaaaaa vvvv       if (*(u16 *)addr != value) skip the next code;
```

```
0B00  34080007  ori   $t0, $zero, 7
0B04  14480006  bne   $v0, $t0, 0xb20
0B08  94A80000  lhu   $t0, ($a1)       ; delay slot
0B10  11060041  beq   $t0, $a2, 0xc18  ; equal -> fall through to the next code
0B18  080002FF  j     0xc18
0B1C  24840008  addiu $a0, $a0, 8      ; not equal -> one extra entry skipped
```

Both arms go to `0xC18`, which itself advances by eight. The unequal arm
advances twice, so exactly one following code is skipped. Nesting therefore does
not work: a conditional guards one line, never a group.

Uses: 589. Usually a "the game is on the right screen" test. Staging forces its
address even (§13), and produces more of them: every C0 line and every D0 that
is not hoisted reaches the engine as a type 7.

```
Xplorer 2.008 UK | Gran Turismo (Euro) | B. License
    7005A4E6 0100      <- only if this halfword reads 0x0100
    B0040002 0000
    1009E3C4 0303
```

The guarded line here is the type B header, and the slide's second line rides
along with it, because the slide handler reads it through `$a0` rather than
through the loop. A conditional in front of a Supercode or Megacode header is
recognised specially by the staging passes so that it is emitted immediately in
front of the block entry (§7).

### Type 8 - 16-bit write

```
80aaaaaa vvvv       *(u16 *)addr = value;
```

```
0B64  34080008  ori   $t0, $zero, 8
0B68  14480003  bne   $v0, $t0, 0xb78
0B70  A4A60000  sh    $a2, ($a1)
```

Uses: 10,689 - seven codes in ten. 63 of them have an odd address; staging turns
each into a byte write of the value's low byte, a type E one byte down (§13).

```
Xplorer 2.008 UK |  To Kill |  Health
    800D720A 4E20
```

### Type 9 - execute next code if not equal

```
90aaaaaa vvvv       if (*(u16 *)addr == value) skip the next code;
```

```
0B20  34080009  ori   $t0, $zero, 9
0B24  14480007  bne   $v0, $t0, 0xb44
0B2C  94A80000  lhu   $t0, ($a1)
0B34  15060038  bne   $t0, $a2, 0xc18  ; different -> run the next code
0B3C  080002FF  j     0xc18
0B40  24840008  addiu $a0, $a0, 8      ; equal -> skip it
```

The mirror image of type 7, same skip-exactly-one rule. Unlike type 7, staging
leaves its address alone.

Uses: 43.

### Type A - inline data block

```
A?aaaaaa vvvv       header: 24-bit address, first two payload bytes in the value
<literal rows>      six raw payload bytes each, to the end of the cheat entry
```

No engine handler: staging pass 2 rewrites it as a type 5 entry. It reads
the header's address bytes, forces the type nibble to 5, and copies the value
field plus every following line's six raw bytes into the payload buffer:

```
001AD3A8  24130050  addiu $s3, $zero, 0x50    ; the type nibble it will emit
001AD3CC  00139A00  sll   $s3, $s3, 8         ; ... and code bytes 1,2,3
001AD3D0  90620000  lbu   $v0, ($v1)
001AD3D8  02629825  or    $s3, $s3, $v0
001AD3E8  AEB30000  sw    $s3, ($s5)          ; word0 = 0x50aaaaaa
001AD3F4  02421021  addu  $v0, $s2, $v0       ; word1 = list base + offset
001AD424  90A20004  lbu   $v0, 4($a1)         ; payload[0] = code[4]
001AD430  90A20005  lbu   $v0, 5($a1)         ; payload[1] = code[5]
001AD478  8D050000  lw    $a1, ($t0)          ; then six raw bytes per line
001AD48C  A0820000  sb    $v0, ($a0)          ;   - not decrypted, not classified
001AD4CC  00111040  sll   $v0, $s1, 1
001AD4D0  00511021  addu  $v0, $v0, $s1
001AD4D4  00021040  sll   $v0, $v0, 1
001AD4D8  24420002  addiu $v0, $v0, 2         ; count = 6 * lines + 2
```

The rewrite replaces the whole first byte with `0x50`, so a type A is the one
type whose flag nibble cannot leak into the address (§7). Pass 2 takes every line
whose stored type nibble is A, flag nibble or not, so on a cartridge no type A
reaches the engine; one put in a patch list by hand would do nothing.

Where a Supercode declares its length, a type A block runs to **the end of the
cheat entry**: the copy loop stops at the first line whose list descriptor is not
an enabled code line. It is the hand-entry form of a Supercode - no length to
work out, no payload cipher, just "everything below this line is data".

Uses: 0 in the recovered corpus (§8). The type has no cipher route either, so it
could be stored directly by any tool that writes a database - which the type C
specimens show did happen - as well as typed in by hand.

### Type B - slide code

```
B0ccssss tttt       cc = repeat count, ssss = address step, tttt = value step
10aaaaaa vvvv       start address and start value  (any type with no handler)
```

The only type that reads a second list entry.

```
0AC4  3408000B  ori   $t0, $zero, 0xb
0AC8  1502000D  bne   $t0, $v0, 0xb00
0ACC  00054402  srl   $t0, $a1, 0x10    ; delay slot: count = addr field >> 16
0AD0  8C860008  lw    $a2, 8($a0)       ; next entry's word0 = start address
0AD4  8C82000C  lw    $v0, 0xc($a0)     ; next entry's word1 = start value
0AD8  00663024  and   $a2, $v1, $a2     ; mask off its type nibble
0ADC  84850000  lh    $a1, ($a0)        ; address step: low half of word0, signed
0AE0  84830004  lh    $v1, 4($a0)       ; value step:   low half of word1, signed
0AE4  1100004C  beqz  $t0, 0xc18        ; <- loop
0AEC  A4C20000  sh    $v0, ($a2)        ; 16-bit writes
0AF0  2508FFFF  addiu $t0, $t0, -1
0AF4  00A63021  addu  $a2, $a1, $a2     ; address += step
0AF8  1000FFFA  b     0xae4
0AFC  00621021  addu  $v0, $v1, $v0     ; value   += step
```

so the header's address field is not an address at all: bits 16 to 27 of `word0`
are the count and bits 0 to 15 the address step. The top four of those twelve
count bits are the flag nibble, which the cipher clears, so in practice the
count is the two hex digits after it and tops out at 255. Both steps are
sign-extended, so a slide can walk backwards or count down. The writes are
16-bit regardless.

When the loop finishes, control reaches `0xC18`, which advances by *one* entry.
The second line is then dispatched normally - see type 1 for why that is safe.

Uses: 159. Staging forces the address step even (§13). 25 of the 159 slides use
a type 8 or type 3 second line instead of a type 1, and that line then also runs
as an ordinary write after the slide - harmless in every shipped case, because it
repeats the slide's first write.

```
Xplorer 2.008 UK | G-Police | All weapons
    B00D0004 0000      <- 13 iterations, address += 4, value += 0
    100F60D4 0030      <- start at 0x0F60D4 with 0x0030
    800F60F0 0000
```

Thirteen consecutive weapon slots, four bytes apart, all set to 0x30.

### Type C - equality guard, by staging

```
C0aaaaaa vvvv       staged as 70aaaaaa vvvv:
                    if (*(u16 *)addr != value) skip the next code;
Cfaaaaaa vvvv       f != 0: nothing
```

No engine handler and no route in the cipher's jump table, so type C lines are
stored and read back verbatim. What gives them a meaning is the last staging pass:
its normaliser (§13) rewrites a line whose decrypted first byte is exactly `C0` as
`70`, address forced even, so a C0 is a type 7 by the time the console sees it.
The match is on the whole byte. A C with any flag nibble - `CD`, `C6`, `C8` -
passes through untouched, reaches the engine and does nothing, and that is what
makes C useful as a type that does nothing, as long as the nibble is set. The 27
lines in the databases are three different uses of the type, and only one of them
is a C0. Most of them are filler: the information is in the *cheat name*, and the
code line only exists because a cheat entry needs at least one.

```
Xplorer Pro 2.20 UK | Nuclear Strike | *****ISLAND STRIKE*****
    CDEEF45C 0008
Xplorer Pro 2.20 UK | Blast Radius | ALWAYS ACTIVATE THE NEXT ONE
    CDE0E478 0006
Xploder V2 2.004 US | Wipeout  |  Turbo Level 1
    C6671C0E 505A      <- stored; the line below is stored as 86671C0E 5061
    8013C5BA FF09
```

The Wipeout pair is not filler at all: it is a code switched off by giving it a
type that, with a flag nibble set, nothing implements, its ciphertext left
intact. The two stored lines share their three ciphertext address bytes and
differ in the type nibble and the last byte, and putting an `8` back in that
nibble and decrypting settles what the difference is - see the end of this
section.

The Japanese Pro database uses type C for something else entirely - joker codes:

```
Xplorer Pro 2.14 JP | ワールドスタジアム2 | R1+×で豪速球
    C006A2EA B7FF
    8006E9C0 03E7
Xplorer Pro 2.14 JP | ワールドスタジアム2 | R2+×でスローボール
    C006A2EA BDFF
    8006E9C0 0032
Xplorer Pro 2.14 JP | ワールドスタジアム2 | 上+R1+×で速フォーク
    C006A2EA B7EF
    8006E9BC 00FF
```

Those values decode exactly as PlayStation pad masks, active low: `0xB7FF` is
`~(R1 | cross)`, `0xBDFF` is `~(R2 | cross)`, `0xB7EF` is `~(R1 | cross | up)` -
and the cheat names say R1+×, R2+× and up+R1+×. The type C line is a button test
guarding the write below it, and it works as one. All six jokers are stored `C0`,
the cipher copies them, and Pro 2.14's own staging passes emit `C006A2EA B7FF` as
`7006A2EA B7FF` (executed, §13): the write happens while the pad halfword at that
address equals the mask, that is, while exactly those buttons are held.

Three things `typecx.py` settles about the 27 lines. **The Wipeout pair is a
disabled code, and the ciphertext proves it**: put an `8` back in the type nibble
of `C6671C0E 505A` and decrypt with key 6, which its own flag nibble declares,
and out comes `8013C5BA FF00` - the address of the type 8 line below it exactly,
value `FF00` where the live one writes `FF09`. Four for four across the four
Wipeout entries. **The filler lines are one line copied and edited**: all
seventeen of them read `CD E?`, in three databases, so they are a habit rather
than seventeen decisions - and a habit that keeps them inert, since a `C0` would
have been staged as a live guard. **And the Japanese joker masks are not FCD's.**
`XLink.exe` prints its own "PlayStation Joypad Values" table, and that table is
the pad halfword *byte-swapped* - `FFFE` is L2, `FEFF` is Select, every entry the
hardware bit plus eight. The Japanese type C values decode the other way round:
`C0007572 FFFE` is the cheat `セレクトボタンでカギGET！` ("get the key with
SELECT") and `C0007572 FEFF` is `L2ボタンでカギ消える！`. Six for six under the
raw hardware layout, none out of six under FCD's. The same database tests the pad
FCD's way five times over, in other games, with type 7 and the *active-high* masks
straight out of that table - `L1` is `0004`, `L2+R2` is `0003`. So the type C
codes and the type 7 codes in one database follow two conventions: two hands,
which the `(X-T用)` / `(X-Tのみ)` ("for X-T" / "X-T only") markers elsewhere in
that database would fit - it was compiled from a code list that covered more than
this cartridge - or two games that keep their pad state differently. The firmware
does not say which.

Uses: 27 - 17 filler (`CD`) and 4 disabled codes (`C6`), all inert, and 6 jokers
(`C0`), all live.

### Type D - single anchor code, or a guard

```
D0aaaaaa vvvv       the only D in the selection, and no F: hoisted as F0aaaaaa vvvv
                    otherwise: staged as 70aaaaaa vvvv, a type 7 guard
```

No engine handler. Staging pass 3 scans the enabled lines for one, testing the
*stored* bytes, before anything is decrypted:

```
001ACB9C  91040000  lbu   $a0, ($t0)          ; the stored first byte
001ACBA4  308300F0  andi  $v1, $a0, 0xf0
001ACBA8  14620008  bne   $v1, $v0, 0x1acbcc  ; v0 = 0xF0: a type F line?
001ACBAC  308300FF  andi  $v1, $a0, 0xff      ; (delay slot: v1 = the whole byte)
001ACBB4  A0A00000  sb    $zero, ($a1)        ;   consume it
001ACBC0  304200FE  andi  $v0, $v0, 0xfe      ;   clear bit 0 of stored byte 3
001ACBC4  0806B30E  j     0x1acc38            ;   and hoist it
001ACBCC  240200D0  addiu $v0, $zero, 0xd0
001ACBD0  14620005  bne   $v1, $v0, 0x1acbe8  ; exactly D0 - the whole byte?
001ACBD8  1D40001F  bgtz  $t2, 0x1acc58       ;   a second one -> give up entirely
001ACBE0  254A0001  addiu $t2, $t2, 1
001ACBE4  01205821  move  $t3, $t1            ;   remember where it was
...
001ACC00  15420015  bne   $t2, $v0, 0x1acc58  ; exactly one D, or nothing happens
001ACC24  A1030000  sb    $v1, ($t0)          ; rewrite its type byte to 0xF0
001ACC28  304200FE  andi  $v0, $v0, 0xfe      ; clear bit 0 of stored byte 3
001ACC38  0C06B2C7  jal   0x1acb1c            ; shift the list up by two words
001ACC4C  0C06B2A2  jal   0x1aca88            ; and decrypt and emit it at index 0
```

`0x1ACB1C` copies every existing entry two words further along, so the promoted
line ends up **first in the list** and is therefore evaluated before anything
else on every pass. Since type F aborts the whole list on a mismatch, one type D
line gates every enabled cheat at once.

The rules are asymmetric and worth stating plainly. A type F line is hoisted if
it is the first one found, whatever else is in the list, and it is found by its
type nibble. A type D line is hoisted only if its stored first byte is exactly
`D0` and it is the *only* such line in the whole enabled selection. Every other
D0 - a second one, or one beside an F - is left in place, and pass 4's normaliser
then turns it into a type 7 guard over the line below it (executed, §13). An
encrypted D (stored `D4` to `D7`) is never hoisted, but it decrypts to `D0` and
becomes a type 7 the same way. Only a D stored with a low nibble the cipher does
not scrub - `D1` to `D3`, which take the copy route, or `D8` and up in the clear -
reaches the engine as a type D, and does nothing.

The even address is made on the stored bytes, which is right for a line stored in
the clear and wrong for an encrypted one: clearing bit 0 of a ciphertext byte
changes the decryption. Three shipped anchors have that bit set, all key 4 and
all in the USA database - `F425BD7F D32A` twice in Diablo, decrypting to
`F00047AC 0001`, and Golden Nugget's `F4257FAF 25E6`. Hoisted, the USA firmware
emits the first as `F00047AD 0707` (executed): an odd address, which the R3000
traps on, and the wrong value - an anchor that cannot match. If one of those
three is the first type F in the selection, no code in it runs.

Uses: 3, all in the Xplorer Pro 2.20 database, each stored `D0` and alone in its
cheat.

```
Xplorer Pro 2.20 UK | Sentinel Returns - MUL | L1+SEL gives 20 Energy
    D01A5C00 0880      <- reaches the engine as F01A5C00 0880, first in the list,
    801A5A38 0014         if it is the only D enabled - as 701A5C00 0880 if not
```

### Type E - 8-bit write, one byte up

```
E0aaaaaa 00vv       *(u8 *)(addr + 1) = value;
```

```
0B54  3408000E  ori   $t0, $zero, 0xe
0B58  14480002  bne   $v0, $t0, 0xb64
0B60  A0A60001  sb    $a2, 1($a1)
```

Type 3 with an offset of one - the high byte of the halfword at `addr`, on a
little-endian machine. Present and working in all nine firmwares, and the type
the last staging pass emits for every byte write at an odd address: a type 3 at
`addr` - or a type 8 or misaligned type 0, reduced to one - comes out as a type E
at `addr - 1`, so the engine's halfword reads of the address stay aligned (§13).

Uses: 0 stored - no shipped line is a type E, and like A and 2 it has no cipher
route. But 1,156 of the shipped codes reach the console as one: 1,093 type 3 and
63 type 8 lines with an odd address.

### Type F - anchor: abort everything on a mismatch

```
F0aaaaaa vvvv       if (*(u16 *)addr != value) stop processing the list;
```

```
0A8C  3408000F  ori   $t0, $zero, 0xf
0A90  14480005  bne   $v0, $t0, 0xaa8
0A94  94A80000  lhu   $t0, ($a1)       ; delay slot
0A9C  11060057  beq   $t0, $a2, 0xc18  ; match -> carry on
0AA4  08000301  j     0xc20            ; mismatch -> abandon the whole list
```

The one type that goes to `0xC20` instead of `0xC18`. Nothing after it runs this
pass - not the rest of its own cheat, not any other cheat. Combined with the
hoisting in pass 3, that makes it a whole-session guard: the cartridge checks
that the disc in the drive is the game the codes were written for, and if it is
not, it applies nothing.

Uses: 245. Mostly named "Auto Activation", and 189 of them are in the Xploder
USA database, which uses the mechanism far more heavily than the European ones.

```
Xplorer 2.008 UK | MediEvil | Auto Activation
    F00F81A8 F90C
```

## 5. Executed

`engineemu.py` loads each firmware's engine where the firmware puts it -
PSX kernel RAM at `0xA00` - feeds it a synthetic patch list, enters it the way
the BIOS hook does (`$t1` = 0x17), and records every access outside four quiet
regions (the engine's own code, the stack, and the cartridge, which it walks on
every pass regardless of what the codes say). Two entries of the cartridge's own
vector table are stubbed and named in the source; everything else, including the
type 4 delay helper, runs for real. Anything outside the modelled map is recorded
rather than silently read as zero, which is what makes the `!` lines meaningful.

The 26 cases are handed word pairs and control blocks that are already staged,
so each is about one type and nothing else. The same script then runs staging on
its own, out of the same nine images plus 2.005: ten selections through all
four passes, and 29 codes through the pass-4 normaliser alone. That half is in
§13; its output is at the end of the listing below.

```
$ uv run --with capstone python engineemu.py
9 firmwares x 26 cases, executed

0 32-bit write    all 9  lh 00100000=0 | lh 00100000=0 | sw 00100000=ABCD
1 no-op           all 9  lh 00100000=0 | lh 00100000=0
2 no-op           all 9  lh 00100000=0 | lh 00100000=0
3 8-bit write     all 9  lh 00100000=0 | lh 00100000=0 | sb 00100000=CD
4 slow motion     DIFFERS
    5 rom(s) V2, Pro       lh 00100000=0 | lh 00000C84=0 | sw 00000C84=1234 |
                           sw 00000C84=0 | lh 00100000=0
    4 rom(s) FX            lh 00100000=0 | lh 00100000=0
5 Supercode       all 9  lh 00100000=0 | lh 00100000=0 | sb 00100000=DE |
                         sb 00100001=AD | sb 00100002=BE | sb 00100003=EF
6 Megacode        all 9  lh 00100000=0 | lh 00100000=0 | mtc0 DCIC=0 |
                         mtc0 BPCM=FFFFFFFC | mtc0 BDAM=FFFFFFFC |
                         mtc0 BPC=80012340 | mtc0 BDA=80012340 | mtc0 TAR=80012340 |
                         sw A0000040=11111111 | sw A0000044=22222222 |
                         mtc0 DCIC=EA800000
7 if equal, yes   all 9  lh 00100000=1234 | lh 00100000=1234 | lh 00100100=0 |
                         lh 00100100=0 | sh 00100100=BEEF
7 if equal, no    all 9  lh 00100000=9999 | lh 00100000=9999
8 16-bit write    all 9  lh 00100000=0 | lh 00100000=0 | sh 00100000=ABCD
9 if differs, yes all 9  lh 00100000=9999 | lh 00100000=9999 | lh 00100000=9999 |
                         lh 00100100=0 | lh 00100100=0 | sh 00100100=BEEF
9 if differs, no  all 9  lh 00100000=1234 | lh 00100000=1234 | lh 00100000=1234
A inline data     all 9  lh 00100000=0 | lh 00100000=0
B slide           all 9  lh 00030004=0 | sh 00100000=10 | sh 00100004=11 |
                         sh 00100008=12 | lh 00100000=10 | lh 00100000=10
C no-op           all 9  lh 00100000=0 | lh 00100000=0
D anchor          all 9  lh 00100000=1234 | lh 00100000=1234 | lh 00100100=0 |
                         lh 00100100=0 | sh 00100100=BEEF
D inert on a miss all 9  lh 00100000=9999 | lh 00100000=9999 | lh 00100100=0 |
                         lh 00100100=0 | sh 00100100=BEEF
E 8-bit write +1  all 9  lh 00100000=0 | lh 00100000=0 | sb 00100001=CD
F anchor, match   all 9  lh 00100000=1234 | lh 00100100=0 | lh 00100100=0 |
                         sh 00100100=BEEF
F anchor, miss    all 9  lh 00100000=9999
8 + default-off   all 9  lh 08100000! | lh 08100000! | sh 08100000=ABCD!
4 + default-off   DIFFERS
    5 rom(s) V2, Pro       lh 08100000! | lh 00000C84=0 | sw 00000C84=1234 |
                           sw 00000C84=0 | lh 08100000!
    4 rom(s) FX            lh 08100000! | lh 08100000!
C + default-off   all 9  lh 08100000! | lh 08100000!
5 of length 0     all 9  lh 00100000=0 | lh 00100000=0 | sb 00100000=0 |
                         ... RUNAWAY
6 of length 0     all 9  mtc0 DCIC=0 | mtc0 BPCM=FFFFFFFC | mtc0 BDAM=FFFFFFFC |
                         ... RUNAWAY
7 miss, list end  all 9  lh 00100000=9999 | lh 00100000=9999 | lh 00100100=0 |
                         lh 00100100=0 | sh 00100100=BEEF

FX entry clears DCIC on every B() call, B(17h) and B(33h) alike: english-452.dec,
english.dec, german-450.dec, v452d.rom;
    never on V2/Pro.  Taken out of the per-type traces above; the FX installer
    nops it when 0x8000002F is set

staging, executed: 10 firmwares x 10 selections, 29 codes through the normaliser
pass-4 normaliser                  all 10 as expected
C0, D0 and odd addresses           all 10  7006A2EA 0000B7FF | 8006E9C0 000003E7 |
                                           70100000 00001234 | 80100100 0000BEEF |
                                           70100200 00005678 | E0100400 000000AB | ...
one D: hoisted as an F             all 10  F01A5C00 00000880 | 80100000 00000001 | ...
an F and a D: the D is a 7         all 10  F0100000 00001234 | 80100000 00000001 |
                                           701A5C00 00000880 | 801A5A38 00000014
guards in front of blocks          all 10  70100000 0000AAAA | 50102000 P+0 |
                                           D0100000 00000001 | 50103000 P+A | ...
two Megacodes                      all 10  F01FE3C9 0000120F | 60000000 CTRL |
                                           80100000 00000001 | 60000000 00000004 | ...
MGS Verliere Chaff                 all 10  60000000 CTRL | 80100004 00000004
a hoisted encrypted F              all 10  F000857D 000003FD | 801E26A2 0000FFFF
a 507-byte Supercode               all 10  50100000 P+0 | 80100002 00000002
... with a 6 in its 43rd row       by build
    5  rom(s) Xploder V2,xteng.dec,xtger.dec RUNAWAY
    4  rom(s) english-45,english.de,german-4 60000000 CTRL | 11111111 00001111 | ...
    1  rom(s) xtepro.dec                     60000000 CTRL | 50100000 P+0
a Supercode longer than its cheat  by build
    5  rom(s) Xploder V2,xteng.dec,xtger.dec RUNAWAY
    4  rom(s) english-45,english.de,german-4 80100006 00000006 | 80100008 00000008
    1  rom(s) xtepro.dec                     70100000 0000AAAA | 50102000 P+0

2 of 26 cases differ between firmwares
```

(`!` marks an access outside the PlayStation's 2 MB of RAM. The two differing
cases are the same difference twice: type 4 is not implemented on FX. The FX
breakpoint disarm is checked apart from the 26, by entering each engine with
B(17h) and with B(33h) over an empty list.)

Every runtime semantic in §4 comes out of that run. Five things it shows that
reading the chain does not:

* **Type D is inert in the engine.** "D inert on a miss" seeds a value the anchor
  does *not* match, and the code below it still fires. At run time a type D line
  gates nothing - but staging never hands the engine a D0: it hoists a lone one as
  a type F and turns the others into type 7 (§13). Only a D whose flag nibble
  survived decryption reaches the engine as a D.
* **Nearly every code dereferences its own address twice before its type is
  known**, and one reads it three times. The type F and type 7 handlers put their
  `lhu` in the `bne` delay slot, so an entry that gets past both is read twice
  before it does anything - and type 9's own test adds a third:

  | entry | reads of its masked address field |
  |---|---|
  | 9 | 3 |
  | 0, 1, 2, 3, 4, 5, 6, 7, 8, A, C, D, E | 2 |
  | F, B | 1 |

  F reads once because its handler is the first link in the chain, and B once
  because its own link comes before type 7's. Type 4 is not spared either: the
  delay helper ignores the address, but the dispatcher reads it on the way in and
  again on the way out of the call. A type B slide's "address" is
  `0x00030004`, its count and step field, which is not an address at all.
* **Type 4 is the whole difference between the families**, seen twice because two
  cases exercise it.
* **The Megacode path is exactly the breakpoint programming** claimed in §4:
  DCIC off, BPCM/BDAM/BPC/BDA/TAR loaded, payload copied to `0xA0000040`, DCIC
  armed from the descriptor.
* **Three boundary cases go wrong** - a Supercode and a Megacode of declared
  length zero, which hang, and a conditional at the end of the list, which steps
  over the terminator and dispatches whatever is behind it. The last needs a list
  with something behind its terminator, which staging only leaves at full
  capacity. See §7.

## 6. Support across the nine firmwares

The engine was located in every image, its dispatch chain extracted
mechanically, its handler bodies normalised over branch targets and compared
instruction by instruction - and then all nine were executed over the same 26
cases (§5). This table is measured three ways over, not sampled.

| type | V2 2.004 US | 2.008 UK | 2.0081 DE | Pro 2.14 JP | Pro 2.20 UK | FX 3.20 | FX 4.50 | FX 4.52 (x2) |
|---|---|---|---|---|---|---|---|---|
| 0 32-bit write | yes | yes | yes | yes | yes | yes | yes | yes |
| 1 no-op | - | - | - | - | - | - | - | - |
| 2 no-op | - | - | - | - | - | - | - | - |
| 3 8-bit write | yes | yes | yes | yes | yes | yes | yes | yes |
| **4 slow motion** | **yes** | **yes** | **yes** | **yes** | **yes** | **no** | **no** | **no** |
| 5 Supercode | yes | yes | yes | yes | yes | yes | yes | yes |
| 6 Megacode | yes | yes | yes | yes | yes | yes | yes | yes |
| 7 if equal | yes | yes | yes | yes | yes | yes | yes | yes |
| 8 16-bit write | yes | yes | yes | yes | yes | yes | yes | yes |
| 9 if not equal | yes | yes | yes | yes | yes | yes | yes | yes |
| A inline data | staging only | staging only | staging only | staging only | staging only | staging only | staging only | staging only |
| B slide | yes | yes | yes | yes | yes | yes | yes | yes |
| C guard (C0 → 7) | staging only | staging only | staging only | staging only | staging only | staging only | staging only | staging only |
| D anchor (→ F or 7) | staging only | staging only | staging only | staging only | staging only | staging only | staging only | staging only |
| E 8-bit write +1 | yes | yes | yes | yes | yes | yes | yes | yes |
| F anchor | yes | yes | yes | yes | yes | yes | yes | yes |

**The only difference in the whole matrix is type 4.** Ten of the eleven engine
handlers are the same instructions in the same order in all nine images; the
dispatch chain is even in the same order, `F 4 B 7 9 3 E 8 0 5 6`, with the FX
builds simply missing the `4` link. Slow-motion codes are silently dead on an FX
cartridge.

Three differences that are not differences in the type system:

* **where the engine lives.** The three older V2 images carry it inside the
  packed firmware and copy it out; the two Pro images and all four FX images
  keep it unpacked in the ROM.
* **where it reaches into the cartridge.** Three word-sized addresses on the
  V2/Pro side - the per-pass callback, the patch list, the type 4 helper - plus,
  on FX, a different way of finding all of them and a different enable flag.
* **when it disarms the breakpoint.** FX puts `mtc0 $zero, $7` - DCIC = 0 - at
  `0xA08`, the delay slot of its first branch, the test for B(17h), so it runs
  on every BIOS B() call the game makes, codes or no codes. A Megacode's
  breakpoint is armed again only by the next ReturnFromException pass with codes
  switched on. V2 and Pro touch DCIC only in the type 6 handler. The FX installer
  can take the instruction out again, storing a zero over it when the byte at
  `0x8000002F` is set (§2). `engineemu.py` checks this apart from the 26 type
  cases - B(17h) and B(33h), all four FX images and no other - and keeps it out
  of their traces.

The last two are in the blob itself, so it is *not* byte-identical across the
corpus. All nine blobs are 0x24C bytes (the Pro and FX installers copy one word
more, §2) and SHA-256 puts them in three groups: the three V2 images, the two
Pro images, the four FX images. A word-by-word diff says what separates them.

V2 against Pro is three instructions, all of them support-module addresses that
moved with the generation:

| offset | V2 | Pro | what it names |
|---|---|---|---|
| `0x50` | `ori $t0, $t0, 0x30B0` | `ori $t0, $t0, 0x50B0` | per-pass callback |
| `0x60` | `ori $a0, $a0, 0x2600` | `ori $a0, $a0, 0x4600` | patch list base |
| `0xB8` | `ori $v1, $v1, 0x30A0` | `ori $v1, $v1, 0x50A0` | type 4 helper |

Offsets are from the start of the blob, which runs at RAM `0xA00`. Each is the
low half of a `lui $r, 0x1F02` pair, so the callback is `0x1F0230B0` on V2 and
`0x1F0250B0` on the Pro, and the type 4 helper `0x1F0230A0` / `0x1F0250A0` -
tracking where each generation puts its support module. The enable gate is *not*
among them: V2 and Pro both read bit 0 of the cartridge port at `0x1F060000`.
V2 against FX is 124 words, because FX loads a support module pointer from
`0x1F00007C` and forms every one of those addresses off it (callback at `+0xB0`,
a second callback at `+0x100` on the way out, and the list base *loaded from* the
slot at `+0xBC` - the slot holds the base, it is not the base), gates on a byte at
RAM `0x178` instead of the port, clears DCIC on entry, and drops the type 4
handler entirely - which shifts everything after it.

What is identical is the per-type behaviour, once type 4 is set aside.

The staging side is uniform in what it classifies and how it normalises, and not
in how it fails. The pass-4 normaliser is the same instructions in all six
V2/Pro images and the same behaviour in all ten under execution (§13). A
Supercode that declares more payload rows than its cheat has is handled three
ways (§7). And the classifying constants are the same everywhere. Enumerating
`andi rX, rY, 0xf0` - the idiom this compiler emits to isolate a type nibble -
finds 13 to 15 occurrences per image, nine of which sit next to a constant the
scan can read, and those nine name exactly the same set in all nine images:

```
$ uv run --with capstone python engine.py -s
Xploder V2 (USA) r2.004 …    14 andi sites,  9 read, types 5 6 7 9 A D F
english.dec                  13 andi sites,  9 read, types 5 6 7 9 A D F
... and the rest
```

Blocks, anchors, conditionals. The addresses move between builds; the constants
do not.

Two limits on what that is worth. The scan does not rule out a classifier
written some other way - a shift, a different mask, a range test, a jump table -
so it enumerates one shape, not every classifier, and there is one it misses:
the pass-4 normaliser compares whole bytes and tests 0, 3, 7, 8, B, C and D
without an `andi` (§13). And it does not resolve every occurrence of its own
idiom: the remaining four to six per image compare against a register loaded
further back than the window, or are not classifying a code at all. The union
holds at every window size tried (6, 16, 32 and 64 instructions back, 67 to 81
of the 124 occurrences resolved), which is the reason to believe it - not the
count.

## 7. Interactions and traps

All of these are executed: the engine-side ones by the 26 cases of §5, the
staging-side ones - conditionals moved with a block, one anchor per session, two
Megacodes, a Supercode longer than its cheat - by the staging runs of §13. Type
A's extent is the one still only read.

**Payload rows are not codes.** The rows following a type 5, 6 or A header are
data. Their first nibble is whatever the payload happens to contain, and reading
one as a code type is a bug - a real one, fixed in `7d15818`, where a Bloody Roar
Megacode descriptor `1F800198 EA80` was decrypted as an ordinary key-7 code.

**A conditional guards exactly one line.** Types 7 and 9 skip a single list
entry. There is no block form and no nesting. A type B slide following a
conditional is guarded as a unit only because the slide consumes its second line
through `$a0` rather than through the loop.

**Conditionals in front of a block are moved with it.** The staging passes look
at the line *before* a type 5, 6 or A header and, if it is a type 7, 9 or D,
emit it immediately in front of the block's list entry, so that the guard still
sits directly before what it guards after the passes have reordered everything
else. Type A only accepts 7 and 9 there; the block types accept D as well, even
though the engine will ignore it.

**Type A eats the rest of the cheat.** There is no length field, so everything
below a type A header in the same cheat entry becomes payload.

**One anchor per session.** Only the first type F, or the single type D, is
hoisted. Further type F lines stay where they are and still work - they just
abort the list from that point on rather than up front. Further D lines become
type 7 guards over the line below them.

**The list is capacity-limited, and nothing checks it.** Entries occupy the first
`0x400` bytes - 128 pairs - with payload bytes from `+0x400` and the Megacode
control block at `+0x780`. None of the four passes tests either bound. There is
room for exactly one Megacode, and a second is worse than dropped: pass 1 stages
the first type 6 it meets and returns, so a second one's rows stay selected and
the later passes take them for codes. Executed with two keyless Megacodes, in
all ten images: pass 3 hoists the second one's mask row `FFFFFFFC 4444` as a type
F anchor, decrypting it as a key-7 code on the way - which runs the copyright
check of `FINDINGS.md` §5.3b - and pass 4 emits its header as a raw
`60000000 00000004`, an entry that would read its control block from RAM `0x4`.
The anchor comes out as `F01FE3C9 120F` and all but certainly mismatches, so with
two Megacodes enabled no code runs at all.

**A block that declares no payload runs away.** Both copy loops copy one unit
*before* they decrement the count and test it, so a declared length of zero wraps
to `0xFFFFFFFF`: type 5 copies bytes forever from `0x1F0xxxxx` into RAM, type 6
copies words forever into `0xA0000040` upward. Executed; all nine firmwares hang
(§5). Nothing upstream stops it either - staging pass 2 writes the list entry and
the zero-count block header before the `blez` at `0x1AD22C` that skips the
payload-row loop, so the guard prevents the *rows* being consumed and not the
block being emitted.

Two shipped cheats are written that way, both in the German database:

```
Xplorer 2.0081 DE | War Games | Oeffnet alle Levels fuer NORAD
    50000702 0000      <- stored 56565A56 595A: a Supercode of 0 bytes
    800AA370 0101
Xplorer 2.0081 DE | War Games | Oeffnet alle Levels fuer WOPR
    50000702 0000
    800AA3A0 0101
```

For a *crypto* stream the right reading is the one `xp_parse_block()` and
`dbtypes.py` take - a size-zero type 5 is not a block, and the line below it is
an ordinary code, which it plainly is here. That is not what the cartridge does
with it. No zero-length type 6 was found in the corpus.

**A Supercode longer than its cheat is handled three ways.** Pass 2 copies a
Supercode's payload rows while their descriptors say "enabled code line". When one
does not - the cheat ran out of lines first - the builds part company, executed
in all ten:

* V2 2.004, 2.005, 2.008, 2.0081 and Pro 2.14 spin on a `j .` (`0x1AD270` in
  `xteng.dec`). The cartridge hangs in the menu, on the way to the game.
* Pro 2.20 jumps to the epilogue one instruction too late, past the `move` that
  sets its return value, and returns `0x18` as the list length. The later passes
  append after twelve entries' worth of zeros, so every code staged after the
  block sits behind a terminator and never runs.
* FX drops the block and the guard in front of it and carries on.

No shipped Supercode is long enough to find out. The type 6 stager checks the
same thing and stops quietly in every build - but only after the descriptor and
mask, which it never checks at all (see type 6 for what that does).

**Every code is dereferenced before its type is known.** The type F and type 7
handlers issue their `lhu` from the `bne` delay slot, so the engine reads a
halfword from the code's address for *every* entry that gets past them, whatever
its type - including the types it goes on to ignore, and including type 4, whose
handler is uninterested in the address. §5 has the exact counts. A code with a
bad address therefore makes bad loads before it makes a bad store, which matters
for the next item - and a code with an *odd* address makes a misaligned one,
which an R3000 raises an address error for. That is what the pass-4 normaliser
is for (§13). It covers what it can recognise: types 0, 3, 7, 8, B, C and D with
a zero flag nibble. A type 9, an F that is not hoisted, a Supercode's
destination and any row whose flag nibble survived are left as they are. Four
shipped rows still have an odd address after staging: Pro 2.20's `3805DA51 0002`
and `380C7ACF 00C0`, the USA's `31001643 500F` and 2.0081's filler
`CDEEC037 595F`.

**A conditional at the end of the list steps over the terminator.** Types 7 and 9
skip by reaching `0xC18` with an extra `addiu $a0, $a0, 8`, and nothing checks
what is being skipped. If the entry it skips is the zero word that ends the list,
the walk carries on into whatever is behind it. Executed: with a word pair
planted past the terminator, all nine engines dispatch it as a code. Staging
builds the list in a zeroed buffer (`0x1AA928` in `xteng.dec`), so behind a
terminator there is another zero pair - unless the list is full, and then what is
behind it is the payload area.

**The default-off bit lands in the address of an unencrypted code.** The flag
nibble is bits 24 to 27 of `word0`, and the engine masks `word0` with
`0x0FFFFFFF`, which keeps bit 27. That is harmless for a code that went through
one of the four cipher routes, because those end with `dst[0] = src[0] & 0xF0`.
But the route index is `(src[0] & 0xF7) - 4`, so `0x80` and `0x88` share an
entry - and that entry is the verbatim copy at `0x1AC2B0`:

```
first byte 80 -> index  7C -> route 001AC2B0   (copy)
first byte 88 -> index  7C -> route 001AC2B0   (copy)
first byte 84 -> index  80 -> route 001AC0D0   (key 4)
```

So a code stored in the clear with the default-off bit set keeps that bit through
decryption, through staging, and into the engine, which adds `0x08000000` to the
address. Both halves executed, the decrypt routine and the engine, out of
`xteng.dec`:

```
decrypt routine            8002A798FFFF -> 8002A798FFFF
                           8802A798FFFF -> 8802A798FFFF   (byte 0 survives)
                           8602A798FFFF -> 80AC5040AEAF   (key 6: nibble cleared)
                           8E02A798FFFF -> 80AC5040AEAF   (off bit + key 6: ditto)

engine, word0 = 8002A798   lh 0002A798 | lh 0002A798 | sh 0002A798=FFFF
engine, word0 = 8802A798   lh 0802A798 | lh 0802A798 | sh 0802A798=FFFF
                              ^^^^^^^^ all three outside the 2 MB of RAM
```

The Xplorer Pro 2.20 database has the bit set on 133 of its 2,910 code lines.
Three different numbers come out of those 133 and they are not interchangeable:

```
133  rows with the default-off bit set - and every one keeps it through decryption
121  of those stored with key bits 0: the copy route keeps byte 0
120  of those 121 whose handler then uses the wrong address
       77 type 8, 31 type 3, 12 type 7
  1  of those 121 is a type 4, whose handler ignores the address
 12  of the 133 are type C rows with key bits 5 - no cipher route, so the
       whole flag nibble survives, and a C with a flag nibble does nothing
```

So: **120 lines store or compare at the wrong address**, and all 133 make
out-of-range *reads* in the dispatcher - the type 4 and the type C rows are not
spared that, whatever their handlers do or do not do (§5). 111 of the 133 sit on
the first line of their cheat and 22 further down, so the bit is not a clean
per-cheat marker either. The other four databases are almost entirely encrypted,
so the bit survives there only on type C lines, which have no cipher route.
Every row in the corpus where the bit survives decryption, by where it sits in
its cheat:

```
                                          line 0   a later line
Xplorer Pro 2.20 UK   keyless, types 3/4/7/8   99         22
Xplorer Pro 2.20 UK   type C                   12          -
Xploder V2 2.004 US   type C                    4          -
Xplorer 2.0081 DE     type C                    1          -
Xplorer 2.008 UK      none - all 121 flagged code rows carry key 6
Xplorer Pro 2.14 JP   none - no flagged rows at all
```

All 121 of those Pro 2.20 codes also appear in another database, byte for byte
identical apart from that bit (117 distinct rows). The rule is in
`defaultoff.py`: clear bit 3 of the first byte and look for the same six bytes as
a *dispatched* code row - not a block payload row - somewhere else. It gives 121
against all four other databases and against only the three that ship encrypted.
The former figures of 101 and 118 came from incomplete record chains.

```
Xplorer 2.008 UK    | LiberoGrande | P1 Scores No Goals   301287A0 0000
Xplorer Pro 2.20 UK | LiberoGrande | P1 Scores No Goals   381287A0 0000

Xplorer 2.0081 DE   | Command & Conquer 2 - GER | Unendlich Geld    8002A798 FFFF
Xplorer Pro 2.20 UK | Command & Conquer Red Alert | Soviets. Unlimited Money
                                                                    8802A798 FFFF
```

Same cheat, same intended address - `0x1287A0` on one cartridge and
`0x081287A0` on the other. It breaks inside a single cheat, too: Bust A Groove
"Always Win P2" is `7806879C 0000` followed by `3006879C 0001`, so the
conditional tests `0x0806879C` and the write it guards goes to `0x0006879C`.
The flagged rows also escape the normaliser, which matches whole bytes: a `38` or
a `78` is neither `30` nor `70`, so two of the type 3 rows reach the engine at an
odd address as well.

Bit 3 is the case that ships 120 times, but any flag nibble that survives the
copy route lands in the address the same way. The USA's `31001643 500F`, the one
code with no room for a key, stores a 1 there and writes to `0x01001643`. In
2.0081, Alundra's `F21EAB7C 00FF` carries a 2 - key 2 has no route for type F -
and becomes an anchor on `0x021EAB7C`, which would abort the whole list whenever
it is the first F enabled.

Where the defect sits is a question about seams, not about the engine. The
engine strips the type nibble and trusts that the flag nibble is already gone;
the four cipher routes guarantee that and the copy route does not; nobody owns
clearing it in between. The cheapest fix is one instruction in the engine: the
address is 24-bit, so the mask should be `0x00FFFFFF`.

What kept it latent is narrower than "the earlier databases were encrypted",
which is the obvious story and the wrong one. Counting the stored key nibbles of
the dispatched code rows (`defaultoff.py` asserts every cell):

```
                       clear   key 6   key 4   clear + off   key 6 + off   other
Xplorer 2.008 UK           -   2,767       -             -           121       -
Xplorer 2.0081 DE          -   2,371       -             -            66       3
Xplorer Pro 2.14 JP    1,826       -       -             -             -       -
Xplorer Pro 2.20 UK    2,693      84       -           121             -      12
Xploder V2 2.004 US        -   4,007     552             -           311       5
                                                         ^ the broken ones
```

"Other" is everything that is neither clear nor key 4 or 6: 2.0081's `F2` line,
its key-5 Megacode header and one `CD`; Pro 2.20's twelve `CD` lines; the USA's
`31` and four `CD`.

Pro 2.20 is not the first database in the clear - Pro 2.14 is entirely in the
clear, one release earlier - and it is not entirely in the clear itself, since 84
of its rows still carry key 6. What is new in 2.20 is *combining* the two: it is
the first database to set the default-off bit on rows that carry no key. 2.14 has
no default-off rows at all, and the encrypted databases set the bit only
alongside a key, where the cipher scrubs it in passing. Two habits that were each
safe on their own.

What has *not* been established: what a PlayStation actually does with a store to
`0x0802A798`. It is outside RAM, and the two loads that precede it are outside
RAM as well, inside an exception handler - but the emulator models a memory map,
not a console.

**A row-count bug in the list walker.** Staging pass 1 computes a Supercode's row
count as `((hi & 0xF) << 8) | (lo + 5)` where pass 2 uses `+`:

```
001ACD24  3042000F  andi  $v0, $v0, 0xf
001ACD28  00021200  sll   $v0, $v0, 8
001ACD2C  24630005  addiu $v1, $v1, 5
001ACD30  00431025  or    $v0, $v0, $v1     ; <- or, not addu
```

`lo + 5` carries into bit 8 when `lo >= 0xFB`, and then `or` produces `hi | 1`
where `+` produces `hi + 1`. Those differ only when `hi` is **odd**; for an even
`hi`, including zero, the two agree. So the bug needs `lo >= 0xFB` *and* an odd
`hi` - a payload of 507 to 511 bytes, or 1,019 to 1,023, and so on; 251 to 255
is safe - and pass 1 then skips 256 bytes' worth of lines too few, and reads a
payload row as a line of its own. That only matters if the row starts with a 6:
pass 1 then stages a Megacode out of the payload, consuming rows pass 2
expects. Executed in all ten, with a 507-byte Supercode whose 43rd row starts
`60`: the V2 builds and Pro 2.14 hang (the overrun above), Pro 2.20 stages the
bogus Megacode and cuts the list short, FX stages it and turns the rest of the
payload into codes. Without the 6, the same Supercode stages normally. No
recovered database has a Supercode that triggers it.

**Which types the cipher covers is a separate question, but not an unrelated
one.** The decrypt routine's 244-entry jump table gives no route to the types 2,
A, C and E, so codes of those types are stored in the clear (`XP_KEYED_TYPES =
0xABFB` in `crypto.c`). That set does not line up with what the engine
implements, and it was easy to read it as designed independently: E is a working
write instruction that is never encrypted, while 1 - which does nothing at all -
is. It lines up with staging instead. A is rewritten into a 5, C0 into a 7, and E
is what staging itself emits for an odd-address byte write - an opcode nobody
needs to store. Three of the four routeless types are staging's. Only 2 has no
part anywhere, and D, which staging also rewrites, does have a route - so the
table is not simply "the staging types" either. What the corpus shows is the
overlap, not the reason for it.

## 8. Usage in the shipped databases

Counted over the five in-ROM databases, block headers counted once, payload rows
excluded.

**Scope.** `db2.find_db()` now starts each database at the first record after its
erased-flash boundary rather than resynchronizing at a later printable suffix.
That yields the complete record chain present in each image: 15,349 lines,
14,939 of them dispatched codes. It is still a five-ROM corpus rather than proof
about every database ever shipped, so a zero means "none in this corpus". (The
FX images carry LZW-packed databases too - `AUDIT.md`, ninth pass - which are
not counted here.) The types are the *stored* ones; what the console is handed
differs by the staging rewrites of §13.

| type | 2.008 UK | 2.0081 DE | Pro 2.14 JP | Pro 2.20 UK | V2 2.004 US | total |
|---|---|---|---|---|---|---|
| 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| 1 | 52 | 21 | 2 | 52 | 7 | 134 |
| 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| 3 | 625 | 465 | 686 | 623 | 589 | 2988 |
| 4 | 2 | 2 | 0 | 2 | 0 | 6 |
| 5 | 17 | 8 | 0 | 17 | 2 | 44 |
| 6 | 4 | 3 | 0 | 4 | 0 | 11 |
| 7 | 132 | 142 | 11 | 134 | 170 | 589 |
| 8 | 1962 | 1734 | 1119 | 1972 | 3902 | 10689 |
| 9 | 18 | 6 | 0 | 18 | 1 | 43 |
| A | 0 | 0 | 0 | 0 | 0 | 0 |
| B | 62 | 26 | 2 | 62 | 7 | 159 |
| C | 0 | 1 | 6 | 12 | 8 | 27 |
| D | 0 | 0 | 0 | 3 | 0 | 3 |
| E | 0 | 0 | 0 | 0 | 0 | 0 |
| F | 14 | 31 | 0 | 11 | 189 | 245 |

Types 8 and 3 are 92% of the dispatched codes. Everything else is a rounding
error, and three of the sixteen types - 2, A and E - are stored nowhere in the
corpus. E is still the type 1,156 of these codes have when the console runs
them, because staging makes every odd-address type 3 and type 8 one.

The type 5 and type 6 rows count *headers*, and three of those headers are
malformed: two of the 44 type 5 entries declare a payload of zero bytes and one
of the 11 type 6 entries declares 9,212 rows that are not there. So the corpus
holds 42 well-formed Supercodes and 10 well-formed Megacodes.

## 9. The cartridge's side of the hook

The engine is 0x24C bytes because it delegates. It calls into a support module
that stays in the cartridge - unpacked, so it is executable in place - through a
fixed vector table of `b` instructions. `*(u32 *)0x1F00007C` points at it:
`0x1F023000` on the three V2 builds, `0x1F025000` on both Pro builds,
`0x9F001500` on all four FX ones. In `xteng.dec`, at ROM `0x23080`:

```
  +0x00  b 0x9F0230D0   putchar over the link port at 0x1F060000/1
  +0x08  b 0x9F0232C0   print a byte as hex
  +0x10  b 0x9F0232F0   print a halfword as hex
  +0x18  b 0x9F023320   print a word as hex
  +0x20  b 0x9F02334C   the delay        <- this is all code type 4 is
  +0x28  b 0x9F023394   link port handshake
  +0x30  b 0x9F0231A4   save every register, then 0x9F0237C8
  +0x38  .word 0x1F025000              the cheat database - data, not a branch
  +0x40  b 0x9F023420   load the COP0 breakpoint registers
  +0x48  b 0x9F023440   the breakpoint exception handler: prints "BK" and a
                        register dump over the link - the built-in debugger
```

The engine uses exactly two of these: `+0x20` for type 4, and `+0x30` once per
pass, before it looks at a single code (§3). Entries `+0x40` and `+0x48` are the
same hardware breakpoint machinery type 6 drives, reached the other way round.

**The per-pass callback is a second poke mechanism**, and it has nothing to do
with the patch list. `0x9F0237C8` first walks a table in PSX kernel RAM at
`0x700`, eight bytes per entry:

```
9F0237DC  lbu   $v0, 0x703($zero)   ; entry 0's flag byte gates the whole table
9F0237E4  addiu $v1, $zero, 0x80
9F023804  beq   $v0, $v1, 0x9f023818
9F023810  j     0x9f023878          ; not 0x80 -> one more test, for 0x30, then
                                    ;   neither -> skip straight to the link loop
9F023818  lbu   $v1, 2($s2)         ; <- per entry: a 24-bit address
9F02381C  lbu   $v0, 1($s2)
9F02382C  lbu   $v0, ($s2)
9F023830  lbu   $v1, 4($s2)
9F023838  sb    $v1, ($s3)          ; poke one byte
9F02383C  lbu   $v0, 3($s2)
9F023844  bne   $v0, $v1, 0x9f02385c
9F023858  sb    $v0, 1($s3)         ; flag 0x80 -> poke a second byte at addr+1
9F02385C  addiu $s2, $s2, 8         ; next entry, while its flag is 0x80 or 0x30
```

then falls into the link-port command loop. So a host on the other end of the
cable can poke memory on every interrupt without going near the cheat database.
The V2 engine installer disables it:

```
001A0140  sw    $v0, 0x700($zero)   ; = -1, so 0x703 reads 0xFF, neither 0x80 nor 0x30
```

The Pro and FX installers make no such store. Their callbacks walk the same table
(`lbu $v0, 0x703($zero)` at ROM `0x25C90` in `xtepro.dec`, `0x56AC` in
`english.dec`), and their support modules write `0x703` elsewhere; what leaves the
table disarmed on those builds was not followed.

**And one slot is reserved and never used.** The V2 installer also writes

```
001A0138  sw    $v0, 0x9f0($zero)   ; = 0x001A3F70
```

into the four bytes immediately below the engine - `0x9F0` is where the
trampoline sits in the source image but is *not* part of what gets copied to
`0xA00`. `0x001A3F70` is `jr $ra; nop`, an empty function. Only the four V2
images write it, and nothing in any of the ten reads `0x9F0`. A hook slot,
initialised to a no-op, for something that was never wired up or was removed.

## 10. Firmware corpus

| image | release | family | engine trampoline at |
|---|---|---|---|
| `Xploder V2 (USA) r2.004 …` | 2.004 | Xploder V2 USA | firmware image `0x001A32D0` |
| `xteng.dec` | 2.008 | Xplorer UK | firmware image `0x001A3768` |
| `xtger.dec` | 2.0081 | Xplorer German | firmware image `0x001A3768` |
| `xtjpro.dec` | 2.14 | Xplorer Pro Japanese | ROM `0x22B20` |
| `xtepro.dec` | 2.20 | Xplorer Pro UK | ROM `0x005C8` |
| `english.dec` | 3.20 | Xplorer FX | ROM `0x0063C` |
| `german-450.dec` | 4.50 | Xplorer FX German | ROM `0x0063C` |
| `english-452.dec`, `v452d.rom` | 4.52 | Xplorer FX | ROM `0x0063C` |
| `pc/ROMS/Xteng.fcd` (the tenth) | 2.005 | Xplorer UK | firmware image `0x001A348C` |

Located mechanically, by the four-word trampoline `lui $t0, 0 / addiu $t0, $t0,
0xa00 / jr $t0 / nop` that gets copied over the BIOS entry point at `0xB0`. The
V2 images - the three oldest of the nine, and 2.005 - keep the engine inside the
packed firmware; the rest keep it unpacked in the ROM. All ten blobs are 0x24C
bytes and fall into three byte-distinct groups - V2 (2.005 included), Pro, FX. V2
and Pro differ in three words, all of them support-module addresses; FX differs in
124, because it reaches them through a support-module pointer - the patch list
twice removed, in a slot at `+0xBC` - gates on RAM instead of the port, clears
DCIC on entry, and has no type 4 handler (§6).

Addresses in the listings above are from `xteng.dec` unless stated otherwise;
engine listings use the RAM addresses the blob runs at, cartridge-side listings
use `0x9F0xxxxx`. `REVERSING.md` has the method for the cipher - how the images
are unpacked, how the load address is recovered, how the crypto was read out.
Part II below is the same thing for the engine.

# Part II - how it was found

## 11. Three things that looked like the answer

Worth recording because each one is a plausible-looking dead end, and two of them
cost real time.

### 11.1 The 244-entry jump table

`REVERSING.md` §6.2 dumps it and calls it "the route table", which it is - but it
routes *ciphers*, not semantics. It answers "is a code of this type encrypted",
and the temptation is to read the four gaps (types 2, A, C, E) as "these types do
not exist". They are unrelated questions with unrelated answers: type E is a
working store instruction that is never encrypted, and type 1 does nothing at all
and is.

### 11.2 The 37-entry table right behind it

At `0x1BF67C` in `xteng.dec`, immediately after the 244 crypto entries - so
immediately that a jump-table scanner reports one contiguous run of 281 words.
Seven distinct targets - six handlers and a default - dispatched by masking an
input byte with `0x26` after testing it against `0x18`. It looks exactly like an
opcode table with an operand width field.

It is the code *entry* screen. The byte it dispatches on is a per-line descriptor
in the cartridge's UI list (`0x22` game, `0x02` cheat name, `0x00` code line,
`0x20`/`0x24`/`0x82` end markers, `|0x18` when the user selects a line), not a
code type. Two different eight-bit values in two different tables in adjacent
memory, and the wrong one is the one that looks more like a virtual machine.

The tell, in hindsight: `0x18` is not a plausible code type, and the mask `0x3E`
never appears next to a decrypted code anywhere.

### 11.3 The exception handler at ROM `0x23500`

Searching all nine ROMs for `rfe` (`0x42000010`) finds exactly one aligned
instance per V2 and Pro image, inside a 4 KB module at ROM `0x23000` (`0x25000`
on the Pro builds) that also holds `mtc0` sequences, a register dump and the
string "BK". An exception handler that saves every register and prints them is a
debugger, not a cheat engine - and this one talks to `0x1F060000`, the Xplorer's
PC link port.

It is not wasted: the engine calls into that module, and the search ended up
mapping the whole vector table - see §9, which is where code type 4 turns out to
live and where a second, host-driven poke list turned up that has nothing to do
with the cheat database at all.

## 12. Finding it properly

The firmware writes a signature into PSX RAM:

```
001A0E68  lui   $v0, 0x5748          ; 'WH'
001A0E6C  ori   $v0, $v0, 0x422e     ; 'B.'
001A0E70  lui   $at, 0x8000
001A0E74  sw    $v0, 0x30($at)
```

`"WHB."` at `0x80000030` - Wayne Hughes Beckett again (`REVERSING.md` §5.5), and
low kernel RAM is where cheat devices live. (`0x1A0788` reads it back: it
compares the word with `WHB.` and, when asked to, overwrites it with `GAME`.)
That narrows the search but does not end it, because the blob is data as far as
the firmware's own address space is concerned.

What ended it was searching for a *behaviour already known from the format*
rather than for an address. `FINDINGS.md` §2 records that a Megacode payload is
installed at the breakpoint vector `0x80000040`; whatever does that has to build
that address, and it builds its uncached alias:

```python
lui  $a1, 0xa000 ; addiu $a1, $a1, 0x40     # 3C05A000 24A50040
```

One aligned hit per image, nine for nine. In three of them it is inside the
unpacked firmware and in six it is in the raw ROM, which is the part that would
have gone unnoticed: a scan of the unpacked images alone finds the engine in
`xteng`/`xtger`/the USA ROM and concludes the Pro and FX firmwares do not have
one.

The installer sits nearby and gives up the whole layout without any inference:

```
001A00B4  addiu $a0, $a0, 0x3778     ; src
001A00BC  addiu $v0, $v0, 0x39c4     ; end       -> 0x24C bytes
001A00D0  addiu $a1, $zero, 0xa00    ; dst = PSX RAM 0xA00
001A00F4  addiu $a0, $a0, 0x3768     ; src
001A0110  addiu $a1, $zero, 0xb0     ; dst = the BIOS B-function entry point
```

Two copies, one of them sixteen bytes over `0xB0`. That is the hook.

### 12.1 The absolute jumps are the load address

Inside the blob:

```
001A3990  08000299  j     0xa64
001A381C  08000308  j     0xc20
```

`j` targets that are four-digit low addresses in a firmware linked at
`0x801A0000` are not a disassembly artefact - they are the giveaway that the code
is *relocated*, and they hand you the load address for nothing. `0x1A3778 ->
0xA00` from the installer, and every one of those targets then lands on a
sensible instruction: `0xA64` is the list loop head, `0xC18` is "next code",
`0xC20` is "stop". Same lesson as the FX boot stub in `REVERSING.md` §10.1 - the
code that does the loading names everything in the clear.

### 12.2 The hook

```
09F0  3C080000  lui   $t0, 0
09F4  25080A00  addiu $t0, $t0, 0xa00
09F8  01000008  jr    $t0
09FC  00000000  nop
```

copied over `0xB0`, and the engine's own tail:

```
0C40  340805E0  ori   $t0, $zero, 0x5e0
0C44  01000008  jr    $t0
```

`0x5E0` is where the original `0xB0` stub went, so the replacement is
transparent. `$t1` carries the BIOS function number, the engine screens for
`0x17` = `ReturnFromException`, and everything else goes straight through. There
is no per-frame timer and no "apply once" pass: codes are re-applied on every
interrupt, which is why a 16-bit store and a permanent unlock are the same code
type.

## 13. Staging: the types with no runtime handler

The engine answers eleven of sixteen. For the rest, ask the staging code. Asking
it by pattern rather than by following calls gets most of the way, because where
this firmware isolates a type nibble it mostly does so with one instruction:

```sh
# every occurrence in the image, and the constants near it
andi  rX, rY, 0xf0
```

13 to 15 occurrences per image; nine of them sit close enough to the constant
they are compared against for the scan to read it, and those nine name exactly
the same set in all nine images:

```
$ uv run --with capstone python engine.py -s
Xploder V2 (USA) r2.004 …    14 andi sites,  9 read, types 5 6 7 9 A D F
english.dec                  13 andi sites,  9 read, types 5 6 7 9 A D F
xtjpro.dec                   15 andi sites,  9 read, types 5 6 7 9 A D F
... and the rest
```

Blocks (5, 6, A), the anchors (D, F), the conditionals (7, 9). The union does not
move at four window sizes, resolving 67 to 81 of the 124 occurrences across the
corpus. `typecx.py` widens it from one idiom to three - this one, `srl rX, rY,
0x1C` (which is how the engine itself does it) and `andi rX, rY, 0xF000` - over
ten images, and the union grows to `3 4 5 6 7 8 9 A B D E F`, because the images
that keep the engine inside the packed firmware contribute the dispatch chain
too. None of the three idioms finds a 1, a 2 or a C.

That was read, for a long time, as "nothing looks at 1, 2 or C". It is wrong about
C, and the reason is a classifier none of the idioms can see.

### 13.1 The pass-4 normaliser

Pass 4 decrypts each line it emits with key −1 and then, before turning it into a
list entry, hands the six bytes to one function - in `xteng.dec` the loop
decrypts at `0x1AA9EC` and calls `0x1A835C` at `0x1AA9F8`, its only caller. That
function compares *whole first bytes* - `lbu`, a constant, `beq`/`bne` - and
rewrites:

```c
if (c[0] == 0x00 && (c[3] & 3)) c[0] = 0x80;     /* misaligned word write: halfword */
if (c[0] == 0x80) {
    if (c[3] & 1) c[0] = 0x30;                   /* odd halfword write: byte */
} else if (c[0] == 0xD0 || c[0] == 0x70 || c[0] == 0xC0) {
    c[0] = 0x70; c[3] &= 0xFE;                   /* D0, C0 become 70; even address */
} else if (c[0] == 0xB0) {
    c[3] &= 0xFE;                                /* slide: even address step */
}
if (c[0] == 0x30 && (c[3] & 1)) {
    c[0] = 0xE0; c[3] &= 0xFE;                   /* odd byte write: E, one down */
}
```

It is in all ten images, with one caller each - `0x1A7E40` (2.004), `0x1A8010`
(2.005), `0x1A835C` (2.008), `0x1A8360` (2.0081), `0x1A9338` (Pro 2.14),
`0x1A9978` (Pro 2.20), `0x80031C08` (FX 3.20), `0x80032398` (4.50) and
`0x80032024` (4.52, both dumps) - and `engine.py` finds it by the bytes it
rewrites to and from and asserts exactly that. The V2 and Pro copies are the same
instructions; FX schedules them differently. `engineemu.py` runs it in all ten
over 29 codes, and all ten give the same answers (§5).

Every rule makes an address even. The engine reads every entry's address as a
halfword before it knows the type (§3, §5), and on an R3000 a halfword read at an
odd address is an address-error exception - a MIPS I rule, not something observed
here, but it is the one reading under which every line of the function has a
purpose. A byte write at an odd address cannot be made even, so it is re-expressed:
type E writes one byte *above* its address, so `E0` at `addr - 1` is the same
store. That is what type E is for, and why no database stores one.

Because it matches the whole byte, the normaliser leaves alone any line whose flag
nibble survived decryption - `CD`, `C6`, `C8`, `D8`, `38`, `88` - which is what
keeps type C useful as filler and what lets §7's default-off rows through
unrepaired.

### 13.2 What staging does with each of them - executed

`engineemu.py` runs the four passes out of each image, from the call of pass 1 to
the end of the pass-4 loop, over hand-built selections (§5 has the output): the
menu firmware's own code, with only the BIOS strncpy and the copyright checker
stubbed. What is not run is the menu that builds a selection - the descriptor and
pointer arrays are constructed by hand.

* **type A** is rewritten as a type 5 with the header's value field as the first
  two payload bytes, and swallows every following line of the cheat entry as six
  raw bytes each. No length field, no payload cipher - the hand-entry form of a
  Supercode. (Its extent is read, not yet executed.)
* **type C**, stored `C0`, is rewritten as a type 7 equality guard with an even
  address. With a flag nibble it is left alone, and the engine ignores it.
* **type D**, stored exactly `D0`, is rewritten as a type F and *hoisted to the
  front of the list*, by shifting every existing entry two words along - if it is
  the only D0 in the whole enabled selection and no type F is enabled. A type F
  line is hoisted too, found by its nibble, and wins over a D. Every D0 that is
  not hoisted becomes a type 7 guard. Only a D with a flag nibble reaches the
  engine as a D.
* **type E** is never consumed - it is produced, for every odd-address byte write.

The hoist makes the address even on the *stored* bytes, before decryption. For a
line in the clear that is the address; for an encrypted one it is ciphertext, and
the USA database ships three key-4 anchors that the hoist turns into anchors that
cannot match (type D, §4; executed).

That hoisting is what makes F an anchor rather than an ordinary conditional: it
is evaluated first and, on a mismatch, abandons every enabled cheat at once.

So "five types never reach the console" would be wrong, and the split matters.
Types 1 and 2 reach the engine and are ignored. A never reaches it. C and D reach
it as something else - a 7, or an F - unless their flag nibble is set, and then
they reach it as themselves and are ignored. E, which no database stores,
reaches it more often than any type but 8 and 3.

## 14. The databases as a cross-check

`dbtypes.py` counts types across the five in-ROM databases, following blocks so
that payload rows are never counted as codes. 14,939 code lines out of the 15,349
lines the complete record chains hold - the other 410 are payload - and the
shape of the result is itself evidence:

```
 8  10689     3   2988     7    589     F    245     B    159     1    134
 5     44     9     43     C     27     6     11     4      6     0      1
 2      0     A      0     E      0     D      3
```

Three things fell out of this that reading the firmware alone would not have
given:

* **type 1 is used 134 times and does nothing.** Every occurrence in the
  recovered corpus is the second line of a type B slide. The slide handler reads
  that line as data through `$a0`, but the loop still advances by only eight
  bytes, so the line is dispatched on its own afterwards - giving it a type with
  no handler is what stops it running twice.
* **type C is three different conventions** (`typecx.py` sorts all 27 lines by
  what they are rather than by which database they are in). Seventeen are filler,
  carrying no information at all - the cheat *name* is the message
  (`*****ISLAND STRIKE*****`, `ALWAYS ACTIVATE THE NEXT ONE`) - and all seventeen
  begin `CD E?`, so they are one line copied and edited. Four are the Wipeout
  entries in the USA database, and those are *disabled type 8 codes*: put the
  `8` back in the type nibble, decrypt with the key the flag nibble declares, and
  the address is the address of the type 8 line below it, four times out of four.
  And six are Japanese joker codes whose values decode exactly as pad masks:
  `0xB7FF` is `~(R1 | cross)`, `0xBDFF` is `~(R2 | cross)`, `0xB7EF` is
  `~(R1 | cross | up)`, and the cheat names say R1+×, R2+× and up+R1+×. The
  filler and the disabled codes carry a flag nibble and are inert; the jokers are
  stored `C0`, so staging makes each a type 7 guard and they work as written
  (§13).
* **types 2, A and E are stored nowhere in the recovered corpus.** E works, and
  staging produces it 1,156 times from these databases; A works, through staging.
  Nothing in nine firmwares or five databases says what 2 was for - nor in the
  tenth firmware and sixth database `typecx.py` adds, which is 2,244 more code
  lines and still not one.

## 15. Stop reading it, run it

Everything above is a reading of a disassembly. `fwemu.py` already executes the
*decrypt* routine out of any of the nine images (`REVERSING.md` §10.3), and the
engine is a much smaller target: one entry point, no BIOS calls, 0x24C bytes.
`engineemu.py` loads it where the firmware puts it, feeds it a synthetic patch
list, enters it the way the hook does (`$t1` = 0x17) and records every access
outside four quiet regions.

The 26 cases are the runtime only: the emulator is handed word pairs and control
blocks that are already staged. Staging is a second harness in the same script
(`Stager`, §13), which runs the passes out of the menu firmware the same way and
stops at the end of the pass-4 loop. What neither runs is the menu that builds a
selection, so the descriptor and pointer arrays staging reads are built by hand.
That line is worth keeping sharp, because the temptation once an emulator works
is to describe the whole document as executed.

Five things had to be got right, and four of them were wrong first:

* **`fwemu` was missing `lh`, `lhu`, `sh`, the COP0 moves and the multiply
  unit** - the decrypt routine uses none of them, and the engine and its helpers
  use all of them. Adding opcodes to an interpreter cannot change the behaviour
  of code that does not execute them, but `fxtest.py` was re-run anyway: all nine
  firmwares still agree.
* **The patch list address is not a constant.** The engine names it inline, and
  it is `0x1F022600` on the three V2 builds but `0x1F024600` on both Pro builds;
  FX loads a pointer out of its support module instead. Hard-coding it made
  xtjpro read the ROM as a code list and spin. Read it out of each engine.
* **The cartridge has to be mapped twice, as an alias.** V2 forms cartridge
  pointers in KSEG and FX in KSEG1, and the FX engine reads back a pointer the
  firmware wrote through the other window. Two independent copies of the same
  bytes silently produced "the FX engines do nothing".
* **The engine leaves through `0x5E0`**, the BIOS dispatcher it displaced. Park a
  jump to the interpreter's return sentinel there. `jr $ra` is not enough: FX
  clobbers `$ra` on the way out.
* **The patch list is inside the cartridge's address range**, and the first
  matching segment wins. Mapped after the cartridge, it was shadowed by it, so
  the engine read the shipped image's bytes at that offset for everything the
  harness had not explicitly written - including the entry after the terminator.
  Map it first. A test case that walks past the end of the list is what turned
  this up.

Two entries of the cartridge's own vector table are stubbed, and the source says
which and why: the engine calls `+0xB0` once per pass and FX calls `+0x100` on
the way out. Neither is handed the patch list or a code; on the V2 builds both
run to completion unstubbed and touch nothing outside the cartridge but the poke
table's flag byte at RAM `0x703` (§9); on FX the first polls a port this map does
not model and never returns. The type 4 delay helper is *not* stubbed - it is the
observable for type 4.

The result is 9 firmwares x 26 cases, and it reproduces every runtime semantic in
§4 while adding four things reading did not give:

* **type D is inert at run time** - seed the anchor with a value it does not
  match and the code below it still fires. On a cartridge only a D with its flag
  nibble set gets that far (§13);
* **nearly every code dereferences its own address twice before its type is
  known**, because the type F and type 7 handlers put their `lhu` in a `bne`
  delay slot - and type 9 reads it three times, while F and B read it once. Even
  the types the engine ignores read their address, and so does type 4, whose
  helper does not want it. A type B slide reads `0x00030004` - its count and step
  field, which is not an address at all;
* **two boundary cases hang all nine engines**: a Supercode or Megacode that
  declares a payload of zero bytes, which the shipped German database contains
  twice;
* **two cases in twenty-six differ across the nine firmwares**, and both are the
  same missing branch: type 4. Apart from the cases, the FX engines clear DCIC on
  entry, on every B() call, which the harness checks on its own rather than
  letting it into every trace (§6).

That last line is worth the whole exercise. The static diff of §6 said the same
thing, but it said it about *instructions*; this says it about behaviour, and the
two agreeing is what makes either believable.

## 16. What this does not settle

* **Type 2.** Narrowed as far as absence can be narrowed, and no further
  (`typecx.py`). Ten firmwares, three classifier idioms, six databases, 17,183
  code lines, four PC binaries and a contemporary third party's own type list:
  no handler, no classifier, no route, no specimen, `"2" : ??`. It reads as an
  unused opcode rather than a lost feature, and the likely reason it exists as a
  nibble at all is that the Xplorer shares its 16-way type space with the Datel
  GameShark, where `20`/`21` are 8-bit increment/decrement (web: psx-spx, which
  partitions the first digit as "1,2,C,D,E = Gameshark; 4,6,7,9,B,F = Xplorer").
  The Xplorer implements its own quadrant and leaves the GameShark-only nibbles
  dead - type 2 among them. Only FCD documentation, the X-Link PRO / v1.10 that
  `pc/RelNotes.txt` promises, or a database nobody here has would turn "unused"
  into a fact.
* **Who wrote the Japanese type C jokers.** Not what they do: they work, as
  type 7 guards, on every cartridge in the corpus (§13). Every contemporary
  write-up of the Xplorer format (web sources: the "Advanced Xplorer Codes" FAQ,
  May 2000; Hackman's in-depth FAQ, June 2000; GS Central's compatibility table)
  documents type C as an if-then conditional carried over "for Action Replay /
  Datel compatibility", and `x-killer.exe` (1999) has "supported - Datel code,
  obsolete" - all of them right, for a C stored with a zero flag nibble. The
  GameHacking wiki, testing it, reports "in no cases did those types work"; the
  firmware says that is true only of a C with its flag nibble set, and which of
  the two the wiki tried is not recorded. What is still open is whose
  convention the jokers follow. *Not FCD's PC tooling*: the Advanced Code
  Generator's Joker in `XLink.exe` emits a type 7 or type 9 guard over a type 3
  write and never a type C, and the masks it documents are byte-swapped where the
  Japanese ones are not. *Not the X-Terminator*: that is this cartridge, under
  its Japanese name (below). That leaves another hand working to the Datel-style
  type list, or games that keep their pad state the other way round from the
  ones FCD's table was written for. The corpus cannot tell the two apart.
* **The X-Terminator is not another device.** `pc/RelNotes.txt` names it beside
  the Xplorer and reads like a second product, and `XLink.exe` really does carry
  a second saved-codes banner for it. It is the Japanese name of this cartridge:
  the packed firmware carries seven brand strings, in the same seven places in
  every language, reading Xplorer (UK) / Xploder (DE) / X-Terminator (JP), and
  the Japanese UI says "X-Terminator plug-in CD" exactly where the UK one says
  "Xplorer Plugin CD`s". Independently confirmed off-corpus (web: psx-spx lists
  "Xploder (Germany/USA) / Xplorer (England/Spain/Netherlands) / X-Terminator
  (Japan)" as one device; Gametech's own site shipped its firmware as `xtjap.fcd`
  flashed with X-Link, and its release numbers - 2.005, 2.006, 3.18 Pro, 4.55
  Pro - interleave with the corpus here). In `XLink.exe` the whole X-Terminator branch is a name
  and a contact address behind a predicate whose entire body is `xor eax, eax;
  ret`. `X-Assist`, which both Pro firmwares detect by a `WHB!` magic at PSX RAM
  `0x38` and import from, is FCD's own PSX-side helper and hands over an address
  and a 16-bit value with no type nibble at all.
* **What the console does with a bad address.** §7 is executed, but against a
  memory map, not a PlayStation. That the engine dereferences `0x0802A798` is
  now observed; what an R3000 does about it is not. Nor is what it does about an
  odd one - the MIPS I answer is an address-error exception, which is the reason
  §13 gives for the normaliser, but no console has been watched taking one.
* **The row-count bug in the wild.** Staging pass 1 computes a Supercode's row
  count with `or` where pass 2 uses `add` (`REVERSING.md` §7 already noted it).
  It is reproduced now, executed in all ten: a 507-byte Supercode is fine, and the
  same one with a 6 at the start of its 43rd payload row makes pass 1 stage a
  Megacode out of the payload, after which pass 2 finds rows missing - so the V2
  builds and Pro 2.14 hang, and Pro 2.20 and FX stage a bogus Megacode (§7). No
  recovered database has a Supercode long enough.
* **What is in front of the record chains.** `db2.find_db()` returns the chain it
  can parse, and in `xteng.dec` printable game data starts about 0x3000 bytes
  ahead of it. Every count in §8 and §14 is over what was recovered.
* **The menu that builds a selection.** The staging passes are executed (§13),
  but over descriptor and pointer arrays built by hand. What the menu really puts
  there - in particular what a cheat-name line's pointer points at, which is what
  the malformed MGS record takes for its descriptor - is a reading. Type A's
  extent, which depends on those descriptors, is not executed either.

## 17. Transferable checklist

* Ask *when* the code you are looking for runs. A cartridge menu and a cheat
  engine never run at the same time, so they cannot be in the same address space,
  and looking for one in the other's image is a category error, not a hard search.
* Search for a constant the *format* already told you about. `0x80000040` came
  out of the Megacode layout months before anyone knew where the engine was; the
  instruction pair that builds it is a one-hit signature in every image.
* Search the raw ROM as well as the unpacked image, always. Six of nine
  firmwares keep the interesting blob outside the container.
* Absolute low-address `j` targets in relocatable code are a gift: they name the
  load address, and they mark the real basic blocks.
* Two adjacent tables can dispatch on two unrelated byte encodings. Before
  reading a jump table as a specification, find the instruction that *produces*
  its index.
* When a call graph is not converging, enumerate the instruction instead. One
  pass over `andi rX, rY, 0xf0` answered what the call graph had not. Enumerate
  *every* occurrence, though, and report the ones you cannot read as unresolved:
  a scan that quietly drops them turns "13 occurrences, 9 read" into "7 sites",
  which sounds like a complete answer and is not one.
* An idiom scan finds the idiom, not the question. The function that decides what
  type C means compares whole bytes and has no `andi` in it, and three widening
  scans walked past it. Following the data instead - from the decrypt call to the
  store of the list entry, one call in between - finds it in one step.
* Diff behaviour across builds mechanically, not by reading. Normalising over
  branch targets turns "are these the same routine" into a string comparison, and
  it is what made the missing type 4 obvious rather than something to notice.
* A type that does nothing may be load-bearing. Type 1 is used 134 times
  *because* it is unimplemented.
* When two encodings of the same data disagree about a bit - the encrypted and
  plaintext forms of the same cheat - follow the bit, not the value.
* Count one population per sentence. "133 rows have the bit", "121 of them are
  stored without a key" and "120 of those use a wrong address" are three
  different numbers about the same defect, and using them interchangeably makes
  every one of them unciteable.
* The obvious release-history story is worth one more query. "The first database
  shipped in the clear" explained the default-off defect and was wrong - the
  previous release was already in the clear. What was new was a *combination*,
  which only showed up in a per-release histogram of stored key nibbles.
* A boundary the format cannot express is where the implementation is untested.
  Nothing in a header field forbids a length of zero, and both block handlers
  copy before they test - so both hang, and the shipped database has two.
* An interpreter you already have is cheaper than the reading you are about to
  do. `fwemu.py` needed five opcode groups and an hour to go from decrypting
  codes to running the whole engine, and it turned a document full of "the
  disassembly says" into one full of "the run shows".
* A wrong memory map fails *silently* and looks like a result. "The FX engines do
  nothing" was two copies of the cartridge where there should have been one
  alias. Prefer maps that raise, and treat a clean negative as a bug report
  against the harness until it is explained.
* Emulate the seam, not just the routine. The bug in §7 needs the decrypt routine
  and the engine, one after the other; either alone looks fine.
