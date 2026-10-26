# Reversing the Xplorer PSX crypto from the cartridge ROM

A step-by-step account of how the code crypto was located and read out of the
firmware, including the dead ends. Everything here can be reproduced with the
scripts in this directory; `FINDINGS.md` has the conclusions, this file has the
method and the annotated listings.

Target: `roms/xteng.dec` (Xplorer V2.008 UK, decrypted with `xpcrypt -r`).
§10 does the same to the Xplorer FX ROMs, which take one more step to open and
then turn out to run the identical cipher, and widens the corpus to nine
firmwares. §11 is the anti-tamper check none of that needed — and that I nearly
missed by stubbing it.

`AUDIT.md` is an external review of this directory. Its corrections have been
folded in here; where one of them overturned something this file used to assert,
the old version is left standing next to the correction rather than quietly
deleted, because being wrong in a particular way is part of the method.

This file is about the *cipher*. What the decrypted codes actually do is a
separate hunt with a separate quarry - six of the nine images do not keep the
code engine in the firmware image at all - written up in `ENGINE.md`.


## The four findings that matter

If you read nothing else, read this. Details in the sections named.

**1. The constants are not in the code** (§6.2, §6.3). Key 5's addends live in a
data table at `0x1BF294` as the string `" WB123"`; key 4 seeds a four-byte
sliding window with `"WHBX"`, key 7 with `"FCD!"`. Which is why no amount of
searching for immediates finds them, and why the first three attempts came up
empty. `code[1] += 0x57; code[2] += 0x42; code[3] += 0x31; ...` is nothing but
the string `WB123` being added byte by byte.

**2. Brute force and the silicon agree, once the algebra is unfolded** (§6.5,
§6.6). Key 4 is not five separate equations - it is one window sum, evaluated
five times, with each output byte pushed back into the window. Unroll it and
every constant of the brute-forced version appears:

```
i=1   window "WHBX"    0x8F + 0x48 + 0x50 + 0xFE = 0x225 -> 0x25
                                            our C:  code[1] ^= 0x25
i=2   window "HBX"+o1  0xFA + (o1 & 0x11)
                                            our C:  (code[1] & 0x11) + 0xFA
```

Two identities bridge the two forms, and both are worth keeping in your head for
any byte-level cipher:

```
x | 0xEE  ==  (x & 0x11) + 0xEE        because 0xEE = ~0x11
x ^ 0x7F  ==  0x7F - x   (mod 256)     hence (x ^ 0xEF) + 0x76
                                             == 0xF5 - (x ^ 0x90)
```

The second one is what turns the ROM's `+ (w2 ^ 0xEF)` into our
`- (code[i+2] ^ 0x90) + 0xF5`. Different-looking algebra, same function, derived
years apart from opposite ends - one from known plaintext, one from the ROM.

**3. A jump table is a specification; prefer it to inference** (§6.2). Which
first bytes are encrypted is not a matter of opinion or of sampling: it is 244
words at `0x1BF2AC`, identical in all three ROMs. Before dumping it I had argued
from two suspicious-looking Wipeout codes that the reference implementation's
route gaps were an error. They were not. One `lw` at `0x801AC028` settles what a
database survey could not - and I had the ROM in hand the whole time. When a
question is "what does this program do", stop reasoning about its output.

**4. The decrypt routine bricks the cartridge if you touch the copyright**
(§11). Hidden behind the one call I had written off as inert: a comparison of
the cheat database's header against `"(C) 1997/8 FCD"` — stored bitwise NOTed so
`strings` cannot see it — and, on a mismatch, `flash_write(0x3E8, 0x1F000000,
0x18000)`, which programs 96 KB of low PSX RAM over the cart's own firmware.
Present in nine of the ten firmwares (the tenth being 2.005, shipped inside the
DOS X-Link tool), and the FX builds hide it harder. One of them, Pro 2.14, does
not even need the copyright touched: its check string predates its own header,
so the first key-7 or Special32 code a user activates sets it off (§11.3). This
is what FCD's protection actually looks like; everything else in this file is
just a cipher.


## 0. Tools

```sh
uv run --with capstone python3 mipscan.py <file> <constants> <ctx> <base>
```

capstone in a throwaway env, no system install. `llvm-objdump` can do MIPS too,
but a scriptable disassembler matters here: most of the work is *searching* the
disassembly, not reading it.

**Decode one word at a time**, rather than linear-sweeping with
`md.skipdata = True`. This note used to say that `skipdata` skips a single
*byte* and decodes everything after the first data word at the wrong alignment.
That is wrong, and an audit caught it: capstone's `skipdata_size()` returns 4
for MIPS, so alignment survives. Word-at-a-time is still what `mipscan.py`
does — undecodable words stay visible as data, and nothing depends on a
per-architecture constant inside capstone — but the alignment argument was not
the reason:

```python
for off in range(start, end, 4):
    try:    d = next(md.disasm(data[off:off+4], base + off))
    except StopIteration:  # not an instruction, print .word
```

That is all `mipscan.py:dis()` does, and it changes the results completely.

Two more things to keep in front of you while reading MIPS:

* **Every branch and jump has a delay slot.** The instruction *after* a branch
  executes before the branch is taken. Half the constants in this firmware are
  set in delay slots.
* **Segments.** The boot stub unpacks the V2 firmware to KSEG0 `0x801A0000` and
  enters it at `0x801A0008`, but the image is linked for KUSEG: every absolute
  pointer it holds - data (`0x001Cxxxx`) and code alike, the jump-table entries
  of §6.2 included - is `0x001Axxxx`/`0x001Cxxxx`, so after the first jump
  through a table the firmware runs in KUSEG. Same physical memory, 0x80000000
  apart. The listings in §4-§7 are quoted at the KSEG0 address they were first
  read at, §11 and `fwimage.load()` at the KUSEG one. File offset =
  (address & 0x1FFFFFFF) - 0x1A0000 for the unpacked image, whichever segment
  the address was written in.


## 1. Where does the ROM start

```
00000000: 0001 001f 4c69 6365 6e73 6564 2062 7920  ....Licensed by
00000050: 2146 4344 203d 2057 4842 2050 4a48 2044  !FCD = WHB PJH D
00000100: 7700 c00b 0000 0000                      w.......
```

Word 0 is `0x1F000100`, so the cart is mapped at `0x1F000000` (PSX EXP1) and the
first word points at its own entry. Confirm by decoding `0x0BC00077` at
`0x100`: opcode `000010` = `j`, target `(0x3C00077 & 0x03FFFFFF) << 2` with the
top nibble of PC = `j 0x1F0001DC`. Base confirmed - now every address in the
listing is a file offset plus `0x1F000000`.

`"FCD = WHB PJH DN MW IN R?"` in the header is the team's initials; WHB is Wayne
Hughes Beckett. A second copy of it sits at `0xD0`, and his name turns up in full
as a credit at `0x560`, `"Wayne Hughes Beckett!"`. Keep that in mind, it becomes
load-bearing in §4.1.


## 2. First attempt, and why it failed

The obvious move is to search for the cipher constants. `xp_crypto.c` is full of
them: `0x57 0x42 0x31 0x32 0x33` (key 5), `0xAB` (key 6), `0x25 0xFA 0x12`
(key 4), `0x73 0x90 0x35` (key 7).

```sh
uv run --with capstone python3 mipscan.py roms/xteng.dec 0x57,0x42,0x31,0x32,0x33 0
# 0 hits
```

Nothing, in any of the five ROMs I had at that point — nor in the four that
turned up later (§10). The few hits that did appear were in the code
database region (data decoded as instructions) or were the bytes of the string
`"Wayne Hughes Beckett!"` itself. Three separate reasons, and each one is worth
internalising:

1. **The body is packed.** Only ~4 KB of the 204 KB ROM is plain MIPS.
2. **Constants get folded by the compiler.** `+ 0xFA` on a byte is `- 6`;
   capstone prints `addiu $v0, $v0, -6` and a search for `0xfa` misses it. Add
   the two's-complement form of every constant to the search
   (`0xFA -> 0xFFFA`, `0xAB -> 0xFFAB`, ...).
3. **Some constants are not immediates at all.** Key 5's addends live in a data
   table. No amount of immediate-searching finds them.

Reason 3 is the general lesson: *search for the shape of the code, not only for
its constants*. Which is what step 4 ends up doing.


## 3. Mapping the ROM

Two cheap maps tell you where to look.

**Code density.** Decode each 0x100 block and count how many words are common
MIPS opcodes (`addiu`, `lw`, `sw`, `jr`, `lbu`, `sb`, `beq`, ...). Blocks above
~55% are code:

```
roms/xteng.dec
  code 0x000100 - 0x000500   <- loader stub
  code 0x002F00 - 0x003200
  code 0x01D700 - 0x01DA00
  code 0x023000 - 0x024000   <- database header
```

**Magic strings.**

```
COMP   0x580    b'COMP01\xd5\xfe\xfe\xb3\x00\x02\xbf\x18'
COMP   0x15BCF  b'COMP01Iwda\x00\x00\x04\x00\x01\x06'
FCD    0x2300B  b'FCD  release 2.008'
```

So: a small loader at `0x100`, immediately followed by a `COMP01` container at
`0x580`. The crypto is inside the container. Read the loader.


## 4. The container format, from the loader

`j 0x1F0001DC` leads to a register-saving wrapper that calls the unpacker with
three arguments and then jumps into whatever it produced:

```
1F00022C  lui   $a0, 0x1f00
1F000230  addiu $a0, $a0, 0x580      ; a0 = packed data, right after the stub
1F000234  lui   $a1, 0x801a          ; a1 = unpack to 0x801A0000
1F000238  lui   $a2, 0x1f02
1F00023C  addiu $a2, $a2, 0x1650     ; a2 = unused by the callee
1F000240  jal   0x1f0002ac           ; unpack()
1F000244  nop
1F000248  lui   $v0, 0x801a
1F00024C  ori   $v0, $v0, 8
1F000250  jalr  $v0                  ; call 0x801A0008, the unpacked entry
```

`0x801A0000` is the load address - remember it for the disassembly base.

### 4.1 The header is XOR-masked with the credit string

```
1F0002AC  addiu $sp, $sp, -0x30
1F0002B0  move  $t6, $a0             ; t6 = packed base
1F0002B4  move  $t0, $zero           ; t0 = output position
1F0002B8  addiu $t3, $zero, 0xe      ; t3 = input position, header is 14 bytes
1F0002BC  move  $a2, $zero
1F0002C0  move  $t1, $sp             ; t1 = sp[0..9], the decoded header
1F0002C4  move  $a3, $t6

1F0002C8  lbu   $v0, 0xa($t6)        ; size, 4 bytes, big-endian
1F0002CC  lbu   $v1, 0xb($t6)
1F0002D0  lbu   $a0, 0xc($t6)
1F0002D4  sll   $v0, $v0, 0x18
1F0002D8  sll   $v1, $v1, 0x10
1F0002DC  addu  $v0, $v0, $v1
1F0002E0  sll   $a0, $a0, 8
1F0002E4  lbu   $v1, 0xd($t6)
1F0002E8  addu  $v0, $v0, $a0
1F0002EC  addu  $t7, $v0, $v1        ; t7 = uncompressed size

1F0002F0  lbu   $v0, ($a3)           ; <- loop: byte of the header
1F0002F4  addiu $a3, $a3, 1
1F0002F8  lui   $at, 0x1f00
1F0002FC  addu  $at, $at, $a2
1F000300  lbu   $v1, 0x560($at)      ; <- "Wayne Hughes Beckett!" at 0x1F000560
1F000304  addiu $a2, $a2, 1
1F000308  xor   $v0, $v0, $v1        ; header[i] ^= "Wayne Hugh"[i]
1F00030C  sb    $v0, ($t1)
1F000310  slti  $v0, $a2, 0xa        ; ten bytes
1F000314  bnez  $v0, 0x1f0002f0
1F000318  addiu $t1, $t1, 1          ; delay slot
```

The first ten header bytes are XORed with the first ten bytes of the credit
string. Bytes 0..5 are the literal `"COMP01"`, so only bytes 6..9 carry
information - they are the four escape codes, masked with `"Hugh"`. For this
ROM: `D5 FE FE B3` ^ `48 75 67 68` = `9D 8B 99 DB`.

The vanity string is not decoration. It is the key.

### 4.2 The four escape codes

Main loop, `t1` = current input byte, `t0` = output position:

```
1F00032C  lbu   $t1, ($a3)           ; fetch a byte
1F000344  addu  $a2, $t3, $t6        ; a2 -> the byte after it
1F00034C  andi  $t4, $t1, 0xff
1F000350  lbu   $v0, ($v1)           ; <- loop over sp[6..9], the escapes
1F000358  bne   $t4, $v0, 0x1f00038c
1F000360  lbu   $v0, ($a2)
1F000368  bnez  $v0, 0x1f00038c      ; escape followed by 0x00 ...
1F000370  sb    $t1, ($a0)           ; ... emits the escape byte literally
1F000388  addiu $t2, $zero, 1
```

then four `bne`-chained cases, one per escape:

| escape | operands | meaning |
|---|---|---|
| `sp[6]` | `[count][b]` | write `b` count times |
| `sp[7]` | `[count][b1][b2]` | write the pair count times |
| `sp[8]` | `[count][step][start]` | `out[i] = start + step*i` |
| `sp[9]` | `[count][lo][hi]` | copy count bytes from `out - (lo\|hi<<8)` |

The arithmetic-progression escape is unusual and worth noticing - it is the case
that compresses a run with a constant step, which is what a gradient table or an
index array is. What it was put there *for* is not something the decoder says.
The back-reference case:

```
1F0004DC  lbu   $v0, 1($a3)          ; distance low
1F0004E0  lbu   $v1, 2($a3)          ; distance high
1F0004E4  subu  $a0, $t0, $v0
1F0004E8  sll   $v1, $v1, 8
1F0004EC  lbu   $v0, ($a3)           ; count
1F0004F4  blez  $v0, 0x1f000530
1F0004F8  subu  $a0, $a0, $v1        ; delay slot: src = outpos - distance
1F000500  addu  $v1, $t0, $a2        ; byte-by-byte, so overlap is allowed
```

That is the whole format. `comp01.py` is a direct transcription:

```sh
python3 comp01.py roms/xteng.dec 0x580 > xteng.unp   # 179992 bytes
```

**Check the output before building on it.** `strings` gives
`"(C) Future Console Design"`, `"WHB & PJH"`, `"Should not be here!"`, and a
register-name table (`t9 k0 k1 gp sp s8 ra c0 ...`) - the Xplorer's built-in
debugger. The image also contains further `COMP01` blocks: nested resources.

### 4.3 Reading the format's biography

A format tells you about the people who wrote it, and it is worth pausing to
ask whether the thing you just reversed is standard. This one is not, and the
evidence is in the format itself:

* **no entropy coding at all** - no Huffman, no arithmetic or range coder. Every
  contemporary format built like this (deflate, LZH, LZX) has one. Ratio comes
  out ~0.75, exactly what plain LZ77 gives on mixed code and data;
* **the escape bytes are chosen per stream from the data** - `9D 8B 99 DB` here,
  `7B D1 F3 F2` in the USA ROM, and they are the rare bytes of the stream they
  escape: the first is the rarest of the 256 in every image, and all four are
  among the 14 rarest (`escrank.py`). That the compressor got there by counting
  frequencies is the obvious reading, not a recovered fact. The three formats we
  read - DEFLATE, the LHA/LZH methods in `jca02266/lha`, and Microsoft's LZXD -
  fix the bitstream grammar and what each token means instead, and none of them
  picks byte values per stream to serve as opcode sentinels. Their token *codes*
  are Huffman and not fixed tags, so that is the contrast to draw, not "a fixed
  tag byte or bit flags";
* **the arithmetic-run opcode** has no counterpart in those three: none emits
  `start + n*step`. Whether it was aimed at this firmware's pointer and index
  tables is a guess about intent; what is measured is that it fires 9-14 times
  per image.

`packstats.py` settles it by counting what each opcode actually buys:

```
xteng.dec       escapes 9D 8B 99 DB   0x210CB -> 0x2BF18  ratio 0.75
   literal          102736 uses        +0 bytes
   lz-match           7883 uses    +43583 bytes
   rle8                251 uses     +1063 bytes
   rle16                 4 uses       +56 bytes
   arith-run            12 uses       +70 bytes
   literal-escape      136 uses      -136 bytes
```

**Two of the four opcodes barely pay for themselves.** Across all nine images
`rle16` fires 4-19 times and `arith-run` 9-14, saving 56-108 and 58-73 bytes -
against 23 KB to 86 KB saved per image. That much is measured, and it is all that
is. "Someone designed those on intuition and never profiled them" is my reading
of it, not a fact about the bytes - the same numbers are equally consistent with
a stock library whose two rarer opcodes this particular data hardly exercises. I
believe the first reading; I cannot show it from here.

The same measurement answers a question I had already answered wrongly. I had
written that a ROM could not be rebuilt without FCD's compressor. Not so: the
decompressor is the specification, and *any* stream it accepts is valid, so an
encoder need not resemble theirs at all. What actually constrains you is size -
a store-only encoder runs +33% over the original packed size (`0x2BFC8` against
`0x210CB` on `xteng.dec`, both counted with the header) and collides with the
code database, while the LZ opcode alone accounts for 96-97% of what their own
matcher saved. That last figure bounds the prize, not the effort: it says what
*their* matcher found, not what a new one would find. (This note used to give
`0x2BFAE`, which doubles only the 136 escape bytes the original stream had to
escape. A store-only stream has nothing to hide them in and must escape every
one of the 162 in the output.)
Reversing a decoder gives you an encoder for free; reversing it and then not
noticing that is the mistake.


## 5. Finding the crypto in the unpacked image

Now search with the folded constants from step 2. Key 6 decrypt is
`(x + 0xAB) ^ i`, and `+0xAB` on a byte is `-0x55`:

```sh
uv run --with capstone python3 mipscan.py xteng.unp 0xffab,0x1,0x2 40 0x801A0000
```

Two hits, adjacent, at `0x801AC2D8` and `0x801AC37C`. Walk backwards to the
prologue: `0x801ABF94`. One function, and it is the only one - a scan of the
whole image for `xori 0x12`, `ori 0xee`, `xori 0xef`, `andi 0x73` returns
exactly four sites, all inside it. **No image in this corpus contains an encrypt
routine.** The cart only ever decrypts, which is all a cart needs to do. Where
the encrypt side did live - FCD's authoring tools, presumably - is a guess these
images cannot settle.


## 6. The crypto function, annotated

`decrypt(a0 = src, a1 = dst, a2 = key)`, `a2 == -1` for a normal code,
otherwise the payload key of a Supercode/Megacode.

### 6.1 Entry and dispatch

```
801ABF94  addiu $sp, $sp, -0x30
801ABF9C  move  $s0, $a0             ; s0 = src
801ABFA4  move  $s1, $a1             ; s1 = dst
801ABFAC  lui   $a1, 0x1c
801ABFB0  addiu $a1, $a1, -0xd6c     ; 0x1BF294, the constant table
801ABFB4  lwl   $v0, 3($a1)          ; copy 7 bytes of it to sp[0x18..0x1E]
801ABFB8  lwr   $v0, ($a1)
801ABFCC  sb    $v1, 0x1c($sp)
801ABFE0  addiu $v1, $s1, 1
801ABFE4  addiu $a0, $s1, 6
801ABFE8  sb    $zero, ($v1)         ; dst[1..5] = 0 (dst[0] is NOT cleared)
801ABFEC  addiu $v1, $v1, 1
801ABFF0  slt   $v0, $v1, $a0
801ABFF4  bnez  $v0, 0x801abfe8
801ABFF8  addiu $v0, $zero, -1       ; delay slot

801ABFFC  bne   $a2, $v0, 0x801ac2e0 ; key != -1 -> payload path
801AC000  addiu $a3, $zero, 6        ; delay slot: a3 = 6, used there as "key 6"

801AC004  lbu   $v0, ($s0)
801AC00C  andi  $v0, $v0, 0xf7       ; <- default-off bit masked out for routing
801AC010  addiu $v1, $v0, -4
801AC014  sltiu $v0, $v1, 0xf4       ; 244 entries, first byte 0x04..0xF7
801AC018  beqz  $v0, 0x801ac2b0      ; out of range -> copy verbatim
801AC01C  sll   $v0, $v1, 2          ; delay slot
801AC020  lui   $at, 0x1c
801AC024  addu  $at, $at, $v0
801AC028  lw    $v0, -0xd54($at)     ; jump table at 0x1BF2AC
801AC030  jr    $v0
```

Two things to take from this. The `addiu $a3, $zero, 6` sits in a delay slot, so
it executes even when the branch is taken - that is how you learn that the
comparison `beq $a2, $a3` further down means "key 6". And `dst[0]` is
deliberately not zeroed, which explains why two of the routes never write it.

### 6.2 The jump table is the route table

`0x1BF2AC` is `0x1F2AC` in the image. Dump 244 words and group by target:

```python
t = img.find(b'\x20WB123') + 0x18          # table sits 0x18 after the constants
ents = [int.from_bytes(img[t+4*i:t+4*i+4],'little') for i in range(0xF4)]
```

```
copy verbatim  192 first bytes
001AC0D0        12: 04 14 34 44 54 64 74 84 94 B4 D4 F4   key 4
001AC170        12: 05 15 35 45 55 65 75 85 95 B5 D5 F5   key 5
001AC1B0        12: 06 16 36 46 56 66 76 86 96 B6 D6 F6   key 6
001AC1F4        12: 07 17 37 47 57 67 77 87 97 B7 D7 F7   key 7
001AC038         2: 32 82
001AC08C         2: 33 83
```

This is *the* answer to "which codes are encrypted": high nibbles 2, A, C, E are
not in the table, so `24`, `A5`, `C6`, `E7`... are copied through untouched.
Identical in all three ROMs. A table like this is worth more than any amount of
inference from sample data - I had previously argued from a suspicious-looking
pair of Wipeout codes that the gaps were an error in SkillerCMP's port. The ROM
says otherwise, and the ROM wins.

The constants sit just before the table:

```
0x1BF294:  20 57 42 31 32 33 00 00     " WB123"   key 5 addends, index 1..5
0x1BF29C:  57 48 42 58                 "WHBX"     key 4 window
0x1BF2A4:  46 43 44 21                 "FCD!"     key 7 window
```

The whole cipher is seeded with the authors' initials and the company name.

### 6.3 Key 5 - table addition

```
801AC170  addiu $a0, $s1, 1          ; dst+1
801AC174  addiu $a2, $sp, 0x19       ; the copied table, +1 -> 'W'
801AC178  addiu $a1, $s0, 1          ; src+1
801AC17C  addiu $a3, $s1, 6
801AC180  lbu   $v0, ($a2)           ; W B 1 2 3
801AC184  addiu $a2, $a2, 1
801AC188  lbu   $v1, ($a1)
801AC190  addu  $v1, $v1, $v0        ; dst[i] = src[i] + tbl[i]
801AC194  sb    $v1, ($a0)
801AC1A0  bnez  $v0, 0x801ac180
```

`code[1] += 0x57; code[2] += 0x42; ...` - our key 5, exactly.

### 6.4 Key 6 - the simple one

```
801AC1B0  addiu $a3, $zero, 1        ; i = 1
801AC1BC  lbu   $v0, ($v1)
801AC1C4  addiu $v0, $v0, -0x55      ; -0x55 == +0xAB on a byte
801AC1C8  xor   $v0, $v0, $a3
801AC1CC  sb    $v0, ($a0)
801AC1D0  addiu $a3, $a3, 1
801AC1D4  slti  $v0, $a3, 6
801AC1D8  bnez  $v0, 0x801ac1bc
```

`(x + 0xAB) ^ i` for i = 1..5. Ours, exactly.

### 6.5 Key 4 - a sliding window

This is where the folding matters. The window is four bytes, seeded `"WHBX"`,
and each output byte is fed back into it:

```
801AC0D0  addiu $a0, $sp, 0x10
801AC0D8  addiu $a1, $a1, -0xd64     ; 0x1BF29C = "WHBX"
801AC0DC  jal   0x801a3d0c           ; strncpy(sp+0x10, "WHBX", 4), BIOS A(0x1A)
801AC0E0  addiu $a2, $zero, 4

801AC104  lbu   $a0, 0x10($sp)       ; w0
801AC108  lbu   $v1, 0x11($sp)       ; w1
801AC10C  lbu   $v0, 0x12($sp)       ; w2
801AC110  addiu $a0, $a0, 0x38       ; w0 + 0x38
801AC114  addu  $v1, $v1, $a0
801AC118  xori  $v0, $v0, 0x12       ; w2 ^ 0x12
801AC11C  addu  $v1, $v1, $v0
801AC120  lbu   $a0, 0x13($sp)       ; w3
801AC124  lbu   $v0, ($t1)           ; src[i]
801AC128  ori   $a0, $a0, 0xee       ; w3 | 0xEE
801AC12C  addu  $v1, $v1, $a0
801AC130  xor   $v0, $v0, $v1        ; dst[i] = src[i] ^ sum
801AC134  sb    $v0, ($a3)
801AC138  sb    $v0, 0x14($sp)       ; push into the window
801AC13C  lbu   $v0, ($a2)           ; shift sp[0x11..0x14] -> sp[0x10..0x13]
801AC150  bnez  $v0, 0x801ac13c
801AC160  bnez  $v0, 0x801ac0f8      ; next byte
```

`x | 0xEE` looks nothing like `(x & 0x11) + 0xFA` until you notice that
`0xEE = ~0x11`, so `x | 0xEE == 0xEE + (x & 0x11)`. Unroll the window by hand:

| i | window | sum | our C |
|---|---|---|---|
| 1 | W H B X | `0x8F+0x48+0x50+0xFE = 0x225` -> `0x25` | `code[1] ^= 0x25` |
| 2 | H B X o1 | `0xFA + (o1 & 0x11)` | `(code[1] & 0x11) + 0xFA` |
| 3 | B X o1 o2 | `0xC0 + (o1^0x12) + (o2&0x11)` | `... - 0x40` |
| 4 | X o1 o2 o3 | `0x7E + o1 + (o2^0x12) + (o3&0x11)` | `... - 0x82` |
| 5 | o1 o2 o3 o4 | `0x26 + o1 + o2 + (o3^0x12) + (o4&0x11)` | `... - 0xDA` |

Every constant in misfire's brute-forced key 4 falls out of `"WHBX"` plus
`0x38`. Same routine.

### 6.6 Key 7 - the same shape, backwards

```
801AC1FC  addiu $a1, $a1, -0xd5c     ; 0x1BF2A4 = "FCD!"
801AC208  addiu $a3, $zero, 5        ; from byte 5 down to byte 1
801AC214  addiu $t2, $s1, 5
801AC218  addiu $t1, $s0, 5
801AC234  addiu $a0, $a0, 0x76       ; w0 + 0x76
801AC23C  xori  $v0, $v0, 0xef       ; w2 ^ 0xEF
801AC24C  andi  $a0, $a0, 0x73       ; w3 & 0x73
801AC254  addu  $v0, $v0, $v1        ; dst[i] = src[i] + sum   (add, not xor)
801AC284  bgtz  $a3, 0x801ac21c
```

The identity to know here: for any byte, `x ^ 0x7F == 0x7F - x (mod 256)`, hence

```
(x ^ 0xEF) + k  ==  (x ^ 0x90 ^ 0x7F) + k  ==  0x7F - (x ^ 0x90) + k
```

With `0x76 + 0x7F = 0xF5` this turns the ROM's `+ (w2 ^ 0xEF)` into our
`- (code[i+2] ^ 0x90) + 0xF5`. Identical again, all five bytes.

### 6.7 The two odd routes

```
801AC038  lbu   $v0, 1($s0)
801AC040  addiu $v0, $v0, 0x46       ; 'F'
801AC044  sb    $v0, 1($s1)
801AC048  lbu   $v0, 2($s0)
801AC050  addiu $v0, $v0, 0x43       ; 'C'
801AC058  lbu   $v0, 3($s0)
801AC060  addiu $v0, $v0, 0x44       ; 'D'
801AC068  lbu   $v0, 4($s0)          ; bytes 4 and 5 copied
801AC07C  jal   0x801a4620           ; the copyright check (§11), also in key 7
```

First bytes `32`/`82`: add `"FCD"` to bytes 1, 2, 3. The reference
implementation has this as `+'C'` and `+'D'` on bytes 1 and 2 - wrong, and we
had briefly ported that error.

```
801AC08C  addiu $v1, $s1, 1
801AC098  lbu   $v0, ($a0)
801AC0A0  nor   $v0, $zero, $v0      ; complement
801AC0B0  bnez  $v0, 0x801ac098      ; bytes 1..3
801AC0B8  lbu   $v0, 4($s0)          ; 4 and 5 copied
```

First bytes `33`/`83`: complement bytes 1-3. Neither route writes `dst[0]`.

### 6.8 The tail

```
801AC1E0  lbu   $v0, ($s0)
801AC1E8  andi  $v0, $v0, 0xf0       ; dst[0] = src[0] & 0xF0
801AC1EC  j     0x801ac408
```

The cart throws the whole low nibble away, including the default-off bit. A tool
that has to re-encrypt cannot do that, which is the one intentional difference
between xpcrypt and the firmware.

### 6.9 The payload path

```
801AC2E0  beq   $a2, $a3, 0x801ac314 ; a3 = 6 (set in the delay slot at BFFC)
801AC2E4  slti  $v0, $a2, 7
801AC2E8  beqz  $v0, 0x801ac300      ; key >= 7
801AC2F0  beqz  $a2, 0x801ac3e4      ; key 0 -> copy 6 bytes
801AC2F8  j     0x801ac408           ; keys 1..5 -> return, dst[1..5] still 0
801AC300  addiu $v0, $zero, 7
801AC304  beq   $a2, $v0, 0x801ac380 ; key 7
801AC30C  j     0x801ac408           ; keys 8..15 -> return, ditto
```

Unknown payload keys return with `dst[1..5]` zeroed and `dst[0]` never written -
see the `addiu $a3, $zero, 6` note in 6.1 for why byte 0 is the odd one out.
There are no other payload routines, which closes the question of whether keys
1-5 and 8-15 exist. They don't.

```
801AC314  lbu   $v0, ($s0)           ; key 6
801AC31C  addiu $v0, $v0, -0x34
801AC320  sb    $v0, 1($s1)          ; dst[1] = src[0] - 0x34
801AC32C  nor   $v0, $zero, $v0
801AC330  sb    $v0, ($s1)           ; dst[0] = ~src[1]
801AC340  subu  $v0, $v0, $v1
801AC344  sb    $v0, 5($s1)          ; dst[5] = src[2] - src[0]
801AC354  xor   $v0, $v0, $v1
801AC358  sb    $v0, 3($s1)          ; dst[3] = src[3] ^ src[1]
801AC364  addiu $v0, $v0, -0x1b
801AC368  sb    $v0, 2($s1)          ; dst[2] = src[4] - 0x1B
801AC374  addiu $v0, $v0, -0x55
801AC37C  sb    $v0, 4($s1)          ; dst[4] = src[5] - 0x55
```

Note the destination indices: the "byte swap" xpcrypt used to apply separately
for Supercodes is simply built into this routine. It is not a property of the
code type, and it therefore applies to Megacodes as well.

```
801AC380  lbu   $v0, ($s0)           ; key 7
801AC388  addiu $v0, $v0, -0x55
801AC38C  sb    $v0, 5($s1)          ; dst[5-i] = src[i] - 0x55, six times
```

`-0x55`, not `-0xAB` as the reference had it, and no extra swap.


## 7. The block stagers

Same image, two callers that pass a real key. They confirm the header layout
without any guesswork. The addresses below are of the instructions quoted, not of
function entries: the Supercode stager starts at `0x801AD010`, and the Megacode
one is not a function of its own but the tail of the list walker at `0x801ACC74`,
which skips Supercode blocks on its way to the first Megacode.

Supercode, in `0x801AD010`:

```
801AD1B4  lui   $a0, 0x2aaa
801AD1B8  ori   $a0, $a0, 0xaaab     ; the reciprocal of 6
801AD1F0  or    $t1, $v0, $v1        ; t1 = ((b4 & 0xF) << 8) | b5
801AD1F4  addiu $v1, $t1, 5
801AD1F8  mult  $v1, $a0             ; divide by 6
801AD218  srl   $a3, $t0, 4          ; payload key = b4 >> 4
801AD228  subu  $s1, $t5, $v1        ; s1 = row count = (nbytes + 5) / 6
801AD284  move  $a2, $a3             ; every row decrypted with that key
801AD290  jal   0x801abf94
801AD2B4  lbu   $v0, ($v1)           ; and copied out in order
```

Megacode, in `0x801ACC74`:

```
801ACE2C  jal   0x801abf94           ; header, a2 = -1
801ACE34  lbu   $v0, 0x14($sp)
801ACE40  or    $s5, $v0, $v1        ; s5 = nnnn
801ACE44  lbu   $v0, 0x13($sp)
801ACE48  addiu $a0, $s5, 3
801ACE4C  andi  $v0, $v0, 0xf        ; payload key = b3 & 0x0F
801ACE50  bgez  $a0, 0x801ace5c
801ACE54  sw    $v0, 0x18($sp)       ; delay slot
801ACE58  addiu $a0, $s5, 6
801ACE70  sra   $v0, $a0, 2          ; word count = (nnnn + 3) / 4
801ACE90  lw    $a2, 0x18($sp)
801ACE94  jal   0x801abf94           ; row 0, the descriptor - same key!
801ACEA4  sb    $v0, 0x787($s7)      ; stored back to front
801ACEF4  jal   0x801abf94           ; row 1, the mask
801ACF3C  addiu $s5, $s5, -2         ; two payload bytes rode along in row 1
801ACF70  lw    $a2, 0x18($sp)
801ACF80  jal   0x801abf94           ; rows 2.. , same key
801ACFB0  addiu $s5, $s5, -6
801ACFB4  bgtz  $s5, 0x801acf54
```

Row count `2 + ceil((nnnn - 2) / 6)` = our `ceil((nnnn + 10) / 6)`. And there is
no special case anywhere: the descriptor is decrypted with the payload key like
every other row. That is the bug this exposed in xpcrypt - see `br.txt`.

(Trivia: the *list walker*, at `0x801ACD30` in the same function, computes the
type 5 row count it skips as `((hi & 0xF) << 8) | (lo + 5)` - an `or` where the
stager uses `add`. It miscounts when `lo + 5` carries into bit 8, which needs
`lo >= 0xFB`, *and* the carry is lost, which needs an odd `hi`; an even `hi` gives
the same answer either way. A genuine firmware bug, and a narrow one.)


## 8. Validating the reading

Never trust a hand-read routine. Port it and test it against known plaintext.

`romcrypt.py` is a line-by-line transcription of everything above. Three tests,
in increasing strength:

1. **Known plaintext.** `pb.enc` is a Supercode stored with payload key 6 in one
   ROM; `pb.clear` is the same cheat stored in the clear in another. The port
   reproduces all 30 payload rows.
2. **Differential.** Run every one of the 8903 codes in the three databases
   through both the model and `xpcrypt`, and *classify* the differences instead
   of just counting them:

   ```
   178  default-off bit   (by design)
    20  route gap         (by design)
     1  payload MISMATCH  <- the real bug
   ```

   One line out of 8903. That is what a differential test buys you: without the
   classification it would have drowned in the 198 expected differences.
3. **Round trip against the ROM.** After the fix, `xpcrypt -e 6` applied to the
   decrypted Rayman Megacode reproduces the 14 lines byte for byte as they are
   stored in `xteng.dec`. Encrypting back to the original bits is the strongest
   statement available.


## 9. Transferable checklist

* Establish the load address before reading a single instruction.
* Map first (density, magic strings), read second.
* Decode word-aligned; never let a disassembler resync on data.
* Search for constants in *every* form they can take: literal, two's complement,
  folded into a neighbouring mask, or in a data table.
* When a search fails three times, the thing you are looking for is probably
  behind a decompressor.
* Read delay slots as part of the preceding instruction.
* A jump table is a specification. Prefer it to any inference from samples.
* Port what you read into a testable model, then attack it with known plaintext
  and a classified diff.
* Before trusting that a format is standard, count what each opcode buys. A
  design nobody profiled - opcodes that save 60 bytes out of 45 KB - is a house
  format, whatever it resembles.
* A decompressor is a specification, and it hands you an encoder for free: any
  stream it accepts is valid, and yours need not resemble the original.
* Vanity strings in a binary are often load-bearing (`"Wayne Hugh"` as an XOR
  mask, `"WHBX"` and `"FCD!"` as cipher seeds, `"WB123"` as addends).


## 10. The Xplorer FX, and how to prove two firmwares agree

The FX ROMs (V3.20 `english.dec`, V4.52 `v452d.rom`) resisted the whole method
above: no `COMP01` anywhere, none of the constant tables, no game names. The
conclusion recorded at the time — "the FX ROMs use a different container" — was
wrong, and worth dwelling on, because the mistake is a common one: **a failed
search for a magic string proves nothing about the format.** It only proves the
bytes are not there *in that form*.


### 10.1 Read the boot stub instead of searching

The lesson from §2 applied again: when three searches fail, stop searching and
find the code that does the loading. On an FX ROM that code is not hidden at
all — ROM offset `0x100` is plain MIPS, because something has to run before
anything is unpacked. Twenty instructions in:

```
9F000150  3C041F06   lui   $a0, 0x1f06
9F000154  34840001   ori   $a0, $a0, 1
9F000158  A0800000   sb    $zero, ($a0)      ; 0x1F060001 = 0, bank select
9F00015C  3C049F01   lui   $a0, 0x9f01
9F000160  2484D2D0   addiu $a0, $a0, -0x2d30 ; a0 = 0x9F00D2D0   packed blob
9F000164  3C058001   lui   $a1, 0x8001       ; a1 = 0x80010000   where it goes
9F000168  3C069F04   lui   $a2, 0x9f04
9F00016C  24C64378   addiu $a2, $a2, 0x4378  ; a2 = 0x9F044378   end of blob
9F000170  0FC03038   jal   0x9F00C0E0        ; unpack
9F000174  00000000   nop
9F000178  3C028001   lui   $v0, 0x8001
9F00017C  0040F809   jalr  $v0               ; and run it
```

That is the load address, the source range and the unpacker, for free. Note the
`jal` target: `0x0FC03038`, target field `<< 2` combined with the top nibble of
the *delay slot's* PC — `0x9F000174 & 0xF0000000 | 0x0F00C0E0` = `0x9F00C0E0`.


### 10.2 The descrambler

```
9F00C0E4  24090099   addiu $t1, $zero, 0x99   ; key   = 0x99
9F00C0E8  24880004   addiu $t0, $a0, 4        ; src   = blob + 4   (4 bytes skipped)
9F00C0EC  3C0B8010   lui   $t3, 0x8010        ; out   = 0x80100000 (scratch)
9F00C0F0  240A0006   addiu $t2, $zero, 6      ; state = 6
9F00C0F4  00C86023   subu  $t4, $a2, $t0      ; n     = end - src
                                     ; loop, once per byte:
9F00C124  91060000   lbu   $a2, ($t0)         ; b     = *src
9F00C12C  31430007   andi  $v1, $t2, 7        ; state & 7          <- OLD state
9F00C130  25240005   addiu $a0, $t1, 5        ; key'  = key + 5
9F00C134  01441026   xor   $v0, $t2, $a0      ; state ^ key'
9F00C138  244A0001   addiu $t2, $v0, 1        ; state'= that + 1
9F00C140  01A31823   subu  $v1, $t5, $v1      ; 8 - (state & 7)    (t5 = 8)
9F00C144  30630007   andi  $v1, $v1, 7
9F00C148  00C93026   xor   $a2, $a2, $t1      ; b ^= key           <- OLD key
9F00C150  00621004   sllv  $v0, $v0, $v1      ; \
9F00C154  00021A02   srl   $v1, $v0, 8        ;  | rotate left by v1
9F00C158  00623025   or    $a2, $v1, $v0      ; /
9F00C15C  A1660000   sb    $a2, ($t3)         ; *out++ = b
9F00C16C  00804821   move  $t1, $a0           ; key = key'   (delay slot!)
```

Two things a careless reading gets wrong. The XOR uses the key from *before* the
update (`$t1`, updated in the branch's delay slot at the very bottom), while the
state update uses the key from *after* (`$a0`). And `sllv`/`srl 8`/`or` on a
value already masked to 8 bits is a rotate, not a shift — the `sb` truncates.

Neither `$t1` nor `$t2` is ever masked to 8 bits; they run away as 32-bit
values. Only `$t1`'s low byte reaches the XOR, but `$t2` feeds back into itself,
so a model has to keep all 32 bits. `fxunp.descramble` does. (Ninth pass: it does
not have to. XOR and `+ 1` only ever carry upwards, so the low three bits of the
state - all the rotate reads - depend on nothing but the low three bits of the
state and the key. Masking both to a byte gives the same output; keeping 32 bits
is harmless, not necessary.)

Then the payoff:

```
9F00C170  3C068010   lui   $a2, 0x8010
9F00C174  3C048010   lui   $a0, 0x8010        ; src = the descrambled scratch
9F00C178  0FC000A3  jal   0x9F00028C          ; a1 still = 0x80010000
9F00C17C  01863021   addu  $a2, $t4, $a2
```

and `0x9F00028C` reads ten header bytes, XORs them against `0x9F000544`, and
picks four escape codes out of the result — §4, verbatim. The FX container *is*
COMP01. One `print` confirms it:

```
$ python -c "import fxunp; print(fxunp.descramble(open('roms/english.dec','rb').read(),0xD2D0,0x44378)[:16])"
b'COMP01\xa3\x9a\x9c\x95\x00\x04\xc1\xf4'
```

`0x0004C1F4` bytes declared, `0x0004C1F4` bytes produced. Everything from §5 on
then applies unchanged, and both FX images give up `" WB123"`, `"WHBX"`, `"FCD!"`
and a 244-entry jump table with the same four gaps.


### 10.3 Don't diff instructions, diff behaviour

The obvious next step — diff the routine against the V2 one — is a trap. It
reports four routes differing, all of it noise:

* the constant tables are reached through KSEG0 (`0x8005xxxx`) in FX and KUSEG
  (`0x001Cxxxx`) in V2, so every `lui` differs;
* V2 shares one copy of the `dst[0] = src[0] & 0xF0` tail between keys 4, 5
  and 6 (the first two `j` to the end of key 6) and inlines a second into key
  7, where the checker call follows it; FX jumps to one copy from all four;
* the one call the routine makes besides `strncpy` sits at the top of a route
  in FX and at the bottom in V2.

A canonicalising diff (`fxcmp.py`) shrinks this but cannot eliminate it, because
the difference is real — it is just not a difference in *meaning*. At that point
the honest move is to stop reading and start executing.

`fwemu.py` is a MIPS I interpreter, about 120 lines when this was written (under
300 now, with what the engine work added): the ~30 opcodes this routine
uses, correct branch-delay semantics via the standard `pc`/`npc` pair, and the
four unaligned `lwl/lwr/swl/swr` — needed because that is how `" WB123"` gets
onto the stack. Memory is two segments, the image at its own base and 1 MB of
scratch; **anything else raises**, so a wrong guess about the map surfaces
instead of quietly reading zero.

Two calls get stubbed, and the second one is instructive. It takes no pointer to
either buffer (`f(0x1F000000, 0x18000)` in V2, `f(6, 0x18000)` in FX), so it
*should* be irrelevant — but "should" is not evidence. Two things turn it into
evidence: in the Xplorer Pro firmware that function is literally `jr $ra; nop`,
an empty function; and the emulator, with the stub in place, decrypts the
known-plaintext Supercode 30/30 on all five images available at that point —
and on all nine once the rest turned up (§10).

Then just run everything against everything:

```
$ uv run --with capstone python fxtest.py
   1536 codes x 17 key settings
   romcrypt.py (the model) 0 disagreement(s)
   Xplorer FX V3.20        0 disagreement(s) vs Xplorer V2.008 UK
   Xplorer FX V4.52        0 disagreement(s) vs Xplorer V2.008 UK
```

26,112 code/key combinations per image. The FX carts decrypt cheat codes exactly
the way the V2 carts do — and `XP_KEYED_TYPES = 0xABFB` holds for all five, which
is what makes the route table in `xp_crypto.c` safe rather than lucky.


### 10.4 One bug worth keeping

The first run of the comparison crashed on an index of `-4`. The route for a
given first byte is `table[(first & 0xF7) - 4]`, and I had picked `0x08` as the
representative "type with no key" — but `0x08 & 0xF7` is `0`, because the mask
exists precisely to clear bit 3. Python indexed from the end of the table and
compared the wrong route.

The firmware gets this right, and it is worth seeing how:

```
8003070C  2443FFFC   addiu $v1, $v0, -4
80030710  2C6200F4   sltiu $v0, $v1, 0xf4     ; unsigned!
80030714  10400009   beqz  $v0, <default>
```

`sltiu` is unsigned, so `-4` is `0xFFFFFFFC`, comfortably `>= 0xF4`, and every
first byte that masks to below 4 - `0x00`-`0x03`, and `0x08`-`0x0B` with bit 3
cleared - takes the default route through the *same* bounds check that catches
the top end. One comparison, both ends. A signed compare there would have been a
jump through a table entry at a negative offset. (`0x04`-`0x07` and `0x0C`-`0x0F`
are in range: they are type 0 codes with keys 4-7 and go through the table like
any other.)


### 10.5 Asking the binary where its data lives

The FX databases had been "not located" for a session, on the strength of a
string search: no game names in the ROM, therefore no database. That is the §2
mistake again, and the fix is the same — ask the code, not the bytes.

The question "where does this firmware keep its codes?" has a mechanical answer:
**every ROM address the firmware can reach, it has to build with a `lui`**, so
collect them all and look at which 4K pages come out (`fxdb.py`).

```
xteng.dec    0x00000 0x22000 0x23000 0x25000 0x60000
english.dec  0x00000 0x40000 0x60000 0x7F000 0x80000
v452d.rom    0x00000 0x3F000 0x40000 0x60000 0x7F000 0x80000
```

V2 names `0x23000`, the database header (`*(ROM + 0x7C)`), and `0x25000`, where
`db2.py`'s record chain begins, plus `0x22000`, a second executable module it
`jalr`s into. (`0x60000` in every image is the cartridge control port at
`0x1F060000`, not flash.) FX names `0x7F000` and `0x80000`, and **both are past
the end of the dump files** (`0x4D4CF` and `0x60000`). Reading the code there:

```
8003BEEC  lui   $v1, 0x1f07 ; ori $v1, 0xfff8    ; descriptor at 0x1F07FFF8
8003BEF4  lui   $v0, 0x1f08                      ; region ends at 0x1F080000
8003BF04  sw    $v0, -0x71d8($at)                ; both stashed as globals
...
8003BF50  subu  $v0, $v0, $s0                    ; size = 0x80000 - firmware_end...
```

`0x1F080000` is the top of the PSX expansion window — 512 KB. The FX keeps codes
in flash up there, behind an 8-byte descriptor; the three V2 firmwares name that
address zero times. So the missing databases were never encrypted, compressed or
cleverly encoded. **The dumps are simply short.** No further reverse engineering
of these two files can produce them.

> **Superseded (ninth pass).** Every sentence of that conclusion is wrong. The FX
> databases are in the dumps, and they *are* compressed. The version header the
> self-destruct reads, `*(ROM + 0x7C)` = `0x9F001500`, holds at `+0xB8` a pointer
> to a container just past the scrambled firmware - `0x9F044400` in `english.dec`.
> It is an 8-byte header (packed size, unpacked size, little-endian) and then
> 14-bit LZW codes, MSB first, the dictionary starting at 256, `0x3FFF` for the end
> and no clear code. The firmware's own decompressor is `0x80025E80` in
> `english.dec`. Decoded, it gives exactly the declared size - `0xCC34` bytes for
> 3.20, `0xDE5F` for 4.50, `0xCC06` for both 4.52 builds - and a record chain that
> starts `"A-Train"` and ends `FF FF FF FF`. The packed sizes end exactly at the end
> of the three `.fcd` images; in `v452d.rom` the container ends at `0x493A5`.
>
> What `0x1F07FFF8` is: free flash above that database, behind a bank switch. The
> FX flash accessors (`0x8001EF3C` in `v452d.rom`) treat `0x1F000000`-`0x1F07FFFF`
> as a flat 512 KB, and reach offsets from `0x60000` up through the
> `0x1F040000`-`0x1F05FFFF` window after writing `0x21` to `0x1F060001`. So the
> CPU never puts `0x1F07FFF8` on the bus, and "past the end of the dump" is true
> only of that flat address. The formula's "firmware_end" is the container
> pointer, and its `n` is the packed size.
>
> The page scan missed it because the firmware never builds the container's
> address with a `lui`: it reads it out of a pointer slot in data. That breaks
> the checklist rule below as stated, and it is the §2 mistake one level up - a
> claim about a search, written down as a claim about the file.

Knowing *why* a search fails is worth as much as the search succeeding, and it
costs one scan over the `lui` immediates - provided the scan can see the thing.
This one could not.


### 10.6 Nine firmwares, and a base address that lied

Four more ROMs turned up on the vendor's own site through the Wayback Machine
(`xtger` 2.0081, `xtjpro` 2.14, a second `english` that is really a 4.52, and
`german` 4.50), taking the corpus to nine firmwares in three languages — and
two more V2 databases, which lifted the differential test from 8903 real code
lines to 13205 with the database locator used at that stage. All nine agree,
`XP_KEYED_TYPES = 0xABFB` throughout.

The `-x` extraction work later exposed one more framing error. Name bytes 1-7
are abbreviations in both game and cheat names; accepting them only in cheats
made `db2.py` reject an early game and resume at a printable suffix. Starting at
the first record after the erased-flash run recovers the complete chains at
`0x25000` or `0x2B000`: 15,349 lines in 11,718 cheats, 2,144 more lines than the
suffix scan. Same lesson as the load-address bug below: choose a boundary the
format establishes instead of scoring plausible content inside it.

Getting there meant dropping two file-name tables and detecting everything from
the bytes. The load address is the interesting half. The obvious approach —
every `lui`/`addiu` pair that names one of the three constant tables votes for a
base, best score wins — works on eight of the nine and quietly picks a base
`0x1000` too low on the German V2, because that image carries what look like
**two** sets of table references, and the vote ties. (Only one set is real; see
the ninth-pass note at the end of this section.)

The symptom was worth reading properly: the jump table said the default route
was at `0x1AC2B4`, but the dispatcher branched to `0x1AB2B4`. When two things
that must agree differ by exactly a round number, the frame is wrong, not the
code. And the fix is right there — those two *are* the same thing, so

```
base = table[(0x24 & 0xF7) - 4] - <branch target, disassembled at base 0>
```

is not a vote at all, it is an equation. Validate by requiring all 244 entries to
land inside the image. Derive the frame from something that must hold, rather
than scoring candidates and hoping the margin is real.

The same lesson applies one level up: `fwemu` used to find the routine's *extent*
by scanning to the next `jr $ra` and collect the calls inside it. The German
firmware seemed to put its routes 0x1000 bytes away from the dispatcher, so that
swallowed unrelated functions and found 17 call targets instead of 2. (Ninth pass:
not so. Read at the right base, the German routes follow the dispatcher directly,
exactly as in 2.008. The 0x1000 came from the wrong base, and the "second set" of
table references is `lui`/`addiu` pairs naming `"Here1!!"`-style debug strings that
happen to sit 0x1000 below the tables - `0x1BEB84`, `0x1BEB8C`, `0x1BEB94` against
`0x1BFB84`, `0x1BFB8C`, `0x1BFB94`. In `xtger.dec` the routine runs from `0x1ABF98`
to its first `jr $ra` at `0x1AC41C`, routes included.) A routine reached through a
jump table has no contiguous extent to find. Classifying each callee at
the moment control actually reaches it needs no extent at all — and it prints
what it stubbed, so the assumption stays checkable.


### 10.7 What this adds to the checklist

* A failed magic-string search proves the bytes are not there *in that form* —
  nothing more. Find the loader instead.
* The first unpacked bytes of any ROM are the boot stub, and a boot stub has to
  name the load address, the source range and the unpacker in the clear.
* Read the delay slot at the bottom of a loop before deciding which value an
  operation used — `move $t1, $a0` down there means the XOR above it saw the
  *old* key.
* When two builds of the same routine differ only in scheduling, a diff will
  never converge. Emulate and compare outputs.
* Stub a call only when you can point at evidence it does nothing. "It doesn't
  receive the buffer" is an argument; an empty implementation in a sibling
  firmware, plus a known-plaintext check, is evidence.
* To find where a firmware keeps something, collect every address it builds with
  `lui` and bucket them into pages. Code cannot reach data without naming it -
  but it can name it through a pointer stored in other data, which no `lui` scan
  sees. The FX database is reached that way (§10.5); follow the pointer slots too.
* "Not found" is a claim about your search, not about the file. Turn it into a
  claim about the file — here, that the address the firmware uses lies past the
  end of the dump — or say plainly that you do not know. (§10.5 did the first and
  was wrong: the address it found was not the one the codes live at.)
* Derive a load address from an identity that must hold, not from a vote between
  candidates. A tie you never notice is worse than no answer.
* When two values that must agree differ by a round number, suspect the frame.
* A routine reached through a jump table has no contiguous extent. Do not compute
  one; resolve what you need at the point control reaches it.


## 11. The call I dismissed: a self-bricking copyright check

The decrypt routine calls exactly two functions. One is `strncpy`. I stubbed the
other, wrote "it gets neither the source nor the destination, so it cannot touch
the result", proved that empirically with known plaintext, and moved on. That
reasoning was sound and the stub was safe — but "cannot affect *this output*" is
not "does nothing", and I let the second sentence stand in for the first. It is
the nastiest thing in the ROM.


### 11.1 Reading it

`f(0x1F000000, 0x18000)`, `0x1A4620` in `xteng.dec`:

```
001A4644  8E51007C  lw    $s1, 0x7c($s2)     ; s1 = *(u32*)(ROM + 0x7C) = 0x1F023000
001A4648  3C04001D  lui   $a0, 0x1d          ; \  a0 = 0x1CB8EC
001A464C  2484B8EC  addiu $a0, $a0, -0x4714  ; /
001A4650  0C069104  jal   0x1a4410           ; v0 = strlen(a0) + 1 - it counts the NUL
001A4658  2442FFFF  addiu $v0, $v0, -1       ; 15 - 1 = 14
001A465C  0202102B  sltu  $v0, $s0, $v0
001A4660  1040000F  beqz  $v0, 0x1a46a0      ; i >= 14 -> done, no complaint
001A4668  3C01001D  lui   $at, 0x1d          ; \
001A466C  00300821  addu  $at, $at, $s0      ;  | v0 = masked[i]
001A4670  9022B8EC  lbu   $v0, -0x4714($at)  ; /
001A4674  92230000  lbu   $v1, ($s1)         ; v1 = database[i]
001A4678  00021027  nor   $v0, $zero, $v0    ; unmask: ~masked[i]
001A467C  304200FF  andi  $v0, $v0, 0xff
001A4680  14430004  bne   $v0, $v1, 0x1a4694 ; mismatch -> punish, immediately
001A4684  240403E8  addiu $a0, $zero, 0x3e8  ; (delay slot) src = 0x3E8
001A4688  26310001  addiu $s1, $s1, 1
001A468C  08069192  j     0x1a4648
001A4690  26100001  addiu $s0, $s0, 1
001A4694  02402821  move  $a1, $s2           ; dst = 0x1F000000
001A4698  0C068D79  jal   0x1a35e4           ; flash_write(0x3E8, 0x1F000000, 0x18000)
001A469C  02603021  move  $a2, $s3           ; len = 0x18000
```

The `nor $zero, $v0` is the tell. A string you have to NOT before comparing is a
string someone did not want found:

```python
>>> bytes(~b & 0xFF for b in img[0x2B8EC:0x2B8FA])
b'(C) 1997/8 FCD'
```

And `*(u32*)0x1F00007C` is `0x1F023000` — the header of the cheat database, the
one `db2.py` walks past to reach the game names.

All 14 characters are compared, not 13. This note used to read the `- 1` as
"stop one short of the string", which is what it would mean after a real
`strlen`. But `0x1A4410` starts its count at 1 and counts the terminator too, so
the `- 1` only takes that back. Executed: on `xteng.dec`, changing header byte 13
sets it off, and byte 14 does not.


### 11.2 What `0x1A35E4` does

```
001A365C  3C011F00  lui   $at, 0x1f00
001A3660  A0225555  sb    $v0, 0x5555($at)   ; 0xAA -> 0x1F005555  \
001A3664  24020055  addiu $v0, $zero, 0x55   ;                      | JEDEC unlock
001A3670  A0222AAA  sb    $v0, 0x2aaa($at)   ; 0x55 -> 0x1F002AAA  /
001A3678  16620002  bne   $s3, $v0, 0x1a3684 ; chip type from 0x1A3444
001A367C  240200A0  addiu $v0, $zero, 0xa0   ; 0xA0 = byte program
```

That is a flash programmer, and the loop under it reads

```c
flash_write(const u8 *src /*s4*/, u8 *dst /*s5*/, u32 len /*s7*/)
{
    for (i = 0; i < len; i++) {
        if (dst[i] == src[i]) continue;         /* already right, skip */
        i &= page_mask;                         /* 0xFFFF80 or 0xFFFF00 */
        unlock(); command(0xA0);
        do { *dst++ = *src++; i++; } while (dst & page_size);
        delay(500); wait_ready();
    }
}
```

The cart uses it legitimately elsewhere — `flash_write(buf, 0x1F022600, 0x10)`
saves settings. Pointed at `(0x3E8, 0x1F000000, 0x18000)` it programs 96 KB over
the boot stub and the packed firmware, sourced from `0x3E8`: low PSX RAM, not a
staged image - kernel RAM up to `0xFFFF`, then on into user RAM to `0x183E7`,
which on an FX cart is the running firmware itself (loaded at `0x80010000`). `s4`
really is a source pointer, not a count — it is dereferenced two instructions
into the loop.


### 11.3 When it fires

Not on every decrypt. Each generation wires the check into one key - key 7 on
V2, plus the Special32 route, and key 4 on FX - which you can measure by
clearing the stub cache between calls and seeing which first bytes reach it.
(This used to say "exactly one route", against its own table.)

| firmware | fires while decrypting |
|---|---|
| Xploder V2 2.004, Xplorer 2.005 / 2.008 / 2.0081 / 2.14 | a **key-7** code, or `32`/`82` (Special32) |
| Xplorer FX 3.20 / 4.50 / 4.52 | a **key-4** code |
| Xplorer Pro 2.20 | never — the callee is emptied to `jr $ra; nop`, the two calls to it remain |

Never on a payload row, never on an unencrypted code. A check that ran on every
code would be easy to notice and easy to correlate with the damage; one that runs
on a single key is not.

One build does not need the header touched. Pro 2.14 compares
`"(C) 1997/8 FCD"` against its own header, which already reads
`"(C) 1997-9 FCD  "`, and mismatches at index 8. So on a stock 2.14 cart the first
key-7 or Special32 code a user activates - typed in or uploaded - programs the
96 KB. Nothing it ships does that: the decrypt runs over the cheats a user turns
on, and all 1,826 rows of its own database carry key nibble 0, so every one takes
the copy route. `selfdestruct.py` executes it.


### 11.4 The FX version is harder on purpose

`0x80024BE8` makes no direct calls and contains no obvious compare loop, which is
why it reads as a table-builder at a glance. It:

* stages the masked string (`"(C) 1997-9 FCD  "`, XOR `0xEB`) onto the stack with
  `lwl`/`lwr` instead of reading it in place, together with two code pointers,
  `0x80017384` and `0x8001EDBE`;
* walks an index list stored right after the string — `0, 1, 2, 12, 11, 13, -1`,
  i.e. `"(C)"` and `"FCD"`, deliberately out of order — so no contiguous compare
  over a string ever appears;
* counts mismatches instead of bailing on the first;
* and calls the punisher indirectly, through the staged pointer **plus `0x66`**:

```
80024CD8  384200EB  xori  $v0, $v0, 0xeb     ; unmask the database byte
80024CDC  1062FFF6  beq   $v1, $v0, 0x80024cb8
80024CE8  24A50001  addiu $a1, $a1, 1        ; count the mismatch
80024CEC  10A00006  beqz  $a1, 0x80024d08    ; all six matched -> return
80024CF0  240403E8  addiu $a0, $zero, 0x3e8  ; (delay slot) src = 0x3E8 again
80024CF4  8FA20024  lw    $v0, 0x24($sp)     ; staged pointer 0x8001EDBE
80024CFC  24420066  addiu $v0, $v0, 0x66     ; -> 0x8001EE24
80024D00  0040F809  jalr  $v0                ; no xref names the target
```

`0x8001EE24` masks its destination with `0x7FF80` and programs the same `0x18000`
bytes from the same `0x3E8`. The staged base `0x8001EDBE` is not a function start
and is not even word-aligned — it only becomes one after the `+ 0x66`. (A
decompiler that propagates constants - Ghidra's does - resolves the call anyway;
it is a plain `xref` that comes up empty.) The destination it is handed is `6`,
which the mask turns into `0`.

`fxprot.py` finds the string, the mask and the index list in any of the nine ROMs.

Not executed, for obvious reasons: this is a static reading. It is a
well-supported one — the argument registers, the dereference of `s4`, and the
legitimate `flash_write(buf, 0x1F022600, 0x10)` call site all corroborate — but I
have not watched a cartridge destroy itself. (Since then `selfdestruct.py` has
executed it under an emulator with the flash modelled, on all ten images, and the
ninth pass did it again under unicorn. Still no cartridge.)


### 11.5 What this adds to the checklist

* "It cannot affect the output I am looking at" and "it does nothing" are
  different claims. Stub on the first, but do not write down the second.
* A constant that has to be transformed before use — NOTed, XORed, assembled on
  the stack — is a constant someone hid. Follow it.
* Grep the binary for its own vendor strings *under every single-byte mask*, not
  just as plaintext. Two of the nine ROMs' most interesting strings are invisible
  to `strings`.
* An indirect call through a pointer plus an odd displacement is not compiler
  output. Neither is an out-of-order index list over a string.
* When a routine's behaviour differs across builds of the same product, diff the
  builds: the one where a check is *missing* tells you what the check was.
