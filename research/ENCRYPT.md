# The encrypt side of the code cipher, and where it lives

The question this answered: `xp_encrypt_code()` and `xp_encrypt_block_line()`
were written as the algebraic inverse of routines read out of the cartridge, and
the cartridge has no encrypt side to check them against. `oracle_test.py` can
only ask whether the firmware decrypts back what xpcrypt encrypted, which leaves
every choice the round trip cannot see resting on xpcrypt's own inverse being the
intended one. Is there a real encrypter anywhere?

Short answer: **yes, and it is the vendor's own.** `XLink.exe`, the DOS upgrade
and trainer utility, holds one function at `0x297B0` with an eight-way method
table that encrypts all four code keys and both Supercode/Megacode payload keys -
the direction the cartridge never had. Executed, it produces exactly what
`xpcrypt -e` produces, byte for byte, over 3,000 codes. A third party's tool,
`x-killer.exe`, has keys 6 and 7 in *both* directions and computes them from the
same closed forms `crypto.c` uses rather than from the firmware's sliding
windows. Neither Windows build has a code cipher at all.

`FCD.md` is about the other cipher in these same four binaries - the whole-image
`.fcd` transform - and section 4 of it has where the files come from. This one is
the *code* cipher of `REVERSING.md` and `romcrypt.py`. `xlink.py` finds the first;
`xcode.py`, added here, finds this one.


## The findings that matter

**1. The encrypt side exists, in `XLink.exe`, once.** One function, `0x297B0`,
Watcom register convention: `eax` = source, `edx` = destination, `ebx` = a method
index that is *not* the key nibble. Eight methods, of which six are ciphers:

| method | address | what it computes | xpcrypt |
|---|---|---|---|
| 0 | `0x297EA` | copy six bytes | - |
| 1 | `0x29808` | code key 4 encrypt | `xp_encrypt_code(.., XP_KEY_4)` |
| 2 | `0x29882` | code key 5 encrypt | `.., XP_KEY_5` |
| 3 | `0x298B0` | code key 6 encrypt | `.., XP_KEY_6` |
| 4 | `0x298DE` | code key 7 encrypt | `.., XP_KEY_7` |
| 5 | `0x29800` | nothing at all | - |
| 6 | `0x29956` | payload key 6 encrypt | `encrypt_payload(.., 6)` |
| 7 | `0x29992` | payload key 7 encrypt | `encrypt_payload(.., 7)` |

**2. It is the firmware's own arithmetic, not xpcrypt's.** The DOS tool slides
the same windows over the same three seed strings the cartridge does - `"WHBX"`
at `0x46F04`, `"FCD!"` at `0x46F09`, `" WB123"` at `0x4B470`, each referenced
exactly once, and each from inside this function. The cartridge keeps them at
`0x1BF29C`, `0x1BF2A4` and `0x1BF294`. `crypto.c` carries the closed forms
instead, which is why its key 4 says `0x25` where both of these say
`'W' + 0x38 + 'H' + ('B' ^ 0x12) + ('X' | 0xEE)`.

**3. `x-killer.exe` is the closed forms, from a stranger, in 1999.** Four
routines, `cdecl(src, dst)`: key 6 and key 7, encrypt and decrypt each. Its key 7
is `crypto.c`'s expression instruction for instruction, down to writing
`add al, 0x0B` for the C's `-= ... + 0xF5` - the same byte, signed the other way.
It is by Tim
Schuerewegen, not FCD, and it sits directly after the two `.fcd` routines
`FCD.md` found in the same binary.

**4. The Windows builds have none.** 1,491 and 1,492 functions probed by
execution, none of them any of the sixteen transforms; and no constant set that
would let one exist (section 5).

**5. Three implementations, three answers on byte 0** - and they agree wherever
it matters (section 3).

**6. Nothing anywhere implements Special32/33.** The `0x32`/`0x82` and
`0x33`/`0x83` routes of `REVERSING.md` 6.7 have no encrypter in any of the four
binaries, so the note in `crypto.c` about them stands unchanged: still no
authority, still deliberately unimplemented.


## 1. The DOS tool's routine

The prologue copies the key 5 table onto the stack and clears the destination,
and the way it clears it is the firmware's habit rather than a compiler's:

```
000297B7  89c5             mov ebp, eax           ; src
000297B9  89d1             mov ecx, edx           ; dst
000297BB  895c2410         mov [esp+0x10], ebx    ; method
000297BF  89e7             mov edi, esp
000297C1  8d4201           lea eax, [edx+1]
000297C4  be70b40000       mov esi, 0x4b470       ; " WB123"
000297C9  83c206           add edx, 6
000297CC  a5               movsd                  ; seven bytes of it,
000297CD  66a5             movsw                  ;   onto the stack
000297CF  a4               movsb
000297D0  c60000           mov byte ptr [eax], 0  ; dst[1..5] = 0
000297D3  40               inc eax
000297D4  39d0             cmp eax, edx
000297D6  75f8             jne 0x297d0
000297D8  8b542410         mov edx, [esp+0x10]
000297DC  83fa07           cmp edx, 7
000297DF  771f             ja 0x29800
000297E1  89d0             mov eax, edx
000297E3  ff248588970200   jmp dword ptr [eax*4 + 0x29788]
```

It clears **bytes 1 to 5 of the destination and not byte 0**, which is exactly
what the cartridge's decrypt does at `0x1ABFE0`-`0x1ABFF4` in `xteng.dec`; and method 5 then returns
without writing anything else, leaving that row of zeros - which is what the
cartridge does for a payload key it does not implement. Two ends of the same
codebase.

The jump table is at `0x29788`, immediately above the function, and every entry
in it is a load-time fixup: read out of the file each entry holds only its target's
offset within the object (`0x197EA`...`0x19992`), so unfixed the dispatch lands
`0x10000` below the real target (ninth pass; this used to say "eight zeros"). `xcode.py` applies the
LE fixup section for this reason - `xlink.py` deliberately does not, because the
`.fcd` routines need no relocation and an unfixed image is what lets a data
reference be found by searching for its offset within its object.

### Key 4, and the window

```
00029808  be046f0000       mov esi, 0x46f04       ; "WHBX", copied to [esp+8]
...
00029834  8a442409         mov al, [esp+9]        ; w1
00029838  8a542408         mov dl, [esp+8]        ; w0
0002983C  0438             add al, 0x38
0002983E  00d0             add al, dl             ;      (w1 + 0x38) + w0
00029840  8a64240a         mov ah, [esp+0xa]      ; w2
00029844  80f412           xor ah, 0x12
00029847  00c4             add ah, al             ;    + (w2 ^ 0x12)
00029849  8a44240b         mov al, [esp+0xb]      ; w3
0002984D  0cee             or  al, 0xee
0002984F  00c4             add ah, al             ;    + (w3 | 0xEE)
00029851  8a06             mov al, [esi]          ; the plaintext byte
00029853  8844240c         mov [esp+0xc], al      ;   ... into the window
00029857  30e0             xor al, ah
00029859  8807             mov [edi], al          ; the ciphertext byte
0002985B  31c0             xor eax, eax           ; slide w0..w3 <- w1..w4
0002985D  40               inc eax
0002985E  8a540408         mov dl, [esp+eax+8]
00029862  88540407         mov [esp+eax+7], dl
00029866  83f804           cmp eax, 4
00029869  7cf2             jl 0x2985d
0002986B  46               inc esi
0002986C  47               inc edi
0002986D  39de             cmp esi, ebx
0002986F  75c3             jne 0x29834
```

`romcrypt.py`'s decrypt is the same four terms with the first two written the
other way round, and the same slide. The one thing worth reading twice is what
goes into the window: **the plaintext byte, in both directions**. Decrypting,
that is the byte just produced; encrypting, it is the byte just consumed. That
is the whole reason a five-round chain over its own output inverts at all, and
seeing the encrypter do it settles that it was intended rather than incidental.

Key 7 at `0x298DE` is the mirror: `"FCD!"`, `+ 0x76`, `^ 0xEF`, `& 0x73`, walking
from byte 5 down to byte 1, and subtracting where key 4 xors.

Key 5 is the table on the stack:

```
0002988D  8a16             mov dl, [esi]          ; src[i]
00029890  8a3404           mov dh, [esp+eax]      ; " WB123"[i]
00029894  28f2             sub dl, dh
```

and key 6 is two instructions:

```
000298BB  8a16             mov dl, [esi]
000298BE  30c2             xor dl, al             ; ^ i
000298C1  80c255           add dl, 0x55           ; crypto.c writes - 0xAB
```

### The payload routes

Payload key 6, at `0x29956`, is `encrypt_payload()` case 6 line for line,
including the two places a destination byte is used as an input to a later one:

```
00029956  8a4501           mov al, [ebp+1]
00029959  0434             add al, 0x34
0002995B  8801             mov [ecx], al          ; dst[0] = src[1] + 0x34
0002995D  8a4500           mov al, [ebp]
00029960  34ff             xor al, 0xff
00029962  884101           mov [ecx+1], al        ; dst[1] = ~src[0]
00029965  8a4505           mov al, [ebp+5]
00029968  8a21             mov ah, [ecx]
0002996A  00e0             add al, ah
0002996C  884102           mov [ecx+2], al        ; dst[2] = src[5] + dst[0]
0002996F  8a5101           mov dl, [ecx+1]
00029972  8a4503           mov al, [ebp+3]
00029975  30d0             xor al, dl
00029977  884103           mov [ecx+3], al        ; dst[3] = src[3] ^ dst[1]
0002997A  8a4502           mov al, [ebp+2]
0002997D  041b             add al, 0x1b
0002997F  884104           mov [ecx+4], al        ; dst[4] = src[2] + 0x1B
00029982  8a4504           mov al, [ebp+4]
00029985  0455             add al, 0x55
00029987  884105           mov [ecx+5], al        ; dst[5] = src[4] + 0x55
```

Payload key 7 at `0x29992` is six unrolled copies of `dst[i] = src[5-i] + 0x55`.

### Who calls it

`0x299D0` wraps it for callers that hold a code as a 4-byte address and a 2-byte
value: byte-swap both halves, call, byte-swap back. Its five callers are all in
one function at `0x29550`, which walks a list of six-byte codes, notices a `5` or
a `6` in the top nibble of one and treats the codes below it as payload rows, and
takes the key for each from a field of a structure rather than from the code -
so which key a code gets encrypted with is a setting, not a property of the code.
That function references no strings of its own and nothing calls it directly; its
neighbours in `0x29000`-`0x29500` are the ones holding `"$no code"` and
`"Game Name '%s' is too long (by %d characters)"`, which places it on the
cheat-list side of the tool rather than the ROM-upgrade side.

Worth noting for what it does *not* do: neither the routine nor that caller
checks the code's type. `crypto.c` refuses to encrypt a code whose type the
cartridge gives no crypto route (`XP_KEYED_TYPES`), because the cartridge would
run the ciphertext; hand the same code to `0x297B0` and it encrypts it. Whether
anything further up the tool filters those out is not established here - only
that this path does not.


## 2. X-Killer, the same functions from the other side

Four routines, `cdecl(src, dst)`, selected by an inline dispatch at `0x401440`
that maps a UI index of 0 or 1 to key 6 or key 7 and a flag at `[esp+0x80]` to
the direction:

| address | key | direction |
|---|---|---|
| `0x408440` | 6 | decrypt |
| `0x408470` | 6 | encrypt |
| `0x4084A0` | 7 | encrypt |
| `0x408540` | 7 | decrypt |

Key 6 is one loop each way - `(src[i] - 0x55) ^ i` and `(src[i] ^ i) + 0x55` -
and key 7 is fully unrolled in the closed form:

```
004084C5  80c335           add bl, 0x35           ; dst[5] = c5 + 0x35
004084D1  80e373           and bl, 0x73
004084DA  80c235           add dl, 0x35           ; dst[4] = c4 - (c5 & 0x73) + 0x35
004084E5  80f290           xor dl, 0x90
004084F3  80ea5a           sub dl, 0x5a           ; dst[3] = c3 - ((c4 & 0x73)
                                                  ;            - (c5 ^ 0x90) + 0x5A)
0040850D  80eb16           sub bl, 0x16           ; dst[2] = ... + 0x16 + c5
00408523  040b             add al, 0x0b           ; dst[1] = ... + 0xF5 + c4 + c5
0040852A  3407             xor al, 7              ; byte 0
```

`0x0B` and `0xF5` are the same byte with the sign the other way, so this is
`xp_encrypt_code()`'s key 7 exactly. Two things follow. The closed forms are not
xpcrypt's invention - somebody outside the company had them in 1999. And the
`^ key` on byte 0, which `crypto.c` also uses, is not the vendor's spelling of
it (section 3).

X-Killer has no key 4, no key 5 and no payload cipher, which its own UI agrees
with: `"5" : not supported - super code`, `"6" : not supported - mega code`.


## 3. Byte 0

Byte 0 is not ciphertext - it carries the type nibble, the key in bits 0 to 2 and
the "switched off by default" bit 3 - and all three implementations do something
different with it:

| | byte 0 out |
|---|---|
| cartridge, decrypting | `b & 0xF0` - drops the off-by-default bit too |
| `XLink.exe`, encrypting | `(b & 0xF8) \| key` - masks the key bits, keeps bit 3 |
| `x-killer.exe`, either way | `b ^ key` |
| `crypto.c` | `b ^ key`, and refuses the input if bits 0-2 are set |

They agree on every input any of them will accept: a code presented for
encryption has its key bits clear, and on those `(b & 0xF8) | k` and `b ^ k` are
the same value. The difference is only in what happens to a malformed input -
XLink silently masks, xpcrypt returns `-1`. `xcode.py` classifies this by probing
rather than by reading, which is why the routines are identified on bytes 1 to 5
alone.


## 4. Checking it by running it

`xcode.py` executes every routine it finds under Unicorn as a 32-bit x86 process
and requires three things of it:

* **agreement with `romcrypt.py`** - the firmware's own decrypt, transcribed -
  over 128 pseudorandom codes per routine, on bytes 1 to 5;
* for the encrypters, **agreement with `../xpcrypt -e`** over 500 codes per key,
  on all six bytes: 3,000 for the DOS tool, 1,000 for X-Killer;
* and before any of that, the eight encrypt references in `xcode.py` itself have
  to round-trip through `romcrypt.py` on 4,096 codes each, so "the PC tool
  encrypts" is a claim about the cartridge's routine and not about a second
  transcription of it.

```
8 encrypt routines are the inverse of romcrypt.py, checked on 4096 codes each
pc/XLink.exe: LE, 2 segments, 793 functions probed, 6 routines
  000297B0  key4      encrypt watcom_regs sel=1  byte 0 -> (b & 0xF8) | k
  000297B0  key5      encrypt watcom_regs sel=2  byte 0 -> (b & 0xF8) | k
  000297B0  key6      encrypt watcom_regs sel=3  byte 0 -> (b & 0xF8) | k
  000297B0  key7      encrypt watcom_regs sel=4  byte 0 -> (b & 0xF8) | k
  000297B0  payload6  encrypt watcom_regs sel=6  byte 0 -> ciphertext
  000297B0  payload7  encrypt watcom_regs sel=7  byte 0 -> ciphertext
  vs ../xpcrypt -e: 3000 codes, byte for byte
pc/Xlink95-19990702.exe: PE, 4 segments, 1492 functions probed, 0 routines
pc/Xlink95.exe: PE, 4 segments, 1491 functions probed, 0 routines
pc/x-killer.exe: PE, 4 segments, 144 functions probed, 4 routines
  00408440  key6      decrypt cdecl_sd           byte 0 -> b ^ k
  00408470  key6      encrypt cdecl_sd           byte 0 -> b ^ k
  004084A0  key7      encrypt cdecl_sd           byte 0 -> b ^ k
  00408540  key7      decrypt cdecl_sd           byte 0 -> b ^ k
  vs ../xpcrypt -e: 1000 codes, byte for byte
10 routines in 4 binaries out of 3920 functions probed
```

(Each binary also prints a `constants:` line, which is section 5's business.)

**Nothing above was searched for by constant.** The routines are found by taking
every direct call target in the binary, running it with six bytes of input under
each of seven calling conventions, and asking whether what comes out is one of
the sixteen transforms `romcrypt.py` describes. Which convention a routine wants,
which key it is, which direction it goes and - for the DOS tool - which method
index selects it are all outputs of that, not inputs to it.

That matters here more than it did for the `.fcd` cipher, where every build spelled
the addend the same way. A search for `0x76`, `0xEF` and `0x73` finds XLink's key
7 and walks straight past X-Killer's, which computes the same function out of
`0x73`, `0x90`, `0x16`, `0x5A` and `0x35`; there was no reason to expect two
spellings until both were in front of us.

**One gotcha, and it cost an afternoon.** Running thousands of functions that
were never meant to be entered this way means most of them fault, and some faults
leave Unicorn's emulated CPU in a state that writing the registers back does not
clear: after one of those, every later probe faults at its first instruction and
the binary reads as containing nothing. `XLink.exe` reported zero routines for
exactly this reason - the function that poisoned the machine was the *fifth* of
793, so the sweep was dead almost from the start and said so quietly.
`uc.context_restore()` of a context saved before the first probe fixes it
completely, and any sweep of this kind wants it from the beginning.


## 5. Why the Windows builds really are empty

A null result from a search is worth what the search is worth, so this one is
made twice.

**By execution:** 2,983 functions across the two builds, each tried under seven
conventions, none of them any of the sixteen transforms.

**By constants:** a routine can be shaped however the compiler likes, but it has
to spell the numbers. `xcode.py` reports, per binary, the tightest window
containing a complete constant set:

```
pc/XLink.exe             key4 window @0002983D+17, key7 window @0002990E+20,
                         payload6 @0002995A+44, 'WHBX' @00046F04,
                         'FCD!' @00046F09, ' WB123' @0004B470,
                         8 candidate add/sub 0x55 or 0xAB
pc/Xlink95-19990702.exe   key7 window @0042E218+278, 7 candidates
pc/Xlink95.exe            key7 window @0042E288+278, 7 candidates
pc/x-killer.exe           key7 window @0040B436+278,
                          key7 closed @00408577+46, 3 candidates
```

The width is the point. A real routine spells its constants inside seventeen to
forty-six bytes; the 278-byte "key 7 window" hit is the same MSVC C runtime
function in all three PE binaries - byte-identical between them, and nothing to
do with the cipher - which happens to contain a `0x76`, an `0xEF` and a `0x73`
scattered through it. Neither Windows build has the key 5 table or either seed
string.

Key 6 is the one route with no constant *set* to match - it is a xor with the
byte index and one addition - so all it can be pinned by is a single `add` or
`sub` of `0x55`/`0xAB`, and those get counted rather than judged. There are seven
in each Windows build, and disassembling all fourteen puts every one of them
inside a longer instruction: they are the second byte of a `mov` displacement or
similar, not instructions at all. The three in `x-killer.exe` are the two key 6
routines and one more of the same kind.

What the Windows tool does instead is **not** answered here, and guessing from
the strings is not worth much - it has a full trainer (`"%d Codes Active"`,
`"Manually Activate Cheat Code"`, an "ACG" code generator) and a text code-list
format. Two readings fit a tool with no cipher: it only ever handles codes the
user typed, already encrypted, or it emits them with a key nibble of 0 to 3,
which the cartridge's route table passes through untouched. The constant sweep
trips over its hex-digit parsers at `0x407930` and `0x40CF70` - `sub al, 0x57`
turning `'a'..'f'` into 10..15, not key 5.


## 6. Reproducing

```sh
uv run --with capstone --with unicorn python xcode.py       # find and run all ten
uv run --with capstone --with unicorn python xcode.py -s    # ... and disassemble
uv run --with capstone --with unicorn python xcode.py -q FILE   # ... one binary
```

`make encrypt` runs it. Like `xlink.py` it skips with a note when `pc/` is
absent, and drops the `../xpcrypt` comparison when the binary is not built.
Runtime is about eleven seconds, nearly all of it the two Windows builds proving
a negative.


## 7. What this changes

Nothing in the shipped source, which is the result worth having: the encrypt side
was already right.

* `xp_encrypt_code()` for all four keys and `encrypt_payload()` for both payload
  keys now have an authority that is not xpcrypt's own inverse. It is the
  vendor's, it predates every cartridge dump we have, and it agrees on 3,000
  codes including byte 0.
* The closed forms in `crypto.c` are confirmed as *a* correct spelling rather
  than the original one - the vendor's tool and the cartridge both slide windows
  over `"WHBX"`, `"FCD!"` and `" WB123"` - and X-Killer shows the closed forms
  were already in circulation in 1999.
* `XP_KEYED_TYPES` is xpcrypt being stricter than the vendor, not matching it.
  XLink encrypts any type it is given.

Still open, and now more pointedly: **Special32 and Special33 have no encrypter
anywhere.** Four binaries, one of them the vendor's, and not one of them
implements the `0x32`/`0x82` and `0x33`/`0x83` routes. Every argument in
`crypto.c`'s comment for leaving them out survives this - and the absence is
now a small piece of evidence in its own right that those two routes were dead on
the shelf rather than in use.
