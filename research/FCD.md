# The .fcd image cipher, and why it is not in the ROM

The question this answered: xpcrypt carried 1 KB of seed tables that were brute
forced out of matched encrypted/decrypted ROM pairs, plus the dead
`xp_bf_rom()` routine that produced them. Where is the real thing?

Short answer: **not in the ROM, and there never were any tables.** The cipher is
a twenty-two-instruction loop and three constants, it lives in the vendor's PC-side
upgrade tool, and the cartridge firmware neither contains it nor could use it.
Both directions of it have been recovered from four PC binaries - the vendor's
DOS tool, two builds of its Windows successor, and a third party's - and every
one of the eight routines, *executed*, agrees with xpcrypt's former tables and
current expressions. The image the DOS tool ships, whose plaintext exists
nowhere else, decrypts to firmware that unpacks and links at the right address.

This file is about the whole-*image* transform between a `.fcd` file and a
plaintext ROM. `FINDINGS.md` and `REVERSING.md` are about the *code* cipher
inside the firmware, which is a different thing that happens to live one function
call away in xpcrypt. `romcrypt.py` is the code cipher; `fcdcrypt.py`, added
here, is this one.

These same four binaries turned out to hold the code cipher as well, including
the encrypt direction the cartridge has no trace of - `ENCRYPT.md` and
`xcode.py`. Nothing below changes; the two ciphers do not meet.


## The four findings that matter

**1. The cipher.** Over the absolute file offset `i`, with no block structure:

```
mask(i)   = (u8) (i ^ ((i >> 1) + 0x45))
addend(i) = (u8) ((i & 0x37) ^ 0x2C)

decrypt:  dec[i] = (enc[i] ^ mask(i)) + addend(i)
encrypt:  enc[i] = (dec[i] - addend(i)) ^ mask(i)
```

`mask` depends on offset bits 0..8 and `addend` on bits 0..5, so the keystream
repeats every 512 bytes. That is where the removed `XP_ROM_BLKSIZE` came from: it
was a consequence of the arithmetic, not a parameter of the design, and its
"Xploder ROMs are encrypted in ECB mode" comment described the shadow rather
than the object. There is no key and no block; `i ^ (i >> 1)` is a Gray code of
the offset, and `0x45` and `0x2C` were `seeds1[0]` and `seeds2[0]`.

**2. It is not in the cartridge, and cannot be.** The one routine that programs
the firmware region of flash is reached from the link command dispatcher, and it
writes the bytes it received, byte for byte (section 2). The cartridge therefore
never sees an `.fcd`, which is also why
every raw cartridge dump we have is plaintext: the PSX executes the cartridge in
place out of EXP1, so the flash has to hold code.

**3. It is in `XLink.exe`**, the vendor's DOS upgrade utility (the binary reports
X-Link V1.091), twice - once per direction, at `0x2A4A0` (decrypt) and `0x2A640`
(encrypt) - and in every other build of every tool that reads an `.fcd`, with the
same three constants: both 1999 builds of the Windows successor `Xlink95.exe`, and
`x-killer.exe`, which is a third party's. Section 4 has where to get the files,
section 5 how the routines were found and section 5a how they were checked by
running them. The `.fcd` on disk is simply the transport form of an image: before
flashing a new one, XLink reads the cartridge's current ROM back, *encrypts* it,
and writes it out as `ROMS\BackUp.FCD` - 256 KB from `0x1F000000` in the DOS
build, a `0x80000`-byte read from the same base in both Windows builds (ninth
pass).

**4. xpcrypt's former tables are right as a function and wrong as bytes.** They agree
with the routine on all 512 x 256 (offset, byte) inputs, and differ from the
constants it computes at 256 of the 512 offsets, because `(a, b)` and
`(a ^ 0x80, b - 0x80)` are the same function on a byte - `x ^ 0x80 == x + 0x80`
mod 256 - and the brute force took whichever it found first. The brute force also
read the mask as 256-periodic and put the ninth offset bit into the addend table,
where the real mask is 512-periodic and the real addend 64-periodic. Nothing
downstream is affected; it is the same map either way.


## 1. What the images pin down, and what they do not

Worth doing first, because it bounds how much the binary could add - and worth a
correction, because the first version of this section overstated it.

**The correction.** `roms/*.dec` are not independent plaintext. They are produced
locally by `xpcrypt -r` from the `.fcd` files (`FINDINGS.md` has the commands), so
the seven "pairs" are the tables' own output, and anything measured over them that
is a statement about the *mapping* is circular. Specifically: that the map
`(offset mod 512, byte) -> byte` has zero conflicts over all seven images, and
that `(x ^ a) + b` fits every offset in exactly two ways, are both true by
construction and prove nothing. They are struck from the record here.

What the seven images do say, because these are statements about the encrypted
bytes and about the table values rather than about the pairing:

* **Coverage is 250 to 256 of 256 byte values per offset** (177 of the 512 offsets
  see all 256), so 566 of the 131,072 (offset, byte) cells appear in no `.fcd` we
  have. Whatever originally produced the tables could not have been constrained by
  data there.
* **`(x + c) ^ d` fits only 20 of the 512 offsets** as a description of the shipped
  tables. The xor-then-add order was never a guess.

The evidence that the tables were nevertheless right all along is not in the pairs
at all - it is that the images they produce are *working firmware*. Nine of them
unpack, disassemble, agree with each other on their own crypto routines, and run
in an emulator: that is what the rest of this directory does, and none of it would
if the transform were wrong anywhere it was exercised. Section 5a adds the same
argument in one self-contained step, on an image whose plaintext we never had.

The 1,868,896-byte pair check in `fcdcrypt.py` is retained as an end-to-end smoke
test, not as evidence; the coverage and solution-count measurements above were
one-off and are not kept.


## 2. Why it is not in the ROM

Done as a search, then as a reading, because a search that finds nothing proves
little on its own.

**Searched, found nothing.** All nine firmwares plus the seven `.fcd` files, as
raw images and as COMP01-unpacked firmware (`fwimage.load()`): neither seed table
appears, nor its first 256, 64, 32 or 16 bytes, nor those bytes with the high bit
flipped. Neither do the constants a generator would need, nor the 16-byte
sub-patterns the tables decompose into.

**Read the flash path instead.** In `xteng.dec` (V2 2.008, addresses in the
unpacked image; all nine are the same shape):

* `0x1A3444` probes the flash: unlock `0xAA` to `0x5555` and `0x55` to `0x2AAA`,
  `0x90` to autoselect, device ID read back from `0x1F000001` and compared
  against `0xDA`, `0xA4`, `0xD5`.
* `0x1A35E4` is the page programmer, called as `(src, dst, len)` - the destination
  is the second argument, which is worth pinning down before reading its callers.
  It skips bytes that already match, then copies the rest with `lbu`/`sb` in 0x80
  or 0x100-byte pages depending on the device. **No transform.**
* It has six callers. Three pass literal addresses in the cheat-database region -
  `0x1F022600` twice (0x10 and 0x900 bytes) and `0x1F025000` once (0x1AFFC bytes,
  the database itself); one takes the destination from a register and is a
  read-modify-write of a single flash page. Two pass the base of the firmware,
  `0x1F000000`: `0x1A1B80`, below, and `0x1A4698`, which is the self-destruct of
  `FINDINGS.md` §5.3b, `flash_write(0x3E8, 0x1F000000, 0x18000)` (ninth pass; this
  used to count it as a page read-modify-write).
* That caller is the link command dispatcher. It reads a command byte, and on
  `'U'` (0x55) programs the received buffer over the firmware and answers `"OK"`
  or `"OF"`. The receive loop above it is:

```
001A1A50  jal   0x1a12c0     ; receive one byte -> $v0
001A1A54  nop
001A1A58  move  $s2, $v0
001A1A5C  addiu $v0, $zero, 0x55
001A1A60  bne   $s6, $v0, 0x1a1acc
001A1A64  sb    $s2, ($s3)   ; delay slot: store it, unmodified
...
001A1AD0  addu  $s1, $s1, $v0    ; 16-bit additive checksum, exchanged and
001A1AD4  addiu $s0, $s0, 1      ; compared once the buffer is full
```

  The byte goes to memory exactly as it arrived. `0x1A12C0`, the receive helper,
  is pure handshake - poll `0x1F060002` bit 0, read `0x1F060001`, acknowledge
  with 8, wait, clear - and returns the raw byte.
* The FX generation is identical in shape (`english.dec:0x800269B8`: `jal` recv,
  `move $s1, $v0`, `sb $s1, ($s0)`, then `lui $a1, 0x1f00` and the programmer).

So the cartridge expects plaintext on the wire. Whatever decrypts an `.fcd` runs
on the PC.

Every address above is `xteng.dec`'s; the commands in section 6 relocate them in
any of the nine images.


## 3. What the tables' shape was saying

Recorded because the structure is legible from the tables alone, and because
getting most of the way there is what made the binary easy to search:

* `seeds2` is exactly `(i & 0x37) ^ 0x2C` once the 256 offsets of finding 4 are
  taken the other way. Pure offset bits.
* `seeds1` decomposes as a 16-byte column pattern XOR a row-parity bit, over a
  high nibble that follows the 3-bit Gray code of the row index. The Gray code is
  the `i ^ (i >> 1)`; the row-parity quirk - the high nibble drops by one from
  column 6 of each row on - is the carry out of `+ 0x45`; and `seeds1[0] = 0x45`
  is the constant itself, sitting in plain sight at the top of the table.
* Neither table is GF(2)-affine in the offset bits, which is what ruled out a
  pure wire-level scramble and said an addition was involved.


## 4. Where the binaries are

The vendor's site is on the Wayback Machine, and its CDX index holds exactly two
non-404 `.zip` or `.exe` captures: `xlink/xcuk.zip`, which is a cheat list, and
**`xlink/xlinkuk.zip`**, 1,406,411 bytes, captured 2001-06-11.

```sh
curl -sS "http://web.archive.org/cdx/search/cdx?url=x-plorer.co.uk\
&matchType=domain&collapse=urlkey&fl=timestamp,original,mimetype,statuscode\
&filter=original:.*zip.*"
```

**Gotcha worth keeping:** fetching that capture the obvious way returns the
Wayback "has not archived that URL" page, with a 200 and a plausible size.
Appending a bare `?` to the target URL gets the bytes:

```sh
curl -sSL -o xlinkuk.zip "https://web.archive.org/web/20010611232557if_/\
http://www.x-plorer.co.uk/xlink/xlinkuk.zip?"
```

That one is the Windows build. **The mirror is easier**, and it carries the DOS
build unpacked plus a second copy of the Windows installer:

```sh
cd pc                                # research/pc/, gitignored like roms/
curl -sSLO https://www.murraymoffatt.com/xplorer/xlink_dos_uk.zip
curl -sSLO https://www.murraymoffatt.com/xplorer/xlink_95_uk.zip
curl -sSLO https://www.murraymoffatt.com/xplorer/x-killer-v0.55.zip
```

The DOS zip is plain: `XLink.exe` (319,514 bytes, DOS/4GW linear executable),
`dos4gw.exe`, `RelNotes.txt`, and `ROMS/Xteng.fcd` - 196,458 bytes, an image the
tool ships to flash, and one whose plaintext is in no `roms/` pair.

Both Windows zips are InstallShield 3.x installers, where the files live
compressed in `_SETUP.1` (magic `13 5D 65 8C`, PKWARE DCL implode). `unshield`
does not read these - it handles the v5 cabinets - but
[`wfr/unshieldv3`](https://github.com/wfr/unshieldv3) does. It needs one nudge to
build on macOS, because `blast.h` has no `extern "C"` and the linker then wants a
C++-mangled `blast`:

```sh
git clone --depth 1 https://github.com/wfr/unshieldv3 && cd unshieldv3
printf '#pragma once\n#define CMAKE_PROJECT_NAME "u"\n#define CMAKE_PROJECT_VER "0"\n' > config.h
clang -O2 -c blast.c -o blast.o
clang++ -std=c++17 -O2 -o unshieldv3 main.cpp ISArchiveV3.cpp blast.o
./unshieldv3 list -v ../_SETUP.1
mkdir out && ./unshieldv3 extract ../_SETUP.1 out   # it will not mkdir for you
```

Five files come out of each: `Xlink95.exe`, `XLinkWin.doc`, `RelNotes.txt`,
`Xlink.mrf`, `cset.bin`. The two `Xlink95.exe` are both 1,765,376 bytes and both
report `Xlink95 Version 1.1` in their About text (the version resource of both
says `1.07`), but they are different builds - stamped 1999-07-02
in the mirror's zip and 1999-08-04 in the Wayback one - and the later one is a
substantial relayout, 215,702 bytes of `.text` differing. Its cipher routines are
not among the changes: those are byte-identical between the two builds, at
different addresses.

So `pc/` ends up holding four binaries, and eight routines:

| file | | |
|---|---|---|
| `XLink.exe` | DOS X-Link V1.091, "Released : 19/10/98" | Watcom, DOS/4GW LE |
| `Xlink95-19990702.exe` | Xlink95 v1.1, 1999-07-02 build | MSVC/MFC, Win32 PE |
| `Xlink95.exe` | Xlink95 v1.1, 1999-08-04 build | same, `.text` differs |
| `x-killer.exe` | X-Killer v0.55, 1999-10-02 | third party, Win32 PE |

`x-killer.exe` is the interesting one. It is by Tim Schuerewegen, not FCD, and it
is an **independent implementation**: same three constants, same order of
operations, but `shr` where the vendor writes `sar`, `cdecl` where the vendor uses
Watcom registers (DOS) or `stdcall` (Windows), and in place over one buffer instead
of src/dst. Its file-type list offers `"FCD N64 ROM - Encrypted"` beside the PSX
ones, and it holds only these two cipher routines, so as far as that tool is
concerned one transform covered FCD's N64 product too. The binary pins that down
rather than just the UI string (ninth pass): its file-type classifier at
`0x4083D0` calls a file an encrypted N64 ROM when byte `0x200` is `'i'` and byte
`0x40` is `'?'`, which is exactly this cipher applied to the N64 plaintext marks
`'X'` at `0x200` and `'F'` at `0x40` (mask `0x45`, addend `0x2C` at `0x200`; mask
`0x25`, addend `0x2C` at `0x40`), and the loader that accepts it (`0x4061A0`)
decrypts it with the same routine, `0x408350`. The same author's other tool,
`x-flash-v1.2-beta-3.zip` from the same mirror, does *not* contain the cipher:
`xflash.exe` is a PSX-side executable and its `romfile.exe` builder takes `*.rom`,
already plaintext.

`XLink.exe` is not packed and its strings are plain: the `.fcd` filename table,
`"ARE YOU SURE YOU WISH TO UPGRADE?"`, `"Uploading ROM to PlayStation"`,
`"ROM Upgraded OK"`, and

```
 Paul J Herbert  / FCD  (Paul@X-plorer.co.uk)
```

which is the **PJH** of `"FCD = WHB PJH DN MW IN R?"`, the credit string in the
ROM header that `REVERSING.md` section 1 starts from. Same team, both ends. The
Windows builds carry `XLink Trainer V2.00 : P J Herbert` and the source paths
`C:\Projects\Xlink95\Xlink95Dlg.cpp`.

**What does not survive.** `RelNotes.txt` documents releases from V1.06 (1998-07-01)
to V1.091 (1998-10-13), and the notes for V1.091 promise a V1.10 "Xlink PRO". No
binary of any of those is anywhere we could find: the vendor's whole domain has
exactly two non-404 archive captures, and listing everything ever requested under
`/xlink/` shows the rest as 404s (`Xlink95.zip`, `xlwinuk.exe`, `xp2uk.zip`,
`xcus.zip`).

```sh
curl -sS "http://web.archive.org/cdx/search/cdx?url=x-plorer.co.uk/xlink\
&matchType=prefix&fl=timestamp,original,statuscode,length&collapse=urlkey"
```

A patched `Xlink95` v1.1 was posted on psxdev.net (thread 746, region check and
`0x1F000000` address restriction removed, GiveIO for NT); its attachments need a
login and the site has been down since October 2025, but it is a patch of the same
v1.1 binary we have, and it is the region check it patches, not the cipher.


## 5. Finding the routines

`xlink.py` does all of this. Starting with the DOS build, because that is the one
whose routine the closed form was transcribed from; the parts worth knowing:

**Loading.** A 32-bit MZ stub with `LE` at the `e_lfanew` offset (`0x30A8`), a
page map naming each object's physical pages, and two objects: code at `0x10000`
(192,949 bytes) and data at `0x40000`. Every address here is linear in that
image, not a file offset. No iterated (RLE) pages, so the tables really are
absent rather than compressed.

**Cross-referencing without applying fixups.** Absolute addresses are patched at
load time from the fixup section. Searching the code for a string's *linear*
address therefore finds nothing - but an unfixed site still holds the target's
offset **within its object**, so searching for that works:
`"ARE YOU SURE YOU WISH TO UPGRADE?"` is at `0x408AA`, and `AA 08 00 00` appears
once in the code, at `0x10E29`. That lands in the upgrade UI, which walks down to

* `0x2A500` - open the `.fcd`, size-check it against `0x40000`, `malloc`, `fread`,
  `fclose`, and then:

```
0002A622  mov ebx, edi        ; len
0002A624  mov edx, esi        ; dst
0002A626  mov eax, esi        ; src - in place
0002A628  call 0x2a4a0        ; the cipher
0002A62D  mov eax, esi        ; return the plaintext image
```

* `0x2A6A0` - the mirror image: read the cartridge's ROM, `call 0x2a640`, write
  `ROMS\BackUp.FCD`.

**The routine.** Watcom register convention, `eax` = src, `edx` = dst,
`ebx` = len:

```
0002A4A6  mov edi, eax
0002A4AC  xor eax, eax           ; i = 0
0002A4AE  test ebx, ebx
0002A4B0  jle 0x2a4f0
0002A4B6  mov edx, eax           ; loop: edx = i
0002A4B8  sar edx, 1             ;     = i >> 1
0002A4BA  mov edi, eax
0002A4BC  add edx, 0x45          ;     = (i >> 1) + 0x45
0002A4BF  xor edi, edx           ; edi = i ^ ((i >> 1) + 0x45)
0002A4C1  mov dword ptr [esp], edi
0002A4C4  mov dl, byte ptr [esp]
0002A4C7  mov byte ptr [esp + 8], dl      ; the mask, one byte of it
0002A4CB  mov dl, al             ; dl = i
0002A4CD  and dl, 0x37
0002A4D0  xor dl, 0x2c           ;    = (i & 0x37) ^ 0x2C
0002A4D3  mov byte ptr [esp + 4], dl      ; the addend
0002A4D7  mov dl, byte ptr [ecx]          ; src[i]
0002A4D9  xor dl, byte ptr [esp + 8]      ;   ^ mask
0002A4DD  inc ebx
0002A4DE  mov dh, byte ptr [esp + 4]
0002A4E2  inc ecx
0002A4E3  add dl, dh                      ;   + addend
0002A4E5  inc eax
0002A4E6  mov byte ptr [ebx - 1], dl      ; dst[i]
0002A4E9  cmp eax, esi
0002A4EB  jl 0x2a4b6
```

`0x2A640` is the same instruction for instruction with the last two swapped -
`sub dl, addend` then `xor dl, mask`. The two are told apart by that alone, which
is how `xlink.py` labels them.

One faithfulness note: the shift is arithmetic (`sar`), so a hypothetical input
above 2 GiB would differ from the logical shift `fcdcrypt.py` uses. Not
reachable - the caller caps the buffer at `0x40000` (the Windows builds at
`0x80000`).

**In the other three binaries** the same search works, because the one thing every
build spells identically is the addend - `and r8, 0x37` then `xor r8, 0x2c`, in
some 8-bit register. That is all `xlink.py` looks for; everything else it
determines rather than assumes. Two hits per binary, and the entry of each is the
largest direct `call` target within 0x90 bytes above the hit, which beats walking
backwards through variable-length instructions and guessing at a prologue.

The Windows compiler is not Watcom and the codegen is not the same, but the
function is. Its decrypt loop keeps the mask in 8 bits throughout and splits the
xor in two, which is the same value because truncation commutes with xor:

```
0041AB78  8bd0       mov edx, eax        ; edx = i
0041AB7A  8d3428     lea esi, [eax+ebp]  ; dst + i
0041AB7D  d1fa       sar edx, 1
0041AB7F  8a1c37     mov bl, [edi+esi]   ; src[i]
0041AB82  80c245     add dl, 0x45        ; dl = (u8)((i >> 1) + 0x45)
0041AB85  32d3       xor dl, bl          ;    ^= src[i]
0041AB87  8ad8       mov bl, al
0041AB89  80e337     and bl, 0x37
0041AB8C  32d0       xor dl, al          ;    ^= i        - mask complete
0041AB8E  80f32c     xor bl, 0x2c        ; bl = addend
0041AB91  02d3       add dl, bl
0041AB93  40         inc eax
0041AB94  3bc1       cmp eax, ecx
0041AB96  8816       mov [esi], dl
0041AB98  7cde       jl 0x41ab78
```

`x-killer.exe` is shorter still - `cdecl(buf, len)`, one buffer, `shr` for the
shift - and lands on the same fifteen-instruction loop (`0x408360`-`0x40837D`;
ninth pass, this used to say twelve). The DOS loop above is twenty-two.

**There is no second, legacy path.** Each of the Windows routines has exactly one
caller, and the strings around them say which: `0x41ACCF` is the "Upgrade ROM"
load - `"Cannot open file"`, `"Cannot allocate memory"`,
`"Rom size mismatch (%d / %d)"` - and `0x41ADB2` is the save, next to
`"ROMS\BackUp.FCD"` and `"Your old ROM has been backed up as BACKUP.FCD"`. So the
tool has one way to read an `.fcd` and one way to write one, and these are they.


## 5a. Checking it by running it

Reading a loop and doing the algebra is how the above was arrived at, but it is
not proof, and by the fourth binary it is not even good use of attention. So
`xlink.py` executes each routine it finds, under Unicorn, as a 32-bit x86 process:
map the file's segments where the loader would put them, map a stack and a source
and destination buffer somewhere far away, push a magic return address, and run
until control reaches it.

The calling convention is *not* asserted anywhere. It is discovered: the harness
tries each of the three it knows in both directions and keeps the ones that come
out equal to `fcdcrypt.py` over one full 512-byte period of pseudorandom input.
Exactly one combination may pass, or the script fails. A wrong convention faults
or writes rubbish, so this cannot pass by luck - and to be sure the check bites,
changing that one `0x45` byte to `0x46` in a copy of `x-killer.exe` makes it
report `0 conventions worked, wanted 1`.

Each routine is then run over a real image - the smallest `.fcd`/`.dec` pair in
`roms/`, 207,161 bytes - and must reproduce the other member of the pair exactly.
That is scale and real data rather than independent evidence, and worth being
clear about: the `.dec` files were made by running `xpcrypt -r` over the `.fcd`
files, so a routine matching them is a routine matching xpcrypt's tables. The
independence comes from elsewhere, and there is plenty of it - see below, and note
that every other suite in this directory is built on those `.dec` files and finds
nine mutually consistent MIPS firmwares in them.

```
pc/XLink.exe: LE, 2 segments, 2 routines
  0002A4A0  decrypt watcom_regs  xtger.fcd (207161 bytes) exact
  0002A640  encrypt watcom_regs  xtger.fcd (207161 bytes) exact
pc/Xlink95-19990702.exe: PE, 4 segments, 2 routines
  0041AB00  decrypt stdcall_3    xtger.fcd (207161 bytes) exact
  0041ACE0  encrypt stdcall_3    xtger.fcd (207161 bytes) exact
pc/Xlink95.exe: PE, 4 segments, 2 routines
  0041AB60  decrypt stdcall_3    xtger.fcd (207161 bytes) exact
  0041AD40  encrypt stdcall_3    xtger.fcd (207161 bytes) exact
pc/x-killer.exe: PE, 4 segments, 2 routines
  00408350  decrypt cdecl_2      xtger.fcd (207161 bytes) exact
  00408390  encrypt cdecl_2      xtger.fcd (207161 bytes) exact
pc/ROMS/Xteng.fcd (shipped with the DOS tool, plaintext nowhere else): decrypts to a ROM whose firmware unpacks, 179140 bytes at 001A0000
8 routines in 4 binaries, every one of them reproduces fcdcrypt.py
```

**The last-but-one line is the check that leans on nothing else here**, and it is
the one that closes the question. `ROMS/Xteng.fcd` came with the DOS tool, its
plaintext is in no `roms/` pair, and nothing but the cipher says what is inside it,
so whatever comes out has to stand up by itself. It does. Decrypting gives the
`0x00 0x01` ROM header and the `"FCD = WHB PJH DN MW IN R?"` credit string; it
re-encrypts to the original byte for byte; and handing it to `fwimage.load()` -
the same loader the firmware suites use - finds a COMP01 stream that decompresses
to 179,140 bytes of firmware whose *own* link address reads back as `0x001A0000`,
the address every other V2 firmware is linked at. It is a build we did not
otherwise have; `roms/xteng.dec` unpacks to 179,992 bytes.

A cipher wrong in any byte does not get that far. COMP01 is a back-referencing
stream, so one wrong byte early derails every copy after it - and `base_of()` is
not a guess either: it locates the `' WB123'` constant tables, disassembles MIPS
from offset 0 to find the dispatcher's `sltiu $v0, $v1, 0xf4`, takes the base from
the default route, and then refuses it unless all 244 jump-table entries land
inside the image.

Runtime for all of that is about a second.


## 6. Reproducing

```sh
uv run python fcdcrypt.py                      # the cipher, against the tables
                                               # and every pair in roms/
uv run --with capstone --with unicorn python xlink.py       # find the routines in
                                               # pc/*.exe and run all eight
uv run --with capstone --with unicorn python xlink.py -s    # ... and disassemble
uv run --with capstone --with unicorn python xlink.py FILE  # ... or one binary
```

Both skip with a note rather than failing when `roms/` or `pc/` is absent;
`fcdcrypt.py`'s table check needs neither, and `xlink.py` drops the real-image
check but keeps everything else. `make fcd` runs the pair.

Section 2 was read with `fwscan.py`, which is `mipscan.py`'s two operations over
the *unpacked* firmware, so its addresses are the ones quoted above. On any of the
nine images:

```sh
F="uv run --with capstone python fwscan.py roms/xteng.dec"
$F -c 0xaa,0x55 48        # the flash driver
$F -c 0xa0,0x5555 12      # the page programmer inside it
$F -c 0x58,0x55,0x4f,0x4b 60   # the link command dispatcher
$F -x 0x1a35e4            # the programmer's six callers
$F -d 0x1A1A50 40         # the receive loop
$F -d 0x1A12C0 24         # the receive helper: handshake only
```


## 7. What this changed in xpcrypt

Now implemented in the shipped source:

* The 1 KB of seed tables in `xp_crypto.c` became two expressions, and
  `xp_encrypt_rom()`/`xp_decrypt_rom()` two-line loops. The tables were not wrong;
  they were 1024 bytes spelling out six operations.
* `XP_ROM_BLKSIZE` and the "ECB mode" comment are gone. The explicit functions
  take `size_t` and accept any buffer length; automatic conversion only needs
  `XP_ROM_MIN_SIZE`, through the `Sony` marker it uses to choose a direction.
* The encrypt direction finally has an authority. `xp_encrypt_rom()` was written
  as the algebraic inverse of a brute-forced table and has been checked by
  round-tripping only. Now there are four encrypters to check it against, and the
  vendor's own is one of them: `fcdcrypt.encrypt()` matches all four, executed,
  over a full keystream period and over a 207 KB image.
* The dead `xp_bf_rom()` table-recovery routine is gone.

What is left genuinely open is small, and it is archaeology rather than
uncertainty about the cipher. No binary of X-Link V1.06 through V1.09, or of the
promised V1.10, appears to survive anywhere (section 4), so the oldest
implementation we can execute is V1.091 from October 1998 - the binary says
"Released : 19/10/98", `RelNotes.txt` dates the release 13/10/98. Two things make that
a formality rather than a gap. The cipher is pinned by the files, not by the
tools: every `.fcd` the vendor shipped, spanning firmware 2.008 to 4.52 and both
hardware generations, decrypts with these three constants into an image that
unpacks as firmware - so any earlier release had to compute the same function to
read the same files. And a stranger reimplemented it from the outside in 1999,
in a different compiler with a different convention, and arrived at the same
three constants. That is what a format that never moved looks like.
