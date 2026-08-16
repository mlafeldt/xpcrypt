# Compatibility of the "Advanced Xplorer Codes" FAQ

Checked 2026-07-31 against the current
[Advanced Xplorer Codes](https://gamehacking.org/faqs/advancedexplorercodes.htm)
page, its [archived copy used for this
review](https://web.archive.org/web/20111014093554id_/http://gamehacking.org/faqs/advancedexplorercodes.htm),
xpcrypt, and the recovered Xploder firmware corpus. The live endpoint returned
a Cloudflare block to the automated fetch; the archived text identifies itself
as last modified May 5, 2000 and contains the same technical material.

## Verdict

The page is a useful contemporary description of the **decrypted/raw Xplorer
instruction set**, and most of its worked Xplorer examples agree with the
firmware research. Compatibility has two separate layers:

* **Format and crypto:** xpcrypt converts six-byte Xplorer records and tracks
  type 5/6/A payload boundaries. The page describes raw records but does not
  document any normal or payload cipher. Its key-0 Xplorer blocks fit xpcrypt
  after presentation punctuation is removed.
* **Runtime semantics:** xpcrypt does not execute cheats. The recovered cartridge
  engine in [ENGINE.md](ENGINE.md) is the authority for what a decrypted record
  actually does. Most page descriptions match it, but types C/D, keyless
  default-off codes, and FX type 4 behavior do not.

The page is therefore not an xpcrypt input specification, a crypto
specification, or a completely reliable description of every firmware family.

The strongest match is the page's 14-line Rayman Megacode. After removing the
page's `$` decoration and normalizing hex case, its six-byte records are exactly
the fixture in [ray.txt](ray.txt), including header `60000000 003F`, breakpoint
descriptor `801FAB92 EA80`, mask `FFFFFFFF`, inline payload `F4FF`, and the
remaining rows. The recovered block stager consumes exactly 13 rows after that
header. See [FINDINGS.md, section 4.4](FINDINGS.md#44-specimens-kept-here) and
[REVERSING.md, section 7](REVERSING.md#7-the-block-stagers).

The page should be used with these qualifications:

| Page topic | Result against xpcrypt and the firmware | Verdict |
|---|---|---|
| `T = 0/8` and `8` means off by default | Bit 3 is the default-off flag; bits 0-2 are the normal cipher key. xpcrypt preserves bit 3 for round trips, while the cartridge's key 4-7 decrypt routes clear the whole low nibble. Contrary to the page's unconditional "this bit is then masked out", a keyless/default-off raw code never visits a cipher route, keeps the `8`, and the engine interprets it as address bit 27: the access moves by `0x08000000`. The page describes raw codes, not their stored encrypted form. The claim that one flag controls the rest of a cheat is menu/database behavior and is not established by xpcrypt's stream interface. | Flag definition matches; universal masking claim conflicts with the engine. |
| Type 0 | The engine performs a 32-bit store of the zero-extended 16-bit value. On little-endian PSX RAM it is equivalent to a type 8 write at `addr` and a zero type 8 write at `addr + 2`, exactly as the page says. | Match. |
| Type 1 | All nine engines have no handler, and shipped databases use it as the canonical safe second-line carrier for type B slides. The page's conditional-specific reason is behaviorally sound: when a false condition skips the B header, the loop encounters its carrier next, and type 1 prevents an unexpected write. Without a condition, an executable type 3/8 carrier would be dispatched after the slide and merely repeat its first write, so type 1 remains the clean general form. | Match. |
| Types 3 and 8 | Type 3 writes one byte; type 8 writes one 16-bit halfword. | Match. |
| Type 4 | V2/Pro executes a busy loop for `value << 12`, matching the page exactly. All four recovered FX firmwares omit type 4 entirely, so it does nothing there. | Match only for V2/Pro; page is not portable to FX. |
| Types 7 and 9 | Type 7 executes the next entry only on equality; type 9 executes it only on inequality. Each guards one entry, and the stager keeps a guard in front of a Supercode or Megacode so the block behaves as one entry. | Match. |
| Type 5 Supercode | `5?aaaaaa Knnn`, with `nnn` payload bytes and `ceil(nnn/6)` following rows. The page's `0YYY` form is the key-0 subset. xpcrypt additionally handles payload keys 6 and 7 and treats every following row as payload data, not as a code. | Match for the clear/key-0 form shown. |
| Type 6 Megacode | `6?aaaaaK nnnn`, followed by 10 descriptor bytes and `nnnn` logical handler bytes. The page's address, DCIC, mask, and installation-at-`0x80000040` layout matches. Its template fixes `K=0`, while xpcrypt also supports payload keys 6 and 7. The Rayman `003F` field declares 63 logical bytes; the runtime rounds that to 64 bytes/16 words, explaining the page's "exactly 64 bytes" statement. | Match for the key-0 example, with missing key and rounding details. |
| Type B slide | The page's address step, value step, and 16-bit writes match the handler. Its even-address/even-step caution follows from halfword alignment; the handler itself loads signed steps and does not contain a separate evenness test. Canonical encrypted/raw Xplorer format has only an 8-bit repeat count: the apparent high nibble of `RRR` is actually the key/default-off nibble. All page examples (`005`, `0A6`) fit that restriction. The handler has no explicit 0x0F/0x7F firmware cap, so the page's ROM-specific maxima are empirical behavior, not a format rule confirmed by the engine. | Mostly match; `RRR` notation overstates the usable count width. |
| Type C | The page says C acts like a D conditional. In all nine recovered firmwares, type C has no engine handler and no cipher route. The Japanese database even contains apparent type C button guards whose following writes therefore run unconditionally. | Conflict. |
| Type D | The page presents D as Datel compatibility. Actual staging promotes exactly one selected type D to type F, moves it to the head of the whole list, and uses it as a global anchor. Two or more type D lines are left unhandled. A GameShark `D0` one-line equality guard must be converted to Xplorer type 7; feeding `D0` unchanged is not equivalent. | Conflict/important missing rule. |
| Type F | The page's "type 7 affecting all cheats" summary is directionally right: on mismatch, F aborts the entire list for that pass. The stager hoists the first F to the front; later F lines are not all independently promoted. | Match with a first-anchor qualification. |
| GameShark/AR type 50 slide conversion | xpcrypt does no cross-device semantic conversion. `500005B0 0002` is an Xplorer type 5 Supercode header to xpcrypt, not a GameShark slide. Encrypting that page example as Xplorer changes it to `56565C08 595C` and treats the following line as key-0 payload. | Incompatible as xpcrypt input; convert to type B first. |
| `$` and hyphen presentation syntax | The page prints rows such as `$60000000 003F` and diagrams such as `00xxxxxx-yyyy`. xpcrypt accepts only twelve hex digits plus whitespace, so `$` or `-` makes the entire line non-code text and it is passed through unchanged. | Strip `$` and replace/remove hyphen separators before processing. |

The per-type engine evidence is in
[ENGINE.md, sections 1 and 4](ENGINE.md#4-the-instruction-set). The normal-code
route table, key nibble behavior, payload ciphers, and block stagers come from
the cartridge routine and callers transcribed in
[REVERSING.md, sections 6-7](REVERSING.md#6-the-crypto-function-annotated).
The converter implementation follows those results in
[crypto.c](../crypto.c) and documents its deliberate departures at the
top of that file.

As an independent source-code cross-check, SkillerCMP's current implementation
also treats a type B slide as an 8-bit count plus a type 1 carrier, and models
type 5/6 rows contextually rather than reclassifying them by their first nibble:

* [`XploderCodeTypes.hpp` at commit `5bade92`](https://github.com/SkillerCMP/PSX-Xploder/blob/5bade9248d1f15feb2cc34e6e1a5f404d257acfd/src/XploderCodeTypes.hpp#L188-L214)
* [`XploderMemoryCryptEngine.hpp` at commit `5bade92`](https://github.com/SkillerCMP/PSX-Xploder/blob/5bade9248d1f15feb2cc34e6e1a5f404d257acfd/src/XploderMemoryCryptEngine.hpp#L54-L79)
* [Canonical type 5/6 size parsing in the same file](https://github.com/SkillerCMP/PSX-Xploder/blob/5bade9248d1f15feb2cc34e6e1a5f404d257acfd/src/XploderMemoryCryptEngine.hpp#L377-L414)

## What the page does not cover

The FAQ is about code-engine behavior, not the subjects xpcrypt was built to
recover. It does not specify:

* normal line encryption keys 4, 5, 6, and 7;
* the payload-key 6 and 7 transforms;
* the firmware's keyed-type gaps (types 2, A, C, and E are stored in the clear);
* type A inline blocks, type E, or the Special32/Special33 decrypt routes;
* encrypted ROM transforms or cheat-database extraction;
* malformed/zero-length block behavior and block boundaries between cheats.

Accordingly, the page can supplement [ENGINE.md](ENGINE.md), but it cannot
replace [REVERSING.md](REVERSING.md), [FINDINGS.md](FINDINGS.md), or the
behavior documented in the [README](../README).

## Reproduction

The current executable was checked directly against the page's examples:

```text
./xpcrypt < research/ray.txt
    reproduces all 14 Rayman lines unchanged

./xpcrypt -e 6 < research/ray.txt | ./xpcrypt
    reproduces research/ray.txt byte-for-byte (the header uses normal key 6;
    its key-0 payload remains raw)

printf '%s\n' '$60000000 003F' | ./xpcrypt
    passes the dollar-prefixed line through unchanged

B00500B0 0002 + 101CF458 E03C
    survives an xpcrypt key-6 encrypt/decrypt round trip

500005B0 0002 + 801CF458 E03C | ./xpcrypt -e 6
    becomes 56565C08 595C + unchanged payload, demonstrating the
    GameShark-type-50/Xplorer-type-5 collision
```

The repository's broader checks also pass:

```text
python3 oracle_test.py ../xpcrypt
    47,071 checks, 0 failed; 15,349 real database lines, 0 failed

make engine
    9 firmware images executed; only the expected two type-4 cases differ
```

These results establish compatibility with xpcrypt's converter subset and the
recovered firmware evidence, not with the FAQ's separate X-Terminator claims or
its anecdotal hardware stability limits.
