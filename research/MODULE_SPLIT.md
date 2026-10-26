# A general module split for `xpcrypt`

> Implemented on 2026-08-01 on the `module-split` branch (`fed8a70`, forked from
> `854c1e1`), which is **not merged** into `main` or `research`. Here `xpcrypt.c`
> is still the monolith beside `crypto.c`/`crypto.h` (renamed from `xp_crypto.*`
> on `main` in `8f9b90b`, the same rename that branch makes). It also
> predates the empty-game fix (`7070614`): its `db.c` still rejects a zero-cheat
> game, so it needs that fix ported before it can merge. References to `xpcrypt.c`
> line numbers below describe the pre-split baseline used to choose the seams.

## Decision

Split `xpcrypt.c` by behavior, not by helper type.

The useful seams are:

1) a stateful code-stream module shared by text conversion and database extraction;
2) a text-filter module that owns the exact stdin/stdout contract;
3) a database-traversal module that hides locating, parsing, name decoding, and
   bounds checks behind one visitor interface; and
4) a ROM-file command module that owns file buffers, extraction presentation,
   diagnostics, and the two file-oriented workflows.

Leave `xpcrypt.c` with option parsing, operand validation, help/version output,
and dispatch only. Leave `crypto.c/h` intact during this work. Its interface
already hides the code equations, block layout, payload equations, ROM marker,
and image transform from its callers
([`crypto.h:31-175`](../crypto.h#L31-L175)); splitting that implementation
at the same time would add churn without helping the `xpcrypt.c` seams.

This is broader than moving the database cursor. A parser-only extraction would
remove about one quarter of the file but leave the shared code-stream state,
text grammar, warnings, file ownership, output ordering, and command workflows
in the CLI.

## What is monolithic today

`xpcrypt.c` is 865 lines and contains six distinct kinds of knowledge:

| Responsibility | Current implementation | Coupling that matters |
|---|---|---|
| CLI policy | option tables, modes, key parsing, operand validation, dispatch ([`xpcrypt.c:31-73`](../xpcrypt.c#L31-L73), [`xpcrypt.c:766-865`](../xpcrypt.c#L766-L865)) | Chooses a command, but currently also owns every command implementation. |
| Text format and streaming I/O | hex parsing, bounded line reads, pass-through, code printing, stdin/stdout error handling ([`xpcrypt.c:75-182`](../xpcrypt.c#L75-L182), [`xpcrypt.c:260-343`](../xpcrypt.c#L260-L343)) | The text contract is byte-sensitive: non-code lines, NUL bytes, and overlong lines must survive unchanged. |
| Stateful code transformation | block recognition, payload position, direction, key, warnings, and per-row transformation ([`xpcrypt.c:184-258`](../xpcrypt.c#L184-L258)) | Both stdin conversion and each extracted cheat use it ([`xpcrypt.c:284-306`](../xpcrypt.c#L284-L306), [`xpcrypt.c:594-613`](../xpcrypt.c#L594-L613)). |
| Database format | abbreviation table, valid name bytes, record cursor, candidate validation and ranking ([`xpcrypt.c:345-564`](../xpcrypt.c#L345-L564)) | This is in-process parsing over borrowed `(rom, size)` memory, with no file I/O. |
| Database rendering | abbreviation expansion, quoting, separators, per-cheat decryption ([`xpcrypt.c:566-619`](../xpcrypt.c#L566-L619)) | Correctness depends on resetting code-stream state for each cheat at line 604, not just on parsing records. |
| ROM-file workflows | loading and allocation, plaintext normalization, extraction, conversion, safe output ordering, close/write errors ([`xpcrypt.c:621-764`](../xpcrypt.c#L621-L764)) | Extraction and conversion share input ownership; conversion must not open the output until conversion succeeds. |

The shared call relationships are the stronger evidence for seams than line
count. `crypt_code()` already has two callers with different input adapters, and
`read_rom()` already has two command callers. Conversely, helpers such as
`hex_digit()` and `db_name_end()` have only one behavioral owner and should stay
private inside their owning module.

## Recommended modules and interfaces

### `code_stream.c/h`: block-aware row transformation

This module owns the state now in `struct code_stream`, `start_block()`,
`init_code_stream()`, and `crypt_code()`
([`xpcrypt.c:184-258`](../xpcrypt.c#L184-L258)). It depends only on
`crypto.h`; it performs no I/O and emits no text.

An illustrative interface is:

```c
enum xp_direction {
	XP_DECRYPT,
	XP_ENCRYPT
};

enum xp_code_event {
	XP_CODE_EVENT_NONE                = 0,
	XP_CODE_EVENT_LEFT_CLEAR          = 1u << 0,
	XP_CODE_EVENT_UNKNOWN_PAYLOAD_KEY = 1u << 1,
	XP_CODE_EVENT_INLINE_BLOCK        = 1u << 2
};

struct xp_code_stream {
	/* State is concrete for stack allocation, but private by convention. */
	struct xp_block block;
	int payload_index;
	enum xp_direction direction;
	enum xp_key key;
};

void xp_code_stream_init(struct xp_code_stream *stream,
		enum xp_direction direction, enum xp_key key);
unsigned xp_code_stream_apply(struct xp_code_stream *stream,
		uint8_t code[XP_CODE_LEN]);
```

The interface includes these invariants:

- initialize once before applying rows;
- apply rows in source order;
- reinitialize at a cheat boundary; and
- the row is always the result, while the bitmask reports noteworthy but
  non-fatal outcomes.

Those facts are already part of the current behavior. A type A header consumes
the remainder of an unbounded text stream
([`xpcrypt.c:299-309`](../xpcrypt.c#L299-L309)), while extraction creates a new
stream inside the record loop so the same block ends with its cheat
([`xpcrypt.c:594-610`](../xpcrypt.c#L594-L610)). The README documents both
contracts ([`README:108-116`](../README#L108-L116),
[`README:123-135`](../README#L123-L135)).

Returning events instead of printing warnings keeps this an in-process module.
The current code prints unknown-payload and unencryptable-code warnings from the
state machine itself ([`xpcrypt.c:188-197`](../xpcrypt.c#L188-L197),
[`xpcrypt.c:247-254`](../xpcrypt.c#L247-L254)); callers should render those
events in their own output context. The same event mechanism can later carry
the default-off, zero-length, and optional lint diagnostics already proposed in
the TODO ([`TODO.md:70-125`](TODO.md#L70-L125)) without adding callbacks or
putting CLI strings into the crypto implementation.

This is a deep module: two callers learn two operations and one lifecycle rule,
while block recognition, header timing, payload position, direction-sensitive
ordering, and low-level crypto return conventions stay behind the seam.

### `text.c/h`: the code-text filter

This module owns `hex_digit()`, `parse_code()`, `read_line()`, `print_code()`,
and `crypt_codes()`
([`xpcrypt.c:75-182`](../xpcrypt.c#L75-L182),
[`xpcrypt.c:260-329`](../xpcrypt.c#L260-L329)). It depends on
`code_stream.h`.

```c
int xp_text_transform(FILE *in, FILE *out, FILE *diag,
		enum xp_direction direction, enum xp_key key);
```

The interface is intentionally one operation. It hides all of these observable
rules:

- exactly twelve hex digits plus whitespace form a code
  ([`README:69-72`](../README#L69-L72));
- incomplete chunks from an overlong line are never reclassified as codes
  ([`xpcrypt.c:140-179`](../xpcrypt.c#L140-L179));
- arbitrary non-code bytes pass through unchanged, including bytes after an
  embedded NUL ([`xpcrypt.c:151-153`](../xpcrypt.c#L151-L153),
  [`xpcrypt.c:286-297`](../xpcrypt.c#L286-L297));
- transformed codes have one canonical printed form
  ([`xpcrypt.c:260-263`](../xpcrypt.c#L260-L263)); and
- read, write, and final flush failures fail the operation
  ([`xpcrypt.c:315-328`](../xpcrypt.c#L315-L328)).

`FILE *` is the right dependency here. It is local-substitutable with `tmpfile()`
for focused C tests, so no callback port or I/O adapter is justified. Passing
`diag` rather than reaching for `stderr` makes the dependency explicit while
preserving current warning text. The function should own diagnostic formatting
for code-stream events and return only success/failure to the CLI.

### `db.c/h`: locate, parse, and visit a database

The recommended seam is one level higher than exposing the current cursor.
Keep the cursor, locator, bounds checks, and abbreviation decoding inside the
module, and expose semantic cheat records through one traversal operation:

```c
enum xp_db_status {
	XP_DB_OK,
	XP_DB_NOT_FOUND,
	XP_DB_VISITOR_STOPPED,
	XP_DB_NO_MEMORY
};

struct xp_db_record {
	const char *game_name;       /* decoded, callback-scoped */
	size_t game_name_len;
	const char *cheat_name;      /* decoded, callback-scoped */
	size_t cheat_name_len;
	const uint8_t *codes;        /* borrowed from the ROM */
	size_t nlines;
	int first_in_game;
	int last_in_game;
};

typedef int (*xp_db_visitor)(void *context,
		const struct xp_db_record *record);

enum xp_db_status xp_db_visit(const uint8_t *plain_rom, size_t size,
		xp_db_visitor visit, void *context);
```

The input and code rows are borrowed for the duration of the call and must
already be a plaintext ROM. Decoded names are scratch values valid only during
the callback; no record or name escapes the call. Current records already keep
borrowed pointers into the ROM
([`xpcrypt.c:363-381`](../xpcrypt.c#L363-L381),
[`xpcrypt.c:476-485`](../xpcrypt.c#L476-L485)); decoding the abbreviation bytes
behind the seam prevents the edge adapter from learning the database encoding.

This module should hide:

- the erased-flash framing and richest-candidate rule
  ([`xpcrypt.c:502-564`](../xpcrypt.c#L502-L564));
- the name-byte and abbreviation rules, including high bytes used by the
  Japanese database ([`xpcrypt.c:345-355`](../xpcrypt.c#L345-L355),
  [`xpcrypt.c:390-413`](../xpcrypt.c#L390-L413));
- the game/cheat/count record walk and every bounds check
  ([`xpcrypt.c:415-489`](../xpcrypt.c#L415-L489));
- database traversal order and clean termination.

Exposing `db_cursor_next()` would be a shallow interface: the caller would need
to learn cursor initialization, the record grammar, abbreviation encoding,
candidate selection, and clean termination. With `xp_db_visit()`, the edge sees
only decoded records and callback lifetimes. Deleting the module would force all
the hidden format knowledge back into its caller, which is evidence that the
module earns its depth.

The visitor is justified here because presentation is required to remain at the
CLI edge: the production adapter renders the current text format, while a
focused parser test can collect records without parsing presentation output.
Do not add separate callbacks for games, cheats, names, or code lines; one
record callback keeps the interface narrow.

### `rom_file.c/h`: file-oriented ROM commands

This module owns `read_rom()`, `extract_codes()`, `crypt_rom()`, and the
extraction-rendering helpers
([`xpcrypt.c:621-764`](../xpcrypt.c#L621-L764)). It depends on `crypto.h` and
`db.h`, and uses `code_stream.h` inside its database visitor.

```c
int xp_rom_file_convert(const char *input_path, const char *output_path,
		FILE *diag);
int xp_rom_file_extract(const char *input_path, FILE *out, FILE *diag);
```

These two operations are CLI-edge adapters, and they are deeper than a generic
`read_file()`/`write_file()`
interface. They hide buffer allocation, minimum-size validation, input-close
policy, normalization or automatic conversion, database status mapping, output
formatting and warnings, flushes, and cleanup. The exact `-x` presentation stays
here at the edge, including quoting, separators, and a fresh code stream for
each visited cheat; the README promises that output
([`README:87-89`](../README#L87-L89)). The current loader initializes its output, allocates one
buffer, transfers ownership on success, and frees on failure
([`xpcrypt.c:621-671`](../xpcrypt.c#L621-L671)); both current commands must then
remember to free it ([`xpcrypt.c:675-703`](../xpcrypt.c#L675-L703),
[`xpcrypt.c:709-763`](../xpcrypt.c#L709-L763)). Keeping ownership wholly inside
the new module removes that cross-command obligation from the interface.

`xp_rom_file_convert()` must preserve one non-obvious ordering invariant: fully
convert the input before opening the output, so a failed conversion cannot
truncate an existing destination or an in-place input
([`xpcrypt.c:727-755`](../xpcrypt.c#L727-L755)). It must also treat the final
`fclose()` as part of the write result
([`xpcrypt.c:745-755`](../xpcrypt.c#L745-L755)). These are part of the interface,
not incidental implementation details.

Do not introduce a generic filesystem port. Production and tests both use local
files, and the existing Python tests already create temporary files. A second
adapter does not exist.

### `xpcrypt.c`: composition root and CLI policy

After the moves, `xpcrypt.c` retains:

- application/version/help strings and getopt tables;
- mode and encryption-key selection;
- operand-count diagnostics; and
- calls to `xp_text_transform()`, `xp_rom_file_extract()`, or
  `xp_rom_file_convert()`.

That is the correct seam for CLI policy because the README exposes exactly
those four modes and their operand shapes
([`README:54-67`](../README#L54-L67), [`README:83-89`](../README#L83-L89)). It
should not know what constitutes a database name, how a payload advances, when
a ROM buffer is freed, or how a long text line is preserved.

## Dependency direction

```text
xpcrypt.c
  |---> text.c --------> code_stream.c ------> crypto.c
  |
  `---> rom_file.c ----> db.c
             |       |
             |       `-------> code_stream.c ---> crypto.c
             `---------------> crypto.c
```

More plainly:

- the CLI depends on command modules;
- command modules never depend on the CLI;
- text and the ROM-file extraction adapter share the code-stream interface;
- only the ROM-file module owns paths, `FILE *` opened from paths, and heap ROM
  buffers; and
- crypto remains the leaf module.

The `rom_file.c -> db.c` and `rom_file.c -> code_stream.c`
directions are intentional. Extraction composes database traversal with code
transformation at the CLI edge; neither core module learns about presentation,
paths, or diagnostics. Crypto must not learn the database format. The existing
`crypto.c` scope comment already says that
the CLI reads the database but the crypto implementation does not emulate it
([`crypto.c:27-54`](../crypto.c#L27-L54)).

## Error and ownership policy

Preserve behavior while making each fact local:

| Concern | Owner after the split | Required behavior |
|---|---|---|
| Low-level unsupported code/key | `xp_code_stream` | Leave the row as the crypto functions do and return an event; `xp_encrypt_code()` documents untouched error cases ([`crypto.h:43-53`](../crypto.h#L43-L53)). |
| User-facing code warnings | `xp_text` or `xp_rom_file` | Render stream events to the supplied `diag`; do not print inside the state machine or database parser. |
| Text read/write/flush error | `xp_text` | Print the current command-level error and return failure ([`xpcrypt.c:315-328`](../xpcrypt.c#L315-L328)). |
| No valid database | `xp_db`, mapped by `xp_rom_file` | Return `NOT_FOUND`; the edge distinguishes that from its own output failure so current messages remain accurate ([`xpcrypt.c:690-697`](../xpcrypt.c#L690-L697)). |
| ROM allocation and lifetime | `xp_rom_file` | One owning local buffer, freed on every exit; no ownership in its interface. |
| Input close failure | `xp_rom_file` | Preserve the current warning-only policy after a complete read ([`xpcrypt.c:667-671`](../xpcrypt.c#L667-L671)). |
| Output creation and final close | `xp_rom_file` | Open only after successful conversion; fail if writing or the final close fails ([`xpcrypt.c:727-755`](../xpcrypt.c#L727-L755)). |

Avoid a shared `xp_error` abstraction during the split. The existing program has
three sinks (`out`, `diag`, and a destination path), not multiple error adapters.
Enums are useful only where a caller must choose a different message, as with
database-not-found versus database-write-failed.

## Plausible seam sets compared

| Seam set | Depth and leverage | Locality | Verdict |
|---|---|---|---|
| Parser cursor only: move `db_*` cursor and locator into `db.c/h` | The parser becomes callable, but the interface exposes cursor setup, iteration, encoded names, record flags, and candidate selection. | Bounds checks improve in locality; decoding and cursor sequencing leak to the edge. | Better than today, but too shallow as the whole answer. |
| Mechanical helper split: `parse.c`, `format.c`, `io.c`, `db.c` | Many small interfaces mirror individual helpers. Callers still compose exact ordering and error rules, so little complexity disappears under any one interface. | Changes such as a new warning or output rule cross several files. | Reject. This organizes lines, not behavior. |
| One `xp_app.c` with `xp_run(argc, argv)` | One tiny interface hides almost everything, so nominal depth is high. | The 800-line implementation remains one place with unrelated reasons to change; tests still have no useful internal seam. | Reject. It renames the monolith. |
| Behavior-centered modules proposed above | Each interface has one or two operations. Shared stream semantics live once, text grammar stays with text I/O, database knowledge stays behind one traversal, and ROM ownership stays with file workflows. | A block bug changes `xp_code_stream`; a text grammar bug changes `xp_text`; a record-bound bug changes `xp_db`; an in-place write bug changes `xp_rom_file`. | Recommend. |

## Incremental migration order and existing coverage

Move code without changing behavior, one seam at a time. Update `OBJS` and
explicit header dependencies as each file appears; the root Makefile currently
knows only `xp_crypto.o` and `xpcrypt.o` and gives both the same header dependency
([`Makefile:6-18`](../Makefile#L6-L18)).

1) **Extract `code_stream.c/h`.** Keep the old static call shape temporarily,
   then replace the two callers. `oracle_test.py` exercises generated normal
   decrypt/encrypt paths ([`oracle_test.py:94-153`](oracle_test.py#L94-L153)),
   Supercode/Megacode payloads and row counts
   ([`oracle_test.py:156-239`](oracle_test.py#L156-L239)), and unbounded type A
   payloads in both directions
   ([`oracle_test.py:242-267`](oracle_test.py#L242-L267)). Its real-database pass
   runs one process per cheat specifically to enforce the reset boundary
   ([`oracle_test.py:310-345`](oracle_test.py#L310-L345)). The sanitizer fixture
   also walks ordinary, type 5, type 6, and type A state
   ([`Makefile:96-108`](Makefile#L96-L108)).

2) **Extract `text.c/h`.** The same oracle invokes the public binary through
   textual stdin and parses canonical stdout for every generated code
   ([`oracle_test.py:46-64`](oracle_test.py#L46-L64)). `roundtrip.py` exercises
   both directions and isolates cheats that contain block headers
   ([`roundtrip.py:35-71`](roundtrip.py#L35-L71)). Existing tests are strong on
   transformed code lines but do not directly assert comment/blank pass-through,
   embedded NUL, overlong-line chunking, or text I/O failure. Add focused cases
   for those existing contracts before moving this module; the implementation
   comments show why each case matters
   ([`xpcrypt.c:89-153`](../xpcrypt.c#L89-L153)).

3) **Extract `db.c/h` at the visitor seam.** `extract_test.py` builds a synthetic
   ROM with abbreviation bytes, an ordinary encrypted code, a bounded block, an
   inline block, and a following cheat that proves reset
   ([`extract_test.py:19-58`](extract_test.py#L19-L58)). It checks exact output
   for plaintext and encrypted input, all accepted option spellings, and a
   no-database error ([`extract_test.py:61-87`](extract_test.py#L61-L87)). With
   the private corpus, it checks all 15,349 lines in 11,718 cheats and identical
   plaintext/encrypted output
   ([`extract_test.py:145-182`](extract_test.py#L145-L182)). `fuzz_test.py`
   generates truncated, corrupted, edge-count, multiple-candidate, encrypted,
   and noisy ROMs ([`fuzz_test.py:100-140`](fuzz_test.py#L100-L140)); its gate
   requires sanitizer instrumentation and enough cases to reach the record walk
   ([`fuzz_test.py:182-231`](fuzz_test.py#L182-L231)).

4) **Extract `rom_file.c/h`.** The extraction tests above cover the load,
   plaintext-normalization, dump, and flush workflow. `fcdcrypt.py` checks
   `-r` in both directions at six lengths from 20 through 4097 bytes
   ([`fcdcrypt.py:70-103`](fcdcrypt.py#L70-L103)). No existing test directly
   covers in-place conversion, output-open timing, final-close failure, or the
   warning-only input-close policy. Add focused command tests for the first
   three before moving this module because they are observable safety behavior,
   not implementation detail.

5) **Reduce `xpcrypt.c` and make dependencies explicit.** Existing suites invoke
   default `-d`, `-e`, `-x`, long extraction spellings, `-r`, and `-V`
   ([`oracle_test.py:46-64`](oracle_test.py#L46-L64),
   [`extract_test.py:70-76`](extract_test.py#L70-L76),
   [`fcdcrypt.py:88-100`](fcdcrypt.py#L88-L100),
   [`fuzz_test.py:182-186`](fuzz_test.py#L182-L186)). They do not constitute a
   complete option-parser suite: help text, invalid keys, missing/extra operands,
   and option ordering need focused cases if `main()` itself is changed rather
   than merely shortened.

The research Makefile already serializes strict builds, sanitizer runs, fuzzing,
oracle comparison, extraction, round trips, and ROM transformation under one
`check` target ([`Makefile:62-78`](Makefile#L62-L78)). The root Makefile still has
no `check` target ([`../Makefile:10-23`](../Makefile#L10-L23)), so each migration
commit should explicitly run the relevant research targets until that separate
TODO is completed.

## Rejected or deferred alternatives

### Keep extraction presentation directly in `xpcrypt.c`

Presentation and diagnostic formatting should stay at the CLI edge, but the
composition root need not implement them. Keeping them in `xpcrypt.c` would
leave option policy mixed with quoting, separators, per-cheat stream lifetime,
and output failure. Put that edge adapter in `rom_file.c`, where it already
owns the extraction command's output and error transaction.

### Expose the database cursor directly

The current cursor is implementation-shaped. Exporting it would expose
initialization, encoded name slices, count-driven state, and end conditions. A
single `xp_db_visit()` traversal keeps those facts behind the seam while still
letting the CLI edge own presentation and errors.

### Create generic `xp_io.c/h`

`read_rom()` is reusable code, but a generic buffer reader would be a shallow
module: allocation, minimum-size policy, conversion-before-output, status
mapping, and cleanup would reappear in both callers. Put the two complete ROM
file workflows behind `rom_file.h` instead.

### Split `crypto.c/h` in the same series

Code crypto and ROM crypto are separate families in the header, and a later
split into `xp_code_crypto` and `xp_rom_crypto` could narrow compile-time
dependencies. It does not unlock the monolithic CLI refactor: callers already
use the small function interfaces, and the existing behavior-oriented test
suites exercise them through the binary. Defer that change so moves out of
`xpcrypt.c` remain reviewable and bisectable.

### Add dependency injection for libc I/O

All dependencies are either in-process computation or local files/streams.
Temporary files and `FILE *` already provide local substitutes in tests
([`extract_test.py:61-68`](extract_test.py#L61-L68),
[`fcdcrypt.py:84-92`](fcdcrypt.py#L84-L92)). New port and adapter types would
increase the interface without adding a second behavior.

## Expected end state

The split should leave these reasons to change:

| File | One primary reason to change |
|---|---|
| `xpcrypt.c` | CLI syntax or dispatch policy |
| `text.c/h` | textual code-stream syntax, pass-through, or text diagnostics |
| `code_stream.c/h` | stateful code/block transformation or row-level events |
| `db.c/h` | database framing, records, bounds, or name decoding |
| `rom_file.c/h` | ROM path I/O, extraction presentation, diagnostics, buffer ownership, or command transaction safety |
| `crypto.c/h` | recovered cipher or block equations |

That end state gives callers leverage through small interfaces and gives
maintainers locality without introducing hypothetical adapters. Most
importantly, it separates the two kinds of state that currently make
`xpcrypt.c` risky to edit: stream state is reset at cheat boundaries, while ROM
memory is owned for exactly one file command.
