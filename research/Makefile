# Verification rig for the Xploder research.
#
# Everything the notes claim is meant to be re-derivable by running something.
# This is that something.  `make` runs the suites listed below; each also stands
# on its own.  It is not the whole directory - the one-off scripts that produced
# a single paragraph are not here, only the results the notes lean on.
#
#   make            every target below
#   make crypto     xpcrypt against the firmware's own crypto routines
#   make extract    ROM database location, extraction and bounded decryption
#   make roundtrip  ... and against itself, over every recovered database code
#   make encrypt    the encrypt side, against the vendor's own encrypter
#   make fcd        the .fcd image cipher against the PC tools' own routines
#   make comms      the X-Link parallel-port protocol, PC and cartridge ends
#   make firmware   the nine firmwares agree with each other
#   make engine     the code engine, executed out of all nine images
#   make tables     the published tables, regenerated
#   make analyses   the published counts: COMP01, per-route diff, DB scan,
#                   COMP01 escape rarity, the default-off bit
#   make strict     the C builds under the strict warning set
#   make sanitize   ... and runs clean under ASan/UBSan
#   make fuzz       ... and on malformed ROMs too: `-x` against generated images
#   make typecx     ENGINE.md 16's two open questions: type 2 and type C
#   make plugin     the FCDEXE1138 memory-card upgrade loader, every image
#   make prechain   what lies in front of the record chains
#   make fxdb       the FX databases: LZW-packed, decoded and counted
#   make rom2005    release 2.005, the tenth image, against the corpus
#   make payloads   the shipped block payloads, disassembled
#   make selfdestruct  the copyright check executed under a flash model
#
# The ROM images are cartridge firmware dumps and are not in the repo (see
# research/.gitignore).  Drop them in roms/ to enable the targets that need
# them; without roms/ the crypto suite still runs against romcrypt.py and the
# rest skip with a note rather than failing.

# Most suites here are a Python program piped through a filter to keep the output
# short, and a pipeline reports the *filter's* status - so a crashed suite reads
# as a pass unless the shell is told otherwise.  `.SHELLFLAGS` would be the tidy
# way; make 3.81, which is what macOS ships, does not have it.  Hence bash plus
# $(P) on every filtered suite pipeline.  The exceptions need no prefix:
# `strict` and `sanitize` are C builds, and `oracle` prints its own five lines
# unfiltered.
# Check it still bites:  make firmware PYCS=false   must fail.
SHELL = /bin/bash
P     = set -o pipefail;

PY      = uv run python
PYCS    = uv run --with capstone python        # needs a disassembler
PYEMU   = uv run --with capstone --with unicorn python   # ... and an emulator
ROOT    = ..
ROMS    = $(wildcard roms/*)

# Two compilers, whatever they turn out to be.  On macOS `gcc` is Apple Clang,
# so the targets below report what each one says it is instead of assuming that
# two names mean two implementations.  Point CC1/CC2 at anything you like:
#   make strict CC2=gcc-14
CC1     = cc
CC2     = clang
STRICT  = -std=c99 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion \
	  -Werror -O2
SANFLAGS = -std=c99 -g -O1 -Wall -fsanitize=address,undefined \
	   -fno-omit-frame-pointer

# Every ROM-fed target routes through this, so a missing roms/ reads as "not
# run" instead of a traceback.
ifeq ($(ROMS),)
need_roms = @echo '  skipped: no roms/ - drop the firmware dumps in and re-run'
endif

.PHONY: all check crypto blocks oracle extract roundtrip encrypt fcd comms firmware engine \
	tables analyses plugin prechain fxdb rom2005 payloads typecx selfdestruct strict sanitize \
	fuzz clean

# Every C target builds the *same* objects and binary in the parent directory,
# with different flags - `strict` twice over, `sanitize` with the sanitizers,
# and `oracle`/`roundtrip` need a plain one to exist while they run. Under -j
# they trip over each other: `make -j4 check` fails with a missing ../xpcrypt
# or a half-sanitized link. Giving each target its own build tree would be the
# other way out; one shared tree and no parallelism is the smaller answer.
.NOTPARALLEL:

all: check

check: strict sanitize fuzz oracle extract roundtrip encrypt fcd comms firmware engine \
	tables analyses plugin prechain fxdb rom2005 payloads typecx selfdestruct
	@echo
	@echo 'all suites passed'

# ---------------------------------------------------------------- the C side

# Build twice under the strict set.  Two *names*, which on a given host may or
# may not be two implementations - hence the version line: read it before
# believing this covers your compiler.
strict:
	@echo '== strict C99 builds =='
	@for cc in $(CC1) $(CC2); do \
		printf '  %-8s %s\n' "$$cc" "$$($$cc --version | head -1)"; \
		$(MAKE) -C $(ROOT) clean >/dev/null; \
		$(MAKE) -C $(ROOT) CC=$$cc CFLAGS='$(STRICT)' >/dev/null \
			|| exit 1; \
		echo '           -Werror: clean'; \
	done
	@$(MAKE) -C $(ROOT) clean >/dev/null

# The README's own sample plus one of each block type, decrypted under the
# sanitizers.  The block rows are the reason this exists: an ordinary code is
# handled statelessly, so only a Supercode, a Megacode and an inline data block
# walk the payload state machine and can walk off the end of it.
sanitize:
	@echo '== ASan/UBSan =='
	@$(MAKE) -C $(ROOT) clean >/dev/null
	@$(MAKE) -C $(ROOT) CC=$(CC2) CFLAGS='$(SANFLAGS)' >/dev/null
	@$(ROOT)/xpcrypt < fixture.codes > sanitize.out 2> sanitize.err
	@diff -u fixture.expect sanitize.out
	@grep -q 'code type A' sanitize.err   # the unbounded-block warning fired
	@echo '  ordinary, 5, 6 and A fixtures decrypt correctly, no reports'
	@$(RM) sanitize.out sanitize.err
	@$(MAKE) -C $(ROOT) clean >/dev/null

# `sanitize` above runs well-formed input through the payload state machine.
# This runs malformed *ROMs* through the database reader, which is the one part
# of xpcrypt that walks embedded lengths and names out of a buffer instead of
# fixed six-byte codes - so it is the one that can be walked off the end of.
# The images are generated here, so this needs no roms/.
#
# fuzz_test.py refuses a binary without the sanitizer runtime and fails if too
# few of its images reach the reader: "no crashes" from a plain build, or from
# a generator that stopped producing anything the parser accepts, is not a
# result.  Turn it up for a real soak:  make fuzz FUZZCASES=100000
FUZZCASES = 4000
fuzz:
	@echo '== malformed ROMs through the database reader =='
	@$(MAKE) -C $(ROOT) clean >/dev/null
	@$(MAKE) -C $(ROOT) CC=$(CC2) CFLAGS='$(SANFLAGS)' >/dev/null
	@$(PY) fuzz_test.py --cases $(FUZZCASES)
	@$(MAKE) -C $(ROOT) clean >/dev/null

# ------------------------------------------------------------ the crypto side

# oracle_test.py is one program with six suites; the first five need no ROMs at
# all, the sixth widens to the databases when roms/ is populated.
crypto blocks: oracle          # both names lead here
oracle:
	@echo '== xpcrypt vs the firmware crypto =='
	@$(MAKE) -C $(ROOT) >/dev/null
	@$(PY) oracle_test.py

extract:
	@echo '== ROM database extraction =='
	@$(MAKE) -C $(ROOT) >/dev/null
	@$(PY) extract_test.py

# The other half of the encrypt side: the cartridge cannot check it, so check
# that xpcrypt decrypts what it encrypted, over every code the databases ship.
roundtrip:
	@echo '== xpcrypt -e K | xpcrypt -d, every database code =='
	@$(MAKE) -C $(ROOT) >/dev/null
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PY) roundtrip.py | tail -1
endif

# The half of the code cipher the cartridge does not have. xpcrypt's encrypt side
# was written as the algebraic inverse of the firmware's decrypt, so `roundtrip`
# above can only check it against itself. The vendor's DOS tool has a real one:
# this finds it - and every other code cipher in the four PC binaries - by running
# all 3,920 call-target candidates under an emulator, and holds the six encrypters it
# finds against `xpcrypt -e` code for code. See ENCRYPT.md.
encrypt:
	@echo '== the code cipher in the PC tools =='
	@$(MAKE) -C $(ROOT) >/dev/null
	@$(P) $(PYEMU) xcode.py -q | tail -1

# The other cipher: the whole-image transform between a .fcd file and a plaintext
# ROM.  Three checks - xpcrypt against the closed form in both directions (with
# lengths on both sides of its former 512-byte minimum), against every image pair
# when roms/ is there, and against the PC tools' own routines when pc/ is.  That
# last one runs their machine code under an emulator rather than reading it.  See
# FCD.md.
fcd:
	@echo '== the .fcd image cipher =='
	@$(MAKE) -C $(ROOT) >/dev/null
	@$(PY) fcdcrypt.py
	@$(P) $(PYEMU) xlink.py | tail -2

# The X-Link parallel-port protocol, both ends: the PC's byte primitives and
# command opcodes out of XLink.exe, the cartridge's dispatcher and jump table
# out of every firmware, the opcodes matched across the wire, and the read sizes
# of the PC ends (DOS 256 KB, both Windows builds the full 512 KB into
# ROMS\BackUp.FCD).  Runs on whichever of pc/ and roms/ are present.  See
# comms.py's header.  Check it still bites:  make comms PYCS=false   must fail.
comms:
	@echo '== the X-Link comms protocol, both ends =='
	@$(P) $(PYCS) comms.py | tail -3

# Do the nine firmwares implement the same cipher?  Runs each one's routines
# against the others over every key setting.
firmware:
	@echo '== the nine firmwares against each other =='
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PYCS) fxtest.py | tail -1
	@$(P) $(PYCS) fxprot.py | grep -c live | sed 's/^/  copyright checkers found: /'
endif

# ------------------------------------------------------------ the engine side

# The interesting one: this executes the real engine blob out of each of the ten
# images over a fixed set of staged patch lists and compares the resulting memory
# traces.  engineemu.py fails if the number of disagreeing cases is not the
# expected two - type 4, which the FX builds dropped.  It also runs each image's
# own four staging passes over real selections, the pass-4 normaliser over a set
# of codes, and asserts the FX-only DCIC clear on the B() entry, each on its own.
engine:
	@echo '== the code engine, executed =='
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PYCS) engineemu.py | tail -1
	@$(PYCS) engine.py
endif

# The tables in the notes, regenerated: which types the staging code classifies,
# and how often each type occurs in the recovered databases.
tables:
	@echo '== published tables =='
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PYCS) engine.py -s | grep 'andi sites'
	@$(PY) dbtypes.py
endif

# The remaining published numbers: what COMP01 spends its opcodes on, the static
# per-route diff behind the nine-way equivalence claim, the database scan the
# type counts are drawn from, and the cross-database payload oracle.
analyses:
	@echo '== published analyses =='
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PYCS) packstats.py | grep 're-pack'
	@$(P) $(PYCS) fxcmp.py | grep -c 'identical to' \
		| sed 's/^/  crypto routes byte-identical to the V2 baseline: /'
	@$(P) $(PYCS) audit2.py | tail -1
	@$(P) $(PY) xcheck.py | tail -1
	@$(P) $(PY) escrank.py | tail -1
	@$(P) $(PY) defaultoff.py | grep 'wrong address'
endif

# The FCDEXE1138 loader: every firmware runs an unsigned executable from a
# memory-card save.  plugin.py finds the one reference to the filename in each
# image and walks the routine to the jalr, asserting the file-header offsets it
# trusts (load address at +0x44, block count at +0x03) and that the path from
# read to execute is straight-line - nothing checks the bytes.  Runs on the
# tenth image (pc/ROMS) even with roms/ empty; skips only if no image is present.
# What lies between the packed firmware and the record chains (nothing lost -
# pad, erased flash, the support module, and the FX database container), and the
# tenth image, release 2.005: the one whose database `-x` cannot read because a
# single game record declares zero cheats.  Both need firmware dumps; rom2005
# also needs the 2.005 image bundled under pc/ROMS/.
prechain:
	@echo '== in front of the record chains =='
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PYCS) prechain.py | tail -1
endif

# Where each firmware keeps its codes.  V2: the record chain the support module
# points at.  FX: the same pointer names an LZW-packed container, which this
# decodes twice - with its own 14-bit decoder and by running the firmware's own
# decompressor under fwemu.py - and requires the two to agree byte for byte
# before it counts the records.  FINDINGS.md 6.3.
fxdb:
	@echo '== the FX databases, unpacked =='
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PYCS) fxdb.py | tail -1
endif

rom2005:
	@echo '== release 2.005, the tenth image =='
ifeq ($(wildcard pc/ROMS/Xteng.fcd),)
	@echo '  skipped: no pc/ROMS/Xteng.fcd'
else
	@$(MAKE) -C $(ROOT) >/dev/null
	@$(P) $(PYCS) rom2005.py | tail -1
endif

# The actual contents of the shipped Supercode/Megacode/type-A blocks,
# disassembled: what each embedded program does, which ten of the 65 blocks are
# corrupt as shipped (payload rows re-enciphered as if they were ordinary
# codes), and that XLink.exe carries the generators' assembled templates.
payloads:
	@echo '== the shipped block payloads, disassembled =='
	@$(MAKE) -C $(ROOT) >/dev/null
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PYCS) payloads.py | tail -1
endif

# The anti-tamper self-destruct, executed (not read): each image's real decrypt
# routine run under fwemu.py with the checker left LIVE and the cartridge modelled
# as the page-erasing flash parts the firmware identifies (Atmel AT29C device
# codes, or SST via SST's alternate ID entry).  Nine of ten images program 96 KB
# of PSX RAM over their own flash on a header mismatch; release 2.14 does it on a
# stock, unmodified cartridge as soon as a key-7 or Special32 code is activated
# (its check string predates its own database header).  No row of its shipped
# database takes either route.
selfdestruct:
	@echo '== the self-brick, executed under a flash model =='
	$(need_roms)
ifneq ($(ROMS),)
	@$(P) $(PYCS) selfdestruct.py | tail -1
endif

plugin:
	@echo '== the FCDEXE1138 memory-card code loader =='
	@$(PYCS) plugin.py

# ENGINE.md 16's two open questions - what type 2 was and where the Japanese
# type C joker codes came from.  Ten images (the nine in roms/ plus the 2.005
# the DOS tool ships), six databases, the type C specimens decoded three ways,
# and FCD's own joypad table and joker generator read out of XLink.exe.  Skips
# its corpus-wide counts, loudly, when roms/ or pc/ is incomplete.
typecx:
	@echo '== type 2 and type C =='
	@$(PYCS) typecx.py

clean:
	@$(RM) sanitize.out sanitize.err
	@$(RM) -r __pycache__ fuzz-crashes
	@$(MAKE) -C $(ROOT) clean >/dev/null
