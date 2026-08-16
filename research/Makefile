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
#   make firmware   the nine firmwares agree with each other
#   make engine     the code engine, executed out of all nine images
#   make tables     the published tables, regenerated
#   make analyses   the published counts: COMP01, per-route diff, DB scan,
#                   COMP01 escape rarity, the default-off bit
#   make strict     the C builds under the strict warning set
#   make sanitize   ... and runs clean under ASan/UBSan
#   make fuzz       ... and on malformed ROMs too: `-x` against generated images
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

.PHONY: all check crypto blocks oracle extract roundtrip encrypt fcd firmware engine \
	tables analyses strict sanitize fuzz clean

# Every C target builds the *same* objects and binary in the parent directory,
# with different flags - `strict` twice over, `sanitize` with the sanitizers,
# and `oracle`/`roundtrip` need a plain one to exist while they run. Under -j
# they trip over each other: `make -j4 check` fails with a missing ../xpcrypt
# or a half-sanitized link. Giving each target its own build tree would be the
# other way out; one shared tree and no parallelism is the smaller answer.
.NOTPARALLEL:

all: check

check: strict sanitize fuzz oracle extract roundtrip encrypt fcd firmware engine \
	tables analyses
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
# all 3,920 of their functions under an emulator, and holds the six encrypters it
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

# The interesting one: this executes the real 0x24C-byte engine blob out of each
# image over a fixed set of staged patch lists and compares the resulting memory
# traces across all nine.  engineemu.py fails if the number of disagreeing cases
# is not the expected two - type 4, which the FX builds dropped.
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

clean:
	@$(RM) sanitize.out sanitize.err
	@$(RM) -r __pycache__ fuzz-crashes
	@$(MAKE) -C $(ROOT) clean >/dev/null
