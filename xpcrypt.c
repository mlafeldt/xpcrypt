/*
 * xpcrypt.c - Main project file
 *
 * Copyright (C) 2007, 2009 misfire <misfire@xploderfreax.de>
 * All rights reserved.
 *
 * This file is part of xpcrypt, the Xploder PSX Crypto Tool.
 *
 * xpcrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * xpcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with xpcrypt.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "crypto.h"
#include "lzw.h"

/* Application's name and current version */
#define APP_NAME	"xpcrypt"
#define APP_VERSION	"1.1"

/* Text displayed for -h option */
#define HELP_TEXT \
	"Usage: "APP_NAME" [options] [input ROM] [output ROM]\n" \
	"Program to decrypt and encrypt Xploder PSX codes and ROMs\n" \
	"Options are:\n" \
	" -d/--decrypt-codes        decrypt codes (default)\n" \
	" -e/--encrypt-codes <key>  encrypt codes with key [4,5,6,7]\n" \
	" -x/--extract-codes        extract and decrypt codes from a ROM\n" \
	" -r/--rom                  decrypt or encrypt ROM\n" \
	" -h/--help                 display this information\n" \
	" -V/--version              display the version of "APP_NAME"\n\n" \
	"Bug reports and suggestions to <misfire@xploderfreax.de>.\n"

/* Text displayed for -v option */
#define VERSION_TEXT \
	APP_NAME" version "APP_VERSION"\n" \
	"Copyright (C) 2007, 2009 misfire <misfire@xploderfreax.de>\n" \
	"This program is free software; you may redistribute it under the terms of\n" \
	"the GNU General Public License.  This program has absolutely no warranty.\n"

/* Short and long options accepted by getopt */
static const char *shortopts = "de:xrhV";
static const struct option longopts[] = {
	{ "decrypt-codes", no_argument, NULL, 'd' },
	{ "encrypt-codes", required_argument, NULL, 'e' },
	{ "extract-codes", no_argument, NULL, 'x' },
	{ "rom", no_argument, NULL, 'r' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 }
};

/* Program modes */
enum {
	MODE_DECRYPT_CODES,
	MODE_ENCRYPT_CODES,
	MODE_EXTRACT_CODES,
	MODE_CRYPT_ROM
};

/* A code is written as XXXXXXXX XXXX - two hex digits per byte. */
#define XP_CODE_DIGITS	(XP_CODE_LEN * 2)

/*
 * Value of a character that isxdigit() has already accepted.
 */
static u8 hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return (u8)(c - '0');

	return (u8)(tolower((unsigned char)c) - 'a' + 10);
}

/*
 * Parse the @len bytes at @s into the six bytes of a cheat code. Returns
 * non-zero if they are a code, in which case @code holds it; a line that is
 * not a code is left for the caller to pass through untouched.
 *
 * Whitespace is a separator only: the bytes come from the digits themselves,
 * in order, so where the spaces fall cannot change them. Reading the digits
 * left to right in fixed-width pairs instead - the obvious sscanf() - is what
 * makes that untrue, because each conversion skips whatever whitespace it
 * starts on. "1 23456789 ABC" has the twelve digits a code needs, and used to
 * come out as 01234567 89AB with the last one silently dropped.
 */
static int parse_code(const char *s, size_t len, u8 *code)
{
	char hex[XP_CODE_DIGITS];
	int digits = 0;
	int i;

	if (s == NULL)
		return 0;

	while (len--) {
		/*
		 * char may be signed, and the ctype functions are only defined
		 * for the values of an unsigned char and EOF - handing one of
		 * them a negative value other than EOF is undefined, whatever
		 * a particular library happens to do with it.
		 */
		unsigned char c = (unsigned char)*s;

		if (isxdigit(c)) {
			if (digits == XP_CODE_DIGITS)
				return 0;
			hex[digits++] = (char)c;
		}
		else if (!isspace(c)) {
			return 0;
		}
		s++;
	}

	if (digits != XP_CODE_DIGITS)
		return 0;

	for (i = 0; i < XP_CODE_LEN; i++)
		code[i] = (u8)((hex_digit(hex[i * 2]) << 4) |
				hex_digit(hex[i * 2 + 1]));

	return 1;
}

/*
 * Read one line of stdin into @buf, at most @size - 1 of its bytes, and store
 * how many in @len. Returns 1 for a line, 0 for the end of the input, -1 for a
 * read error. @ends_line says whether the line ended here or is longer than
 * the buffer and continues into the following calls.
 *
 * fgets() cannot tell us that: it hands back a chunk that looks exactly like a
 * short line. Nothing that arrives in pieces is a code, and the pieces have to
 * go out as they came in.
 *
 * @len is what the caller works from, rather than the terminator this leaves
 * behind for safety's sake: a line may contain a NUL byte, and "%s" would drop
 * the rest of it.
 */
static int read_line(char *buf, size_t size, size_t *len, int *ends_line)
{
	size_t n = 0;
	int c;

	while ((c = getc(stdin)) != EOF) {
		buf[n++] = (char)c;
		if (c == '\n' || n == size - 1)
			break;
	}

	if (ferror(stdin))
		return -1;
	if (n == 0)
		return 0;

	buf[n] = '\0';
	*len = n;
	/*
	 * A line that stopped on the last byte of the buffer may well have been
	 * about to end anyway, but the only way to find out is to read on. Call
	 * it unfinished: being passed through when it did not have to be costs
	 * a code line nothing, and being taken for a code costs it everything.
	 */
	*ends_line = buf[n - 1] == '\n' || feof(stdin);

	return 1;
}

/* Direction of a pass over codes. */
enum direction {
	DECRYPT,
	ENCRYPT
};

/*
 * What processing a code turned up. crypt_code() and end_code_stream() return
 * a set of them, EV(event) for each. Most are codes the cartridge will run
 * differently from what their text says. The stream itself does no I/O: the
 * text filter prints a warning per event, and -x counts them and reports each
 * kind once for the database. The order is the order the warnings come out in.
 */
enum code_event {
	EV_UNKNOWN_KEY,		/* block whose payload key we lack */
	EV_LEFT_CLEAR,		/* code the Xploder doesn't encrypt */
	EV_DEFAULT_OFF,		/* default-off bit kept, keyed type */
	EV_DEFAULT_OFF_COPY,	/* ... on a type that takes no key */
	EV_SPECIAL32,		/* route xpcrypt leaves undone */
	EV_SPECIAL33,		/* ditto */
	EV_NO_CIPHER_HEADER,	/* block header with key bits 1-3 */
	EV_NO_CIPHER,		/* code with key bits 1-3 */
	EV_EMPTY_BLOCK,		/* block declaring no payload */
	EV_INLINE,		/* type A: payload to the end */
	EV_CUT_SHORT,		/* payload ended before its length */
	NUM_EVENTS
};

#define EV(event)	(1u << (event))

/* State shared by the text-code reader and one extracted cheat entry. */
struct code_stream {
	struct xp_block blk;
	int index;
	enum direction dir;
	enum xp_key key;
	u8 in[XP_CODE_LEN];		/* the last code row, as it came in */
	u8 out[XP_CODE_LEN];		/* ... and as it went out */
	u8 header[XP_CODE_LEN];		/* the current block's header, as it came in */
};

static void init_code_stream(struct code_stream *stream, enum direction dir,
		enum xp_key key)
{
	stream->index = -1;
	stream->dir = dir;
	stream->key = key;
}

/* The last code as the Xploder stores it, and as xpcrypt shows it. */
static const u8 *stored_code(const struct code_stream *stream)
{
	return stream->dir == DECRYPT ? stream->in : stream->out;
}

static const u8 *plain_code(const struct code_stream *stream)
{
	return stream->dir == DECRYPT ? stream->out : stream->in;
}

/*
 * Start a block if the last code is a header with payload rows below it.
 * Returns the events that says, and sets @started.
 */
static unsigned start_block(struct code_stream *stream, int *started)
{
	unsigned events = 0;

	*started = 0;
	if (xp_parse_block(plain_code(stream), &stream->blk))
		return 0;
	if (stream->blk.declared == 0)
		events |= EV(EV_EMPTY_BLOCK);
	if (!xp_in_payload(&stream->blk, 0))
		return events;

	stream->index = 0;
	memcpy(stream->header, stream->in, XP_CODE_LEN);
	*started = 1;
	if (!stream->blk.known_key)
		events |= EV(EV_UNKNOWN_KEY);
	if (stream->blk.kind == XP_BLOCK_INLINE)
		events |= EV(EV_INLINE);
	return events;
}

/*
 * What the cartridge will make of @stored, the code as the Xploder gets it.
 */
static unsigned check_code(const struct code_stream *stream, const u8 *stored,
		int header)
{
	enum xp_route route = xp_code_route(stored);
	unsigned events = 0;

	/*
	 * The Xploder clears the default-off bit along with the key, so it
	 * never reaches the code engine - except on a code stored without a
	 * key: the copy route leaves it, and the engine, which masks only the
	 * type nibble off, adds 0x08000000 to the address. Encrypting the code
	 * with any key is what clears it, for a type that takes one.
	 */
	if ((stored[0] & (XP_DEFAULT_OFF | XP_KEY_MASK)) == XP_DEFAULT_OFF &&
			xp_code_addressed(stored))
		events |= route == XP_ROUTE_COPY ? EV(EV_DEFAULT_OFF_COPY) :
			EV(EV_DEFAULT_OFF);

	/*
	 * Key bits 1 to 3 select no cipher: the Xploder copies the code as
	 * stored, and the engine reads the bits as part of the address - or
	 * takes a block header's size as stored. 32/82 and 33/83 have routes
	 * of their own instead, which xpcrypt leaves undone. A code we encrypt
	 * never carries such bits; one we could not is reported as such.
	 */
	if (stream->dir == DECRYPT) {
		if (route == XP_ROUTE_SPECIAL32)
			events |= EV(EV_SPECIAL32);
		else if (route == XP_ROUTE_SPECIAL33)
			events |= EV(EV_SPECIAL33);
		else if (route == XP_ROUTE_NO_CIPHER)
			events |= header ? EV(EV_NO_CIPHER_HEADER) : EV(EV_NO_CIPHER);
	}

	return events;
}

/*
 * Process one code in a stream, in place. Returns the events it turned up.
 *
 * A block starts on the type a header is stored with, before anything is
 * decrypted, and takes its size and payload key from the decrypted header -
 * which is how the Xploder stages it. Key bits 1 to 3 select no cipher, so a
 * header carrying them is taken as stored, and the codes below it are payload.
 */
static unsigned crypt_code(u8 *code, struct code_stream *stream)
{
	unsigned events = 0;
	int started;

	if (stream->index >= 0) {
		/* This row is raw block payload, not a code of its own. */
		if (stream->dir == DECRYPT)
			xp_decrypt_block_line(code, &stream->blk, stream->index);
		else
			xp_encrypt_block_line(code, &stream->blk, stream->index);

		if (!xp_in_payload(&stream->blk, ++stream->index))
			stream->index = -1;
		return 0;
	}

	memcpy(stream->in, code, XP_CODE_LEN);
	if (stream->dir == DECRYPT)
		xp_decrypt_code(code, stream->key);
	else if (xp_encrypt_code(code, stream->key))
		events |= EV(EV_LEFT_CLEAR);
	memcpy(stream->out, code, XP_CODE_LEN);

	events |= start_block(stream, &started);
	events |= check_code(stream, stored_code(stream), started);
	return events;
}

/*
 * End a code stream, at the end of the input or of a cheat. A block whose
 * payload has not ended by then was cut short.
 */
static unsigned end_code_stream(const struct code_stream *stream)
{
	return stream->index >= 0 && stream->blk.kind != XP_BLOCK_INLINE ?
		EV(EV_CUT_SHORT) : 0;
}

#define CODE_FMT	"%02X%02X%02X%02X %02X%02X"
#define CODE_ARGS(c)	(c)[0], (c)[1], (c)[2], (c)[3], (c)[4], (c)[5]

/* Say what the last code of @stream turned up, one warning per event. */
static void print_events(const struct code_stream *stream, unsigned events)
{
	const u8 *stored = stored_code(stream);

	if (events & EV(EV_UNKNOWN_KEY))
		fprintf(stderr, "Warning: unknown payload key %i, payload of "
			"block left as it is\n", stream->blk.payload_key);
	if (events & EV(EV_LEFT_CLEAR))
		fprintf(stderr, "Warning: the Xploder doesn't encrypt code "
			CODE_FMT ", left as it is\n", CODE_ARGS(stream->out));
	if (events & EV(EV_DEFAULT_OFF))
		fprintf(stderr, "Warning: " CODE_FMT " is switched off by "
			"default but carries no key, so the Xploder applies it "
			"0x08000000 away from its address - encrypting it with "
			"any key clears the bit\n", CODE_ARGS(stored));
	if (events & EV(EV_DEFAULT_OFF_COPY))
		fprintf(stderr, "Warning: " CODE_FMT " is switched off by "
			"default but carries no key, so the Xploder applies it "
			"0x08000000 away from its address\n", CODE_ARGS(stored));
	if (events & EV(EV_SPECIAL32))
		fprintf(stderr, "Warning: " CODE_FMT " takes the Xploder's "
			"Special32 route, which xpcrypt does not implement\n",
			CODE_ARGS(stored));
	if (events & EV(EV_SPECIAL33))
		fprintf(stderr, "Warning: " CODE_FMT " takes the Xploder's "
			"Special33 route, which xpcrypt does not implement\n",
			CODE_ARGS(stored));
	if (events & EV(EV_NO_CIPHER_HEADER))
		fprintf(stderr, "Warning: " CODE_FMT " has key bits %i, which "
			"select no cipher - the Xploder takes this block header as "
			"stored, size and all\n", CODE_ARGS(stored),
			stored[0] & XP_KEY_MASK);
	if (events & EV(EV_NO_CIPHER))
		fprintf(stderr, "Warning: " CODE_FMT " has key bits %i, which "
			"select no cipher - the Xploder reads them as part of the "
			"address\n", CODE_ARGS(stored), stored[0] & XP_KEY_MASK);
	if (events & EV(EV_EMPTY_BLOCK))
		fprintf(stderr, "Warning: " CODE_FMT " declares an empty "
			"payload, which hangs the Xploder's code engine\n",
			CODE_ARGS(plain_code(stream)));
	if (events & EV(EV_INLINE))
		fprintf(stderr, "Warning: code type A has no payload length, "
			"all following codes are treated as its payload\n");
	if (events & EV(EV_CUT_SHORT))
		fprintf(stderr, "Warning: " CODE_FMT " ends after %i of the %i "
			"payload codes it declares\n", CODE_ARGS(stream->header),
			stream->index, stream->blk.num_lines);
}

/*
 * What -x says about a whole database, once per kind of event: the rest of
 * the sentence after the count, for one and for several. An event without an
 * entry is not reported there: a cheat ends every type A block, and -x only
 * decrypts.
 */
static const struct {
	const char *one;
	const char *many;
} summaries[NUM_EVENTS] = {
	[EV_UNKNOWN_KEY] = {
	  "block in this database has an unknown payload key, so its payload "
	  "is left as it is",
	  "blocks in this database have an unknown payload key, so their "
	  "payload is left as it is" },
	[EV_DEFAULT_OFF] = {
	  "code in this database is switched off by default but carries no "
	  "key, so the Xploder applies it 0x08000000 away from its address - "
	  "encrypting it with any key clears the bit",
	  "codes in this database are switched off by default but carry no "
	  "key, so the Xploder applies them 0x08000000 away from their address "
	  "- encrypting them with any key clears the bit" },
	[EV_DEFAULT_OFF_COPY] = {
	  "code in this database is switched off by default but carries no "
	  "key, so the Xploder applies it 0x08000000 away from its address",
	  "codes in this database are switched off by default but carry no "
	  "key, so the Xploder applies them 0x08000000 away from their "
	  "address" },
	[EV_SPECIAL32] = {
	  "code in this database takes the Xploder's Special32 route, which "
	  "xpcrypt does not implement",
	  "codes in this database take the Xploder's Special32 route, which "
	  "xpcrypt does not implement" },
	[EV_SPECIAL33] = {
	  "code in this database takes the Xploder's Special33 route, which "
	  "xpcrypt does not implement",
	  "codes in this database take the Xploder's Special33 route, which "
	  "xpcrypt does not implement" },
	[EV_NO_CIPHER_HEADER] = {
	  "block header in this database has key bits that select no cipher, "
	  "so the Xploder takes it as stored, size and all",
	  "block headers in this database have key bits that select no cipher, "
	  "so the Xploder takes them as stored, size and all" },
	[EV_NO_CIPHER] = {
	  "code in this database has key bits that select no cipher, which "
	  "the Xploder reads as part of the address",
	  "codes in this database have key bits that select no cipher, which "
	  "the Xploder reads as part of the address" },
	[EV_EMPTY_BLOCK] = {
	  "block in this database declares an empty payload, which hangs the "
	  "Xploder's code engine",
	  "blocks in this database declare an empty payload, which hangs the "
	  "Xploder's code engine" },
	[EV_CUT_SHORT] = {
	  "block in this database ends before the payload it declares",
	  "blocks in this database end before the payload they declare" }
};

/* Count each event of @events in @counts. */
static void count_events(unsigned long *counts, unsigned events)
{
	int i;

	for (i = 0; i < NUM_EVENTS; i++)
		if (events & EV(i))
			counts[i]++;
}

/* Say once per kind what a whole database turned up. */
static void print_summaries(const unsigned long *counts)
{
	int i;

	for (i = 0; i < NUM_EVENTS; i++)
		if (counts[i] && summaries[i].one != NULL)
			fprintf(stderr, "Warning: %lu %s\n", counts[i],
				counts[i] == 1 ? summaries[i].one :
				summaries[i].many);
}

static int print_code(const u8 *code)
{
	return printf("%02X%02X%02X%02X %02X%02X\n", code[0], code[1],
		code[2], code[3], code[4], code[5]) < 0 ? -1 : 0;
}

/*
 * Decrypt or encrypt Xploder codes.
 */
static int crypt_codes(enum direction dir, enum xp_key key)
{
	char line[2048];
	size_t len = 0;
	u8 code[XP_CODE_LEN];
	struct code_stream stream;
	int begins_line = 1; /* The line before this one ended where it should */
	int ends_line = 1;
	int ret;

	/*
	 * Read codes from stdin, decrypt or encrypt them,
	 * and write them to stdout.
	 */
	setbuf(stdin, NULL);
	init_code_stream(&stream, dir, key);

	while ((ret = read_line(line, sizeof(line), &len, &ends_line)) == 1) {
		/* Only a line we have the whole of can be a code. */
		int whole_line = begins_line && ends_line;

		begins_line = ends_line;

		/* Simply output the line if it's not a code. */
		if (!whole_line || !parse_code(line, len, code)) {
			if (fwrite(line, 1, len, stdout) != len)
				break;
			continue;
		}

		/*
		 * A Supercode or Megacode says how long its payload is, so we
		 * can tell where it ends. The payload of a code type A runs to
		 * the end of the cheat, a boundary text input does not carry -
		 * unlike the ROM database, whose records end where the cheat
		 * does.
		 */
		print_events(&stream, crypt_code(code, &stream));

		if (print_code(code))
			break;
	}

	print_events(&stream, end_code_stream(&stream));

	/*
	 * stdout is buffered, so a write that fails may not fail until the
	 * flush. That and a read error both lose codes without saying so.
	 */
	if (ret < 0) {
		fprintf(stderr, "Error: could not read from stdin\n");
		return -1;
	}
	if (fflush(stdout) != 0 || ferror(stdout)) {
		fprintf(stderr, "Error: could not write to stdout\n");
		return -1;
	}

	return 0;
}

/*
 * Write @text to stdout and make sure it got there. -h and -V are output too:
 * a redirect that fails loses them just as quietly as it would lose a code.
 */
static int print_out(const char *text)
{
	if (printf("%s", text) < 0 || fflush(stdout) != 0) {
		fprintf(stderr, "Error: could not write to stdout\n");
		return -1;
	}

	return 0;
}

/* Abbreviations used in game and cheat names in the ROM database. */
static const char *const db_abbr[] = {
	NULL,
	"Infinite",
	"Unlimited",
	" Lives",
	"Player",
	" Energy",
	" Time",
	"Money"
};

struct db_info {
	size_t games;
	size_t cheats;
	size_t lines;
};

/* One cheat, or a game without any: then cheat_name is NULL. */
struct db_record {
	const u8 *game_name;
	size_t game_name_len;
	const u8 *cheat_name;
	size_t cheat_name_len;
	const u8 *codes;
	size_t nlines;
	int first_in_game;
	int last_in_game;
};

struct db_cursor {
	const u8 *rom;
	size_t size;
	size_t pos;
	const u8 *game_name;
	size_t game_name_len;
	size_t cheats_left;
};

static int db_is_term(const u8 *rom, size_t size, size_t pos)
{
	/* Four 0xFF bytes serve as a terminator or an erased-flash boundary. */
	return pos <= size && size - pos >= 4 &&
		memcmp(&rom[pos], "\xFF\xFF\xFF\xFF", 4) == 0;
}

/*
 * Read and validate a database name at @pos. Bytes 1 through 7 are the name
 * abbreviations above; bytes from 0x80 through 0xFE are accepted because the
 * Japanese database stores Shift-JIS. 0x7F and 0xFF are not name bytes.
 */
static int db_name_end(const u8 *rom, size_t size, size_t pos, size_t *end)
{
	size_t i;

	for (i = pos; i < size; i++) {
		u8 c = rom[i];

		if (c == 0) {
			if (i == pos)
				return -1;
			*end = i;
			return 0;
		}
		if (c == 0x7F || c == 0xFF || (c < 0x20 && c > 7))
			return -1;
	}

	return -1;
}

/*
 * Set up a cursor over a database record chain. The chain is a sequence of
 * gameName/N, then N cheatName/M/6*M-byte records, terminated by four 0xFF
 * bytes.
 */
static void init_db_cursor(struct db_cursor *cursor, const u8 *rom,
		size_t size)
{
	cursor->rom = rom;
	cursor->size = size;
	cursor->pos = 0;
	cursor->game_name = NULL;
	cursor->game_name_len = 0;
	cursor->cheats_left = 0;
}

/*
 * Read a name and the count byte after its terminator, advancing @cursor past
 * both. Returns -1 when either is missing or malformed.
 */
static int db_read_name(struct db_cursor *cursor, const u8 **name, size_t *len,
		u8 *count)
{
	size_t name_end;

	if (db_name_end(cursor->rom, cursor->size, cursor->pos, &name_end) ||
			name_end + 1 >= cursor->size)
		return -1;
	*name = cursor->rom + cursor->pos;
	*len = name_end - cursor->pos;
	*count = cursor->rom[name_end + 1];
	cursor->pos = name_end + 2;
	return 0;
}

/*
 * Read and validate one cheat record. Returns 1 for a record, 0 for a clean
 * end, and -1 for a malformed chain. Every size check is made before the
 * corresponding read.
 *
 * A game that declares zero cheats - a name, a count of zero, then the next
 * game - comes back as a record of its own, with no cheat name and no codes.
 * FCD ships them on purpose, as placeholders and as headings: the German FX
 * database opens with five, a legend for the abbreviations of its cheat names.
 */
static int db_cursor_next(struct db_cursor *cursor, struct db_record *record)
{
	u8 nlines;

	if (cursor->rom == NULL || cursor->pos > cursor->size)
		return -1;

	memset(record, 0, sizeof(*record));
	record->first_in_game = cursor->cheats_left == 0;
	if (record->first_in_game) {
		u8 ncheats;

		if (db_is_term(cursor->rom, cursor->size, cursor->pos))
			return 0;
		if (db_read_name(cursor, &cursor->game_name,
				&cursor->game_name_len, &ncheats))
			return -1;
		cursor->cheats_left = ncheats;
	}
	record->game_name = cursor->game_name;
	record->game_name_len = cursor->game_name_len;
	if (cursor->cheats_left == 0) {
		record->last_in_game = 1;
		return 1;
	}

	if (db_read_name(cursor, &record->cheat_name, &record->cheat_name_len,
			&nlines))
		return -1;
	if ((size_t)nlines > (cursor->size - cursor->pos) / XP_CODE_LEN)
		return -1;
	record->codes = cursor->rom + cursor->pos;
	record->nlines = nlines;
	cursor->pos += (size_t)nlines * XP_CODE_LEN;
	record->last_in_game = cursor->cheats_left == 1;
	cursor->cheats_left--;

	return 1;
}

/*
 * Walk the whole record chain at @rom and count it into @info: the games with
 * cheats, their cheats, and their code lines. Returns 0 if the chain ends
 * cleanly at its terminator and holds at least one cheat, -1 if it does not.
 * A chain of nothing but empty games is not a database.
 */
static int db_scan(const u8 *rom, size_t size, struct db_info *info)
{
	struct db_cursor cursor;
	struct db_record record;
	int ret;

	info->games = info->cheats = info->lines = 0;
	init_db_cursor(&cursor, rom, size);
	while ((ret = db_cursor_next(&cursor, &record)) == 1) {
		if (record.cheat_name == NULL)
			continue;
		if (record.first_in_game)
			info->games++;
		info->cheats++;
		info->lines += record.nlines;
	}

	return ret < 0 || info->cheats == 0 ? -1 : 0;
}

static int db_richer(const struct db_info *candidate,
		const struct db_info *best)
{
	if (candidate->games != best->games)
		return candidate->games > best->games;
	if (candidate->cheats != best->cheats)
		return candidate->cheats > best->cheats;
	return candidate->lines > best->lines;
}

/*
 * Locate the database from its framing, without assuming a ROM address or a
 * particular first game. In the known Xploder ROM images, the complete record
 * chain begins immediately after erased flash, so a candidate may start only
 * at offset zero or where its previous four bytes are 0xFF. For every such
 * offset:
 *
 *   1. db_cursor_next() must parse at least one game with cheats, and all
 *      of its declared cheats and six-byte code rows, without running off
 *      the image;
 *   2. every following game must parse the same way; and
 *   3. the chain must end cleanly at its own four-0xFF terminator.
 *
 * Offsets still inside a longer erased run see the terminator before any game
 * and fail step 1. A later game inside a real database may begin a valid
 * suffix, but normally lacks the erased-flash boundary. If several framed
 * chains do validate, prefer the one with the most games, then cheats, then
 * code lines; an exact tie stays with the earlier offset because the scan is
 * ascending.
 *
 * This framing rule matters because names are not simply printable strings:
 * bytes 1 through 7 abbreviate words in both game and cheat names, so a scan
 * that wants printable names starts inside one and finds a suffix.
 */
static int find_database(const u8 *rom, size_t size, size_t *offset)
{
	struct db_info best = { 0, 0, 0 };
	size_t best_offset = 0;
	size_t start;
	int found = 0;

	for (start = 0; start < size; start++) {
		struct db_info candidate;

		if (start != 0 && (start < 4 ||
				!db_is_term(rom, size, start - 4)))
			continue;

		if (db_scan(rom + start, size - start, &candidate))
			continue;

		if (!found || db_richer(&candidate, &best)) {
			best = candidate;
			best_offset = start;
			found = 1;
		}
	}

	if (!found)
		return -1;
	*offset = best_offset;
	return 0;
}

/*
 * The ROM header points at the firmware's support module, and that module
 * holds the address of the cheat database. Both are flash addresses: the low
 * 24 bits are the offset in the image.
 */
#define XP_MODULE_PTR	0x7C	/* ROM offset of the module address */
#define XP_DB_SLOT	0xB8	/* module offset of the database address */
#define XP_FLASH_SIZE	0x80000	/* the largest cartridge flash, 512 KB */

static uint32_t get_le32(const u8 *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
		((uint32_t)p[3] << 24);
}

/*
 * Read the 32-bit flash address at ROM offset @pos and turn it into an offset
 * of the image. Returns -1 if either lies outside the image.
 */
static int read_flash_ptr(const u8 *rom, size_t size, size_t pos,
		uint32_t *addr, size_t *offset)
{
	if (pos > size || size - pos < 4)
		return -1;
	*addr = get_le32(&rom[pos]);
	*offset = *addr & 0x00FFFFFF;
	return *offset < size ? 0 : -1;
}

/* The two cartridge generations, as a ROM's support module tells them apart. */
enum generation {
	GEN_UNKNOWN,
	GEN_V2,
	GEN_FX
};

/*
 * Find the support module of a plaintext ROM. The FX addresses its flash
 * through KSEG0, 0x9F000000, where every V2 firmware uses KUSEG, 0x1F000000,
 * so the module address tells the two generations apart.
 */
static enum generation rom_module(const u8 *rom, size_t size, size_t *module)
{
	uint32_t addr;

	if (read_flash_ptr(rom, size, XP_MODULE_PTR, &addr, module))
		return GEN_UNKNOWN;
	switch (addr >> 24) {
	case 0x1F:
		return GEN_V2;
	case 0x9F:
		return GEN_FX;
	default:
		return GEN_UNKNOWN;
	}
}

/*
 * Unpack the cheat database of an Xplorer FX ROM into @db, which the caller
 * frees. Returns 1 for an FX database, 0 if @rom is not an FX ROM - a V2
 * database is found by find_database() instead - and -1 for an FX ROM whose
 * database is malformed.
 *
 * On V2 the database address names the record chain itself. On FX it names a
 * container: the packed and the unpacked size as two little-endian words,
 * then the record chain, LZW-compressed (see lzw.c). The FX appends the four
 * 0xFF bytes of the terminator before it compresses, so what comes out is the
 * very chain a V2 ROM stores.
 */
static int fx_database(const u8 *rom, size_t size, u8 **db, size_t *db_size)
{
	struct db_info info;
	uint32_t addr;
	size_t module_off, off, packed, unpacked, n;
	u8 *buf;

	*db = NULL;
	*db_size = 0;
	if (rom_module(rom, size, &module_off) != GEN_FX)
		return 0;

	if (module_off > SIZE_MAX - XP_DB_SLOT ||
			read_flash_ptr(rom, size, module_off + XP_DB_SLOT,
				&addr, &off) ||
			size - off < 8)
		return -1;
	packed = get_le32(&rom[off]);
	unpacked = get_le32(&rom[off + 4]);
	if (packed > size - off - 8 || unpacked == 0 ||
			unpacked > XP_FLASH_SIZE)
		return -1;

	buf = (u8 *)malloc(unpacked);
	if (buf == NULL)
		return -1;
	if (lzw_unpack(&rom[off + 8], packed, buf, unpacked, &n) ||
			n != unpacked || db_scan(buf, n, &info)) {
		free(buf);
		return -1;
	}

	*db = buf;
	*db_size = n;
	return 1;
}

static int print_db_name(const u8 *name, size_t len, int quoted)
{
	size_t i;

	if (quoted && putchar('"') == EOF)
		return -1;
	for (i = 0; i < len; i++) {
		u8 c = name[i];

		if (c > 0 && c < sizeof(db_abbr) / sizeof(db_abbr[0])) {
			if (printf("%s", db_abbr[c]) < 0)
				return -1;
		} else if (putchar(c) == EOF) {
			return -1;
		}
	}
	if (quoted && putchar('"') == EOF)
		return -1;
	return putchar('\n') == EOF ? -1 : 0;
}

/*
 * Print one already-located database, decrypting each cheat independently,
 * and count the events of its codes into @counts.
 */
static int print_database(const u8 *rom, size_t size, unsigned long *counts)
{
	struct db_cursor cursor;
	struct db_record record;
	int ret;

	init_db_cursor(&cursor, rom, size);
	while ((ret = db_cursor_next(&cursor, &record)) == 1) {
		struct code_stream stream;
		size_t line;

		if (record.first_in_game && print_db_name(record.game_name,
				record.game_name_len, 1))
			return -1;
		if (record.cheat_name != NULL && print_db_name(record.cheat_name,
				record.cheat_name_len, 0))
			return -1;
		init_code_stream(&stream, DECRYPT, XP_KEY_AUTO);
		for (line = 0; line < record.nlines; line++) {
			u8 code[XP_CODE_LEN];

			memcpy(code, record.codes + line * XP_CODE_LEN,
				XP_CODE_LEN);
			count_events(counts, crypt_code(code, &stream));
			if (print_code(code))
				return -1;
		}
		/* The cheat is where a block ends on the cartridge. */
		count_events(counts, end_code_stream(&stream));
		if (record.last_in_game && printf("\n//=====\n\n") < 0)
			return -1;
	}

	return ret;
}

/*
 * Find the record chain of a plaintext ROM: the one an FX container holds,
 * unpacked into @owned, which the caller frees, or the one a V2 ROM keeps in
 * place. Says what is wrong and returns -1 if there is none.
 */
static int locate_database(const u8 *rom, size_t size, const u8 **chain,
		size_t *len, u8 **owned)
{
	size_t offset;

	switch (fx_database(rom, size, owned, len)) {
	case 1:
		*chain = *owned;
		return 0;
	case 0:
		break;
	default:
		fprintf(stderr, "Error: the Xplorer FX cheat database in the "
			"input ROM is damaged\n");
		return -1;
	}

	if (find_database(rom, size, &offset)) {
		fprintf(stderr, "Error: no cheat database found in input ROM\n");
		return -1;
	}
	*chain = rom + offset;
	*len = size - offset;
	return 0;
}

/* Read a ROM into memory for conversion or extraction. */
static int read_rom(const char *infile, u8 **rom, size_t *rom_size)
{
	FILE *fp;
	long size;
	size_t nbytes;
	u8 *buf = NULL;
	int ret = -1;

	*rom = NULL;
	*rom_size = 0;
	fp = fopen(infile, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error: could not open input ROM %s\n", infile);
		return -1;
	}

	if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0) {
		fprintf(stderr, "Error: could not get the size of input ROM %s\n",
			infile);
		goto out;
	}
	nbytes = (size_t)size;
	if (nbytes < XP_ROM_MIN_SIZE) {
		fprintf(stderr, "Error: input ROM too small\n");
		goto out;
	}

	buf = (u8*)malloc(nbytes);
	if (buf == NULL) {
		fprintf(stderr, "Error: memory allocation failed\n");
		goto out;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		fprintf(stderr, "Error: could not seek in input ROM %s\n", infile);
		goto out;
	}
	if (fread(buf, nbytes, 1, fp) != 1) {
		fprintf(stderr, "Error: could not read from input ROM\n");
		goto out;
	}

	*rom = buf;
	*rom_size = nbytes;
	buf = NULL;
	ret = 0;
out:
	free(buf);
	if (fclose(fp) != 0 && ret == 0)
		fprintf(stderr, "Warning: could not close input ROM %s\n", infile);
	return ret;
}

/* Extract and decrypt every cheat in an Xploder ROM database. */
static int extract_codes(const char *infile)
{
	u8 *rom;
	u8 *db = NULL;
	const u8 *chain;
	size_t size, len;
	unsigned long counts[NUM_EVENTS] = { 0 };
	int ret = -1;

	if (read_rom(infile, &rom, &size))
		return -1;

	if (xp_rom_to_plain(rom, size)) {
		fprintf(stderr, "Error: input is not an Xploder ROM\n");
		goto out;
	}

	if (locate_database(rom, size, &chain, &len, &db))
		goto out;
	if (print_database(chain, len, counts) || fflush(stdout) != 0 ||
			ferror(stdout)) {
		fprintf(stderr, "Error: could not write extracted codes\n");
		goto out;
	}
	print_summaries(counts);

	ret = 0;
out:
	free(db);
	free(rom);
	return ret;
}

/*
 * Decrypt or encrypt an Xploder ROM.
 */
static int crypt_rom(const char *infile, const char *outfile)
{
	FILE *fp = NULL;
	u8 *buf;
	size_t nbytes;
	int ret = -1;

	if (infile == NULL || outfile == NULL)
		return -1;

	if (read_rom(infile, &buf, &nbytes))
		return -1;

	if (xp_crypt_rom(buf, nbytes)) {
		fprintf(stderr, "Error: could not process ROM\n");
		goto out;
	}

	/*
	 * Only now, with a whole converted ROM in hand, open the output. Doing
	 * it any earlier means a ROM we turn out not to be able to convert has
	 * already truncated the file that was there - which is the input itself
	 * when converting one in place, the way "xpcrypt -r rom.bin rom.bin"
	 * does.
	 */
	fp = fopen(outfile, "wb");
	if (fp == NULL) {
		fprintf(stderr, "Error: could not open output ROM %s\n", outfile);
		goto out;
	}

	if (fwrite(buf, nbytes, 1, fp) != 1) {
		fprintf(stderr, "Error: could not write to output ROM\n");
		goto out;
	}

	/*
	 * The ROM goes out through a buffer, so the write above can still fail
	 * here, and closing is the last chance to be told about it.
	 */
	ret = fclose(fp);
	fp = NULL;
	if (ret != 0) {
		fprintf(stderr, "Error: could not write to output ROM\n");
		ret = -1;
		goto out;
	}

out:
	if (buf != NULL)
		free(buf);
	if (fp != NULL)
		fclose(fp);

	return ret;
}

int main(int argc, char *argv[])
{
	int mode = MODE_DECRYPT_CODES;
	enum xp_key key = XP_KEY_AUTO;
	int ret;

	while ((ret = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		switch (ret) {
		case 'd':
			/* The default, but say so after an earlier -e or -r. */
			mode = MODE_DECRYPT_CODES;
			key = XP_KEY_AUTO;
			break;
		case 'e': {
			/*
			 * strtol() into an int, not sscanf("%i") into the enum:
			 * the enum is only as wide as its values need, which an
			 * implementation may make one byte, and %i writes an
			 * int either way. It also lets us insist that the whole
			 * argument was a number, so -e 4junk is an error rather
			 * than a 4.
			 */
			char *end;
			long k;

			errno = 0;
			k = strtol(optarg, &end, 0);
			if (end == optarg || *end != '\0' || errno != 0 ||
					k < XP_KEY_4 || k > XP_KEY_7) {
				fprintf(stderr, "Error: invalid encryption key - must be 4, 5, 6, or 7!\n");
				return EXIT_FAILURE;
			}
			key = (enum xp_key)k;
			mode = MODE_ENCRYPT_CODES;
			break;
		}
		case 'r':
			mode = MODE_CRYPT_ROM;
			break;
		case 'x':
			mode = MODE_EXTRACT_CODES;
			break;
		case 'h':
			return print_out(HELP_TEXT) ? EXIT_FAILURE : EXIT_SUCCESS;
		case 'V':
			return print_out(VERSION_TEXT) ? EXIT_FAILURE : EXIT_SUCCESS;
		default:
			/* getopt_long() already printed an error message */
			return EXIT_FAILURE;
		}
	}

	switch (mode) {
	case MODE_DECRYPT_CODES:
	case MODE_ENCRYPT_CODES:
		/*
		 * Codes come in on stdin, so there is nothing an operand could
		 * mean. Taking one and ignoring it turns "xpcrypt foo.txt" into
		 * a program that sits waiting on the terminal.
		 */
		if (optind < argc) {
			fprintf(stderr, "Error: unexpected argument %s - codes "
				"are read from stdin, use < to read a file\n",
				argv[optind]);
			return EXIT_FAILURE;
		}
		if (crypt_codes(mode == MODE_DECRYPT_CODES ? DECRYPT : ENCRYPT,
				key))
			return EXIT_FAILURE;
		break;
	case MODE_EXTRACT_CODES:
		if (optind >= argc) {
			fprintf(stderr, "Error: input ROM missing\n");
			return EXIT_FAILURE;
		}
		if (optind + 1 < argc) {
			fprintf(stderr, "Error: unexpected argument %s - -x takes "
				"one input ROM\n", argv[optind + 1]);
			return EXIT_FAILURE;
		}
		if (extract_codes(argv[optind]))
			return EXIT_FAILURE;
		break;
	case MODE_CRYPT_ROM:
		if ((optind + 2) > argc) {
			fprintf(stderr, "Error: input/output ROM missing\n");
			return EXIT_FAILURE;
		}
		if ((optind + 2) < argc) {
			fprintf(stderr, "Error: unexpected argument %s - -r "
				"takes an input and an output ROM\n",
				argv[optind + 2]);
			return EXIT_FAILURE;
		}
		if (crypt_rom(argv[optind], argv[optind + 1]))
			return EXIT_FAILURE;
		break;
	}

	return EXIT_SUCCESS;
}
