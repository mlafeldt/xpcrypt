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
#include <getopt.h>
#include "xp_crypto.h"

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
static const char *shortopts = "de:rhV";
static const struct option longopts[] = {
	{ "decrypt-codes", no_argument, NULL, 'd' },
	{ "encrypt-codes", required_argument, NULL, 'e' },
	{ "rom", no_argument, NULL, 'r' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 }
};

/* Program modes */
enum {
	MODE_DECRYPT_CODES,
	MODE_ENCRYPT_CODES,
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
 * short line, so a comment 2000 characters long whose tail happened to read as
 * twelve hex digits was decrypted as a code of its own. Nothing that arrives in
 * pieces is a code, and the pieces have to go out as they came in.
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

/*
 * Set up processing of the payload of a block. Returns the payload position to
 * start at, or -1 if @code is not a block header.
 */
static int start_block(const u8 *code, struct xp_block *blk)
{
	if (xp_parse_block(code, blk))
		return -1;

	if (!blk->known_key)
		fprintf(stderr, "Warning: unknown payload key %i, payload of "
			"block left as it is\n", blk->payload_key);

	/*
	 * A Supercode or Megacode says how long its payload is, so we can tell
	 * where it ends. The payload of a code type A runs to the end of the
	 * cheat, which is a boundary that is not in the codes themselves - so
	 * we take every code that follows.
	 */
	if (blk->kind == XP_BLOCK_INLINE)
		fprintf(stderr, "Warning: code type A has no payload length, "
			"all following codes are treated as its payload\n");

	return 0;
}

/*
 * Decrypt or encrypt Xploder codes.
 */
static int crypt_codes(int mode, enum xp_key key)
{
	char line[2048];
	size_t len = 0;
	u8 code[XP_CODE_LEN];
	struct xp_block blk;
	int index = -1; /* Position in the payload of a Supercode/Megacode */
	int begins_line = 1; /* The line before this one ended where it should */
	int ends_line = 1;
	int ret;

	/*
	 * Read codes from stdin, decrypt or encrypt them,
	 * and write them to stdout.
	 */
	setbuf(stdin, NULL);

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

		if (index >= 0) {
			/*
			 * The code belongs to the payload of a block. It's
			 * data, not a code of its own.
			 */
			if (mode == MODE_DECRYPT_CODES)
				xp_decrypt_block_line(code, &blk, index);
			else
				xp_encrypt_block_line(code, &blk, index);

			if (!xp_in_payload(&blk, ++index))
				index = -1;
		} else if (mode == MODE_DECRYPT_CODES) {
			xp_decrypt_code(code, key);
			/*
			 * The key bits of a header are clear once we have
			 * decrypted it, and of a header that was never
			 * encrypted anyway. If they are still set we could not
			 * decrypt it, so its key and size fields are still
			 * ciphertext and must not be used to start a block.
			 * A code type A header has neither field, and the
			 * Xploder never encrypts one, so it is never in doubt.
			 */
			if (!(code[0] & 0x07) || (code[0] & 0xF0) == 0xA0)
				index = start_block(code, &blk);
		} else {
			/* The header has to be parsed before it's encrypted. */
			index = start_block(code, &blk);
			if (xp_encrypt_code(code, key))
				fprintf(stderr, "Warning: the Xploder doesn't "
					"encrypt code %02X%02X%02X%02X %02X%02X, "
					"left as it is\n", code[0], code[1],
					code[2], code[3], code[4], code[5]);
		}

		if (printf("%02X%02X%02X%02X %02X%02X\n", code[0], code[1],
				code[2], code[3], code[4], code[5]) < 0)
			break;
	}

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

/*
 * Decrypt or encrypt an Xploder ROM.
 */
static int crypt_rom(const char *infile, const char *outfile)
{
	FILE *fp;
	u8 *buf = NULL;
	long size;
	size_t nbytes;
	int ret = -1;

	if (infile == NULL || outfile == NULL)
		return -1;

	/* "b": a ROM is binary, and Windows would translate line endings. */
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

	/*
	 * Nothing was written to this one, so a failure here says only that the
	 * ROM we already hold in memory came off a file that then went wrong.
	 * Say so and carry on: refusing to write the output would be the worse
	 * answer, and pretending we never noticed is not one.
	 */
	if (fclose(fp) != 0)
		fprintf(stderr, "Warning: could not close input ROM %s\n", infile);
	fp = NULL;

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
		if (crypt_codes(mode, key))
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
