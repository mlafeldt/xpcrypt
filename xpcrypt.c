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
#include <limits.h>
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

/*
 * Returns non-zero if string @s indicates a cheat code.
 */
static int is_code(const char *s, int digits)
{
	int i = 0;

	if (s == NULL)
		return 0;

	while (*s) {
		/*
		 * char may be signed, and the ctype functions are only defined
		 * for the values of an unsigned char and EOF - handing one of
		 * them a negative value other than EOF is undefined, whatever
		 * a particular library happens to do with it.
		 */
		unsigned char c = (unsigned char)*s;

		if (isxdigit(c)) {
			if (++i > digits)
				return 0;
		}
		else if (!isspace(c)) {
			return 0;
		}
		s++;
	}

	return (i == digits);
}

/*
 * Set up processing of the payload of a Supercode/Megacode block. Returns the
 * payload position to start at, or -1 if @code is not a block header.
 */
static int start_block(const u8 *code, struct xp_block *blk)
{
	if (xp_parse_block(code, blk))
		return -1;

	if (!blk->known_key)
		fprintf(stderr, "Warning: unknown payload key %i, payload of "
			"block left as it is\n", blk->payload_key);

	return 0;
}

/*
 * Decrypt or encrypt Xploder codes.
 */
static int crypt_codes(int mode, enum xp_key key)
{
	char line[2048] = { 0 };
	u8 code[XP_CODE_LEN];
	struct xp_block blk;
	int index = -1; /* Position in the payload of a Supercode/Megacode */

	/*
	 * Read codes from stdin, decrypt or encrypt them,
	 * and write them to stdout.
	 */
	setbuf(stdin, NULL);

	while (fgets(line, sizeof(line), stdin) != NULL) {
		/* Simply output the line if it's not a code. */
		if (!is_code(line, XP_CODE_LEN * 2)) {
			printf("%s", line);
			continue;
		}

		/* We have a code - process it. */
		sscanf(line, "%02hhx%02hhx%02hhx%02hhx %02hhx%02hhx",
			&code[0], &code[1], &code[2], &code[3],
			&code[4], &code[5]);

		if (index >= 0) {
			/*
			 * The code belongs to the payload of a Supercode or
			 * Megacode. It's data, not a code of its own.
			 */
			if (mode == MODE_DECRYPT_CODES)
				xp_decrypt_block_line(code, &blk, index);
			else
				xp_encrypt_block_line(code, &blk, index);

			if (++index >= blk.num_lines)
				index = -1;
		} else if (mode == MODE_DECRYPT_CODES) {
			xp_decrypt_code(code, key);
			/*
			 * The key bits of a header are clear once we have
			 * decrypted it, and of a header that was never
			 * encrypted anyway. If they are still set we could not
			 * decrypt it, so its key and size fields are still
			 * ciphertext and must not be used to start a block.
			 */
			if (!(code[0] & 0x07))
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

		printf("%02X%02X%02X%02X %02X%02X\n", code[0], code[1],
			code[2], code[3], code[4], code[5]);
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

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	if (size < XP_ROM_BLKSIZE) {
		fprintf(stderr, "Error: input ROM too small\n");
		goto out;
	}
	/*
	 * The crypto takes the size as an int, and the whole ROM has to fit
	 * into memory anyway, so anything larger is not a ROM we can process.
	 */
	if (size > INT_MAX) {
		fprintf(stderr, "Error: input ROM too large\n");
		goto out;
	}
	nbytes = (size_t)size;

	buf = (u8*)malloc(nbytes);
	if (buf == NULL) {
		fprintf(stderr, "Error: memory allocation failed\n");
		goto out;
	}

	fseek(fp, 0, SEEK_SET);
	if (fread(buf, nbytes, 1, fp) != 1) {
		fprintf(stderr, "Error: could not read from input ROM\n");
		goto out;
	}

	fclose(fp);
	fp = fopen(outfile, "wb");
	if (fp == NULL) {
		fprintf(stderr, "Error: could not open output ROM %s\n", outfile);
		goto out;
	}

	if (xp_crypt_rom(buf, (int)size)) {
		fprintf(stderr, "Error: could not process ROM\n");
		goto out;
	}

	if (fwrite(buf, nbytes, 1, fp) != 1) {
		fprintf(stderr, "Error: could not write to output ROM\n");
		goto out;
	}

	ret = 0;
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
			/* default option */
			break;
		case 'e':
			if (sscanf(optarg, "%i", &key) != 1 || !(key >= 4 && key <= 7)) {
				fprintf(stderr, "Error: invalid encryption key - must be 4, 5, 6, or 7!\n");
				return EXIT_FAILURE;
			}
			mode = MODE_ENCRYPT_CODES;
			break;
		case 'r':
			mode = MODE_CRYPT_ROM;
			break;
		case 'h':
			printf(HELP_TEXT);
			return EXIT_SUCCESS;
		case 'V':
			printf(VERSION_TEXT);
			return EXIT_SUCCESS;
		default:
			/* getopt_long() already printed an error message */
			return EXIT_FAILURE;
		}
	}

	switch (mode) {
	case MODE_DECRYPT_CODES:
	case MODE_ENCRYPT_CODES:
		crypt_codes(mode, key);
		break;
	case MODE_CRYPT_ROM:
		if ((optind + 2) > argc) {
			fprintf(stderr, "Error: input/output ROM missing\n");
			return EXIT_FAILURE;
		}
		if (crypt_rom(argv[optind], argv[optind + 1]))
			return EXIT_FAILURE;
		break;
	}

	return EXIT_SUCCESS;
}
