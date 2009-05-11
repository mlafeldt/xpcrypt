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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "mytypes.h"
#include "xp_crypto.h"

/* Application's name and current version */
#define APP_NAME	"xpcrypt"
#define APP_VERSION	"1.1"

/* Text displayed for --help option */
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

/* Text displayed for --version option */
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
		if (isxdigit(*s)) {
			if (++i > digits)
				return 0;
		}
		else if (!isspace(*s)) {
			return 0;
		}
		s++;
	}

	return (i == digits);
}

/*
 * Decrypt or encrypt Xploder codes.
 */
static int crypt_codes(int mode, enum xp_key key)
{
	char line[2048] = { 0 };
	u8 code[XP_CODE_LEN];

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

		if (mode == MODE_DECRYPT_CODES)
			xp_decrypt_code(code, key);
		else
			xp_encrypt_code(code, key);

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
	u8 *buf;
	long size;
	int ret = -1;

	if (infile == NULL || outfile == NULL)
		return -1;

	fp = fopen(infile, "r");
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

	buf = (u8*)malloc(size);
	if (buf == NULL) {
		fprintf(stderr, "Error: memory allocation failed\n");
		goto out;
	}

	fseek(fp, 0, SEEK_SET);
	if (fread(buf, size, 1, fp) != 1) {
		fprintf(stderr, "Error: could not read from input ROM\n");
		goto out;
	}

	fclose(fp);
	fp = fopen(outfile, "w");
	if (fp == NULL) {
		fprintf(stderr, "Error: could not open output ROM %s\n", outfile);
		goto out;
	}

	xp_crypt_rom(buf, size);

	if (fwrite(buf, size, 1, fp) != 1) {
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
