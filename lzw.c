/*
 * lzw.c - LZW decompression
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

#include <stdlib.h>
#include "lzw.h"

/*
 * The Xplorer FX keeps its cheat database LZW-compressed in flash. Its
 * decompressor is Mark Nelson's, from "LZW Data Compression" (Dr. Dobb's
 * Journal, October 1989), built with 14-bit codes: the table sizes it allocates
 * are the ones that article gives for BITS = 14. So the format is his:
 *
 *   - every code is 14 bits wide, packed most significant bit first;
 *   - the codes 0 to 255 are the bytes themselves, and new strings are
 *     numbered from 256 on;
 *   - there is no clear code: once the code 0x3FFE has been assigned, the
 *     table stays as it is for the rest of the stream;
 *   - the code 0x3FFF ends the stream.
 *
 * What is added here is only the checking Nelson's expander leaves out, since
 * a ROM image is not a file we wrote ourselves.
 */
#define LZW_BITS	14
#define LZW_END		((1 << LZW_BITS) - 1)	/* 0x3FFF, ends the stream */
#define LZW_MAX_CODE	(LZW_END - 1)		/* the last code assigned */
#define LZW_FIRST	256			/* the first string code */

struct lzw_state {
	uint16_t prefix[LZW_MAX_CODE + 1];
	uint8_t append[LZW_MAX_CODE + 1];
	/* A string is at most one byte longer than the table has entries. */
	uint8_t stack[LZW_MAX_CODE + 2];
	const uint8_t *src;
	size_t srclen;
	size_t pos;
	uint32_t bits;
	int nbits;
};

/*
 * Read the next code into @code. Returns -1 if the input runs out first.
 */
static int read_code(struct lzw_state *s, int *code)
{
	while (s->nbits < LZW_BITS) {
		if (s->pos == s->srclen)
			return -1;
		s->bits = (s->bits << 8) | s->src[s->pos++];
		s->nbits += 8;
	}
	s->nbits -= LZW_BITS;
	*code = (int)((s->bits >> s->nbits) & LZW_END);

	return 0;
}

/*
 * Push the string of @code onto the stack, last byte first, starting at
 * s->stack[@depth]. Returns the new depth.
 */
static size_t push_string(struct lzw_state *s, size_t depth, int code)
{
	while (code >= LZW_FIRST) {
		s->stack[depth++] = s->append[code];
		code = s->prefix[code];
	}
	s->stack[depth++] = (uint8_t)code;

	return depth;
}

/**
 * lzw_unpack - Decompress a 14-bit LZW stream.
 * @src: compressed stream
 * @srclen: number of bytes in @src
 * @dst: buffer for the decompressed data
 * @dstlen: size of @dst
 * @outlen: number of bytes written to @dst
 * @return: 0: success, -1: the stream is malformed or does not fit into @dst
 */
int lzw_unpack(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstlen,
		size_t *outlen)
{
	struct lzw_state *s;
	size_t out = 0;
	int next_code = LZW_FIRST;
	int old_code, new_code;
	int ret = -1;

	if (src == NULL || dst == NULL || outlen == NULL)
		return -1;

	/* About 64 KB of tables, too much to put on the stack. */
	s = (struct lzw_state *)malloc(sizeof(*s));
	if (s == NULL)
		return -1;
	s->src = src;
	s->srclen = srclen;
	s->pos = 0;
	s->bits = 0;
	s->nbits = 0;

	if (read_code(s, &old_code))
		goto out;
	if (old_code == LZW_END) {
		ret = 0;
		goto out;
	}
	/* Nothing has been defined yet, so the first code must be a byte. */
	if (old_code >= LZW_FIRST || out == dstlen)
		goto out;
	dst[out++] = (uint8_t)old_code;

	for (;;) {
		size_t depth;
		uint8_t first;

		if (read_code(s, &new_code))
			goto out;
		if (new_code == LZW_END)
			break;

		if (new_code < next_code) {
			depth = push_string(s, 0, new_code);
		} else if (new_code == next_code && next_code <= LZW_MAX_CODE) {
			/*
			 * The code the encoder defined with this very string: the
			 * previous string plus its own first byte.
			 */
			depth = push_string(s, 1, old_code);
			s->stack[0] = s->stack[depth - 1];
		} else {
			goto out;
		}
		first = s->stack[depth - 1];

		if (depth > dstlen - out)
			goto out;
		while (depth > 0)
			dst[out++] = s->stack[--depth];

		if (next_code <= LZW_MAX_CODE) {
			s->prefix[next_code] = (uint16_t)old_code;
			s->append[next_code] = first;
			next_code++;
		}
		old_code = new_code;
	}

	ret = 0;
out:
	if (ret == 0)
		*outlen = out;
	free(s);
	return ret;
}
