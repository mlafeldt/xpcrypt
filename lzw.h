/*
 * lzw.h - LZW decompression
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

#ifndef LZW_H
#define LZW_H

#include <stddef.h>
#include <stdint.h>

/**
 * lzw_unpack - Decompress a 14-bit LZW stream.
 * @src: compressed stream
 * @srclen: number of bytes in @src
 * @dst: buffer for the decompressed data
 * @dstlen: size of @dst
 * @outlen: number of bytes written to @dst
 * @return: 0: success, -1: the stream is malformed or does not fit into @dst
 *
 * The stream must end with its end code; running out of input before it is an
 * error, and so is a code that has not been defined yet.
 */
int lzw_unpack(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstlen,
		size_t *outlen);

#endif /*LZW_H*/
