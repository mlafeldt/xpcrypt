/*
 * xp_crypto.h - Cryptographic functions for Xploder PSX
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

#ifndef _XP_CRYPTO_H_
#define _XP_CRYPTO_H_

#include "mytypes.h"

/* Length of an Xploder code in bytes */
#define XP_CODE_LEN	6

/* Xploder code encryption keys */
enum xp_key {
	XP_KEY_AUTO = -1,
	XP_KEY_4 = 4,
	XP_KEY_5,
	XP_KEY_6,
	XP_KEY_7
};

/**
 * xp_encrypt_code - Encrypt an Xploder code.
 * @code: code to be encrypted
 * @key: encryption key
 * @return: 0: success, -1: error
 *
 * A code that uses the lowest three bits of its first byte has no room for a
 * key, and the Xploder doesn't encrypt the code types 2, A, C, and E at all.
 * Such a code is left untouched.
 */
int xp_encrypt_code(u8 *code, enum xp_key key);

/**
 * xp_decrypt_code - Decrypt an Xploder code.
 * @code: code to be decrypted
 * @key: encryption key, use XP_KEY_AUTO to "guess" the key
 * @return: 0: success, -1: error
 *
 * A code of one of the types the Xploder doesn't encrypt is left untouched.
 */
int xp_decrypt_code(u8 *code, enum xp_key key);


/*
 * Number of bytes the breakpoint descriptor of a Megacode occupies in front of
 * the payload: 6 bytes of break address/type plus a 4-byte break mask.
 */
#define XP_MEGA_DESC_LEN	10

/**
 * struct xp_block - Layout of a Supercode/Megacode block.
 * @mega: 0: code type 5 (Supercode), 1: code type 6 (Megacode)
 * @payload_key: key the payload codes are encrypted with
 * @known_key: non-zero if xpcrypt is able to process the payload
 * @num_lines: number of payload codes that follow the header
 */
struct xp_block {
	int mega;
	int payload_key;
	int known_key;
	int num_lines;
};

/**
 * xp_parse_block - Get the layout of a Supercode/Megacode block.
 * @code: decrypted header code of the block
 * @blk: block layout to be filled in
 * @return: 0: success, -1: @code is not a block header
 */
int xp_parse_block(const u8 *code, struct xp_block *blk);

/**
 * xp_decrypt_block_line - Decrypt a payload code of a Supercode/Megacode block.
 * @code: code to be decrypted
 * @blk: block layout returned by xp_parse_block()
 * @index: position of the code in the payload, starting at 0
 * @return: 0: success, -1: error
 */
int xp_decrypt_block_line(u8 *code, const struct xp_block *blk, int index);

/**
 * xp_encrypt_block_line - Encrypt a payload code of a Supercode/Megacode block.
 * @code: code to be encrypted
 * @blk: block layout returned by xp_parse_block()
 * @index: position of the code in the payload, starting at 0
 * @return: 0: success, -1: error
 */
int xp_encrypt_block_line(u8 *code, const struct xp_block *blk, int index);


/* Xploder ROMs are encrypted in ECB mode, this is the block size */
#define XP_ROM_BLKSIZE	512

/**
 * xp_encrypt_rom - Encrypt an Xploder ROM.
 * @rom: buffer holding ROM in raw format
 * @size: size of ROM buffer
 * @return: 0: success, -1: error
 */
int xp_encrypt_rom(u8 *rom, int size);

/**
 * xp_decrypt_rom - Decrypt an Xploder ROM.
 * @rom: buffer holding encrypted ROM
 * @size: size of ROM buffer
 * @return: 0: success, -1: error
 */
int xp_decrypt_rom(u8 *rom, int size);

/**
 * xp_crypt_rom - Automatically decrypt or encrypt an Xploder ROM.
 * @rom: buffer holding ROM
 * @size: size of ROM buffer
 * @return: 0: success, -1: error
 */
int xp_crypt_rom(u8 *rom, int size);

#endif /*_XP_CRYPTO_H_*/
