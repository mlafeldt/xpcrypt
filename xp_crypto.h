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

#ifndef XP_CRYPTO_H
#define XP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;

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

/* The three code types that take a block of payload codes below them */
enum xp_block_kind {
	XP_BLOCK_SUPER,		/* code type 5, Supercode */
	XP_BLOCK_MEGA,		/* code type 6, Megacode */
	XP_BLOCK_INLINE		/* code type A, inline data block */
};

/**
 * struct xp_block - Layout of a block of payload codes.
 * @kind: which of the three block types the header is
 * @payload_key: key the payload codes are encrypted with
 * @known_key: non-zero if xpcrypt is able to process the payload
 * @num_lines: number of payload codes that follow the header. Only a Supercode
 *	and a Megacode say how much payload they have; an XP_BLOCK_INLINE
 *	payload runs to the end of the cheat, and this is 0 for one.
 */
struct xp_block {
	enum xp_block_kind kind;
	int payload_key;
	int known_key;
	int num_lines;
};

/**
 * xp_parse_block - Get the layout of a block of payload codes.
 * @code: decrypted header code of the block
 * @blk: block layout to be filled in
 * @return: 0: success, -1: @code is not a block header
 *
 * The code types 5 and 6 declare how many bytes of payload follow them. The
 * code type A does not: its payload is raw, unencrypted, and runs to the end of
 * the cheat. Such a block is reported as XP_BLOCK_INLINE, and it is up to the
 * caller to say where the cheat ends.
 */
int xp_parse_block(const u8 *code, struct xp_block *blk);

/**
 * xp_in_payload - Is a code at position @index still part of block @blk?
 * @blk: block layout returned by xp_parse_block()
 * @index: position of the code in the payload, starting at 0
 * @return: non-zero if it is
 */
int xp_in_payload(const struct xp_block *blk, int index);

/**
 * xp_decrypt_block_line - Decrypt a payload code of a block.
 * @code: code to be decrypted
 * @blk: block layout returned by xp_parse_block()
 * @index: position of the code in the payload, starting at 0
 * @return: 0: success, -1: error
 */
int xp_decrypt_block_line(u8 *code, const struct xp_block *blk, int index);

/**
 * xp_encrypt_block_line - Encrypt a payload code of a block.
 * @code: code to be encrypted
 * @blk: block layout returned by xp_parse_block()
 * @index: position of the code in the payload, starting at 0
 * @return: 0: success, -1: error
 */
int xp_encrypt_block_line(u8 *code, const struct xp_block *blk, int index);

/* Plaintext ROM marker used to choose the automatic conversion direction. */
#define XP_ROM_SIG_TEXT		"Sony"
#define XP_ROM_SIG_OFFSET	0x10
#define XP_ROM_SIG_LEN		(sizeof(XP_ROM_SIG_TEXT) - 1)
#define XP_ROM_MIN_SIZE		(XP_ROM_SIG_OFFSET + XP_ROM_SIG_LEN)

/**
 * xp_encrypt_rom - Encrypt an Xploder ROM.
 * @rom: buffer holding ROM in raw format
 * @size: number of bytes to process
 * @return: 0: success, -1: error
 */
int xp_encrypt_rom(u8 *rom, size_t size);

/**
 * xp_decrypt_rom - Decrypt an Xploder ROM.
 * @rom: buffer holding encrypted ROM
 * @size: number of bytes to process
 * @return: 0: success, -1: error
 */
int xp_decrypt_rom(u8 *rom, size_t size);

/**
 * xp_crypt_rom - Automatically decrypt or encrypt an Xploder ROM.
 * @rom: buffer holding ROM
 * @size: size of ROM buffer; must be at least XP_ROM_MIN_SIZE
 * @return: 0: success, -1: error
 */
int xp_crypt_rom(u8 *rom, size_t size);

#endif /*XP_CRYPTO_H*/
