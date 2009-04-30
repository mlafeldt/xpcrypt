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
 */
int xp_encrypt_code(u8 *code, enum xp_key key);

/**
 * xp_decrypt_code - Decrypt an Xploder code.
 * @code: code to be decrypted
 * @key: encryption key, use XP_KEY_AUTO to "guess" the key
 * @return: 0: success, -1: error
 */
int xp_decrypt_code(u8 *code, enum xp_key key);


/* Xploder ROMs are encrypted in ECB mode, this is the block size */
#define XP_ROM_BLKSIZE	512

/**
 * xp_encrypt_rom - Encrypt an Xploder ROM.
 * @rom: buffer holding ROM in raw format
 * @size: size of buffer
 * @return: 0: success, -1: error
 */
int xp_encrypt_rom(u8 *rom, int size);

/**
 * xp_decrypt_rom - Decrypt an Xploder ROM.
 * @rom: buffer holding encrypted ROM
 * @size: size of buffer
 * @return: 0: success, -1: error
 */
int xp_decrypt_rom(u8 *rom, int size);

#endif /*_XP_CRYPTO_H_*/
