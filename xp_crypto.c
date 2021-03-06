/*
 * xp_crypto.c - Cryptographic functions for Xploder PSX
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

#include <stdlib.h> /* for NULL */
#include "xp_crypto.h"

/**
 * xp_encrypt_code - Encrypt an Xploder code.
 * @code: code to be encrypted
 * @key: encryption key
 * @return: 0: success, -1: error
 */
int xp_encrypt_code(u8 *code, enum xp_key key)
{
	if (code == NULL)
		return -1;

	code[0] ^= key;

	switch (key) {
	case XP_KEY_4:
		code[5] ^= (code[4] & 0x11) + (code[3] ^ 0x12) - 0xDA + code[2] + code[1];
		code[4] ^= (code[3] & 0x11) + (code[2] ^ 0x12) - 0x82 + code[1];
		code[3] ^= (code[2] & 0x11) + (code[1] ^ 0x12) - 0x40;
		code[2] ^= (code[1] & 0x11) + 0xFA;
		code[1] ^= 0x25;
		break;
	case XP_KEY_5:
		code[1] -= 0x57; /* 'W'ayne */
		code[2] -= 0x42; /* 'B'eckett */
		code[3] -= 0x31; /* '1' */
		code[4] -= 0x32; /* '2' */
		code[5] -= 0x33; /* '3' */
		break;
	case XP_KEY_6:
		code[1] = (code[1] ^ 0x01) - 0xAB;
		code[2] = (code[2] ^ 0x02) - 0xAB;
		code[3] = (code[3] ^ 0x03) - 0xAB;
		code[4] = (code[4] ^ 0x04) - 0xAB;
		code[5] = (code[5] ^ 0x05) - 0xAB;
		break;
	case XP_KEY_7:
		code[1] -= (code[2] & 0x73) - (code[3] ^ 0x90) + 0xF5 + code[4] + code[5];
		code[2] -= (code[3] & 0x73) - (code[4] ^ 0x90) + 0x16 + code[5];
		code[3] -= (code[4] & 0x73) - (code[5] ^ 0x90) + 0x5A;
		code[4] -= (code[5] & 0x73) - 0x35;
		code[5] += 0x35;
		break;
	default:
		return -1;
	}

	return 0;
}

/**
 * xp_decrypt_code - Decrypt an Xploder code.
 * @code: code to be decrypted
 * @key: encryption key, use XP_KEY_AUTO to "guess" the key
 * @return: 0: success, -1: error
 */
int xp_decrypt_code(u8 *code, enum xp_key key)
{
	if (code == NULL)
		return -1;

	if (key == XP_KEY_AUTO)
		key = code[0] & 0x0F; /* Auto process */

	code[0] ^= key;

	switch (key) {
	case XP_KEY_4:
		code[1] ^= 0x25;
		code[2] ^= (code[1] & 0x11) + 0xFA;
		code[3] ^= (code[2] & 0x11) + (code[1] ^ 0x12) - 0x40;
		code[4] ^= (code[3] & 0x11) + (code[2] ^ 0x12) - 0x82 + code[1];
		code[5] ^= (code[4] & 0x11) + (code[3] ^ 0x12) - 0xDA + code[2] + code[1];
		break;
	case XP_KEY_5:
		code[1] += 0x57;
		code[2] += 0x42;
		code[3] += 0x31;
		code[4] += 0x32;
		code[5] += 0x33;
		break;
	case XP_KEY_6:
		code[1] = (code[1] + 0xAB) ^ 0x01;
		code[2] = (code[2] + 0xAB) ^ 0x02;
		code[3] = (code[3] + 0xAB) ^ 0x03;
		code[4] = (code[4] + 0xAB) ^ 0x04;
		code[5] = (code[5] + 0xAB) ^ 0x05;
		break;
	case XP_KEY_7:
		code[5] -= 0x35;
		code[4] += (code[5] & 0x73) - 0x35;
		code[3] += (code[4] & 0x73) - (code[5] ^ 0x90) + 0x5A;
		code[2] += (code[3] & 0x73) - (code[4] ^ 0x90) + 0x16 + code[5];
		code[1] += (code[2] & 0x73) - (code[3] ^ 0x90) + 0xF5 + code[4] + code[5];
		break;
	default:
		return -1;
	}

	return 0;
}


/* Seed tables for ROM encryption/decryption */
static const u8 seeds1[XP_ROM_BLKSIZE] = {
	0x45, 0x44, 0x44, 0x45, 0x43, 0x42, 0x4E, 0x4F, 0x41, 0x40, 0x40, 0x41, 0x47, 0x46, 0x42, 0x43,
	0x5D, 0x5C, 0x5C, 0x5D, 0x5B, 0x5A, 0x46, 0x47, 0x49, 0x48, 0x48, 0x49, 0x4F, 0x4E, 0x4A, 0x4B,
	0x75, 0x74, 0x74, 0x75, 0x73, 0x72, 0x7E, 0x7F, 0x71, 0x70, 0x70, 0x71, 0x77, 0x76, 0x72, 0x73,
	0x6D, 0x6C, 0x6C, 0x6D, 0x6B, 0x6A, 0x56, 0x57, 0x59, 0x58, 0x58, 0x59, 0x5F, 0x5E, 0x5A, 0x5B,
	0x25, 0x24, 0x24, 0x25, 0x23, 0x22, 0x2E, 0x2F, 0x21, 0x20, 0x20, 0x21, 0x27, 0x26, 0x22, 0x23,
	0x3D, 0x3C, 0x3C, 0x3D, 0x3B, 0x3A, 0x26, 0x27, 0x29, 0x28, 0x28, 0x29, 0x2F, 0x2E, 0x2A, 0x2B,
	0x15, 0x14, 0x14, 0x15, 0x13, 0x12, 0x1E, 0x1F, 0x11, 0x10, 0x10, 0x11, 0x17, 0x16, 0x12, 0x13,
	0x0D, 0x0C, 0x0C, 0x0D, 0x0B, 0x0A, 0x76, 0x77, 0x79, 0x78, 0x78, 0x79, 0x7F, 0x7E, 0x7A, 0x7B,
	0x05, 0x04, 0x04, 0x05, 0x03, 0x02, 0x0E, 0x0F, 0x01, 0x00, 0x00, 0x01, 0x07, 0x06, 0x02, 0x03,
	0x1D, 0x1C, 0x1C, 0x1D, 0x1B, 0x1A, 0x06, 0x07, 0x09, 0x08, 0x08, 0x09, 0x0F, 0x0E, 0x0A, 0x0B,
	0x35, 0x34, 0x34, 0x35, 0x33, 0x32, 0x3E, 0x3F, 0x31, 0x30, 0x30, 0x31, 0x37, 0x36, 0x32, 0x33,
	0x2D, 0x2C, 0x2C, 0x2D, 0x2B, 0x2A, 0x16, 0x17, 0x19, 0x18, 0x18, 0x19, 0x1F, 0x1E, 0x1A, 0x1B,
	0x65, 0x64, 0x64, 0x65, 0x63, 0x62, 0x6E, 0x6F, 0x61, 0x60, 0x60, 0x61, 0x67, 0x66, 0x62, 0x63,
	0x7D, 0x7C, 0x7C, 0x7D, 0x7B, 0x7A, 0x66, 0x67, 0x69, 0x68, 0x68, 0x69, 0x6F, 0x6E, 0x6A, 0x6B,
	0x55, 0x54, 0x54, 0x55, 0x53, 0x52, 0x5E, 0x5F, 0x51, 0x50, 0x50, 0x51, 0x57, 0x56, 0x52, 0x53,
	0x4D, 0x4C, 0x4C, 0x4D, 0x4B, 0x4A, 0x36, 0x37, 0x39, 0x38, 0x38, 0x39, 0x3F, 0x3E, 0x3A, 0x3B,
	0x45, 0x44, 0x44, 0x45, 0x43, 0x42, 0x4E, 0x4F, 0x41, 0x40, 0x40, 0x41, 0x47, 0x46, 0x42, 0x43,
	0x5D, 0x5C, 0x5C, 0x5D, 0x5B, 0x5A, 0x46, 0x47, 0x49, 0x48, 0x48, 0x49, 0x4F, 0x4E, 0x4A, 0x4B,
	0x75, 0x74, 0x74, 0x75, 0x73, 0x72, 0x7E, 0x7F, 0x71, 0x70, 0x70, 0x71, 0x77, 0x76, 0x72, 0x73,
	0x6D, 0x6C, 0x6C, 0x6D, 0x6B, 0x6A, 0x56, 0x57, 0x59, 0x58, 0x58, 0x59, 0x5F, 0x5E, 0x5A, 0x5B,
	0x25, 0x24, 0x24, 0x25, 0x23, 0x22, 0x2E, 0x2F, 0x21, 0x20, 0x20, 0x21, 0x27, 0x26, 0x22, 0x23,
	0x3D, 0x3C, 0x3C, 0x3D, 0x3B, 0x3A, 0x26, 0x27, 0x29, 0x28, 0x28, 0x29, 0x2F, 0x2E, 0x2A, 0x2B,
	0x15, 0x14, 0x14, 0x15, 0x13, 0x12, 0x1E, 0x1F, 0x11, 0x10, 0x10, 0x11, 0x17, 0x16, 0x12, 0x13,
	0x0D, 0x0C, 0x0C, 0x0D, 0x0B, 0x0A, 0x76, 0x77, 0x79, 0x78, 0x78, 0x79, 0x7F, 0x7E, 0x7A, 0x7B,
	0x05, 0x04, 0x04, 0x05, 0x03, 0x02, 0x0E, 0x0F, 0x01, 0x00, 0x00, 0x01, 0x07, 0x06, 0x02, 0x03,
	0x1D, 0x1C, 0x1C, 0x1D, 0x1B, 0x1A, 0x06, 0x07, 0x09, 0x08, 0x08, 0x09, 0x0F, 0x0E, 0x0A, 0x0B,
	0x35, 0x34, 0x34, 0x35, 0x33, 0x32, 0x3E, 0x3F, 0x31, 0x30, 0x30, 0x31, 0x37, 0x36, 0x32, 0x33,
	0x2D, 0x2C, 0x2C, 0x2D, 0x2B, 0x2A, 0x16, 0x17, 0x19, 0x18, 0x18, 0x19, 0x1F, 0x1E, 0x1A, 0x1B,
	0x65, 0x64, 0x64, 0x65, 0x63, 0x62, 0x6E, 0x6F, 0x61, 0x60, 0x60, 0x61, 0x67, 0x66, 0x62, 0x63,
	0x7D, 0x7C, 0x7C, 0x7D, 0x7B, 0x7A, 0x66, 0x67, 0x69, 0x68, 0x68, 0x69, 0x6F, 0x6E, 0x6A, 0x6B,
	0x55, 0x54, 0x54, 0x55, 0x53, 0x52, 0x5E, 0x5F, 0x51, 0x50, 0x50, 0x51, 0x57, 0x56, 0x52, 0x53,
	0x4D, 0x4C, 0x4C, 0x4D, 0x4B, 0x4A, 0x36, 0x37, 0x39, 0x38, 0x38, 0x39, 0x3F, 0x3E, 0x3A, 0x3B
};
static const u8 seeds2[XP_ROM_BLKSIZE] = {
	0x2C, 0x2D, 0x2E, 0x2F, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x28, 0x29, 0x2A, 0x2B,
	0x3C, 0x3D, 0x3E, 0x3F, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x38, 0x39, 0x3A, 0x3B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B,
	0x1C, 0x1D, 0x1E, 0x1F, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x18, 0x19, 0x1A, 0x1B,
	0x2C, 0x2D, 0x2E, 0x2F, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x28, 0x29, 0x2A, 0x2B,
	0x3C, 0x3D, 0x3E, 0x3F, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x38, 0x39, 0x3A, 0x3B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B,
	0x1C, 0x1D, 0x1E, 0x1F, 0x18, 0x19, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0x98, 0x99, 0x9A, 0x9B,
	0x2C, 0x2D, 0x2E, 0x2F, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x28, 0x29, 0x2A, 0x2B,
	0x3C, 0x3D, 0x3E, 0x3F, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x38, 0x39, 0x3A, 0x3B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B,
	0x1C, 0x1D, 0x1E, 0x1F, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x18, 0x19, 0x1A, 0x1B,
	0x2C, 0x2D, 0x2E, 0x2F, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x28, 0x29, 0x2A, 0x2B,
	0x3C, 0x3D, 0x3E, 0x3F, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x38, 0x39, 0x3A, 0x3B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B,
	0x1C, 0x1D, 0x1E, 0x1F, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x18, 0x19, 0x1A, 0x1B,
	0xAC, 0xAD, 0xAE, 0xAF, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xA8, 0xA9, 0xAA, 0xAB,
	0xBC, 0xBD, 0xBE, 0xBF, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xB8, 0xB9, 0xBA, 0xBB,
	0x8C, 0x8D, 0x8E, 0x8F, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x88, 0x89, 0x8A, 0x8B,
	0x9C, 0x9D, 0x9E, 0x9F, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0x98, 0x99, 0x9A, 0x9B,
	0xAC, 0xAD, 0xAE, 0xAF, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xA8, 0xA9, 0xAA, 0xAB,
	0xBC, 0xBD, 0xBE, 0xBF, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xB8, 0xB9, 0xBA, 0xBB,
	0x8C, 0x8D, 0x8E, 0x8F, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x88, 0x89, 0x8A, 0x8B,
	0x9C, 0x9D, 0x9E, 0x9F, 0x98, 0x99, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x18, 0x19, 0x1A, 0x1B,
	0xAC, 0xAD, 0xAE, 0xAF, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xA8, 0xA9, 0xAA, 0xAB,
	0xBC, 0xBD, 0xBE, 0xBF, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xB8, 0xB9, 0xBA, 0xBB,
	0x8C, 0x8D, 0x8E, 0x8F, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x88, 0x89, 0x8A, 0x8B,
	0x9C, 0x9D, 0x9E, 0x9F, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0x98, 0x99, 0x9A, 0x9B,
	0xAC, 0xAD, 0xAE, 0xAF, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xA8, 0xA9, 0xAA, 0xAB,
	0xBC, 0xBD, 0xBE, 0xBF, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xB8, 0xB9, 0xBA, 0xBB,
	0x8C, 0x8D, 0x8E, 0x8F, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x88, 0x89, 0x8A, 0x8B,
	0x9C, 0x9D, 0x9E, 0x9F, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0x98, 0x99, 0x9A, 0x9B
};

/**
 * xp_encrypt_rom - Encrypt an Xploder ROM.
 * @rom: buffer holding ROM in raw format
 * @size: size of ROM buffer
 * @return: 0: success, -1: error
 */
int xp_encrypt_rom(u8 *rom, int size)
{
	int i;

	if (rom == NULL || size < XP_ROM_BLKSIZE)
		return -1;

	for (i = 0; i < size; i++)
		rom[i] = (rom[i] - seeds2[i % XP_ROM_BLKSIZE]) ^ seeds1[i % XP_ROM_BLKSIZE];

	return 0;
}

/**
 * xp_decrypt_rom - Decrypt an Xploder ROM.
 * @rom: buffer holding encrypted ROM
 * @size: size of ROM buffer
 * @return: 0: success, -1: error
 */
int xp_decrypt_rom(u8 *rom, int size)
{
	int i;

	if (rom == NULL || size < XP_ROM_BLKSIZE)
		return -1;

	for (i = 0; i < size; i++)
		rom[i] = (rom[i] ^ seeds1[i % XP_ROM_BLKSIZE]) + seeds2[i % XP_ROM_BLKSIZE];

	return 0;
}

/**
 * xp_crypt_rom - Automatically decrypt or encrypt an Xploder ROM.
 * @rom: buffer holding ROM
 * @size: size of ROM buffer
 * @return: 0: success, -1: error
 */
int xp_crypt_rom(u8 *rom, int size)
{
	if (rom == NULL || size < XP_ROM_BLKSIZE)
		return -1;

	/*
	 * Check if ROM needs to be decrypted or encrypted. Decrypted ROMs have
	 * the string "Licensed by Sony Computer Entertainment Inc." in the
	 * header. Let's look for "Sony".
	 */
	if (*(u32*)&rom[0x10] != 0x796e6f53)
		return xp_decrypt_rom(rom, size);
	else
		return xp_encrypt_rom(rom, size);
}

#if 0
#include <stdio.h>
#include <string.h>

/* Number of ROM bytes required to crack a single byte */
#define BF_BYTES 256

/**
 * xp_bf_rom - Brute force encryption seeds of Xploder ROMs.
 * @encrom: buffer holding encrypted ROM
 * @decrom: buffer holding decrypted ROM
 * @size: size of ROM buffers
 * @return: 0: success, -1: error
 *
 * This is the algorithm I used to crack the Xploder ROM encryption. Once I
 * figured out the scheme and its block size by comparing encrypted ROMs to
 * decrypted ones, it was pretty easy to get the complete seed tables.
 */
int xp_bf_rom(const u8 *encrom, const u8 *decrom, int size)
{
	u8 dec[BF_BYTES], enc[BF_BYTES], try[BF_BYTES];
	u8 seeds[2][XP_ROM_BLKSIZE];
	u8 b;
	int a, i, j, found;
	FILE *fp;

	if (encrom == NULL || decrom == NULL)
		return -1;

	if (size < (BF_BYTES * XP_ROM_BLKSIZE)) {
		fprintf(stderr, "Error: ROM size too small for brute force attack\n");
		return -1;
	}

	/* Start brute force attack on all block bytes. */
	for (i = 0; i < XP_ROM_BLKSIZE; i++) {
		found = 0;

		/* Build tables for each block byte. */
		for (j = 0; j < BF_BYTES; j++) {
			enc[j] = encrom[XP_ROM_BLKSIZE * j + i];
			dec[j] = decrom[XP_ROM_BLKSIZE * j + i];
		}

		/* Systematically try every possible seed value. */
		for (a = 0; a <= 0xFF; a++) {
			/* Calculate seed b from seed a. */
			b = dec[0] - (enc[0] ^ (u8)a);

			/*
			 * Decrypt all bytes with candidate seeds and compare
			 * result to bytes from decrypted ROM. If they match, we
			 * got the right seeds.
			 */
			for (j = 0; j < BF_BYTES; j++)
				try[j] = (enc[j] ^ (u8)a) + b;

			if (!memcmp(try, dec, BF_BYTES)) {
				found = 1;
				seeds[0][i] = (u8)a;
				seeds[1][i] = b;
				break;
			}
		}

		if (!found) {
			fprintf(stderr, "Error: brute force failed at offset 0x%02x\n", i);
			return -1;
		}
	}

	/* Write seeds to files. */
	fp = fopen("seeds1.bin", "w");
	if (fp == NULL) {
		fprintf(stderr, "Error: could not create file seeds1.bin\n");
		return -1;
	}
	fwrite(seeds[0], XP_ROM_BLKSIZE, 1, fp);
	fclose(fp);

	fp = fopen("seeds2.bin", "w");
	if (fp == NULL) {
		fprintf(stderr, "Error: could not create file seeds2.bin\n");
		return -1;
	}
	fwrite(seeds[1], XP_ROM_BLKSIZE, 1, fp);
	fclose(fp);

	return 0;
}
#endif
