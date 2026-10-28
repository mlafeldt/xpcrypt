/*
 * crypto.c - Cryptographic functions for Xploder PSX
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
#include <string.h>
#include "crypto.h"

/*
 * This is a code converter, not an emulator of the cartridge. Every cipher
 * equation, block layout and ROM transform below is the firmware's own, but
 * six things are deliberately not what an Xploder does, and a claim that
 * xpcrypt behaves like the hardware has to leave them out:
 *
 *   - the code types 32/82 and 33/83 have firmware crypto routes (Special32
 *     and Special33), and are copied verbatim here - see below;
 *   - the "switched off by default" bit survives decryption, so that a code
 *     round-trips; the cartridge clears the whole key nibble instead. Only the
 *     cartridge does, though: XLink.exe stamps byte 0 as (b & 0xF8) | key and
 *     keeps that bit, so a round trip through the pair of them is what the
 *     format expected. The cartridge's engine keeps the bit too and reads at
 *     an address 0x08000000 away because of it;
 *   - the payload of a block whose key we cannot process is left alone, where
 *     the firmware writes a row of zeros;
 *   - a Supercode header declaring no payload is treated as an ordinary code,
 *     because the line below it is one; the cartridge stages the empty block
 *     and its engine then runs away, which the CLI warns about. A Megacode
 *     cannot say the same thing: its length counts the bytes after the
 *     breakpoint descriptor, so a zero there still means the two codes the
 *     descriptor occupies, and the cartridge's stager reads those two
 *     unconditionally - as this does;
 *   - a code type A takes every code that follows to the end of the input,
 *     because a stream of codes has no cheat-entry boundary in it, where the
 *     cartridge stops at the end of the cheat;
 *   - the code engine, the ROM compressor and the anti-tamper check are not
 *     implemented. The CLI reads the cheat database, but does not emulate it.
 */

/*
 * All the magic numbers of the code keys come from the initials of the authors
 * of the Xploder. The Xploder builds the keys 4 and 7 byte by byte, from a
 * sliding window that starts out as the string "WHBX" and "FCD!", and adds the
 * characters of " WB123" for the key 5. The closed forms below are the same
 * functions: the 0x25 of the key 4, for instance, is
 *
 *   'W' + 0x38 + 'H' + ('B' ^ 0x12) + ('X' | 0xEE)
 *
 * Note that x | 0xEE is (x & 0x11) + 0xEE, and that (x ^ 0xEF) + 0x76 of the
 * key 7 is 0xF5 - (x ^ 0x90).
 *
 * Both spellings are attested on the PC side. XLink.exe, the vendor's DOS
 * X-Link utility, slides the same windows over its own copies of those three
 * strings, and it does so in the *encrypt* direction, which the cartridge has
 * no trace of - so it, not a round trip, is what the encrypt routines below are
 * checked against. X-Killer v0.55, a third party's tool from 1999, computes the
 * keys 6 and 7 from the closed forms instead, the same ones used here.
 */

/*
 * What the sixteen code types are to the cartridge.
 *
 * TYPE_KEYED: the decrypt routine has a cipher route for the type. It picks the
 * route from a table of 244 entries indexed by the first code byte with the
 * default-off bit masked out, and that table gives the types 2, A, C and E
 * none: their entries copy the code verbatim, whatever its key bits say. Which
 * types carry a key is all that is left of the table once the key nibble is
 * taken out.
 *
 * TYPE_ADDRESSED: the code engine stores to or compares at the code's address.
 */
enum {
	TYPE_KEYED = 1,
	TYPE_ADDRESSED = 2
};

static const u8 type_flags[16] = {
	[0x0] = TYPE_KEYED | TYPE_ADDRESSED,	/* 32-bit write */
	[0x1] = TYPE_KEYED,			/* nothing */
	[0x2] = 0,				/* nothing */
	[0x3] = TYPE_KEYED | TYPE_ADDRESSED,	/* 8-bit write */
	[0x4] = TYPE_KEYED,			/* slow motion */
	[0x5] = TYPE_KEYED,			/* Supercode */
	[0x6] = TYPE_KEYED,			/* Megacode */
	[0x7] = TYPE_KEYED | TYPE_ADDRESSED,	/* execute next if equal */
	[0x8] = TYPE_KEYED | TYPE_ADDRESSED,	/* 16-bit write */
	[0x9] = TYPE_KEYED | TYPE_ADDRESSED,	/* execute next if not equal */
	[0xA] = 0,				/* inline data block */
	[0xB] = TYPE_KEYED | TYPE_ADDRESSED,	/* slide */
	[0xC] = 0,				/* nothing */
	[0xD] = TYPE_KEYED,			/* anchor, rewritten in staging */
	[0xE] = TYPE_ADDRESSED,			/* 8-bit write, one byte up */
	[0xF] = TYPE_KEYED | TYPE_ADDRESSED	/* anchor */
};

/**
 * xp_code_route - Get the route the Xploder's decrypt routine takes for a code.
 * @code: code to be checked
 * @return: the route
 */
enum xp_route xp_code_route(const u8 *code)
{
	int key = code[0] & XP_KEY_MASK;
	int first = code[0] & (0xFF ^ XP_DEFAULT_OFF);

	if (!(type_flags[xp_code_type(code)] & TYPE_KEYED))
		return XP_ROUTE_COPY;
	if (key == 0)
		return XP_ROUTE_PLAIN;
	if (key >= XP_KEY_4)
		return XP_ROUTE_KEYED;
	if (first == 0x32 || first == 0x82)
		return XP_ROUTE_SPECIAL32;
	if (first == 0x33 || first == 0x83)
		return XP_ROUTE_SPECIAL33;
	return XP_ROUTE_NO_CIPHER;
}

/**
 * xp_code_addressed - Does the code engine use the address of a code?
 * @code: code to be checked
 * @return: non-zero if it does
 */
int xp_code_addressed(const u8 *code)
{
	return (type_flags[xp_code_type(code)] & TYPE_ADDRESSED) != 0;
}

/*
 * The keys 0 to 3 are not code keys, so a code that carries one is stored as
 * it is - with two exceptions. The Xploder gives the first bytes 32 and 82 a
 * route that adds 'F', 'C' and 'D' to the bytes 1 to 3, and 33 and 83 one that
 * inverts them. Those four bytes are all there is to it, and they are left
 * unimplemented on purpose: no database we have seen uses them, no encrypter
 * implements them - not the cartridge, which encrypts nothing, and not
 * XLink.exe, whose method table has a route for every other key and none for
 * these - and the constants the reference implementation uses for them are
 * wrong.
 */

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

	/*
	 * The key is stored in the lowest three bits of the first code byte. A
	 * code that uses those bits itself has no room for a key, and a code of
	 * a type the Xploder never encrypts must not carry one either.
	 */
	if (xp_code_route(code) != XP_ROUTE_PLAIN)
		return -1;

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
		return -1; /* Leave code untouched */
	}

	code[0] ^= key;

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

	/* Codes of a type the Xploder never encrypts are left as they are. */
	if (xp_code_route(code) == XP_ROUTE_COPY)
		return -1;

	/*
	 * The key is stored in the lowest three bits of the first code byte.
	 * Bit 3 marks a code that is switched off by default and thus must be
	 * kept as it is. The Xploder clears the whole nibble instead, which it
	 * can afford to do because it never has to encrypt the code again.
	 */
	if (key == XP_KEY_AUTO)
		key = code[0] & XP_KEY_MASK; /* Auto process */

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
		return -1; /* Leave code untouched */
	}

	code[0] ^= key;

	return 0;
}


/*
 * The code types 5 (Supercode) and 6 (Megacode) don't fit into a single code.
 * They consist of a header code plus a number of payload codes which hold raw
 * data instead of the usual address/value pair:
 *
 *   Supercode: 5?aaaaaa Knnn   Megacode: 6?aaaaaK nnnn
 *
 * n is the number of payload bytes, K the key the payload is encrypted with.
 * That key is not one of the normal code keys. The payload of a Megacode is
 * preceded by a breakpoint descriptor, see XP_MEGA_DESC_LEN.
 *
 * The block layout and the payload crypto were figured out by SkillerCMP, see
 * https://github.com/SkillerCMP/PSX-Xploder. The routines below follow the ones
 * of the Xploder itself, which decrypts every code of a payload the same way,
 * no matter if it belongs to a Supercode or a Megacode.
 */

/*
 * Returns non-zero if the crypto routine for payload key @key is known. The
 * Xploder only knows the keys 6 and 7; for any other key but 0 it zeroes the
 * last five bytes of the code and writes nothing at all to the first, which
 * makes the block useless whatever was there before. We keep such a payload as
 * it is instead, so that nothing is lost.
 */
static int known_payload_key(int key)
{
	return key == 6 || key == 7;
}

/*
 * Decrypt a payload code with payload key @key.
 */
static int decrypt_payload(u8 *code, int key)
{
	u8 in[XP_CODE_LEN];
	int i;

	memcpy(in, code, XP_CODE_LEN);

	switch (key) {
	case 6:
		code[0] = (u8)~in[1];
		code[1] = in[0] - 0x34;
		code[2] = in[4] - 0x1B;
		code[3] = in[3] ^ in[1];
		code[4] = in[5] - 0x55;
		code[5] = in[2] - in[0];
		break;
	case 7:
		/* Reverse the byte order and subtract 0x55. */
		for (i = 0; i < XP_CODE_LEN; i++)
			code[XP_CODE_LEN - 1 - i] = in[i] - 0x55;
		break;
	default:
		return -1;
	}

	return 0;
}

/*
 * Encrypt a payload code with payload key @key.
 */
static int encrypt_payload(u8 *code, int key)
{
	u8 in[XP_CODE_LEN];
	int i;

	memcpy(in, code, XP_CODE_LEN);

	switch (key) {
	case 6:
		code[0] = in[1] + 0x34;
		code[1] = (u8)~in[0];
		code[2] = in[5] + code[0];
		code[3] = in[3] ^ code[1];
		code[4] = in[2] + 0x1B;
		code[5] = in[4] + 0x55;
		break;
	case 7:
		for (i = 0; i < XP_CODE_LEN; i++)
			code[i] = in[XP_CODE_LEN - 1 - i] + 0x55;
		break;
	default:
		return -1;
	}

	return 0;
}

/**
 * xp_parse_block - Get the layout of a block of payload codes.
 * @code: decrypted header code of the block
 * @blk: block layout to be filled in
 * @return: 0: success, -1: @code is not a block header
 */
int xp_parse_block(const u8 *code, struct xp_block *blk)
{
	int nbytes;

	if (code == NULL || blk == NULL)
		return -1;

	switch (xp_code_type(code)) {
	case 0x5: /* Supercode */
		blk->kind = XP_BLOCK_SUPER;
		blk->payload_key = code[4] >> 4;
		blk->declared = ((code[4] & 0x0F) << 8) | code[5];
		nbytes = blk->declared;
		break;
	case 0x6: /* Megacode */
		blk->kind = XP_BLOCK_MEGA;
		blk->payload_key = code[3] & 0x0F;
		blk->declared = (code[4] << 8) | code[5];
		nbytes = blk->declared + XP_MEGA_DESC_LEN;
		break;
	case 0xA: /* Inline data block */
		/*
		 * No length and no payload key: the Xploder copies the value
		 * field plus the six raw bytes of every code below the header
		 * until the cheat ends. So every following code is payload, and
		 * how many of them there are is not in the header.
		 */
		blk->kind = XP_BLOCK_INLINE;
		blk->payload_key = 0;
		blk->known_key = 1;
		blk->num_lines = 0;
		blk->declared = -1;
		return 0;
	default:
		return -1;
	}

	/*
	 * The payload key 0 means that the payload is not encrypted at all, so
	 * there is nothing we could fail to decrypt.
	 */
	blk->known_key = blk->payload_key == 0 ||
		known_payload_key(blk->payload_key);
	blk->num_lines = (nbytes + XP_CODE_LEN - 1) / XP_CODE_LEN;

	return 0;
}

/**
 * xp_in_payload - Is a code at position @index still part of block @blk?
 * @blk: block layout returned by xp_parse_block()
 * @index: position of the code in the payload, starting at 0
 * @return: non-zero if it is
 */
int xp_in_payload(const struct xp_block *blk, int index)
{
	if (blk == NULL || index < 0)
		return 0;

	return blk->kind == XP_BLOCK_INLINE || index < blk->num_lines;
}

/**
 * xp_decrypt_block_line - Decrypt a payload code of a block.
 * @code: code to be decrypted
 * @blk: block layout returned by xp_parse_block()
 * @index: position of the code in the payload, starting at 0
 * @return: 0: success, -1: error
 */
int xp_decrypt_block_line(u8 *code, const struct xp_block *blk, int index)
{
	if (code == NULL || !xp_in_payload(blk, index))
		return -1;

	if (known_payload_key(blk->payload_key))
		decrypt_payload(code, blk->payload_key);

	return 0;
}

/**
 * xp_encrypt_block_line - Encrypt a payload code of a block.
 * @code: code to be encrypted
 * @blk: block layout returned by xp_parse_block()
 * @index: position of the code in the payload, starting at 0
 * @return: 0: success, -1: error
 */
int xp_encrypt_block_line(u8 *code, const struct xp_block *blk, int index)
{
	if (code == NULL || !xp_in_payload(blk, index))
		return -1;

	if (known_payload_key(blk->payload_key))
		encrypt_payload(code, blk->payload_key);

	return 0;
}


#define XP_ROM_SIG_TEXT		"Sony"
#define XP_ROM_SIG_OFFSET	0x10
#define XP_ROM_SIG_LEN		(sizeof(XP_ROM_SIG_TEXT) - 1)

typedef char xp_rom_min_size_matches_marker[
	XP_ROM_SIG_OFFSET + XP_ROM_SIG_LEN == XP_ROM_MIN_SIZE ? 1 : -1];

/**
 * xp_rom_is_plain - Check whether an Xploder ROM is plaintext.
 * @rom: buffer holding ROM data
 * @size: size of ROM buffer
 * @return: non-zero if the plaintext marker is present
 *
 * Decrypted ROMs have the string "Licensed by Sony Computer Entertainment
 * Inc." in the header, so looking for "Sony" is enough to identify one.
 * Compare the bytes rather than a u32: @rom points into a buffer we do not
 * own, so it need not be aligned, and a word compare would look for the string
 * byte-swapped on a big-endian host.
 */
int xp_rom_is_plain(const u8 *rom, size_t size)
{
	return rom != NULL && size >= XP_ROM_SIG_OFFSET + XP_ROM_SIG_LEN &&
		memcmp(&rom[XP_ROM_SIG_OFFSET], XP_ROM_SIG_TEXT,
			XP_ROM_SIG_LEN) == 0;
}

/*
 * The image cipher is a keystream over the absolute file offset - no key, no
 * block, and nothing the cartridge contains: it lives in the PC-side upgrade
 * tool, which is the only thing that ever sees an .fcd. Both directions were
 * read out of XLink.exe (X-Link V1.091) at 0x2A4A0 and 0x2A640, and out of
 * three other tools that agree with it byte for byte.
 *
 * rom_mask() depends on offset bits 0..8 and rom_addend() on bits 0..5, so the
 * keystream repeats every 512 bytes - a period, not a block size.
 */
static u8 rom_mask(size_t i)
{
	return (u8)(i ^ ((i >> 1) + 0x45));
}

static u8 rom_addend(size_t i)
{
	return (u8)((i & 0x37) ^ 0x2C);
}

/**
 * xp_encrypt_rom - Encrypt an Xploder ROM.
 * @rom: buffer holding ROM in raw format
 * @size: number of bytes to process
 * @return: 0: success, -1: error
 */
int xp_encrypt_rom(u8 *rom, size_t size)
{
	size_t i;

	if (rom == NULL)
		return -1;

	for (i = 0; i < size; i++)
		rom[i] = (u8)((rom[i] - rom_addend(i)) ^ rom_mask(i));

	return 0;
}

/**
 * xp_decrypt_rom - Decrypt an Xploder ROM.
 * @rom: buffer holding encrypted ROM
 * @size: number of bytes to process
 * @return: 0: success, -1: error
 */
int xp_decrypt_rom(u8 *rom, size_t size)
{
	size_t i;

	if (rom == NULL)
		return -1;

	for (i = 0; i < size; i++)
		rom[i] = (u8)((rom[i] ^ rom_mask(i)) + rom_addend(i));

	return 0;
}

/**
 * xp_rom_to_plain - Bring an Xploder ROM into plaintext.
 * @rom: buffer holding ROM data, decrypted in place if encrypted
 * @size: size of ROM buffer
 * @return: 0: success, -1: not an Xploder ROM in either state
 *
 * Unlike xp_crypt_rom(), which trusts the marker to pick a direction, this
 * confirms that decrypting produced the marker. A buffer that fails is not an
 * Xploder ROM, and its contents are left undefined.
 */
int xp_rom_to_plain(u8 *rom, size_t size)
{
	if (xp_rom_is_plain(rom, size))
		return 0;
	if (xp_decrypt_rom(rom, size))
		return -1;
	return xp_rom_is_plain(rom, size) ? 0 : -1;
}

/**
 * xp_crypt_rom - Automatically decrypt or encrypt an Xploder ROM.
 * @rom: buffer holding ROM
 * @size: size of ROM buffer; must be at least XP_ROM_MIN_SIZE
 * @return: 0: success, -1: error
 */
int xp_crypt_rom(u8 *rom, size_t size)
{
	/*
	 * Judge the buffer before converting it: a buffer too short to hold the
	 * marker is not a ROM, where xp_rom_is_plain() alone would call it an
	 * encrypted one and hand back garbage.
	 */
	if (rom == NULL || size < XP_ROM_MIN_SIZE)
		return -1;

	return xp_rom_is_plain(rom, size) ? xp_encrypt_rom(rom, size)
		: xp_decrypt_rom(rom, size);
}
