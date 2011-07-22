/*
 * AES functions
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef AES_H
#define AES_H

#include <stdlib.h> /* size_t */

#define AES_BLOCK_SIZE 16

/* The number of bytes used to encode the payload length.
   Packets have a leading length field since we need to decrypt each
   message as a unit.  */
#define PAYLOAD_LENGTH_SIZE 2

struct aes_ctx;

/* Initialize an encryption context.  */
struct aes_ctx * aes_init (const unsigned char *key, size_t len);

/* Discard the resources obtained by oaes_init.  */
void aes_deinit (struct aes_ctx *ctx);

void aes_encrypt (struct aes_ctx *ctx, const unsigned char *plain,
		  unsigned char *crypt);
void aes_decrypt (struct aes_ctx *ctx, const unsigned char *crypt,
		  unsigned char *plain);

void aes_cbc_encrypt (const unsigned char *in, unsigned char *out,
		      const unsigned long length, struct aes_ctx *ctx,
		      unsigned char *ivec);
void aes_cbc_decrypt (const unsigned char *in, unsigned char *out,
		      const unsigned long length, struct aes_ctx *ctx,
		      unsigned char *ivec);

/* Initialize the counter used to generate random numbers.  */
void aes_init_random (struct aes_ctx *ctx, const unsigned char *buf, size_t len);

/* Generate a new random number in BUF, AES_BLOCK_SIZE bytes long.
   CTX is result of aes_init.  */
void aes_random (struct aes_ctx *ctx, unsigned char *buf, size_t len);

/* Wrapper to read in a gdb encryption specs file.
   The result is NULL for success or an error message string.  */
const char * aes_init_from_file (const char *specs_file,
				 struct aes_ctx ** ctxp);

/* Generate a file for use by aes_init_from_file.
   IV is either "iv" (use an initialization vector) or "noiv" (don't use).
   RANDOM_SOURCE is a file to obtain random numbers from.
   It is typically /dev/random (or /dev/urandom, but /dev/random is
   preferred).
   The result is NULL for success or an error message.  */
const char * aes_generate_init_file (const char *file,
				     const char *random_source);

#endif /* AES_H */
