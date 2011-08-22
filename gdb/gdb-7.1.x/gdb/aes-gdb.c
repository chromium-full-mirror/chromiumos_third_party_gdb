/* GDB read/write routines using AES.
   NOTE: This file is used by both gdb and gdbserver.

   Copyright (C) 2009 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef GDBSERVER
#include <assert.h>
#include "server.h"
#else
#include "defs.h"
#include "gdb_assert.h"
#endif

#include "aes.h"
#include "aes-gdb.h"

#ifdef GDBSERVER
#define aes_assert(expr) assert (expr)
#else
#define aes_assert(expr) gdb_assert (expr)
#endif

/* Initial size of working_buf.  */
#define INITIAL_WORKING_BUF_SIZE 2000

static int debug_encryption = 0;

static void
dump_packet (const char *prefix, const unsigned char *pkt, unsigned len)
{
  const unsigned char *p = pkt;
  fprintf (stderr, "%s:", prefix);
  while (len > 0)
    {
      fprintf (stderr, " %02x", *p);
      if (*p >= 32 && *p < 127)
	fprintf (stderr, "(%c)", *p);
      ++p;
      --len;
    }
  fprintf (stderr, "\n");
}

/* Given PAYLOAD_LENGTH return the total message length, including
   leading length field and padding bytes, not including the optional
   leading initialization-vector.
   Remember that if length+payload is a multiple of AES_BLOCK_SIZE then the
   message includes a trailing padding block of all padding bytes.  */

static int
get_message_length (int payload_length)
{
  return ((((payload_length + PAYLOAD_LENGTH_SIZE)
	    / AES_BLOCK_SIZE)
	   + 1)
	  * AES_BLOCK_SIZE);
}

/* Increase the size of working_buf.
   This also needs to realloc decrypt_queue to keep them in sync.  */

static void
realloc_working_buf (struct aes_gdb_state *ags, int new_size)
{
  ags->working_buf_size = new_size;
  ags->decrypt_queue = realloc (ags->decrypt_queue, ags->working_buf_size);
  ags->working_buf = realloc (ags->working_buf, ags->working_buf_size);
  if (ags->decrypt_queue == NULL || ags->working_buf == NULL)
    {
      fprintf (stderr, "realloc_working_buf: malloc failure\n");
      exit (1);
    }
  ags->dqueue_head = ags->dqueue_tail = ags->decrypt_queue;
}

int
aes_gdb_write (struct aes_gdb_state *ags, int fd,
	       const void *buf, size_t count)
{
  const unsigned char *bufp = buf;
  int length, written, iv_size;
  int count_remaining, padded_block_remaining;
  unsigned char iv[AES_BLOCK_SIZE];
  unsigned char padded_block[AES_BLOCK_SIZE];

  if (debug_encryption)
    dump_packet ("write", buf, count);

  /* The packet size is encoded as two bytes in the packet.
     The top few values are reserved "just in case".  */
  aes_assert (count >= 0 && count <= 60000);

  if (ags->working_buf_size < get_message_length (count) + AES_BLOCK_SIZE)
    {
      int new_size = get_message_length (count) + AES_BLOCK_SIZE;
      if (new_size < (INITIAL_WORKING_BUF_SIZE / AES_BLOCK_SIZE + 2) * AES_BLOCK_SIZE)
	new_size = (INITIAL_WORKING_BUF_SIZE / AES_BLOCK_SIZE + 2) * AES_BLOCK_SIZE;
      realloc_working_buf (ags, new_size);
    }

  written = 0;
  count_remaining = count;

  aes_random (ags->aes_ctx, iv, sizeof (iv));
  memcpy (ags->working_buf, iv, sizeof (iv));
  written += AES_BLOCK_SIZE;
  iv_size = AES_BLOCK_SIZE;

  /* After the optional iv block, the next block is a bit weird in that
     we need to tell the receiver the length.  There are other things we could
     do besides having a leading length field, but this is simple.  */

  padded_block[0] = count & 0xff;
  padded_block[1] = (count >> 8) & 0xff;
  padded_block_remaining = AES_BLOCK_SIZE - 2;

  /* This tests for < instead of <= because there is always a trailing
     padding block, even if the payload ends on a block boundary.  */

  if (count < padded_block_remaining)
    {
      memcpy (padded_block + 2, bufp, count);
      bufp += count;
      count_remaining = 0;
      length = 0;
      padded_block_remaining -= count;
    }
  else
    {
      memcpy (padded_block + 2, bufp, padded_block_remaining);
      count_remaining -= padded_block_remaining;
      bufp += padded_block_remaining;
      aes_cbc_encrypt (padded_block, ags->working_buf + written,
		       AES_BLOCK_SIZE, ags->aes_ctx, iv);
      written += AES_BLOCK_SIZE;

      length = (count_remaining / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
      aes_cbc_encrypt (bufp, ags->working_buf + written, length,
		       ags->aes_ctx, iv);
      written += length;
      bufp += length;
      count_remaining -= length;

      padded_block_remaining = AES_BLOCK_SIZE;
      if (count_remaining > 0)
	{
	  memcpy (padded_block, bufp, count_remaining);
	  padded_block_remaining -= count_remaining;
	}
    }

  /* Now pad any trailing bytes of the plaintext.  */
  if (padded_block_remaining > 0)
    {
      /* PKCS#5 padding: If not block-aligned, pad out with the number of
	 pad byte, e.g. {1}, {2, 2}, etc.  If exactly block aligned, pad with
	 an entire block of 16-valued bytes.  */
      unsigned char pad_value = padded_block_remaining;
      memset (padded_block + AES_BLOCK_SIZE - padded_block_remaining,
	      pad_value, padded_block_remaining);
    }
  aes_cbc_encrypt (padded_block, ags->working_buf + written, AES_BLOCK_SIZE,
		   ags->aes_ctx, iv);
  written += AES_BLOCK_SIZE;

  if (write (fd, ags->working_buf, written) < 0)
    return -1;
  /* This is the number of bytes written as far as the caller is concerned.  */
  return count;
}

/* NOTE: This may return less than the requested count.  */

int
aes_gdb_read (struct aes_gdb_state *ags, int fd,
	      void *buf, size_t count)
{
  unsigned char *bufp;
  int i, initial_read, recvd;
  int iv_size, payload_length, message_length;
  unsigned char iv[AES_BLOCK_SIZE];
  unsigned char pad_value;

  if (ags->working_buf == NULL)
    realloc_working_buf (ags, (BUFSIZ / AES_BLOCK_SIZE + 2) * AES_BLOCK_SIZE);

  aes_assert (ags->dqueue_tail >= ags->dqueue_head);
  aes_assert (ags->dqueue_head >= ags->decrypt_queue);
  aes_assert (ags->dqueue_tail <= ags->decrypt_queue + ags->working_buf_size);

  /* If there is something remaining in DECRYPT_QUEUE, use that first.
     If there is insufficient bytes in DECRYPT_QUEUE to satisfy COUNT we
     could continue to read more, but it's an unnecessary complication.  */
  if (ags->dqueue_head < ags->dqueue_tail)
    {
      unsigned length = ags->dqueue_tail - ags->dqueue_head;
      if (count < length)
	length = count;
      memcpy (buf, ags->dqueue_head, length);
      ags->dqueue_head += length;

      if (debug_encryption)
	dump_packet ("read", buf, length);

      return length;
    }

  aes_assert (ags->dqueue_head == ags->dqueue_tail);

  /* To keep things simple for now, first read enough to know how big
     the packet is, then read the rest of it.  */

  initial_read = AES_BLOCK_SIZE * 2;
  recvd = 0;
  while (recvd < initial_read)
    {
      int to_read = initial_read - recvd;
      int nr_read = read (fd, ags->working_buf + recvd, to_read);
      if (nr_read < 0)
	return -1;
      if (nr_read == 0)
	return 0; /* EOF */
      recvd += nr_read;
    }

  memcpy (iv, ags->working_buf, AES_BLOCK_SIZE);
  iv_size = AES_BLOCK_SIZE;

  aes_cbc_decrypt (ags->working_buf + iv_size, ags->decrypt_queue,
		   AES_BLOCK_SIZE, ags->aes_ctx, iv);
  payload_length = ags->decrypt_queue[0] + (ags->decrypt_queue[1] << 8);
  message_length = get_message_length (payload_length);

  /* If we don't have a big enough buffer, enlarge it.  */

  if (message_length + iv_size > ags->working_buf_size)
    realloc_working_buf (ags, message_length + iv_size);

  /* Fetch and decrypt the rest of the message.
     This tests for >= instead of > because there is always a trailing
     padding block, even if the payload ends on a block boundary.  */

  if (payload_length >= AES_BLOCK_SIZE - PAYLOAD_LENGTH_SIZE)
    {
      int remaining_count = message_length - AES_BLOCK_SIZE;
      bufp = ags->working_buf + iv_size + AES_BLOCK_SIZE;
      recvd = 0;
      while (recvd < remaining_count)
	{
	  int to_read = remaining_count - recvd;
	  int nr_read = read (fd, bufp + recvd, to_read);
	  if (nr_read < 0)
	    return -1;
	  if (nr_read == 0)
	    return 0; /* EOF */
	  recvd += nr_read;
	}

      aes_cbc_decrypt (bufp, ags->decrypt_queue + AES_BLOCK_SIZE,
		       remaining_count, ags->aes_ctx, iv);
    }

  /* Verify the padding bytes.  */
  pad_value = ags->decrypt_queue[message_length - 1];
  if (pad_value == 0 || pad_value > AES_BLOCK_SIZE)
    {
      if (debug_encryption)
	dump_packet ("padding error", ags->decrypt_queue, message_length);
      error ("padding error");
      return -1;
    }
  for (i = 1; i <= pad_value; ++i)
    {
      if (ags->decrypt_queue[message_length - i] != pad_value)
	{
	  if (debug_encryption)
	    dump_packet ("padding error", ags->decrypt_queue, message_length);
	  error ("padding error");
	  return -1;
	}
    }

  /* Set up the queued data and recurse to transfer the data to the caller.  */
  ags->dqueue_head = ags->decrypt_queue + PAYLOAD_LENGTH_SIZE;
  ags->dqueue_tail = ags->dqueue_head + payload_length;
  return aes_gdb_read (ags, fd, buf, count);
}
