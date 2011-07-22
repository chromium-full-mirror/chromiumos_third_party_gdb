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

#ifndef AES_GDB_H
#define AES_GDB_H

struct aes_gdb_state
{
  struct aes_ctx *aes_ctx;	/* Opaque handle of encryption engine */
  int working_buf_size;		/* Size of working_buf */
  unsigned char *working_buf;	/* Staging area for encryption/decryption */
  unsigned char *decrypt_queue;	/* Decrypted chars not yet read */
  unsigned char *dqueue_head;	/* Front of chars in decrypt_queue */
  unsigned char *dqueue_tail;	/* One passed end of chars in decrypt_queue */
};

int aes_gdb_write (struct aes_gdb_state *, int fd,
		   const void *buf, size_t count);

int aes_gdb_read (struct aes_gdb_state *, int fd,
		  void *buf, size_t count);

#endif /* AES_GDB_H */
