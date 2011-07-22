/* Paths common to gdb and gdbserver.
   Copyright (C) 2008, 2009 Google Inc.

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

#ifndef GOOGLE_GDB_PROC_SERVICE_H
#define GOOGLE_GDB_PROC_SERVICE_H

#ifndef LIBTHREAD_DB_SO
#define LIBTHREAD_DB_SO "libthread_db.so.1"
#endif

#ifndef LIBTHREAD_DB_SEARCH_PATH
#if __LP64__
#define LIBTHREAD_DB_SEARCH_PATH \
  "/lib64:/lib64/tls:/usr/grte/v1/lib64:/usr/grte/v2/lib64"
#else
/* ??? This is wrong for gdb32 on ghardy.
   gdb is still able to find the right libthread_db for native gcc-compiled
   binaries because it looks in the directory with libpthread.
   Is adding --with-libthread-db-search-path=PATH worth it?  */
#define LIBTHREAD_DB_SEARCH_PATH \
  "/lib:/lib/tls:/lib/tls/i686/cmov:/usr/grte/v1/lib:/usr/grte/v1/lib/tls:/usr/grte/v2/lib"
#endif
#endif

#endif /* google_gdb_proc_service.h */
