/* Usage logging front end for gdb.

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
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   This is written with the possibility that several ways of logging
   may be chosen from.  For now we just use syslog.  */

#include <limits.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>
#include <utime.h>
#ifdef GDBSERVER
#include <assert.h>
#define gdb_assert assert
#include <unistd.h>
#include "server.h"
#include "../usage-logging.h"
#else
#include "defs.h"
#include "gdb_assert.h"
#include "gdb_string.h"
#include "version.h"
#include "usage-logging.h"
#endif

/* ??? We don't necessarily want to base this on --prefix as we want to use
   the same file even when configuring for a place other than /usr.
   Ideally we want a configure option, but that can wait.  */
static const char usage_logging_checkpoint_file[] =
  "/usr/lib/gdb/logging-checkpoint";

#define GDB_SYSLOG_PRIORITY LOG_INFO
#define GDB_SYSLOG_FACILITY LOG_USER
#define GDB_SYSLOG_OPTIONS LOG_PID

#define CHECKPOINT_INTERVAL 10
#define CHECKPOINT_MODE 0222
#define PARENT_MODE 0755

enum usage_logging_state
{
  USAGE_LOGGING_UNKNOWN,
  USAGE_LOGGING_ENABLED,
  USAGE_LOGGING_DISABLED
};

static enum usage_logging_state usage_logging_state = USAGE_LOGGING_UNKNOWN;

/* gdbserver doesn't have fprintf_unfiltered.
   Wrap the call into something both gdb and gdbserver versions can use.  */

static void
fprintf_stdlog (const char *msg, ...)
{
  va_list args;

  va_start (args, msg);

#ifdef GDBSERVER
  vfprintf (stderr, msg, args);
#else
  vfprintf_unfiltered (gdb_stdlog, msg, args);
#endif

  va_end (args);
}

/* Return non-zero if the checkpoint file is legit,
   e.g., it exists and all the permissions are ok,
   and we're not within the logging interval.  */

static int
verify_checkpoint (const char *checkpoint_file)
{
  struct stat checkpoint_stat, parent_stat;
  char *parent = xstrdup (checkpoint_file);
  char *last_slash = strrchr (parent, '/');

  gdb_assert (last_slash != NULL);
  *last_slash = '\0';

  if (lstat (parent, &parent_stat) == -1)
    {
      fprintf_stdlog ("Unable to lstat() logging checkpoint parent directory: %s.\n",
		      strerror (errno));
      free (parent);
      return 0;
    }
  free (parent);
  parent = NULL;

  if (lstat (checkpoint_file, &checkpoint_stat) == -1)
    {
      fprintf_stdlog ("Unable to lstat() logging checkpoint: %s.\n",
		      strerror (errno));
      return 0;
    }

  if (checkpoint_stat.st_uid != 0 || checkpoint_stat.st_gid != 0
      || (checkpoint_stat.st_mode & ~S_IFMT) != CHECKPOINT_MODE
      || ! S_ISDIR (checkpoint_stat.st_mode))
    {
      fprintf_stdlog ("Logging checkpoint verification failed: bad owner or mode.\n");
      return 0;
    }

  if (parent_stat.st_uid != 0 || parent_stat.st_gid != 0
      || (parent_stat.st_mode & ~S_IFMT) != PARENT_MODE
      || ! S_ISDIR (parent_stat.st_mode))
    {
      fprintf_stdlog ("Logging checkpoint parent directory verification failed: bad owner or mode.\n");
      return 0;
    }

  {
    time_t checkpoint_time = checkpoint_stat.st_mtime;
    time_t current_time = time (NULL);
    if ((current_time - checkpoint_time) < CHECKPOINT_INTERVAL)
      return 0;
  }

  return 1;
}

/* Check if we've been invoked too soon since the last checkpoint,
   and update the checkpoint if not for the next time gdb is started.
   Returns non-zero if it's ok to continue logging.  */

static int
try_to_write_checkpoint (const char *checkpoint_file)
{
  if (! verify_checkpoint (checkpoint_file))
    return 0;

  /* Update mtime to 'now' (as indicated by utime(file, _NULL_)).  */
  if (utime (checkpoint_file, NULL) == -1)
    {
      fprintf_stdlog ("Unable to update mtime of logging checkpoint: %s\n",
		      strerror (errno));
      return 0;
    }

  return 1;
}

/* Return non-zero if we're running on prod (and logging has already been done
   by command_wrapper).  */

static int
on_prod_p (const char *exe_path)
{
  const char *dot = strrchr (exe_path, '.');

  if (dot != NULL && strcmp (dot, ".orig") == 0)
    return 1;
  return 0;
}

/* Return non-zero if we're running on prod using a best guess.
   This is called when we don't have /proc/self/exe (e.g. upx'd gdb).
   Note: What we really care about here is whether we were invoked with
   command_wrapper.  */

static int
no_path_on_prod_p (void)
{
  if (access ("/usr/bin/gdb32.orig", X_OK) == 0)
    return 1;
  return 0;
}

/* Return non-zero if we're running in the build directory.
   We may be running the testsuite.  While we throttle the logging frequency
   it'll still generate a lot of noise in syslog.  */

static int
in_build_dir_p (const char *exe_path)
{
  char *parent_path = xstrdup (exe_path);
  char *slash;
  const char *parent_dir;

  /* ??? IWBN to use ldirname,lbasename here, but gdbserver doesn't have these
   and gdbserver can't use libiberty.  Sigh.  */

  slash = strrchr (parent_path, '/');
  gdb_assert (slash != NULL);
  *slash = '\0';
  slash = strrchr (parent_path, '/');
  gdb_assert (slash != NULL);
  parent_dir = slash + 1;

  if (strcmp (parent_dir, "gdb") == 0
      || strcmp (parent_dir, "gdbserver") == 0
      /* This test catches testsuite/xgdb that's run by the testsuite.  */
      || strcmp (parent_dir, "testsuite") == 0)
    {
      free (parent_path);
      return 1;
    }

  free (parent_path);
  return 0;
}

/* Return non-zero if we're running in the build directory using
   a best guess.
   This is called when we don't have /proc/self/exe (e.g. upx'd gdb).
   We may be running the testsuite.  While we throttle the logging frequency
   it'll still generate a lot of noise in syslog.

   Note: This test is less preferable to in_build_dir_p.  We don't really
   care what directory we're in, we care what gdb we're running.
   This test will flag running /usr/bin/gdb in gdb/testsuite.  */

static int
no_path_in_build_dir_p (void)
{
  char path[PATH_MAX + 1];
  int i, len, max_test_file_len;
  static const char * const test_files[] =
  {
    "/usage-logging.o",
    "/../usage-logging.o",
    "/../../usage-logging.o",
    NULL
  };

  /* Compute how much space we need in `path' to hold any element of
     `test_files'.  This is used to prevent overflowing the buffer.  */
  max_test_file_len = 0;
  for (i = 0; test_files[i] != NULL; ++i)
    {
      len = strlen (test_files[i]);
      if (max_test_file_len < len)
	max_test_file_len = len;
    }

  len = readlink ("/proc/self/cwd", path, sizeof (path) - max_test_file_len - 1);
  if (len <= 0)
    return 0; /* Blech.  Might as well say we're not in build dir.  */

  for (i = 0; test_files[i] != NULL; ++i)
    {
      strcpy (&path[len], test_files[i]);
      if (access (path, R_OK) == 0)
	return 1;
    }

  return 0;
}

/* Copy STR to DST, \-escaping it as necessary for syslog.
   Control chars are escaped as \xXX (except for obvious ones like \n).
   NOTE: This means one byte can expand to four bytes in the output.
   Backslash (\) and double-quote (") are also \-escaped.
   If the string contains a space it is wrapped in double-quotes.
   Returns a pointer to the end of the copied string (a la stpcpy).  */

static char *
copy_for_syslog (char *dst, const char *src)
{
  int quote_string = strchr (src, ' ') != NULL;

  if (quote_string)
    *dst++ = '"';

  while (*src)
    {
      /* command_wrapper_lib.cc:kBadSyslogChars is "\t\f\n\r\v".
	 We just escape all non-printable (ascii) chars.
	 Getting any fancier for this logging is left for another day.  */

      switch (*src)
	{
	case '\n': *dst++ = '\\'; *dst++ = 'n'; break;
	case '\r': *dst++ = '\\'; *dst++ = 'r'; break;
	case '\t': *dst++ = '\\'; *dst++ = 't'; break;
	case '\\': *dst++ = '\\'; *dst++ = '\\'; break;
	case '"':  *dst++ = '\\'; *dst++ = '"'; break;
	default:
	  {
	    unsigned char c = *src;
	    static const char hex[] = "0123456789abcdef";

	    if (c < 32 || c >= 127)
	      {
		*dst++ = '\\';
		*dst++ = 'x';
		*dst++ = hex[c >> 4];
		*dst++ = hex[c & 15];
	      }
	    else
	      {
		*dst++ = *src;
	      }
	    break;
	  }
	}

      ++src;
    }

  if (quote_string)
    *dst++ = '"';

  *dst = '\0';
  return dst;
}

/* Called at the start of gdb to log start-up.  */

void
usage_log_start (int argc, char **argv)
{
  char *user = getenv ("USER");
  int uid = getuid ();
  char path[PATH_MAX + 1];
  int i, len;
  char *text;
  char *p;

  if (usage_logging_state == USAGE_LOGGING_DISABLED)
    return;

  len = readlink ("/proc/self/exe", path, sizeof (path) - 1);
  if (len > 0)
    {
      path[len] = '\0';

      /* Don't log if we're running on prod, we use command_wrapper there.  */
      if (on_prod_p (path))
	{
	  usage_logging_state = USAGE_LOGGING_DISABLED;
	  return;
	}

      /* Don't log invocations of gdb when run from the build directory.  */
      if (in_build_dir_p (path))
	{
	  usage_logging_state = USAGE_LOGGING_DISABLED;
	  return;
	}
    }
  else
    {
      /* This happens for upx'd executables.  Blech.  */
      strcpy (path, "/proc-self-exe-unavailable-maybe-upx-gdb");

      /* Don't log if we're running on prod, we use command_wrapper there.  */
      if (no_path_on_prod_p ())
	{
	  usage_logging_state = USAGE_LOGGING_DISABLED;
	  return;
	}

      /* Don't log invocations of gdb when run from the build directory.  */
      if (no_path_in_build_dir_p ())
	{
	  usage_logging_state = USAGE_LOGGING_DISABLED;
	  return;
	}
    }

  switch (usage_logging_state)
    {
    case USAGE_LOGGING_UNKNOWN:
      if (! try_to_write_checkpoint (usage_logging_checkpoint_file))
	{
	  usage_logging_state = USAGE_LOGGING_DISABLED;
	  return;
	}
      usage_logging_state = USAGE_LOGGING_ENABLED;
      break;
    default:
      gdb_assert (usage_logging_state == USAGE_LOGGING_ENABLED);
      break;
    }

  if (user != NULL)
    usage_log_printf ("session starting, version %s, user %s, exe %s",
		      version, user, path);
  else
    usage_log_printf ("session starting, version %s, uid %d, exe %s",
		      version, uid, path);

  len = readlink ("/proc/self/cwd", path, sizeof (path) - 1);
  if (len <= 0)
    return;
  path[len] = '\0';
  usage_log_printf ("cwd: %s\n", path);

  len = 0;
  for (i = 0; i < argc; ++i)
    len += strlen (argv[i]) * 4; /* *4: see copy_for_syslog */
  text = xmalloc (len + argc + 1);
  p = copy_for_syslog (text, argv[0]);
  for (i = 1; i < argc; ++i)
    {
      *p++ = ' ';
      p = copy_for_syslog (p, argv[i]);
    }
  usage_log_printf ("cmd: %s\n", text);
  free (text);
}

/* Called when gdb is exiting.  */

void
usage_log_end (int exit_code)
{
  usage_log_printf ("session ending, exit code %d", exit_code);
}

void
usage_log_printf (const char *msg, ...)
{
  va_list args;

  if (usage_logging_state == USAGE_LOGGING_DISABLED)
    return;
  gdb_assert (usage_logging_state == USAGE_LOGGING_ENABLED);

  va_start (args, msg);
  openlog ("gdb", GDB_SYSLOG_OPTIONS, GDB_SYSLOG_FACILITY);
  vsyslog (GDB_SYSLOG_PRIORITY, msg, args);
  closelog ();
  va_end (args);
}
