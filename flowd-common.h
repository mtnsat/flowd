/*	$Id: flowd-common.h,v 1.1 2005/10/13 11:27:44 djm Exp $	*/

/*
 * Copyright (c) 2004,2005 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FLOWD_COMMON_H
#define _FLOWD_COMMON_H

#include "flowd-config.h"

#if defined(HAVE_SYS_CDEFS_H)
# include <sys/cdefs.h>
#endif
#if defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#endif

#include <sys/types.h>
#include <sys/poll.h>
#include <unistd.h>

#if defined(HAVE_TIME_H)
# include <time.h>
#endif
#if defined(HAVE_PATHS_H)
# include <paths.h>
#endif
#if defined(HAVE_STRINGS_H)
# include <strings.h>
#endif
#if defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#endif
#if defined(HAVE_ENDIAN_H)
# include <endian.h>
#endif

#ifndef RCSID
# define RCSID(msg) \
	static /**/const char *const flowd_rcsid[] =		\
	    { (const char *)flowd_rcsid, "\100(#)" msg }
#endif

#if defined(__GNUC__)
# ifndef __dead
#  define __dead		__attribute__((__noreturn__))
# endif
# ifndef __packed
#  define __packed		__attribute__((__packed__))
# endif
#endif

/* Prototypes for absent friends */
#ifndef HAVE_CLOSEFROM
void closefrom(int);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif
#ifndef HAVE_SETPROCTITLE
void compat_init_setproctitle(int, char ***);
void setproctitle(const char *, ...);
#endif
#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif

#ifndef INFTIM
# define INFTIM			(-1)
#endif

#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif

#if !defined(HAVE_INT8_T) && defined(OUR_CFG_INT8_T)
typedef OUR_CFG_INT8_T int8_t;
#endif
#if !defined(HAVE_INT16_T) && defined(OUR_CFG_INT16_T)
typedef OUR_CFG_INT16_T int16_t;
#endif
#if !defined(HAVE_INT32_T) && defined(OUR_CFG_INT32_T)
typedef OUR_CFG_INT32_T int32_t;
#endif
#if !defined(HAVE_INT64_T) && defined(OUR_CFG_INT64_T)
typedef OUR_CFG_INT64_T int64_t;
#endif
#if !defined(HAVE_U_INT8_T) && defined(OUR_CFG_U_INT8_T)
typedef OUR_CFG_U_INT8_T u_int8_t;
#endif
#if !defined(HAVE_U_INT16_T) && defined(OUR_CFG_U_INT16_T)
typedef OUR_CFG_U_INT16_T u_int16_t;
#endif
#if !defined(HAVE_U_INT32_T) && defined(OUR_CFG_U_INT32_T)
typedef OUR_CFG_U_INT32_T u_int32_t;
#endif
#if !defined(HAVE_U_INT64_T) && defined(OUR_CFG_U_INT64_T)
typedef OUR_CFG_U_INT64_T u_int64_t;
#endif
#if !defined(HAVE_U_INT)
typedef unsigned int u_int;
#endif

#endif /* _FLOWD_COMMON_H */
