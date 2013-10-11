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

/* $Id: log.c,v 1.4 2005/10/13 11:27:44 djm Exp $ */

#include "flowd-common.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include "flowd.h"

static int logstarted = 0;
static int logstderr = 0;
static int logdebug = 0;

/* Close logging and reset state */
void
logclose(void)
{
	if (!logstarted)
		return;

#ifdef notyet
	/* Redhat doesn't listen in /var/empty/dev/log */
	if (!logstderr)
		closelog();
#endif

	logstarted = logstderr = logdebug = 0;
}

/* (re-)initialise logging */
void
loginit(const char *ident, int to_stderr, int debug_flag)
{
	if (logstarted)
		logclose();

	logstarted = 1;
	logdebug = (debug_flag != 0);

	if (to_stderr)
		logstderr = 1;
	else
		openlog(ident, LOG_PID, LOG_DAEMON);
}

/* Varargs vsyslog-like log interface */
void
vlogit(int level, const char *fmt, va_list args)
{
	if (level == LOG_DEBUG && !logdebug)
		return;

	if (logstderr) {
		vfprintf(stderr, fmt, args);
		fputs("\n", stderr);
	} else
		vsyslog(level, fmt, args);
}

/* Standard syslog-like interface */
void
logit(int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogit(level, fmt, args);
	va_end(args);
}

/* Standard log interface that appends ": strerror(errno)" for convenience */
void
logitm(int level, const char *fmt, ...)
{
	va_list args;
	char buf[1024];

	va_start(args, fmt);
	snprintf(buf, sizeof(buf), "%s: %s", fmt, strerror(errno));
	vlogit(level, buf, args);
	va_end(args);
}

/* logitm and exit (like err(3) */
void
logerr(const char *fmt, ...)
{
	va_list args;
	char buf[1024];

	va_start(args, fmt);
	snprintf(buf, sizeof(buf), "%s: %s", fmt, strerror(errno));
	vlogit(LOG_ERR, buf, args);
	va_end(args);

	exit(1);
}

/* logit() and exit() (like errx(3)) */
void
logerrx(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vlogit(LOG_ERR, fmt, args);
	va_end(args);

	exit(1);
}
