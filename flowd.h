/*	$Id: flowd.h,v 1.19 2007/10/24 01:04:10 djm Exp $	*/

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

#ifndef _FLOWD_H
#define _FLOWD_H

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include "flowd-common.h"
#include "sys-queue.h"
#include "addr.h"
#include "filter.h"

#ifndef PROGNAME
#define PROGNAME			"flowd"
#endif

#define DEFAULT_CONFIG			SYSCONFDIR "/flowd.conf"
#define DEFAULT_PIDFILE			PIDFILEDIR "/flowd.pid"
#define PRIVSEP_USER			"_flowd"

/* Initial stateholding limits */
/* XXX these are not actually tunable yet */
#define DEFAULT_MAX_PEERS		128
#define DEFAULT_MAX_TEMPLATES		8
#define DEFAULT_MAX_TEMPLATE_LEN	1024
#define DEFAULT_MAX_SOURCES		64

struct allowed_device {
	struct xaddr			addr;
	u_int				masklen;
	TAILQ_ENTRY(allowed_device)	entry;
};
TAILQ_HEAD(allowed_devices, allowed_device);

struct listen_addr {
	struct xaddr			addr;
	u_int16_t			port;
	int				fd;
	size_t				bufsiz;
	TAILQ_ENTRY(listen_addr)	entry;
};
TAILQ_HEAD(listen_addrs, listen_addr);

struct join_group {
	struct xaddr			addr;
	/* XXX: add interface name */
	TAILQ_ENTRY(join_group)		entry;
};
TAILQ_HEAD(join_groups, join_group);

#define FLOWD_OPT_DONT_FORK		(1)
#define FLOWD_OPT_VERBOSE		(1<<1)
#define FLOWD_OPT_INSECURE		(1<<2)
struct flowd_config {
	char			*log_file;
	char			*log_socket;
	size_t			log_socket_bufsiz;
	char			*pid_file;
	u_int32_t		store_mask;
	u_int32_t		opts;
	struct listen_addrs	listen_addrs;
	struct filter_list	filter_list;
	struct allowed_devices	allowed_devices;
	struct join_groups	join_groups;
};

/* parse.y */
int parse_config(const char *, FILE *, struct flowd_config *, int);
int cmdline_symset(char *);
void dump_config(struct flowd_config *, const char *, int);

/* log.c */
void logclose(void);
void loginit(const char *ident, int to_stderr, int debug_flag);
void vlogit(int level, const char *fmt, va_list args);
void logit(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void logitm(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void logerr(const char *fmt, ...) __dead __attribute__((format(printf, 1, 2)));
void logerrx(const char *fmt, ...) __dead __attribute__((format(printf, 1, 2)));

#endif /* _FLOWD_H */
