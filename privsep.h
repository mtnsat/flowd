/*	$Id: privsep.h,v 1.9 2007/10/24 01:04:11 djm Exp $	*/

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

/* Privilege separation functions */

#ifndef _PRIVSEP_H
#define _PRIVSEP_H

#include "flowd.h"

/* privsep.c */
void privsep_init(struct flowd_config *, int *, const char *);
int client_open_log(int);
int client_open_socket(int);
int open_listener(struct xaddr *, u_int16_t, size_t, struct join_groups *);
int read_config(const char *, struct flowd_config *);
int client_reconfigure(int, struct flowd_config *);

/* privsep_fdpass.c */
int send_fd(int, int);
int receive_fd(int);

#endif /* _PRIVSEP_H */
