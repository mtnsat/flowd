/*	$Id: filter.h,v 1.18 2007/05/10 01:38:39 djm Exp $	*/

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

/* Flow filtering system */

#ifndef _FILTER_H
#define _FILTER_H

#include "flowd-common.h"
#include "sys-queue.h"
#include "addr.h"
#include "store.h"

#define FF_ACTION_ACCEPT	1
#define FF_ACTION_DISCARD	2
#define FF_ACTION_TAG		3
struct filter_action {
	int		action_what;
	u_int32_t	tag;
};

#define FF_MATCH_SRC_ADDR	(1)
#define FF_MATCH_DST_ADDR	(1<<1)
#define FF_MATCH_SRC_PORT	(1<<2)
#define FF_MATCH_DST_PORT	(1<<3)
#define FF_MATCH_PROTOCOL	(1<<4)
#define FF_MATCH_TOS		(1<<5)
#define FF_MATCH_AGENT_ADDR	(1<<6)
#define FF_MATCH_TCP_FLAGS	(1<<7)
#define FF_MATCH_AF		(1<<8)
#define FF_MATCH_DAYTIME	(1<<9)
#define FF_MATCH_ABSTIME	(1<<10)
#define FF_MATCH_IFNDX_IN	(1<<11)
#define FF_MATCH_IFNDX_OUT	(1<<12)
struct filter_match {
	u_int32_t	match_what;
	u_int32_t	match_negate;
	int		agent_masklen;
	struct xaddr	agent_addr;
	int		af;
	int		src_masklen;
	struct xaddr	src_addr;
	int		dst_masklen;
	struct xaddr	dst_addr;
	int		ifndx_in;
	int		ifndx_out;
	int		src_port;
	int		dst_port;
	int		proto;
	int		tos;
	int		tcp_flags_mask;
	int		tcp_flags_equals;
	int		day_mask;
	int		dayafter;
	int		daybefore;
	int		absafter;
	int		absbefore;
};

struct filter_rule {
	TAILQ_ENTRY(filter_rule) entry;
	struct filter_action	action;
	int			quick;
	struct filter_match	match;
	u_int64_t		evaluations;
	u_int64_t		matches;
	u_int64_t		wins;
};
TAILQ_HEAD(filter_list, filter_rule);

u_int filter_flow(struct store_flow_complete *flow, struct filter_list *filter);
const char *format_rule(const struct filter_rule *rule);

#endif /* _FILTER_H */
