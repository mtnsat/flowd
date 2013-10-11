/*	$Id: peer.h,v 1.6 2005/10/13 11:27:44 djm Exp $	*/

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

/*
 * Routines for tracking state from NetFlow sources. NetFlow v.9 / IPFIX
 * requires this for their overcomplicated template stuff. Read below for the
 * full horror.
 */

#ifndef _PEER_H
#define _PEER_H

#include <sys/types.h>
#include "flowd-common.h"
#include "sys-queue.h"
#include "sys-tree.h"
#include "addr.h"

/* NetFlow v.9 specific state */

/*
 * NetFlow v.9 is really overcomplicated. Not only does it require you to
 * maintain state for each NetFlow host, it requires you to retain disjoint
 * state for different sources on each host. Managing this while considering
 * some of the attacks that it enables on a collector is painful.
 *
 * So, we try to limit the amount of state that we hold on all peers to a
 * maximum of max_peers hosts. Within each host, we can retain max_templates
 * templates of maximum size max_template_len for max_sources distinct
 * sources. So the total is:
 *     max_peers * max_templates * max_sources * (max_template_len + overheads)
 *
 * NB. The peer.c routines are not responsible for filling in the template
 * record structures, just for housekeeping such as allocation and lookup.
 * The filling-in is performed by the netflow v.9 template flowset handler
 *
 * XXX - share these structures with IPFIX in the future
 */

/* A record in a NetFlow v.9 template record */
struct peer_nf9_record {
	u_int type;
	u_int len;
};

/* A NetFlow v.9 template record */
struct peer_nf9_template {
	TAILQ_ENTRY(peer_nf9_template) lp;
	u_int16_t template_id;
	u_int num_records;
	u_int total_len;
	struct peer_nf9_record *records;
};
TAILQ_HEAD(peer_nf9_template_list, peer_nf9_template);

/* A distinct NetFlow v.9 source */
struct peer_nf9_source {
	TAILQ_ENTRY(peer_nf9_source) lp;
	u_int32_t source_id;
	u_int num_templates;
	struct peer_nf9_template_list templates;
};
TAILQ_HEAD(peer_nf9_list, peer_nf9_source);

/* General per-peer state */

/*
 * Structure to hold per-peer state. NetFlow v.9 / IPFIX will require that we
 * hold state for each peer to retain templates. This peer state is stored in
 * a splay tree for quick access by sender address and in a deque so we can
 * do fast LRU deletions on overflow
 */
struct peer_state {
	SPLAY_ENTRY(peer_state) tp;
	TAILQ_ENTRY(peer_state) lp;
	struct xaddr from;
	u_int64_t npackets, nflows, ninvalid, no_template;
	struct timeval firstseen, lastvalid;
	u_int last_version;

	/* NetFlow v.9 specific portions */
	struct peer_nf9_list nf9;
	u_int nf9_num_sources;
};

/* Structures for top of peer state tree and head of list */
SPLAY_HEAD(peer_tree, peer_state);
TAILQ_HEAD(peer_list, peer_state);

/* Peer stateholding structure */
struct peers {
	struct peer_tree peer_tree;
	struct peer_list peer_list;
	u_int max_peers, max_templates, max_sources, max_template_len;
	u_int num_peers, num_forced;
};

/* Peer state handling functions */
struct peer_state *new_peer(struct peers *peers, struct flowd_config *conf,
    struct xaddr *addr);
void scrub_peers(struct flowd_config *conf, struct peers *peers);
void update_peer(struct peers *peers, struct peer_state *peer, u_int nflows,
    u_int netflow_version);
struct peer_state *find_peer(struct peers *peers, struct xaddr *addr);
void dump_peers(struct peers *peers);

/* NetFlow v.9 state handling functions */
struct peer_nf9_template *peer_nf9_find_template(struct peer_state *peer,
    u_int32_t source_id, u_int16_t template_id);
struct peer_nf9_template *
peer_nf9_new_template(struct peer_state *peer, struct peers *peers,
    u_int32_t source_id, u_int16_t template_id);
void peer_nf9_template_update(struct peer_state *peer,
    u_int32_t source_id, u_int16_t template_id);

#endif /* _PEER_H */
