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

/* Peer tracking and state holding code, see peer.h for details */

#include "flowd-common.h"

#include <sys/types.h>
#include <sys/time.h>

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "sys-queue.h"
#include "sys-tree.h"
#include "flowd.h"
#include "peer.h"

RCSID("$Id: peer.c,v 1.9 2005/12/21 12:14:07 djm Exp $");

/* Debugging for general peer tracking */
/* #define PEER_DEBUG */

/* Debugging for NetFlow 9 tracking */
/* #define PEER_DEBUG_NF9 */


/* NetFlow v.9 specific function */

static void
peer_nf9_template_delete(struct peer_nf9_source *nf9src,
    struct peer_nf9_template *template)
{
	TAILQ_REMOVE(&nf9src->templates, template, lp);
	if (template->records != NULL)
		free(template->records);
	free(template);
	nf9src->num_templates--;
}

static void peer_nf9_source_delete(struct peer_state *peer,
    struct peer_nf9_source *nf9src)
{
	struct peer_nf9_template *nf9tmpl;

	while ((nf9tmpl = TAILQ_FIRST(&nf9src->templates)) != NULL)
		peer_nf9_template_delete(nf9src, nf9tmpl);
	peer->nf9_num_sources--;
	TAILQ_REMOVE(&peer->nf9, nf9src, lp);
	free(nf9src);
}

static void
peer_nf9_delete(struct peer_state *peer)
{
	struct peer_nf9_source *nf9src;

	while ((nf9src = TAILQ_FIRST(&peer->nf9)) != NULL)
		peer_nf9_source_delete(peer, nf9src);
}

static struct peer_nf9_source *
peer_nf9_lookup_source(struct peer_state *peer, u_int32_t source_id)
{
	struct peer_nf9_source *nf9src;

	TAILQ_FOREACH(nf9src, &peer->nf9, lp) {
		if (nf9src->source_id == source_id)
			return (nf9src);
	}
	return (NULL);
}

static struct peer_nf9_template *
peer_nf9_lookup_template(struct peer_nf9_source *nf9src, u_int16_t template_id)
{
	struct peer_nf9_template *nf9tmpl;

	TAILQ_FOREACH(nf9tmpl, &nf9src->templates, lp) {
		if (nf9tmpl->template_id == template_id)
			break;
	}
	if (nf9tmpl == NULL)
		return (NULL);

	return (nf9tmpl);
}

struct peer_nf9_template *peer_nf9_find_template(struct peer_state *peer,
    u_int32_t source_id, u_int16_t template_id)
{
	struct peer_nf9_source *nf9src;
	struct peer_nf9_template *nf9tmpl;

	nf9src = peer_nf9_lookup_source(peer, source_id);

#ifdef PEER_DEBUG_NF9
	logit(LOG_DEBUG, "%s: Lookup source 0x%08x for peer %s: %sFOUND",
	    __func__, source_id, addr_ntop_buf(&peer->from),
	    nf9src == NULL ? "NOT " : "");
#endif

	if (nf9src == NULL)
		return (NULL);

	nf9tmpl = peer_nf9_lookup_template(nf9src, template_id);

#ifdef PEER_DEBUG_NF9
	logit(LOG_DEBUG, "%s: Lookup template 0x%04x: %sFOUND", __func__,
	    template_id, nf9tmpl == NULL ? "NOT " : "");
#endif

	if (nf9tmpl == NULL)
		return (NULL);

#ifdef PEER_DEBUG_NF9
	logit(LOG_DEBUG, "%s: Found template %s/0x%08x/0x%04x: %d records %p",
	    __func__, addr_ntop_buf(&peer->from), source_id, template_id,
	    nf9tmpl->num_records, nf9tmpl->records);
#endif
	return (nf9tmpl);
}

void
peer_nf9_template_update(struct peer_state *peer, u_int32_t source_id,
    u_int16_t template_id)
{
	struct peer_nf9_source *nf9src;
	struct peer_nf9_template *nf9tmpl;

#ifdef PEER_DEBUG_NF9
	logit(LOG_DEBUG, "%s: Lookup template %s/0x%08x/0x%04x",
	    __func__, addr_ntop_buf(&peer->from), template_id, source_id);
#endif
	nf9src = peer_nf9_lookup_source(peer, source_id);
	if (nf9src == NULL)
		return;
	nf9tmpl = peer_nf9_lookup_template(nf9src, template_id);
	if (nf9tmpl == NULL)
		return;

#ifdef PEER_DEBUG_NF9
	logit(LOG_DEBUG, "%s: found template", __func__);
#endif
	/* Move source and template to the head of the list */
	if (nf9src != TAILQ_FIRST(&peer->nf9)) {
#ifdef PEER_DEBUG_NF9
		logit(LOG_DEBUG, "%s: update source", __func__);
#endif
		TAILQ_REMOVE(&peer->nf9, nf9src, lp);
		TAILQ_INSERT_HEAD(&peer->nf9, nf9src, lp);
	}
	if (nf9tmpl != TAILQ_FIRST(&nf9src->templates)) {
#ifdef PEER_DEBUG_NF9
		logit(LOG_DEBUG, "%s: update template", __func__);
#endif
		TAILQ_REMOVE(&nf9src->templates, nf9tmpl, lp);
		TAILQ_INSERT_HEAD(&nf9src->templates, nf9tmpl, lp);
	}
}

static struct peer_nf9_source *
peer_nf9_new_source(struct peer_state *peer, struct peers *peers,
    u_int32_t source_id)
{
	struct peer_nf9_source *nf9src;

	/* If we have too many sources, then kick out the LRU */
	peer->nf9_num_sources++;
	if (peer->nf9_num_sources > peers->max_sources) {
		nf9src = TAILQ_LAST(&peer->nf9, peer_nf9_list);
		logit(LOG_WARNING, "forced deletion of source 0x%08x "
		    "of peer %s", source_id, addr_ntop_buf(&peer->from));
		/* XXX ratelimit errors */
		peer_nf9_source_delete(peer, nf9src)    ;
	}

	if ((nf9src = calloc(1, sizeof(*nf9src))) == NULL)
		logerrx("%s: calloc failed", __func__);
	nf9src->source_id = source_id;
	TAILQ_INIT(&nf9src->templates);
	TAILQ_INSERT_HEAD(&peer->nf9, nf9src, lp);

#ifdef PEER_DEBUG_NF9
	logit(LOG_DEBUG, "%s: new source %s/0x%08x", __func__,
	    addr_ntop_buf(&peer->from), source_id);
#endif

	return (nf9src);
}

struct peer_nf9_template *
peer_nf9_new_template(struct peer_state *peer, struct peers *peers,
    u_int32_t source_id, u_int16_t template_id)
{
	struct peer_nf9_source *nf9src;
	struct peer_nf9_template *nf9tmpl;

	nf9src = peer_nf9_lookup_source(peer, source_id);
	if (nf9src == NULL)
		nf9src = peer_nf9_new_source(peer, peers, source_id);

	/* If the source has too many templates, then kick out the LRU */
	nf9src->num_templates++;
	if (nf9src->num_templates > peers->max_templates) {
		nf9tmpl = TAILQ_LAST(&nf9src->templates,
		    peer_nf9_template_list);
		logit(LOG_WARNING, "forced deletion of template 0x%04x from "
		    "peer %s/0x%08x", template_id, addr_ntop_buf(&peer->from),
		    source_id);
		/* XXX ratelimit errors */
		peer_nf9_template_delete(nf9src, nf9tmpl)    ;
	}

	if ((nf9tmpl = calloc(1, sizeof(*nf9tmpl))) == NULL)
		logerrx("%s: calloc failed", __func__);
	nf9tmpl->template_id = template_id;
	TAILQ_INSERT_HEAD(&nf9src->templates, nf9tmpl, lp);

#ifdef PEER_DEBUG_NF9
	logit(LOG_DEBUG, "%s: new template %s/0x%08x/0x%04x", __func__,
	    addr_ntop_buf(&peer->from), source_id, template_id);
#endif

	/* Move source and template to the head of the list */
	if (nf9src != TAILQ_FIRST(&peer->nf9)) {
		TAILQ_REMOVE(&peer->nf9, nf9src, lp);
		TAILQ_INSERT_HEAD(&peer->nf9, nf9src, lp);
	}

	return (nf9tmpl);
}

/* General peer state housekeeping functions */
static int
peer_compare(struct peer_state *a, struct peer_state *b)
{
	return (addr_cmp(&a->from, &b->from));
}

/* Generate functions for peer state tree */
SPLAY_PROTOTYPE(peer_tree, peer_state, tp, peer_compare);
SPLAY_GENERATE(peer_tree, peer_state, tp, peer_compare);

static void
delete_peer(struct peers *peers, struct peer_state *peer)
{
	TAILQ_REMOVE(&peers->peer_list, peer, lp);
	SPLAY_REMOVE(peer_tree, &peers->peer_tree, peer);
	peer_nf9_delete(peer);
	free(peer);
	peers->num_peers--;
}

struct peer_state *
new_peer(struct peers *peers, struct flowd_config *conf, struct xaddr *addr)
{
	struct peer_state *peer;
	struct allowed_device *ad;

	/* Check for address authorization */
	if (TAILQ_FIRST(&conf->allowed_devices) != NULL) {
		TAILQ_FOREACH(ad, &conf->allowed_devices, entry) {
			if (addr_netmatch(addr, &ad->addr, ad->masklen) == 0)
		 		break;
		}
		if (ad == NULL)
			return (NULL);
	}

	/* If we have overflowed our peer table, then kick out the LRU peer */
	peers->num_peers++;
	if (peers->num_peers > peers->max_peers) {
		peers->num_forced++;
		peer = TAILQ_LAST(&peers->peer_list, peer_list);
		logit(LOG_WARNING, "forced deletion of peer %s",
		    addr_ntop_buf(&peer->from));
		/* XXX ratelimit errors */
		delete_peer(peers, peer);
	}

	if ((peer = calloc(1, sizeof(*peer))) == NULL)
		logerrx("%s: calloc failed", __func__);
	memcpy(&peer->from, addr, sizeof(peer->from));
	TAILQ_INIT(&peer->nf9);

#ifdef PEER_DEBUG
	logit(LOG_DEBUG, "new peer %s", addr_ntop_buf(addr));
#endif

	TAILQ_INSERT_HEAD(&peers->peer_list, peer, lp);
	SPLAY_INSERT(peer_tree, &peers->peer_tree, peer);
	gettimeofday(&peer->firstseen, NULL);

	return (peer);
}

void
scrub_peers(struct flowd_config *conf, struct peers *peers)
{
	struct peer_state *peer, *npeer;
	struct allowed_device *ad;

	/* Check for address authorization */
	if (TAILQ_FIRST(&conf->allowed_devices) == NULL)
		return;

	for (peer = TAILQ_FIRST(&peers->peer_list); peer != NULL;) {
		npeer = TAILQ_NEXT(peer, lp);

		TAILQ_FOREACH(ad, &conf->allowed_devices, entry) {
			if (addr_netmatch(&peer->from, &ad->addr,
			    ad->masklen) == 0)
		 		break;
		}
		if (ad == NULL) {
			logit(LOG_WARNING, "delete peer %s (no longer allowed)",
			    addr_ntop_buf(&peer->from));
			delete_peer(peers, peer);
		}
		peer = npeer;
	}
}

void
update_peer(struct peers *peers, struct peer_state *peer, u_int nflows,
    u_int netflow_version)
{
	/* Push peer to front of LRU queue, if it isn't there already */
	if (peer != TAILQ_FIRST(&peers->peer_list)) {
		TAILQ_REMOVE(&peers->peer_list, peer, lp);
		TAILQ_INSERT_HEAD(&peers->peer_list, peer, lp);
	}
	gettimeofday(&peer->lastvalid, NULL);
	peer->nflows += nflows;
	peer->npackets++;
	peer->last_version = netflow_version;
#ifdef PEER_DEBUG
	logit(LOG_DEBUG, "update peer %s", addr_ntop_buf(&peer->from));
#endif
}

struct peer_state *
find_peer(struct peers *peers, struct xaddr *addr)
{
	struct peer_state tmp, *peer;

	bzero(&tmp, sizeof(tmp));
	memcpy(&tmp.from, addr, sizeof(tmp.from));

	peer = SPLAY_FIND(peer_tree, &peers->peer_tree, &tmp);
#ifdef PEER_DEBUG
	logit(LOG_DEBUG, "%s: found %s", __func__,
	    peer == NULL ? "NONE" : addr_ntop_buf(addr));
#endif

	return (peer);
}

void
dump_peers(struct peers *peers)
{
	struct peer_state *peer;
	u_int i;

	logit(LOG_INFO, "Peer state: %u of %u in used, %u forced deletions",
	    peers->num_peers, peers->max_peers, peers->num_forced);
	i = 0;
	SPLAY_FOREACH(peer, peer_tree, &peers->peer_tree) {
		logit(LOG_INFO, "peer %u - %s: "
		    "packets:%llu flows:%llu invalid:%llu no_template:%llu",
		    i, addr_ntop_buf(&peer->from),
		    peer->npackets, peer->nflows,
		    peer->ninvalid, peer->no_template);
		logit(LOG_INFO, "peer %u - %s: first seen:%s.%03u",
		    i, addr_ntop_buf(&peer->from),
		    iso_time(peer->firstseen.tv_sec, 0),
		    (u_int)(peer->firstseen.tv_usec / 1000));
		logit(LOG_INFO, "peer %u - %s: last valid:%s.%03u netflow v.%u",
		    i, addr_ntop_buf(&peer->from),
		    iso_time(peer->lastvalid.tv_sec, 0),
		    (u_int)(peer->lastvalid.tv_usec / 1000),
		    peer->last_version);
		i++;
	}
#ifdef PEER_DEBUG_NF9
	/* XXX netflow 9 data */
#endif
}
