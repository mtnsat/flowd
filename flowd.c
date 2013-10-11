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

#include "flowd-common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>

#include "sys-queue.h"
#include "sys-tree.h"
#include "flowd.h"
#include "privsep.h"
#include "netflow.h"
#include "store.h"
#include "store-v2.h"
#include "atomicio.h"
#include "peer.h"

RCSID("$Id: flowd.c,v 1.79 2008/07/24 23:55:02 djm Exp $");

/* Dump unknown packet types */
/* #define DEBUG_UNKNOWN */

/* Reams of netflow v.9 verbosity */
/* #define DEBUG_NF9 */

/* Number of errors on Unix Domain log socket before we reopen */
#define LOGSOCK_REOPEN_ERROR_COUNT	128

/* Ratelimit for Unix Domain log socket reopens */
#define LOGSOCK_REOPEN_DELAY		60 /* seconds */

/* Prototype this (can't make it static because it only #ifdef DEBUG_UNKNOWN) */
void dump_packet(const char *tag, const u_int8_t *p, int len);

/* Unix domain socket error detection and reopen counters */
static int logsock_first_error = 0;
static int logsock_num_errors = 0;

/* Flags set by signal handlers */
static sig_atomic_t exit_flag = 0;
static sig_atomic_t reconf_flag = 0;
static sig_atomic_t reopen_flag = 0;
static sig_atomic_t info_flag = 0;

/* Input queue management */

#define INPUT_MAX_PACKET_PER_FD		512
struct flow_packet {
	TAILQ_ENTRY(flow_packet) entry;
	struct timeval recv_time;
	struct xaddr flow_source;
	u_int len;
	u_int8_t *packet;
};
TAILQ_HEAD(flow_packets, flow_packet);

struct flow_packets input_queue = TAILQ_HEAD_INITIALIZER(input_queue);

/* Allocate a new packet (XXX: make this use a pool of preallocated entries) */
static struct flow_packet
*flow_packet_alloc(void)
{
	return (calloc(1, sizeof(struct flow_packet)));
}

/* Deallocate a flow packet (XXX: change to return entry to freelist) */
static void
flow_packet_dealloc(struct flow_packet *f)
{
	if (f->packet != NULL)
		free(f->packet);
	free(f);
}

/* Enqueue a flow packet in the input queue */
static void
flow_packet_enqueue(struct flow_packet *f)
{
	TAILQ_INSERT_TAIL(&input_queue, f, entry);
}

/* Pull the first flow packet off the queue */
static struct flow_packet
*flow_packet_dequeue(void)
{
	struct flow_packet *f;

	if ((f = TAILQ_FIRST(&input_queue)) != NULL)
		TAILQ_REMOVE(&input_queue, f, entry);
	return (f);
}

/* Output queue management */

#define OUTPUT_INITIAL_QLEN	(1024*16)
#define OUTPUT_MAX_QLEN		(1024*512) /* Must be 2^x multiple of initial */
u_int8_t *output_queue = NULL;
size_t output_queue_alloc = 0;
size_t output_queue_offset = 0;

/* Enqueue a flow for output, return 0 on success, -1 on queue full */
static int
output_flow_enqueue(u_int8_t *f, size_t len, int verbose)
{
	/* Force flush on overflow */
	if (output_queue_offset + len > OUTPUT_MAX_QLEN) {
		logit(LOG_DEBUG, "%s: output queue full", __func__);
		return (-1);
	}

	if (output_queue == NULL) {
		output_queue_alloc = OUTPUT_INITIAL_QLEN;
		if ((output_queue = malloc(output_queue_alloc)) == NULL) {
			logerrx("Output queue allocation (%u bytes) failed",
			    output_queue_alloc);
		}
		if (verbose) {
			logit(LOG_DEBUG, "%s: initial allocation %u", __func__,
			    output_queue_alloc);
		}
	}
	
	while (output_queue_offset + len > output_queue_alloc) {
		u_int8_t *tmp_q;
		size_t tmp_len = output_queue_alloc << 1;

		/* This should never happen if max = initial * 2^x */
		if (tmp_len > OUTPUT_MAX_QLEN) {
			logit(LOG_DEBUG, "%s: oops, tmp_len (%u) > "
			    "OUTPUT_MAX_QLEN (%u)", __func__, tmp_len,
			    OUTPUT_MAX_QLEN);
			return (-1);
		}
		if ((tmp_q = realloc(output_queue, tmp_len)) == NULL) {
			logit(LOG_DEBUG, "%s: realloc of %u fail", __func__,
			    tmp_len);
			return (-1);
		}
		if (verbose) {
			logit(LOG_DEBUG, "%s: increased output queue "
			    "from %uKB to %uKB", __func__,
			    output_queue_alloc >> 10, tmp_len >> 10);
		}
		output_queue = tmp_q;
		output_queue_alloc = tmp_len;
	}
	memcpy(output_queue + output_queue_offset, f, len);
	output_queue_offset += len;
	if (verbose) {
		logit(LOG_DEBUG, "%s: offset %u alloc %u", __func__,
		    output_queue_offset, output_queue_alloc);
	}
	
	return (0);
}

static void
output_flow_flush(int log_fd, int verbose)
{
	char ebuf[512];

	if (log_fd == -1)
		return;

	if (verbose) {
		logit(LOG_DEBUG, "%s: flushing output queue len %u", __func__,
		    output_queue_offset);
	}

	if (output_queue_offset == 0)
		return;
	
	if (store_put_buf(log_fd, output_queue, output_queue_offset, ebuf,
	    sizeof(ebuf)) != STORE_ERR_OK)
		logerrx("%s: exiting on %s", __func__, ebuf);

	output_queue_offset = 0;
}

/* Signal handlers */
static void
sighand_exit(int signo)
{
	exit_flag = signo;
	signal(signo, sighand_exit);
}

static void
sighand_reconf(int signo)
{
	reconf_flag = 1;
	reopen_flag = 1;
	signal(signo, sighand_reconf);
}

static void
sighand_reopen(int signo)
{
	reopen_flag = 1;
	signal(signo, sighand_reopen);
}

static void
sighand_info(int signo)
{
	info_flag = 1;
	signal(signo, sighand_info);
}

/* Format data to a hex string */
static const char *
data_ntoa(const u_int8_t *p, int len)
{
	static char buf[2048];
	char tmp[3];
	int i;

	for (*buf = '\0', i = 0; i < len; i++) {
		snprintf(tmp, sizeof(tmp), "%02x%s", p[i], i % 2 ? " " : "");
		if (strlcat(buf, tmp, sizeof(buf) - 4) >= sizeof(buf) - 4) {
			strlcat(buf, "...", sizeof(buf));
			break;
		}
	}
	return (buf);
}

/* Dump a packet */
void
dump_packet(const char *tag, const u_int8_t *p, int len)
{
	if (tag == NULL)
		logit(LOG_INFO, "packet len %d: %s", len, data_ntoa(p, len));
	else {
		logit(LOG_INFO, "%s: packet len %d: %s",
		    tag, len, data_ntoa(p, len));
	}
}

static int
start_log(int monitor_fd)
{
	int fd;
	off_t r;
	char ebuf[512];

	if ((fd = client_open_log(monitor_fd)) == -1)
		logerrx("Logfile open failed, exiting");

	/* Don't try to write a v.3 log on the end of a v.2 one */

	r = lseek(fd, 0, SEEK_END);

	/*
	 * If there isn't a full legacy header in the file or an error occurs
	 * (r == -1, e.g. on a FIFO) then don't bother checking for an old 
	 * log header.
	 */
	if (r < sizeof(struct store_v2_header))
		return (fd);

	if ((r = lseek(fd, 0, SEEK_SET)) == -1)
		logerr("%s: lseek", __func__);

	switch (store_v2_check_header(fd, ebuf, sizeof(ebuf))) {
	case STORE_ERR_OK:
		/* Uh oh - an old flow log is in the way, don't try to write */
		logerrx("Error: Cannot append to legacy (version 2) flow log, "
		    "please move it out of the way and restart flowd");
	case STORE_ERR_BAD_MAGIC:
	case STORE_ERR_UNSUP_VERSION:
		/* Good - the existing flow log is a probably a new one */
		if ((r = lseek(fd, 0, SEEK_END)) == -1)
			logerr("%s: lseek", __func__);
		return (fd);
	default:
		logerrx("%s: %s", __func__, ebuf);
	}

	/* NOTREACHED */
	return (-1);
}

static int
start_socket(int monitor_fd)
{
	int fd;

	if ((fd = client_open_socket(monitor_fd)) == -1)
		logerrx("Logsock open failed, exiting");
	return (fd);
}

static void
process_flow(struct store_flow_complete *flow, struct flowd_config *conf,
    int log_fd, int log_socket)
{
	char ebuf[512], fbuf[1024];
	int flen;
	u_int filtres;

	/* Another sanity check */
	if (flow->src_addr.af != flow->dst_addr.af) {
		logit(LOG_WARNING, "%s: flow src(%d)/dst(%d) AF mismatch",
		    __func__, flow->src_addr.af, flow->dst_addr.af);
		return;
	}

	/* Prepare for writing */
	flow->hdr.fields = htonl(flow->hdr.fields);
	flow->recv_time.recv_sec = htonl(flow->recv_time.recv_sec);
	flow->recv_time.recv_usec = htonl(flow->recv_time.recv_usec);

	filtres = filter_flow(flow, &conf->filter_list);
	if (conf->opts & FLOWD_OPT_VERBOSE) {
		char fmtbuf[1024];

		store_format_flow(flow, fmtbuf, sizeof(fmtbuf), 0,
		    STORE_DISPLAY_ALL, 0);
		logit(LOG_DEBUG, "%s: %s flow %s", __func__,
		    filtres == FF_ACTION_DISCARD ? "DISCARD" : "ACCEPT", fmtbuf);
	}

	if (filtres == FF_ACTION_DISCARD)
		return;

	if (store_flow_serialise_masked(flow, conf->store_mask, fbuf,
	    sizeof(fbuf), &flen, ebuf, sizeof(ebuf)) != STORE_ERR_OK)
		logerrx("%s: exiting on %s", __func__, ebuf);

	if (log_fd != -1 && output_flow_enqueue(fbuf, flen,
	    conf->opts & FLOWD_OPT_VERBOSE) == -1) {
		output_flow_flush(log_fd, conf->opts & FLOWD_OPT_VERBOSE);
		/* Must not fail after flush */
		if (output_flow_enqueue(fbuf, flen,
		    conf->opts & FLOWD_OPT_VERBOSE) == -1)
			logerrx("%s: enqueue failed after flush", __func__);
	}

	/* Track failures to send on log socket so we can reopen it */
	if (log_socket != -1 && send(log_socket, fbuf, flen, 0) == -1) {
		if (logsock_num_errors > 0 &&
		    (logsock_num_errors % 10) == 0) {
			logit(LOG_WARNING, "log socket send: %s "
			    "(num errors %d)", strerror(errno),
			    logsock_num_errors);
		}
		if (errno != ENOBUFS) {
			if (logsock_first_error == 0)
				logsock_first_error = time(NULL);
			logsock_num_errors++;
		}
	} else {
		/* Start to disregard errors after success */
		if (logsock_num_errors > 0)
			logsock_num_errors--;
		if (logsock_num_errors == 0)
			logsock_first_error = 0;
	}

	/* XXX reopen log file on one failure, exit on multiple */
}

static void
process_netflow_v1(struct flow_packet *fp, struct flowd_config *conf,
    struct peer_state *peer, struct peers *peers, int log_fd, int log_socket)
{
	struct NF1_HEADER *nf1_hdr = (struct NF1_HEADER *)fp->packet;
	struct NF1_FLOW *nf1_flow;
	struct store_flow_complete flow;
	size_t offset;
	u_int i, nflows;
	struct timeval tv;

	if (fp->len < sizeof(*nf1_hdr)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "short netflow v.1 packet %d bytes from %s",
		    fp->len, addr_ntop_buf(&fp->flow_source));
		return;
	}
	nflows = ntohs(nf1_hdr->c.flows);
	if (nflows == 0 || nflows > NF1_MAXFLOWS) {
		peer->ninvalid++;
		logit(LOG_WARNING, "Invalid number of flows (%u) in netflow "
		    "v.1 packet from %s", nflows,
		    addr_ntop_buf(&fp->flow_source));
		return;
	}
	if (fp->len != NF1_PACKET_SIZE(nflows)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "Inconsistent Netflow v.1 packet from %s: "
		    "len %u expected %u", addr_ntop_buf(&fp->flow_source),
		    fp->len, NF1_PACKET_SIZE(nflows));
		return;
	}

	logit(LOG_DEBUG, "Valid netflow v.1 packet %d flows", nflows);
	update_peer(peers, peer, nflows, 1);

	for (i = 0; i < nflows; i++) {
		offset = NF1_PACKET_SIZE(i);
		nf1_flow = (struct NF1_FLOW *)(fp->packet + offset);

		bzero(&flow, sizeof(flow));

		/* NB. These are converted to network byte order later */
		flow.hdr.fields = STORE_FIELD_ALL;
		/* flow.hdr.tag is set later */
		flow.hdr.fields &= ~STORE_FIELD_TAG;
		flow.hdr.fields &= ~STORE_FIELD_SRC_ADDR6;
		flow.hdr.fields &= ~STORE_FIELD_DST_ADDR6;
		flow.hdr.fields &= ~STORE_FIELD_GATEWAY_ADDR6;
		flow.hdr.fields &= ~STORE_FIELD_AS_INFO;
		flow.hdr.fields &= ~STORE_FIELD_FLOW_ENGINE_INFO;

		flow.recv_time.recv_sec = fp->recv_time.tv_sec;
		flow.recv_time.recv_usec = tv.tv_usec;

		flow.pft.tcp_flags = nf1_flow->tcp_flags;
		flow.pft.protocol = nf1_flow->protocol;
		flow.pft.tos = nf1_flow->tos;

		memcpy(&flow.agent_addr, &fp->flow_source,
		    sizeof(flow.agent_addr));

		flow.src_addr.v4.s_addr = nf1_flow->src_ip;
		flow.src_addr.af = AF_INET;
		flow.dst_addr.v4.s_addr = nf1_flow->dest_ip;
		flow.dst_addr.af = AF_INET;
		flow.gateway_addr.v4.s_addr = nf1_flow->nexthop_ip;
		flow.gateway_addr.af = AF_INET;

		flow.ports.src_port = nf1_flow->src_port;
		flow.ports.dst_port = nf1_flow->dest_port;

#define NTO64(a) (store_htonll(ntohl(a)))
		flow.octets.flow_octets = NTO64(nf1_flow->flow_octets);
		flow.packets.flow_packets = NTO64(nf1_flow->flow_packets);
#undef NTO64

		flow.ifndx.if_index_in = htonl(ntohs(nf1_flow->if_index_in));
		flow.ifndx.if_index_out = htonl(ntohs(nf1_flow->if_index_out));

		flow.ainfo.sys_uptime_ms = nf1_hdr->uptime_ms;
		flow.ainfo.time_sec = nf1_hdr->time_sec;
		flow.ainfo.time_nanosec = nf1_hdr->time_nanosec;
		flow.ainfo.netflow_version = nf1_hdr->c.version;

		flow.ftimes.flow_start = nf1_flow->flow_start;
		flow.ftimes.flow_finish = nf1_flow->flow_finish;

		process_flow(&flow, conf, log_fd, log_socket);
	}
}

static void
process_netflow_v5(struct flow_packet *fp, struct flowd_config *conf,
    struct peer_state *peer, struct peers *peers, int log_fd, int log_socket)
{
	struct NF5_HEADER *nf5_hdr = (struct NF5_HEADER *)fp->packet;
	struct NF5_FLOW *nf5_flow;
	struct store_flow_complete flow;
	size_t offset;
	u_int i, nflows;

	if (fp->len < sizeof(*nf5_hdr)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "short netflow v.5 packet %d bytes from %s",
		    fp->len, addr_ntop_buf(&fp->flow_source));
		return;
	}
	nflows = ntohs(nf5_hdr->c.flows);
	if (nflows == 0 || nflows > NF5_MAXFLOWS) {
		peer->ninvalid++;
		logit(LOG_WARNING, "Invalid number of flows (%u) in netflow "
		    "v.5 packet from %s", nflows,
		    addr_ntop_buf(&fp->flow_source));
		return;
	}
	if (fp->len != NF5_PACKET_SIZE(nflows)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "Inconsistent Netflow v.5 packet from %s: "
		    "len %u expected %u", addr_ntop_buf(&fp->flow_source),
		    fp->len, NF5_PACKET_SIZE(nflows));
		return;
	}

	logit(LOG_DEBUG, "Valid netflow v.5 packet %d flows", nflows);
	update_peer(peers, peer, nflows, 5);

	for (i = 0; i < nflows; i++) {
		offset = NF5_PACKET_SIZE(i);
		nf5_flow = (struct NF5_FLOW *)(fp->packet + offset);

		bzero(&flow, sizeof(flow));

		/* NB. These are converted to network byte order later */
		flow.hdr.fields = STORE_FIELD_ALL;
		/* flow.hdr.tag is set later */
		flow.hdr.fields &= ~STORE_FIELD_TAG;
		flow.hdr.fields &= ~STORE_FIELD_SRC_ADDR6;
		flow.hdr.fields &= ~STORE_FIELD_DST_ADDR6;
		flow.hdr.fields &= ~STORE_FIELD_GATEWAY_ADDR6;

		flow.recv_time.recv_sec = fp->recv_time.tv_sec;
		flow.recv_time.recv_usec = fp->recv_time.tv_usec;

		flow.pft.tcp_flags = nf5_flow->tcp_flags;
		flow.pft.protocol = nf5_flow->protocol;
		flow.pft.tos = nf5_flow->tos;

		memcpy(&flow.agent_addr, &fp->flow_source,
		    sizeof(flow.agent_addr));

		flow.src_addr.v4.s_addr = nf5_flow->src_ip;
		flow.src_addr.af = AF_INET;
		flow.dst_addr.v4.s_addr = nf5_flow->dest_ip;
		flow.dst_addr.af = AF_INET;
		flow.gateway_addr.v4.s_addr = nf5_flow->nexthop_ip;
		flow.gateway_addr.af = AF_INET;

		flow.ports.src_port = nf5_flow->src_port;
		flow.ports.dst_port = nf5_flow->dest_port;

#define NTO64(a) (store_htonll(ntohl(a)))
		flow.octets.flow_octets = NTO64(nf5_flow->flow_octets);
		flow.packets.flow_packets = NTO64(nf5_flow->flow_packets);
#undef NTO64

		flow.ifndx.if_index_in = htonl(ntohs(nf5_flow->if_index_in));
		flow.ifndx.if_index_out = htonl(ntohs(nf5_flow->if_index_out));

		flow.ainfo.sys_uptime_ms = nf5_hdr->uptime_ms;
		flow.ainfo.time_sec = nf5_hdr->time_sec;
		flow.ainfo.time_nanosec = nf5_hdr->time_nanosec;
		flow.ainfo.netflow_version = nf5_hdr->c.version;

		flow.ftimes.flow_start = nf5_flow->flow_start;
		flow.ftimes.flow_finish = nf5_flow->flow_finish;

		flow.asinf.src_as = htonl(ntohs(nf5_flow->src_as));
		flow.asinf.dst_as = htonl(ntohs(nf5_flow->dest_as));
		flow.asinf.src_mask = nf5_flow->src_mask;
		flow.asinf.dst_mask = nf5_flow->dst_mask;

		flow.finf.engine_type = nf5_hdr->engine_type;
		flow.finf.engine_id = nf5_hdr->engine_id;
		flow.finf.flow_sequence = nf5_hdr->flow_sequence;

		process_flow(&flow, conf, log_fd, log_socket);
	}
}

static void
process_netflow_v7(struct flow_packet *fp, struct flowd_config *conf,
    struct peer_state *peer, struct peers *peers, int log_fd, int log_socket)
{
	struct NF7_HEADER *nf7_hdr = (struct NF7_HEADER *)fp->packet;
	struct NF7_FLOW *nf7_flow;
	struct store_flow_complete flow;
	size_t offset;
	u_int i, nflows;

	if (fp->len < sizeof(*nf7_hdr)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "short netflow v.7 packet %d bytes from %s",
		    fp->len, addr_ntop_buf(&fp->flow_source));
		return;
	}
	nflows = ntohs(nf7_hdr->c.flows);
	if (nflows == 0 || nflows > NF7_MAXFLOWS) {
		peer->ninvalid++;
		logit(LOG_WARNING, "Invalid number of flows (%u) in netflow "
		    "v.7 packet from %s", nflows,
		    addr_ntop_buf(&fp->flow_source));
		return;
	}
	if (fp->len != NF7_PACKET_SIZE(nflows)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "Inconsistent Netflow v.7 packet from %s: "
		    "len %u expected %u", addr_ntop_buf(&fp->flow_source),
		    fp->len, NF7_PACKET_SIZE(nflows));
		return;
	}

	logit(LOG_DEBUG, "Valid netflow v.7 packet %d flows", nflows);
	update_peer(peers, peer, nflows, 7);

	for (i = 0; i < nflows; i++) {
		offset = NF7_PACKET_SIZE(i);
		nf7_flow = (struct NF7_FLOW *)(fp->packet + offset);

		bzero(&flow, sizeof(flow));

		/* NB. These are converted to network byte order later */
		flow.hdr.fields = STORE_FIELD_ALL;
		/* flow.hdr.tag is set later */
		flow.hdr.fields &= ~STORE_FIELD_TAG;
		flow.hdr.fields &= ~STORE_FIELD_SRC_ADDR6;
		flow.hdr.fields &= ~STORE_FIELD_DST_ADDR6;
		flow.hdr.fields &= ~STORE_FIELD_GATEWAY_ADDR6;

		/*
		 * XXX: we can parse the (undocumented) flags1 and flags2
		 * fields of the packet to disable flow fields not set by
		 * the Cat5k (e.g. destination-only mls nde mode)
		 */

		flow.recv_time.recv_sec = fp->recv_time.tv_sec;
		flow.recv_time.recv_usec = fp->recv_time.tv_usec;

		flow.pft.tcp_flags = nf7_flow->tcp_flags;
		flow.pft.protocol = nf7_flow->protocol;
		flow.pft.tos = nf7_flow->tos;

		memcpy(&flow.agent_addr, &fp->flow_source,
		    sizeof(flow.agent_addr));

		flow.src_addr.v4.s_addr = nf7_flow->src_ip;
		flow.src_addr.af = AF_INET;
		flow.dst_addr.v4.s_addr = nf7_flow->dest_ip;
		flow.dst_addr.af = AF_INET;
		flow.gateway_addr.v4.s_addr = nf7_flow->nexthop_ip;
		flow.gateway_addr.af = AF_INET;

		flow.ports.src_port = nf7_flow->src_port;
		flow.ports.dst_port = nf7_flow->dest_port;

#define NTO64(a) (store_htonll(ntohl(a)))
		flow.octets.flow_octets = NTO64(nf7_flow->flow_octets);
		flow.packets.flow_packets = NTO64(nf7_flow->flow_packets);
#undef NTO64

		flow.ifndx.if_index_in = htonl(ntohs(nf7_flow->if_index_in));
		flow.ifndx.if_index_out = htonl(ntohs(nf7_flow->if_index_out));

		flow.ainfo.sys_uptime_ms = nf7_hdr->uptime_ms;
		flow.ainfo.time_sec = nf7_hdr->time_sec;
		flow.ainfo.time_nanosec = nf7_hdr->time_nanosec;
		flow.ainfo.netflow_version = nf7_hdr->c.version;

		flow.ftimes.flow_start = nf7_flow->flow_start;
		flow.ftimes.flow_finish = nf7_flow->flow_finish;

		flow.asinf.src_as = htonl(ntohs(nf7_flow->src_as));
		flow.asinf.dst_as = htonl(ntohs(nf7_flow->dest_as));
		flow.asinf.src_mask = nf7_flow->src_mask;
		flow.asinf.dst_mask = nf7_flow->dst_mask;

		flow.finf.flow_sequence = nf7_hdr->flow_sequence;

		process_flow(&flow, conf, log_fd, log_socket);
	}
}

static int
nf9_rec_to_flow(struct peer_nf9_record *rec, struct store_flow_complete *flow,
    u_int8_t *data)
{
	/* XXX: use a table-based interpreter */
	switch (rec->type) {

/* Copy an int (possibly shorter than the target) keeping their LSBs aligned */
#define BE_COPY(a) memcpy((u_char*)&a + (sizeof(a) - rec->len), data, rec->len);
#define V9_FIELD(v9_field, store_field, flow_field) \
	case v9_field: \
		flow->hdr.fields |= STORE_FIELD_##store_field; \
		BE_COPY(flow->flow_field); \
		break
#define V9_FIELD_ADDR(v9_field, store_field, flow_field, sub, family) \
	case v9_field: \
		flow->hdr.fields |= STORE_FIELD_##store_field; \
		memcpy(&flow->flow_field.v##sub, data, rec->len); \
		flow->flow_field.af = AF_##family; \
		break

	V9_FIELD(NF9_IN_BYTES, OCTETS, octets.flow_octets);
	V9_FIELD(NF9_IN_PACKETS, PACKETS, packets.flow_packets);
	V9_FIELD(NF9_IN_PROTOCOL, PROTO_FLAGS_TOS, pft.protocol);
	V9_FIELD(NF9_SRC_TOS, PROTO_FLAGS_TOS, pft.tos);
	V9_FIELD(NF9_TCP_FLAGS, PROTO_FLAGS_TOS, pft.tcp_flags);
	V9_FIELD(NF9_L4_SRC_PORT, SRCDST_PORT, ports.src_port);
	V9_FIELD(NF9_SRC_MASK, AS_INFO, asinf.src_mask);
	V9_FIELD(NF9_INPUT_SNMP, IF_INDICES, ifndx.if_index_in);
	V9_FIELD(NF9_L4_DST_PORT, SRCDST_PORT, ports.dst_port);
	V9_FIELD(NF9_DST_MASK, AS_INFO, asinf.dst_mask);
	V9_FIELD(NF9_OUTPUT_SNMP, IF_INDICES, ifndx.if_index_out);
	V9_FIELD(NF9_SRC_AS, AS_INFO, asinf.src_as);
	V9_FIELD(NF9_DST_AS, AS_INFO, asinf.dst_as);
	V9_FIELD(NF9_LAST_SWITCHED, FLOW_TIMES, ftimes.flow_finish);
	V9_FIELD(NF9_FIRST_SWITCHED, FLOW_TIMES, ftimes.flow_start);
	V9_FIELD(NF9_IPV6_SRC_MASK, AS_INFO, asinf.src_mask);
	V9_FIELD(NF9_IPV6_DST_MASK, AS_INFO, asinf.dst_mask);
	V9_FIELD(NF9_ENGINE_TYPE, FLOW_ENGINE_INFO, finf.engine_type);
	V9_FIELD(NF9_ENGINE_ID, FLOW_ENGINE_INFO, finf.engine_id);

	V9_FIELD_ADDR(NF9_IPV4_SRC_ADDR, SRC_ADDR4, src_addr, 4, INET);
	V9_FIELD_ADDR(NF9_IPV4_DST_ADDR, DST_ADDR4, dst_addr, 4, INET);
	V9_FIELD_ADDR(NF9_IPV4_NEXT_HOP, GATEWAY_ADDR4, gateway_addr, 4, INET);

	V9_FIELD_ADDR(NF9_IPV6_SRC_ADDR, SRC_ADDR6, src_addr, 6, INET6);
	V9_FIELD_ADDR(NF9_IPV6_DST_ADDR, DST_ADDR6, dst_addr, 6, INET6);
	V9_FIELD_ADDR(NF9_IPV6_NEXT_HOP, GATEWAY_ADDR6, gateway_addr, 6, INET6);

#undef V9_FIELD
#undef V9_FIELD_ADDR
#undef BE_COPY
	}
	return (0);
}

static int
nf9_check_rec_len(u_int type, u_int len)
{
	struct store_flow_complete t;

	/* Sanity check */
	if (len == 0 || len > 0x4000)
		return (0);

	/* XXX: use a table-based interpreter */
	switch (type) {
#define V9_FIELD_LEN(v9_field, flow_field) \
	case v9_field: \
		return (len <= sizeof(t.flow_field));

	V9_FIELD_LEN(NF9_IN_BYTES, octets.flow_octets);
	V9_FIELD_LEN(NF9_IN_PACKETS, packets.flow_packets);
	V9_FIELD_LEN(NF9_IN_PROTOCOL, pft.protocol);
	V9_FIELD_LEN(NF9_SRC_TOS, pft.tos);
	V9_FIELD_LEN(NF9_TCP_FLAGS, pft.tcp_flags);
	V9_FIELD_LEN(NF9_L4_SRC_PORT, ports.src_port);
	V9_FIELD_LEN(NF9_IPV4_SRC_ADDR, src_addr.v4);
	V9_FIELD_LEN(NF9_SRC_MASK, asinf.src_mask);
	V9_FIELD_LEN(NF9_INPUT_SNMP, ifndx.if_index_in);
	V9_FIELD_LEN(NF9_L4_DST_PORT, ports.dst_port);
	V9_FIELD_LEN(NF9_IPV4_DST_ADDR, dst_addr.v4);
	V9_FIELD_LEN(NF9_DST_MASK, asinf.src_mask);
	V9_FIELD_LEN(NF9_OUTPUT_SNMP, ifndx.if_index_out);
	V9_FIELD_LEN(NF9_IPV4_NEXT_HOP, gateway_addr.v4);
	V9_FIELD_LEN(NF9_SRC_AS, asinf.src_as);
	V9_FIELD_LEN(NF9_DST_AS, asinf.dst_as);
	V9_FIELD_LEN(NF9_LAST_SWITCHED, ftimes.flow_finish);
	V9_FIELD_LEN(NF9_FIRST_SWITCHED, ftimes.flow_start);
	V9_FIELD_LEN(NF9_IPV6_SRC_ADDR, src_addr.v6);
	V9_FIELD_LEN(NF9_IPV6_DST_ADDR, dst_addr.v6);
	V9_FIELD_LEN(NF9_IPV6_SRC_MASK, asinf.src_mask);
	V9_FIELD_LEN(NF9_IPV6_DST_MASK, asinf.dst_mask);
	V9_FIELD_LEN(NF9_ENGINE_TYPE, finf.engine_type);
	V9_FIELD_LEN(NF9_ENGINE_ID, finf.engine_id);
	V9_FIELD_LEN(NF9_IPV6_NEXT_HOP, gateway_addr.v6);

#undef V9_FIELD_LEN
	default:
		return (1);
	}
}

static int
nf9_flowset_to_store(u_int8_t *pkt, size_t len, struct timeval *tv, 
    struct xaddr *flow_source, struct NF9_HEADER *nf9_hdr,
    struct peer_nf9_template *template, u_int32_t source_id,
    struct store_flow_complete *flow)
{
	u_int offset, i;

	if (template->total_len > len)
		return (-1);

	bzero(flow, sizeof(*flow));

	flow->hdr.fields = STORE_FIELD_RECV_TIME | STORE_FIELD_AGENT_INFO |
	    STORE_FIELD_AGENT_ADDR;
	flow->ainfo.sys_uptime_ms = nf9_hdr->uptime_ms;
	flow->ainfo.time_sec = nf9_hdr->time_sec;
	flow->ainfo.netflow_version = nf9_hdr->c.version;
	flow->finf.flow_sequence = nf9_hdr->package_sequence;
	flow->finf.source_id = htonl(source_id);
	flow->recv_time.recv_sec = tv->tv_sec;
	flow->recv_time.recv_usec = tv->tv_usec;
	memcpy(&flow->agent_addr, flow_source, sizeof(flow->agent_addr));

	offset = 0;
	for (i = 0; i < template->num_records; i++) {
#ifdef DEBUG_NF9
		logit(LOG_DEBUG, "    record %d: type %d len %d: %s",
		    i, template->records[i].type, template->records[i].len,
		    data_ntoa(pkt + offset, template->records[i].len));
#endif
		nf9_rec_to_flow(&template->records[i], flow, pkt + offset);
		offset += template->records[i].len;
	}
	return (0);
}

static int
process_netflow_v9_template(u_int8_t *pkt, size_t len, struct peer_state *peer,
    struct peers *peers, u_int32_t source_id)
{
	struct NF9_FLOWSET_HEADER_COMMON *template_header;
	struct NF9_TEMPLATE_FLOWSET_HEADER *tmplh;
	struct NF9_TEMPLATE_FLOWSET_RECORD *tmplr;
	u_int i, count, offset, template_id, total_size;
	struct peer_nf9_record *recs;
	struct peer_nf9_template *template;

	logit(LOG_DEBUG, "netflow v.9 template flowset from source 0x%x "
	    "(len %d)", source_id, len);
#ifdef DEBUG_NF9
	dump_packet(__func__, pkt, len);
#endif

	template_header = (struct NF9_FLOWSET_HEADER_COMMON *)pkt;
	if (len < sizeof(*template_header)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "short netflow v.9 flowset template header "
		    "%d bytes from %s/0x%x", len, addr_ntop_buf(&peer->from),
		    source_id);
		/* XXX ratelimit */
		return (-1);
	}
	if (ntohs(template_header->flowset_id) != NF9_TEMPLATE_FLOWSET_ID)
		logerrx("Confused template");

	logit(LOG_DEBUG, "NetFlow v.9 template set from %s/0x%x with len %d:",
	    addr_ntop_buf(&peer->from), source_id, len);

	for (offset = sizeof(*template_header); offset < len;) {
		tmplh = (struct NF9_TEMPLATE_FLOWSET_HEADER *)(pkt + offset);

		template_id = ntohs(tmplh->template_id);
		count = ntohs(tmplh->count);
		offset += sizeof(*tmplh);

		logit(LOG_DEBUG, " Contains template 0x%08x/0x%04x with "
		    "%d records (offset %d):", source_id, template_id,
		    count, offset);

		if ((recs = calloc(count, sizeof(*recs))) == NULL)
			logerrx("%s: calloc failed (num %d)", __func__, count);

		total_size = 0;
		for (i = 0; i < count; i++) {
			if (offset >= len) {
				free(recs);
				peer->ninvalid++;
				logit(LOG_WARNING, "short netflow v.9 flowset "
				    "template 0x%08x/0x%04x %d bytes from %s", 
				    source_id, template_id, len, 
				    addr_ntop_buf(&peer->from));
				/* XXX ratelimit */
				return (-1);
			}
			tmplr = (struct NF9_TEMPLATE_FLOWSET_RECORD *)
			    (pkt + offset);
			recs[i].type = ntohs(tmplr->type);
			recs[i].len = ntohs(tmplr->length);
			offset += sizeof(*tmplr);
#ifdef DEBUG_NF9
			logit(LOG_DEBUG, "  record %d: type %d len %d",
			    i, recs[i].type, recs[i].len);
#endif
			total_size += recs[i].len;
			if (total_size > peers->max_template_len) {
				free(recs);
				peer->ninvalid++;
				logit(LOG_WARNING, "netflow v.9 flowset "
				    "template 0x%08x/0x%04x from %s too large "
				    "len %d > max %d", source_id, template_id,
				    addr_ntop_buf(&peer->from), total_size,
				    peers->max_template_len);
				/* XXX ratelimit */
				return (-1);
			}
			if (!nf9_check_rec_len(recs[i].type, recs[i].len)) {
				free(recs);
				peer->ninvalid++;
				logit(LOG_WARNING, "Invalid field length in "
				    "netflow v.9 flowset template %d from "
				    "%s/0x%08x type %d len %d", template_id, 
				    addr_ntop_buf(&peer->from), source_id,
				    recs[i].type, recs[i].len);
				/* XXX ratelimit */
				return (-1);
			}
			/* XXX kill existing template on error! */
		}
	
		template = peer_nf9_find_template(peer, source_id, template_id);
		if (template == NULL) {
			template = peer_nf9_new_template(peer, peers,
			    source_id, template_id);
		}
	
		if (template->records != NULL)
			free(template->records);
	
		template->records = recs;
		template->num_records = i;
		template->total_len = total_size;
	}

	return (0);
}

static int
process_netflow_v9_data(u_int8_t *pkt, size_t len, struct timeval *tv, 
    struct peer_state *peer, u_int32_t source_id, struct NF9_HEADER *nf9_hdr,
    struct flowd_config *conf, int log_fd, int log_socket, u_int *num_flows)
{
	struct store_flow_complete *flows;
	struct peer_nf9_template *template;
	struct NF9_DATA_FLOWSET_HEADER *dath;
	u_int flowset_id, i, offset, num_flowsets;

	*num_flows = 0;

	logit(LOG_DEBUG, "netflow v.9 data flowset (len %d) source 0x%08x",
	    len, source_id);

	dath = (struct NF9_DATA_FLOWSET_HEADER *)pkt;
	if (len < sizeof(*dath)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "short netflow v.9 data flowset header "
		    "%d bytes from %s", len, addr_ntop_buf(&peer->from));
		/* XXX ratelimit */
		return (-1);
	}

	flowset_id = ntohs(dath->c.flowset_id);

	if ((template = peer_nf9_find_template(peer, source_id,
	    flowset_id)) == NULL) {
	    	peer->no_template++;
		logit(LOG_DEBUG, "netflow v.9 data flowset without template "
		    "%s/0x%08x/0x%04x", addr_ntop_buf(&peer->from), source_id,
		    flowset_id);
		return (0);
	}

	if (template->records == NULL)
		logerrx("%s: template->records == NULL", __func__);

	offset = sizeof(*dath);
	num_flowsets = (len - offset) / template->total_len;

	if (num_flowsets == 0 || num_flowsets > 0x4000) {
		logit(LOG_WARNING, "invalid netflow v.9 data flowset "
		    "from %s: strange number of flows %d",
		    addr_ntop_buf(&peer->from), num_flowsets);
		return (-1);
	}

	if ((flows = calloc(num_flowsets, sizeof(*flows))) == NULL)
		logerrx("%s: calloc failed (num %d)", __func__, num_flowsets);

	for (i = 0; i < num_flowsets; i++) {
		if (nf9_flowset_to_store(pkt + offset, template->total_len, tv,
		    &peer->from, nf9_hdr, template, source_id, 
		    &flows[i]) == -1) {
			peer->ninvalid++;
			free(flows);
			logit(LOG_WARNING, "invalid netflow v.9 data flowset "
			    "from %s", addr_ntop_buf(&peer->from));
			/* XXX ratelimit */
			return (-1);
		}

		offset += template->total_len;
	}
	*num_flows = i;

	for (i = 0; i < *num_flows; i++)
		process_flow(&flows[i], conf, log_fd, log_socket);

	free(flows);

	return (0);
}

static void
process_netflow_v9(struct flow_packet *fp, struct flowd_config *conf,
    struct peer_state *peer, struct peers *peers, int log_fd, int log_socket)
{
	struct NF9_HEADER *nf9_hdr = (struct NF9_HEADER *)fp->packet;
	struct NF9_FLOWSET_HEADER_COMMON *flowset;
	u_int32_t i, count, flowset_id, flowset_len, flowset_flows;
	u_int32_t offset, source_id, total_flows;

	if (fp->len < sizeof(*nf9_hdr)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "short netflow v.9 header %d bytes from %s",
		    fp->len, addr_ntop_buf(&fp->flow_source));
#ifdef DEBUG_NF9
		dump_packet(__func__, fp->packet, fp->len);
#endif
		return;
	}

	count = ntohs(nf9_hdr->c.flows);
	source_id = ntohl(nf9_hdr->source_id);

	logit(LOG_DEBUG, "netflow v.9 packet (len %d) %d recs, source 0x%08x",
	    fp->len, count, source_id);

#ifdef DEBUG_NF9
	dump_packet(__func__, fp->packet, fp->len);
#endif

	offset = sizeof(*nf9_hdr);
	total_flows = 0;

	for (i = 0;; i++) {
		/* Make sure we don't run off the end of the flow */
		if (offset >= fp->len) {
			peer->ninvalid++;
			logit(LOG_WARNING,
			    "short netflow v.9 flowset header %d bytes from %s",
			    fp->len, addr_ntop_buf(&fp->flow_source));
			return;
		}

		flowset = (struct NF9_FLOWSET_HEADER_COMMON *)
		    (fp->packet + offset);
		flowset_id = ntohs(flowset->flowset_id);
		flowset_len = ntohs(flowset->length);

#ifdef DEBUG_NF9
		logit(LOG_DEBUG, "offset=%d i=%d len=%d count=%d",
		    offset, i, fp->len, count);
		logit(LOG_DEBUG, "netflow v.9 flowset %d: type %d(0x%04x) "
		    "len %d(0x%04x)",
		    i, flowset_id, flowset_id, flowset_len, flowset_len);
#endif

		/*
		 * Yes, this is a near duplicate of the short packet check
		 * above, but this one validates the flowset length from in
		 * the packet before we pass it to the flowset-specific
		 * handlers below.
		 */
		if (offset + flowset_len > fp->len) {
			peer->ninvalid++;
			logit(LOG_WARNING,
			    "short netflow v.9 flowset length %d bytes from %s",
			    fp->len, addr_ntop_buf(&fp->flow_source));
			return;
		}

		switch (flowset_id) {
		case NF9_TEMPLATE_FLOWSET_ID:
			if (process_netflow_v9_template(fp->packet + offset,
			    flowset_len, peer, peers, source_id) != 0)
				return;
			break;
		case NF9_OPTIONS_FLOWSET_ID:
			/* XXX: implement this (maybe) */
			logit(LOG_DEBUG, "netflow v.9 options flowset");
			break;
		default:
			if (flowset_id < NF9_MIN_RECORD_FLOWSET_ID) {
				logit(LOG_WARNING, "Received unknown netflow "
				    "v.9 reserved flowset type %d "
				    "from %s/0x%08x", flowset_id,
				    addr_ntop_buf(&fp->flow_source), source_id);
				/* XXX ratelimit */
				break;
			}
			if (process_netflow_v9_data(fp->packet + offset,
			    flowset_len, &fp->recv_time, peer, source_id,
			    nf9_hdr, conf, log_fd, log_socket,
			    &flowset_flows) != 0)
				return;
			total_flows += flowset_flows;
			break;
		}
		offset += flowset_len;
		if (offset == fp->len)
			break;
		/* XXX check header->count against what we got */
	}

	/* Don't update peer unless we actually receive data from it */
	if (total_flows > 0)
		update_peer(peers, peer, total_flows, 9);
}

static int
receive_packet(struct flowd_config *conf, struct peers *peers, int net_fd)
{
	struct sockaddr_storage from;
	struct peer_state *peer;
	socklen_t fromlen;
	u_int8_t buf[2048];
	ssize_t len;
	struct xaddr flow_source;
	struct flow_packet *fp;

	if ((fp = flow_packet_alloc()) == NULL) {
		logit(LOG_WARNING, "flow packet metadata alloc failed");
		return (0);
	}

 retry:
	fromlen = sizeof(from);
	if ((len = recvfrom(net_fd, buf, sizeof(buf), 0,
	    (struct sockaddr *)&from, &fromlen)) < 0) {
		if (errno == EINTR)
			goto retry;
		if (errno != EAGAIN)
			logit(LOG_WARNING, "recvfrom(fd = %d)", net_fd);
		/* XXX ratelimit errors */
		flow_packet_dealloc(fp);
		return (0);
	}
	fp->len = len;
	gettimeofday(&fp->recv_time, NULL);

	if (addr_sa_to_xaddr((struct sockaddr *)&from, fromlen,
	    &fp->flow_source) == -1) {
		logit(LOG_WARNING, "Invalid agent address");
		flow_packet_dealloc(fp);
		return (1);
	}

	if ((peer = find_peer(peers, &fp->flow_source)) == NULL)
		peer = new_peer(peers, conf, &fp->flow_source);
	if (peer == NULL) {
		logit(LOG_DEBUG, "packet from unauthorised agent %s",
		    addr_ntop_buf(&fp->flow_source));
		flow_packet_dealloc(fp);
		return (1);
	}

	if (fp->len < sizeof(struct NF_HEADER_COMMON)) {
		peer->ninvalid++;
		logit(LOG_WARNING, "short packet %d bytes from %s", fp->len,
		    addr_ntop_buf(&flow_source));
		flow_packet_dealloc(fp);
		return (1);
	}

	if ((fp->packet = malloc(fp->len)) == NULL) {
		logit(LOG_WARNING, "flow packet alloc failed (len %d)",
		    fp->len);
		flow_packet_dealloc(fp);
		return (0);
	}
	memcpy(fp->packet, buf, fp->len);
	flow_packet_enqueue(fp);

	return (1);
}

static void
receive_many(struct flowd_config *conf, struct peers *peers, int net_fd)
{
	int i;

	for (i = 0; i < INPUT_MAX_PACKET_PER_FD; i++) {
		if (receive_packet(conf, peers, net_fd) == 0) {
			logit(LOG_DEBUG, "Received max number of packets "
			    "(%d) on fd %d", INPUT_MAX_PACKET_PER_FD, net_fd);
			return;
		}
	}
}

static void
process_packet(struct flow_packet *fp, struct flowd_config *conf,
    struct peers *peers, int log_fd, int log_socket)
{
	struct peer_state *peer;
	struct NF_HEADER_COMMON *hdr = (struct NF_HEADER_COMMON *)fp->packet;

	if ((peer = find_peer(peers, &fp->flow_source)) == NULL) {
		logit(LOG_WARNING, "flow source %s was expired between "
		    "between flow packet reception and processing", 
		    addr_ntop_buf(&fp->flow_source));
		return;
	}

	switch (ntohs(hdr->version)) {
	case 1:
		process_netflow_v1(fp, conf, peer, peers, log_fd, log_socket);
		break;
	case 5:
		process_netflow_v5(fp, conf, peer, peers, log_fd, log_socket);
		break;
	case 7:
		process_netflow_v7(fp, conf, peer, peers, log_fd, log_socket);
		break;
	case 9:
		process_netflow_v9(fp, conf, peer, peers, log_fd, log_socket);
		break;
	default:
		logit(LOG_INFO, "Unsupported netflow version %u from %s",
		    ntohs(hdr->version), addr_ntop_buf(&fp->flow_source));
#ifdef DEBUG_UNKNOWN
		dump_packet("Unknown packet type", fp->packet, fp->len);
#endif
		return;
	}
}

static void
process_input_queue(struct flowd_config *conf, struct peers *peers,
    int log_fd, int log_socket)
{
	struct flow_packet *fp;

	while ((fp = flow_packet_dequeue()) != NULL) {
		process_packet(fp, conf, peers, log_fd, log_socket);
		flow_packet_dealloc(fp);
	}
}

static void
init_pfd(struct flowd_config *conf, struct pollfd **pfdp, int mfd, int *num_fds)
{
	struct pollfd *pfd = *pfdp;
	struct listen_addr *la;
	int i;

	logit(LOG_DEBUG, "%s: entering (num_fds = %d)", __func__, *num_fds);

	if (pfd != NULL)
		free(pfd);

	*num_fds = 1; /* fd to monitor */

	/* Count socks */
	TAILQ_FOREACH(la, &conf->listen_addrs, entry)
		(*num_fds)++;

	if ((pfd = calloc((*num_fds) + 1, sizeof(*pfd))) == NULL) {
		logerrx("%s: calloc failed (num %d)",
		    __func__, *num_fds + 1);
	}

	pfd[0].fd = mfd;
	pfd[0].events = POLLIN;

	i = 1;
	TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
		pfd[i].fd = la->fd;
		pfd[i].events = POLLIN;
		i++;
	}

	*pfdp = pfd;

	logit(LOG_DEBUG, "%s: done (num_fds = %d)", __func__, *num_fds);
}

static void
flowd_mainloop(struct flowd_config *conf, struct peers *peers, int monitor_fd)
{
	int i, log_fd, log_socket, num_fds = 0;
	struct listen_addr *la;
	struct pollfd *pfd = NULL;

	init_pfd(conf, &pfd, monitor_fd, &num_fds);

	/* Main loop */
	log_fd = log_socket = -1;
	for(;exit_flag == 0;) {
		if (log_socket != -1 &&
		    logsock_num_errors > LOGSOCK_REOPEN_ERROR_COUNT &&
		    time(NULL) > logsock_first_error + LOGSOCK_REOPEN_DELAY) {
			logit(LOG_INFO, "reopening log socket because of "
			    "frequent errors");
			close(log_socket);
			log_socket = -1;
			logsock_first_error = logsock_num_errors = 0;
		}
		if (reopen_flag && (log_fd != -1 || log_socket != -1)) {
			logit(LOG_INFO, "log reopen requested");
			if (log_fd != -1)
				close(log_fd);
			if (log_socket != -1)
				close(log_socket);
			log_fd = log_socket = -1;
			reopen_flag = 0;
		}
		if (reconf_flag) {
			logit(LOG_INFO, "reconfiguration requested");
			if (client_reconfigure(monitor_fd, conf) == -1)
				logerrx("reconfigure failed, exiting");
			init_pfd(conf, &pfd, monitor_fd, &num_fds);
			scrub_peers(conf, peers);
			reconf_flag = 0;
		}
		if (log_fd == -1 && conf->log_file != NULL)
			log_fd = start_log(monitor_fd);
		if (log_socket == -1 && conf->log_socket != NULL)
			log_socket = start_socket(monitor_fd);

		if (info_flag) {
			struct filter_rule *fr;

			info_flag = 0;
			TAILQ_FOREACH(fr, &conf->filter_list, entry)
				logit(LOG_INFO, "%s", format_rule(fr));
			dump_peers(peers);
		}

		i = poll(pfd, num_fds, INFTIM);
		if (i <= 0) {
			if (i == 0 || errno == EINTR)
				continue;
			logerr("%s: poll", __func__);
		}

		/* monitor exited */
		if (pfd[0].revents != 0) {
			logit(LOG_DEBUG, "%s: monitor closed", __func__);
			break;
		}

		i = 1;
		TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
			if ((pfd[i].revents & POLLIN) != 0)
				receive_many(conf, peers, pfd[i].fd);
			i++;
		}

		process_input_queue(conf, peers, log_fd, log_socket);
		output_flow_flush(log_fd, conf->opts & FLOWD_OPT_VERBOSE);
	}

	if (exit_flag != 0)
		logit(LOG_NOTICE, "Exiting on signal %d", exit_flag);
}

static void
startup_listen_init(struct flowd_config *conf)
{
	struct listen_addr *la;

	TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
		if ((la->fd = open_listener(&la->addr, la->port, la->bufsiz,
		    &conf->join_groups)) == -1) {
			logerrx("Listener setup of [%s]:%d failed",
			    addr_ntop_buf(&la->addr), la->port);
		}
	}
}

/* Display commandline usage information */
static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options]\n", PROGNAME);
	fprintf(stderr, "This is %s version %s. Valid commandline options:\n",
	    PROGNAME, PROGVER);
	fprintf(stderr, "  -d              Run in the foreground and print debug information\n");
	fprintf(stderr, "  -g              Run in the foreground and log to stderr\n");
	fprintf(stderr, "  -h              Display this help\n");
	fprintf(stderr, "  -f path         Configuration file (default: %s)\n",
	    DEFAULT_CONFIG);
	fprintf(stderr, "\n");
}

int
main(int argc, char **argv)
{
	int ch;
	extern char *optarg;
	extern int optind;
	const char *config_file = DEFAULT_CONFIG;
	struct flowd_config conf;
	int monitor_fd;
	struct peers peers;

#ifndef HAVE_SETPROCTITLE
	compat_init_setproctitle(argc, &argv);
#endif
	umask(0077);
	closefrom(STDERR_FILENO + 1);

#ifdef HAVE_TZSET
	tzset();
#endif
	loginit(PROGNAME, 1, 0);

	bzero(&conf, sizeof(conf));
	bzero(&peers, sizeof(peers));
	peers.max_peers = DEFAULT_MAX_PEERS;
	peers.max_templates = DEFAULT_MAX_TEMPLATES;
	peers.max_sources = DEFAULT_MAX_SOURCES;
	peers.max_template_len = DEFAULT_MAX_TEMPLATE_LEN;
	SPLAY_INIT(&peers.peer_tree);
	TAILQ_INIT(&peers.peer_list);

	while ((ch = getopt(argc, argv, "dghD:f:X:")) != -1) {
		switch (ch) {
		case 'X':
			if (strcmp(optarg, "INSECURE") == 0)
				conf.opts |= FLOWD_OPT_INSECURE;
			else
				logerrx("Invalid debugging option %s", optarg);
			break;
		case 'd':
			conf.opts |= FLOWD_OPT_DONT_FORK;
			conf.opts |= FLOWD_OPT_VERBOSE;
			loginit(PROGNAME, 1, 1);
			break;
		case 'g':
			conf.opts |= FLOWD_OPT_DONT_FORK;
			loginit(PROGNAME, 1, 1);
			break;
		case 'h':
			usage();
			return (0);
		case 'D':
			if (cmdline_symset(optarg) < 0)
				logerrx("Could not parse macro "
				    "definition %s", optarg);
			break;
		case 'f':
			config_file = optarg;
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	if (read_config(config_file, &conf) == -1)
		logerrx("Config file has errors");

	/* Start listening (do this early to report errors before privsep) */
	startup_listen_init(&conf);

	/* Start the monitor - we continue as the unprivileged child */
	privsep_init(&conf, &monitor_fd, config_file);

	signal(SIGINT, sighand_exit);
	signal(SIGTERM, sighand_exit);
	signal(SIGHUP, sighand_reconf);
	signal(SIGUSR1, sighand_reopen);
	signal(SIGUSR2, sighand_info);
#ifdef SIGINFO
	signal(SIGINFO, sighand_info);
#endif

	flowd_mainloop(&conf, &peers, monitor_fd);

	return (0);
}
