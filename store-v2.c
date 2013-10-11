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

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>

#include "store-v2.h"
#include "atomicio.h"
#include "crc32.h"

RCSID("$Id: store-v2.c,v 1.5 2006/10/21 04:34:08 djm Exp $");

/* This is a useful abbreviation, used in several places below */
#define SHASFIELD(flag) (fields & STORE_V2_FIELD_##flag)

/* Stash error message and return */
#define SFAILX(i, m, f) do {						\
		if (ebuf != NULL && elen > 0) {				\
			snprintf(ebuf, elen, "%s%s%s",			\
			    (f) ? __func__ : "", (f) ? ": " : "", m);	\
		}							\
		return (i);						\
	} while (0)

/* Stash error message, appending strerror into "ebuf" and return */
#define SFAIL(i, m, f) do {						\
		if (ebuf != NULL && elen > 0) {				\
			snprintf(ebuf, elen, "%s%s%s: %s", 		\
			    (f) ? __func__ : "", (f) ? ": " : "", m, 	\
			    strerror(errno));				\
		}							\
		return (i);						\
	} while (0)

int
store_v2_validate_header(struct store_v2_header *hdr, char *ebuf, int elen)
{
	if (ntohl(hdr->magic) != STORE_V2_MAGIC)
		SFAILX(STORE_ERR_BAD_MAGIC, "Bad magic", 0);
	if (ntohl(hdr->version) != STORE_V2_VERSION)
		SFAILX(STORE_ERR_UNSUP_VERSION, "Unsupported version", 0);

	return (STORE_ERR_OK);
}

int
store_v2_get_header(int fd, struct store_v2_header *hdr, char *ebuf, int elen)
{
	ssize_t r;

	if ((r = atomicio(read, fd, hdr, sizeof(*hdr))) == -1)
		SFAIL(STORE_ERR_IO, "read error", 0);
	if (r < (ssize_t)sizeof(*hdr))
		SFAILX(STORE_ERR_EOF, "premature EOF", 0);

	return (store_v2_validate_header(hdr, ebuf, elen));
}

int
store_v2_calc_flow_len(struct store_v2_flow *hdr)
{
	int ret = 0;
	u_int32_t fields;

	fields = ntohl(hdr->fields);
#define ADDFIELD(flag) do { \
		if (SHASFIELD(flag)) { \
			ret += sizeof(struct store_v2_flow_##flag); \
			fields &= ~STORE_V2_FIELD_##flag; \
		} } while (0)
	ADDFIELD(TAG);
	ADDFIELD(RECV_TIME);
	ADDFIELD(PROTO_FLAGS_TOS);
	ADDFIELD(AGENT_ADDR4);
	ADDFIELD(AGENT_ADDR6);
	ADDFIELD(SRC_ADDR4);
	ADDFIELD(SRC_ADDR6);
	ADDFIELD(DST_ADDR4);
	ADDFIELD(DST_ADDR6);
	ADDFIELD(GATEWAY_ADDR4);
	ADDFIELD(GATEWAY_ADDR6);
	ADDFIELD(SRCDST_PORT);
	ADDFIELD(PACKETS);
	ADDFIELD(OCTETS);
	ADDFIELD(IF_INDICES);
	ADDFIELD(AGENT_INFO);
	ADDFIELD(FLOW_TIMES);
	ADDFIELD(AS_INFO);
	ADDFIELD(FLOW_ENGINE_INFO);
	ADDFIELD(CRC32);
#undef ADDFIELD

	/* Make sure we have captured everything */
	if (fields != 0)
		return (-1);

	return (ret);
}

int
store_v2_flow_deserialise(u_int8_t *buf, int len, struct store_v2_flow_complete *f,
    char *ebuf, int elen)
{
	int offset, r;
	struct store_v2_flow_AGENT_ADDR4 aa4;
	struct store_v2_flow_AGENT_ADDR6 aa6;
	struct store_v2_flow_SRC_ADDR4 sa4;
	struct store_v2_flow_SRC_ADDR6 sa6;
	struct store_v2_flow_DST_ADDR4 da4;
	struct store_v2_flow_DST_ADDR6 da6;
	struct store_v2_flow_GATEWAY_ADDR4 ga4;
	struct store_v2_flow_GATEWAY_ADDR6 ga6;
	u_int32_t fields, crc;

	bzero(f, sizeof(*f));
	flowd_crc32_start(&crc);

	memcpy(&f->hdr.fields, buf, sizeof(f->hdr.fields));

	if (len < sizeof(f->hdr))
		SFAILX(STORE_ERR_BUFFER_SIZE,
		    "supplied length is too small", 1);

	if ((r = store_v2_calc_flow_len((struct store_v2_flow *)buf)) == -1)
		SFAILX(STORE_ERR_FLOW_INVALID,
		    "unsupported flow fields specified", 0);

	if (len - sizeof(f->hdr) < r)
		SFAILX(STORE_ERR_BUFFER_SIZE,
		    "calulated flow length is less than supplied len", 1);

	flowd_crc32_update((u_char *)&f->hdr, sizeof(f->hdr), &crc);

	fields = ntohl(f->hdr.fields);

	offset = sizeof(f->hdr);

#define RFIELD(flag, dest) do { \
		if (SHASFIELD(flag)) { \
			memcpy(&dest, buf + offset, sizeof(dest)); \
			offset += sizeof(dest); \
			if (SHASFIELD(CRC32) && \
			    STORE_V2_FIELD_##flag != STORE_V2_FIELD_CRC32) { \
				flowd_crc32_update((u_char *)&dest, \
				    sizeof(dest), &crc); \
			} \
		} } while (0)

	RFIELD(TAG, f->tag);
	RFIELD(RECV_TIME, f->recv_time);
	RFIELD(PROTO_FLAGS_TOS, f->pft);
	RFIELD(AGENT_ADDR4, aa4);
	RFIELD(AGENT_ADDR6, aa6);
	RFIELD(SRC_ADDR4, sa4);
	RFIELD(SRC_ADDR6, sa6);
	RFIELD(DST_ADDR4, da4);
	RFIELD(DST_ADDR6, da6);
	RFIELD(GATEWAY_ADDR4, ga4);
	RFIELD(GATEWAY_ADDR6, ga6);
	RFIELD(SRCDST_PORT, f->ports);
	RFIELD(PACKETS, f->packets);
	RFIELD(OCTETS, f->octets);
	RFIELD(IF_INDICES, f->ifndx);
	RFIELD(AGENT_INFO, f->ainfo);
	RFIELD(FLOW_TIMES, f->ftimes);
	RFIELD(AS_INFO, f->asinf);
	RFIELD(FLOW_ENGINE_INFO, f->finf);
	RFIELD(CRC32, f->crc32);

	/* Sanity check and convert addresses */
	if (SHASFIELD(AGENT_ADDR4) && SHASFIELD(AGENT_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 agent addrs", 0);
	if (SHASFIELD(SRC_ADDR4) && SHASFIELD(SRC_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 src addrs", 0);
	if (SHASFIELD(DST_ADDR4) && SHASFIELD(DST_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 dst addrs", 0);
	if (SHASFIELD(GATEWAY_ADDR4) && SHASFIELD(GATEWAY_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 gateway addrs", 0);

#define S_CPYADDR(d, s, fam) do {					\
		(d).af = (fam == 4) ? AF_INET : AF_INET6;		\
		memcpy(&d.v##fam, &s, sizeof(d.v##fam));		\
	} while (0)

	if (SHASFIELD(AGENT_ADDR4))
		S_CPYADDR(f->agent_addr, aa4.flow_agent_addr, 4);
	if (SHASFIELD(AGENT_ADDR6))
		S_CPYADDR(f->agent_addr, aa6.flow_agent_addr, 6);
	if (SHASFIELD(SRC_ADDR4))
		S_CPYADDR(f->src_addr, sa4.src_addr, 4);
	if (SHASFIELD(SRC_ADDR6))
		S_CPYADDR(f->src_addr, sa6.src_addr, 6);
	if (SHASFIELD(DST_ADDR4))
		S_CPYADDR(f->dst_addr, da4.dst_addr, 4);
	if (SHASFIELD(DST_ADDR6))
		S_CPYADDR(f->dst_addr, da6.dst_addr, 6);
	if (SHASFIELD(GATEWAY_ADDR4))
		S_CPYADDR(f->gateway_addr, ga4.gateway_addr, 4);
	if (SHASFIELD(GATEWAY_ADDR6))
		S_CPYADDR(f->gateway_addr, ga6.gateway_addr, 6);

	if (SHASFIELD(CRC32) && crc != ntohl(f->crc32.crc32))
		SFAILX(STORE_ERR_CRC_MISMATCH, "Flow checksum mismatch", 0);

#undef S_CPYADDR
#undef RFIELD

	return (STORE_ERR_OK);
}

int
store_v2_get_flow(int fd, struct store_v2_flow_complete *f, char *ebuf, int elen)
{
	int r, len;
	u_int8_t buf[512];

	/* Read header */
	if ((r = atomicio(read, fd, buf, sizeof(struct store_v2_flow))) == -1)
		SFAIL(STORE_ERR_IO, "read flow header", 0);
	if (r < sizeof(struct store_v2_flow))
		SFAILX(STORE_ERR_EOF, "EOF reading flow header", 0);

	if ((len = store_v2_calc_flow_len((struct store_v2_flow *)buf)) == -1)
		SFAILX(STORE_ERR_FLOW_INVALID,
		    "unsupported flow fields specified", 0);
	if (len > sizeof(buf) - sizeof(struct store_v2_flow))
		SFAILX(STORE_ERR_INTERNAL,
		    "Internal error: flow buffer too small", 1);

	if ((r = atomicio(read, fd, buf + sizeof(struct store_v2_flow), len)) == -1)
		SFAIL(STORE_ERR_IO, "read flow data", 0);
	if (r < len)
		SFAILX(STORE_ERR_EOF, "EOF reading flow data", 0);

	return (store_v2_flow_deserialise(buf, len + sizeof(struct store_v2_flow),
	    f, ebuf, elen));
}

int
store_v2_check_header(int fd, char *ebuf, int elen)
{
	struct store_v2_header hdr;
	int r;

	if ((r = store_v2_get_header(fd, &hdr, ebuf, elen)) != STORE_ERR_OK)
		return (r);

	/* store_get_header does all the magic & version checks for us */

	return (STORE_ERR_OK);
}

int
store_v2_put_header(int fd, char *ebuf, int elen)
{
	struct store_v2_header hdr;
	int r;

	bzero(&hdr, sizeof(hdr));
	hdr.magic = htonl(STORE_V2_MAGIC);
	hdr.version = htonl(STORE_V2_VERSION);
	hdr.start_time = htonl(time(NULL));
	hdr.flags = htonl(0);

	r = atomicio(vwrite, fd, &hdr, sizeof(hdr));
	if (r == -1)
		SFAIL(STORE_ERR_IO, "write error on header", 0);
	if (r < (ssize_t)sizeof(hdr))
		SFAILX(STORE_ERR_EOF, "EOF while writing header", 0);

	return (STORE_ERR_OK);
}

int
store_v2_flow_serialise(struct store_v2_flow_complete *f, u_int8_t *buf, int buflen,
    int *flowlen, char *ebuf, int elen)
{
	struct store_v2_flow_AGENT_ADDR4 aa4;
	struct store_v2_flow_AGENT_ADDR6 aa6;
	struct store_v2_flow_SRC_ADDR4 sa4;
	struct store_v2_flow_SRC_ADDR6 sa6;
	struct store_v2_flow_DST_ADDR4 da4;
	struct store_v2_flow_DST_ADDR6 da6;
	struct store_v2_flow_GATEWAY_ADDR4 gwa4;
	struct store_v2_flow_GATEWAY_ADDR6 gwa6;
	u_int32_t fields, crc;
	int offset;

	fields = ntohl(f->hdr.fields);

	/* Convert addresses and set AF fields correctly */
	/* XXX this is too repetitive */
	switch(f->agent_addr.af) {
	case AF_INET:
		if ((fields & STORE_V2_FIELD_AGENT_ADDR4) == 0)
			break;
		memcpy(&aa4.flow_agent_addr, &f->agent_addr.v4,
		    sizeof(aa4.flow_agent_addr));
		fields |= STORE_V2_FIELD_AGENT_ADDR4;
		fields &= ~STORE_V2_FIELD_AGENT_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_V2_FIELD_AGENT_ADDR6) == 0)
			break;
		memcpy(&aa6.flow_agent_addr, &f->agent_addr.v6,
		    sizeof(aa6.flow_agent_addr));
		fields |= STORE_V2_FIELD_AGENT_ADDR6;
		fields &= ~STORE_V2_FIELD_AGENT_ADDR4;
		break;
	default:
		if ((fields & STORE_V2_FIELD_AGENT_ADDR) == 0)
			break;
		SFAILX(STORE_ERR_FLOW_INVALID, "silly agent addr af", 1);
	}

	switch(f->src_addr.af) {
	case AF_INET:
		if ((fields & STORE_V2_FIELD_SRC_ADDR4) == 0)
			break;
		memcpy(&sa4.src_addr, &f->src_addr.v4,
		    sizeof(sa4.src_addr));
		fields |= STORE_V2_FIELD_SRC_ADDR4;
		fields &= ~STORE_V2_FIELD_SRC_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_V2_FIELD_SRC_ADDR6) == 0)
			break;
		memcpy(&sa6.src_addr, &f->src_addr.v6,
		    sizeof(sa6.src_addr));
		fields |= STORE_V2_FIELD_SRC_ADDR6;
		fields &= ~STORE_V2_FIELD_SRC_ADDR4;
		break;
	default:
		if ((fields & STORE_V2_FIELD_SRC_ADDR) == 0)
			break;
		SFAILX(STORE_ERR_FLOW_INVALID, "silly src addrs af", 1);
	}

	switch(f->dst_addr.af) {
	case AF_INET:
		if ((fields & STORE_V2_FIELD_DST_ADDR4) == 0)
			break;
		memcpy(&da4.dst_addr, &f->dst_addr.v4,
		    sizeof(da4.dst_addr));
		fields |= STORE_V2_FIELD_DST_ADDR4;
		fields &= ~STORE_V2_FIELD_DST_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_V2_FIELD_DST_ADDR6) == 0)
			break;
		memcpy(&da6.dst_addr, &f->dst_addr.v6,
		    sizeof(da6.dst_addr));
		fields |= STORE_V2_FIELD_DST_ADDR6;
		fields &= ~STORE_V2_FIELD_DST_ADDR4;
		break;
	default:
		if ((fields & STORE_V2_FIELD_DST_ADDR) == 0)
			break;
		SFAILX(STORE_ERR_FLOW_INVALID, "silly dst addrs af", 1);
	}

	switch(f->gateway_addr.af) {
	case AF_INET:
		if ((fields & STORE_V2_FIELD_GATEWAY_ADDR4) == 0)
			break;
		memcpy(&gwa4.gateway_addr, &f->gateway_addr.v4,
		    sizeof(gwa4.gateway_addr));
		fields |= STORE_V2_FIELD_GATEWAY_ADDR4;
		fields &= ~STORE_V2_FIELD_GATEWAY_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_V2_FIELD_GATEWAY_ADDR6) == 0)
			break;
		memcpy(&gwa6.gateway_addr, &f->gateway_addr.v6,
		    sizeof(gwa6.gateway_addr));
		fields |= STORE_V2_FIELD_GATEWAY_ADDR6;
		fields &= ~STORE_V2_FIELD_GATEWAY_ADDR4;
		break;
	default:
		if ((fields & STORE_V2_FIELD_GATEWAY_ADDR) == 0)
			break;
		SFAILX(STORE_ERR_FLOW_INVALID, "silly gateway addr af", 1);
	}

	flowd_crc32_start(&crc);
	offset = 0;

	/* Fields have probably changes as a result of address conversion */
	f->hdr.fields = htonl(fields);
	if (store_v2_calc_flow_len(&f->hdr) > buflen)
		SFAILX(STORE_ERR_BUFFER_SIZE, "flow buffer too small", 1);

	memcpy(buf + offset, &f->hdr, sizeof(f->hdr));
	offset += sizeof(f->hdr);
	flowd_crc32_update((u_char *)&f->hdr, sizeof(f->hdr), &crc);

#define WFIELD(spec, what) do {						\
	if (SHASFIELD(spec)) {						\
		memcpy(buf + offset, &(what), sizeof(what));		\
		offset += sizeof(what);					\
		if (SHASFIELD(spec) && 					\
		    (STORE_V2_FIELD_##spec != STORE_V2_FIELD_CRC32)) {	\
			flowd_crc32_update((u_char *)&(what),		\
			    sizeof(what), &crc);			\
		}							\
	}  } while (0)

	WFIELD(TAG, f->tag);
	WFIELD(RECV_TIME, f->recv_time);
	WFIELD(PROTO_FLAGS_TOS, f->pft);
	WFIELD(AGENT_ADDR4, aa4);
	WFIELD(AGENT_ADDR6, aa6);
	WFIELD(SRC_ADDR4, sa4);
	WFIELD(SRC_ADDR6, sa6);
	WFIELD(DST_ADDR4, da4);
	WFIELD(DST_ADDR6, da6);
	WFIELD(GATEWAY_ADDR4, gwa4);
	WFIELD(GATEWAY_ADDR6, gwa6);
	WFIELD(SRCDST_PORT, f->ports);
	WFIELD(PACKETS, f->packets);
	WFIELD(OCTETS, f->octets);
	WFIELD(IF_INDICES, f->ifndx);
	WFIELD(AGENT_INFO, f->ainfo);
	WFIELD(FLOW_TIMES, f->ftimes);
	WFIELD(AS_INFO, f->asinf);
	WFIELD(FLOW_ENGINE_INFO, f->finf);
	if (fields & (STORE_V2_FIELD_CRC32))
		f->crc32.crc32 = htonl(crc);
	WFIELD(CRC32, f->crc32);
#undef WFIELD

	*flowlen = offset;
	return (STORE_ERR_OK);
}

int
store_v2_put_flow(int fd, struct store_v2_flow_complete *flow, u_int32_t fieldmask,
    char *ebuf, int elen)
{
	u_int32_t fields, origfields;
	off_t startpos;
	u_int8_t buf[512];
	int len, r, saved_errno, ispipe = 0;

	/* Remember where we started, so we can back errors out */
	if ((startpos = lseek(fd, 0, SEEK_CUR)) == -1) {
		if (errno == ESPIPE)
			ispipe = 1;
		else
			SFAIL(STORE_ERR_IO_SEEK, "lseek", 1);
	}

	origfields = ntohl(flow->hdr.fields);
	fields = origfields & fieldmask;
	flow->hdr.fields = htonl(fields);

	r = store_v2_flow_serialise(flow, buf, sizeof(buf), &len, ebuf, elen);
	if (r != STORE_ERR_OK) {
		flow->hdr.fields = htonl(origfields);
		return (r);
	}

	r = atomicio(vwrite, fd, buf, len);
	saved_errno = errno;
	flow->hdr.fields = htonl(origfields);

	if (r == len)
		return (STORE_ERR_OK);

	if (ispipe)
		SFAIL(STORE_ERR_CORRUPT, "corrupting failure on pipe", 1);

	/* Try to rewind to starting position, so we don't corrupt flow store */
	if (lseek(fd, startpos, SEEK_SET) == -1)
		SFAIL(STORE_ERR_CORRUPT, "corrupting failure on lseek", 1);
	if (ftruncate(fd, startpos) == -1)
		SFAIL(STORE_ERR_CORRUPT, "corrupting failure on ftruncate", 1);

	/* Partial flow record has been removed, return with orig. error */
	errno = saved_errno;
	if (r == -1)
		SFAIL(STORE_ERR_IO, "write flow", 0);
	else
		SFAILX(STORE_ERR_EOF, "EOF on write flow", 0);
}

int
store_v2_flow_convert(struct store_v2_flow_complete *fv2,
    struct store_flow_complete *f)
{
	int len;

	bzero(f, sizeof(*f));
	f->hdr.version = STORE_VERSION;
	f->hdr.fields = fv2->hdr.fields;
	if ((len = store_calc_flow_len(&f->hdr)) == -1)
		return (-1);
	f->hdr.len_words = len / 4;

	f->tag.tag = fv2->tag.tag;
	f->recv_time.recv_sec = fv2->recv_time.recv_sec;
	f->pft.tcp_flags = fv2->pft.tcp_flags;
	f->pft.protocol = fv2->pft.protocol;
	f->pft.tos = fv2->pft.tos;
	f->pft.pad = fv2->pft.pad;
	f->agent_addr = fv2->agent_addr;
	f->src_addr = fv2->src_addr;
	f->dst_addr = fv2->dst_addr;
	f->gateway_addr = fv2->gateway_addr;
	f->ports.src_port = fv2->ports.src_port;
	f->ports.dst_port = fv2->ports.dst_port;
	f->packets.flow_packets = fv2->packets.flow_packets;
	f->octets.flow_octets = fv2->octets.flow_octets;
	f->ifndx.if_index_in = htonl(ntohs(fv2->ifndx.if_index_in));
	f->ifndx.if_index_out = htonl(ntohs(fv2->ifndx.if_index_out));
	f->ainfo.sys_uptime_ms = fv2->ainfo.sys_uptime_ms;
	f->ainfo.time_sec = fv2->ainfo.time_sec;
	f->ainfo.time_nanosec = fv2->ainfo.time_nanosec;
	f->ainfo.netflow_version = fv2->ainfo.netflow_version;
	f->ainfo.pad = fv2->ainfo.pad;
	f->ftimes.flow_start = fv2->ftimes.flow_start;
	f->ftimes.flow_finish = fv2->ftimes.flow_finish;
	f->asinf.src_as = htonl(ntohs(fv2->asinf.src_as));
	f->asinf.dst_as = htonl(ntohs(fv2->asinf.dst_as));
	f->asinf.src_mask = fv2->asinf.src_mask;
	f->asinf.dst_mask = fv2->asinf.dst_mask;
	f->asinf.pad = fv2->asinf.pad;
	f->finf.engine_type = htons(fv2->finf.engine_type);
	f->finf.engine_id = htons(fv2->finf.engine_id);
	f->finf.flow_sequence = fv2->finf.flow_sequence;
	f->crc32.crc32 = fv2->crc32.crc32;

	return (0);
}
