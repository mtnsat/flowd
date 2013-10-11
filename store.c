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

#include "store.h"
#include "atomicio.h"
#include "crc32.h"

RCSID("$Id: store.c,v 1.39 2008/04/23 01:54:26 djm Exp $");

/* This is a useful abbreviation, used in several places below */
#define SHASFIELD(flag) (fields & STORE_FIELD_##flag)

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
store_calc_flow_len(struct store_flow *hdr)
{
	int ret = 0;
	u_int32_t fields;

	fields = ntohl(hdr->fields);
#define ADDFIELD(flag) do { \
		if (SHASFIELD(flag)) { \
			ret += sizeof(struct store_flow_##flag); \
			fields &= ~STORE_FIELD_##flag; \
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
store_flow_deserialise(u_int8_t *buf, int len, struct store_flow_complete *f,
    char *ebuf, int elen)
{
	int offset, allow_extra;
	struct store_flow_AGENT_ADDR4 aa4;
	struct store_flow_AGENT_ADDR6 aa6;
	struct store_flow_SRC_ADDR4 sa4;
	struct store_flow_SRC_ADDR6 sa6;
	struct store_flow_DST_ADDR4 da4;
	struct store_flow_DST_ADDR6 da6;
	struct store_flow_GATEWAY_ADDR4 ga4;
	struct store_flow_GATEWAY_ADDR6 ga6;
	u_int32_t donefields, fields, crc;

	bzero(f, sizeof(*f));
	flowd_crc32_start(&crc);

	if (len < sizeof(f->hdr))
		SFAILX(STORE_ERR_BUFFER_SIZE,
		    "supplied length is too small", 1);

	memcpy(&f->hdr, buf, sizeof(f->hdr));

	if (STORE_VER_GET_MAJ(f->hdr.version) != STORE_VER_MAJOR)
		SFAILX(STORE_ERR_UNSUP_VERSION, "Unsupported version", 0);
	allow_extra = (STORE_VER_GET_MIN(f->hdr.version) > STORE_VER_MINOR);

	if (len - sizeof(f->hdr) < (f->hdr.len_words * 4))
		SFAILX(STORE_ERR_BUFFER_SIZE,
		    "incomplete flow record supplied", 1);

	flowd_crc32_update((u_char *)&f->hdr, sizeof(f->hdr), &crc);

	donefields = fields = ntohl(f->hdr.fields);
	offset = sizeof(f->hdr);

#define RFIELD(flag, dest) do { \
		if (SHASFIELD(flag)) { \
			memcpy(&dest, buf + offset, sizeof(dest)); \
			offset += sizeof(dest); \
			if (SHASFIELD(CRC32) && \
			    STORE_FIELD_##flag != STORE_FIELD_CRC32) { \
				flowd_crc32_update((u_char *)&dest, \
				    sizeof(dest), &crc); \
			} \
			donefields &= ~STORE_FIELD_##flag; \
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

	/* Other fields might live here if minor version > ours */
	if ((donefields & ~STORE_FIELD_CRC32) != 0) {
		if (allow_extra) {
			/* Skip fields we don't understand */
			offset = (f->hdr.len_words * 4) + sizeof(f->hdr) - 
			    sizeof(f->crc32);
			fields = ntohl(f->hdr.fields) & STORE_FIELD_ALL;
		} else {
			/* There shouldn't be any extra if minor_ver <= ours */
			SFAILX(-1, "Flow has unknown fields", 0);
		}
	}
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
store_get_flow(int fd, struct store_flow_complete *f, char *ebuf, int elen)
{
	int r, len;
	u_int8_t buf[512];

	/* Read header */
	if ((r = atomicio(read, fd, buf, sizeof(struct store_flow))) == -1)
		SFAIL(STORE_ERR_IO, "read flow header", 0);
	if (r < sizeof(struct store_flow))
		SFAILX(STORE_ERR_EOF, "EOF reading flow header", 0);

	len = ((struct store_flow *)buf)->len_words * 4;
	if (len > sizeof(buf) - sizeof(struct store_flow))
		SFAILX(STORE_ERR_INTERNAL, "internal flow buffer too small "
		    "(flow is probably corrupt)", 1);

	if ((r = atomicio(read, fd, buf + sizeof(struct store_flow), len)) == -1)
		SFAIL(STORE_ERR_IO, "read flow data", 0);
	if (r < len)
		SFAILX(STORE_ERR_EOF, "EOF reading flow data", 0);

	return (store_flow_deserialise(buf, len + sizeof(struct store_flow),
	    f, ebuf, elen));
}

int
store_read_flow(FILE *f, struct store_flow_complete *flow, char *ebuf, int elen)
{
	int r, len;
	u_int8_t buf[512];

	/* Read header */
	r = fread(buf, sizeof(struct store_flow), 1, f);
	if (r == 0)
		SFAILX(STORE_ERR_EOF, "EOF reading flow header", 0);
	if (r != 1)
		SFAIL(STORE_ERR_IO, "read flow header", 0);

	len = ((struct store_flow *)buf)->len_words * 4;
	if (len > sizeof(buf) - sizeof(struct store_flow))
		SFAILX(STORE_ERR_INTERNAL,
		    "Internal error: flow buffer too small", 1);

	r = fread(buf + sizeof(struct store_flow), len, 1, f);
	if (r == 0)
		SFAILX(STORE_ERR_EOF, "EOF reading flow data", 0);
	if (r != 1)
		SFAIL(STORE_ERR_IO, "read flow data", 0);

	return (store_flow_deserialise(buf, len + sizeof(struct store_flow),
	    flow, ebuf, elen));
}

int
store_flow_serialise(struct store_flow_complete *f, u_int8_t *buf, int buflen,
    int *flowlen, char *ebuf, int elen)
{
	struct store_flow_AGENT_ADDR4 aa4;
	struct store_flow_AGENT_ADDR6 aa6;
	struct store_flow_SRC_ADDR4 sa4;
	struct store_flow_SRC_ADDR6 sa6;
	struct store_flow_DST_ADDR4 da4;
	struct store_flow_DST_ADDR6 da6;
	struct store_flow_GATEWAY_ADDR4 gwa4;
	struct store_flow_GATEWAY_ADDR6 gwa6;
	u_int32_t fields, crc;
	int len, offset;

	f->hdr.version = STORE_VERSION;
	fields = ntohl(f->hdr.fields);

	/* Convert addresses and set AF fields correctly */
	/* XXX this is too repetitive */
	switch(f->agent_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_AGENT_ADDR4) == 0)
			break;
		memcpy(&aa4.flow_agent_addr, &f->agent_addr.v4,
		    sizeof(aa4.flow_agent_addr));
		fields |= STORE_FIELD_AGENT_ADDR4;
		fields &= ~STORE_FIELD_AGENT_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_AGENT_ADDR6) == 0)
			break;
		memcpy(&aa6.flow_agent_addr, &f->agent_addr.v6,
		    sizeof(aa6.flow_agent_addr));
		fields |= STORE_FIELD_AGENT_ADDR6;
		fields &= ~STORE_FIELD_AGENT_ADDR4;
		break;
	default:
		if ((fields & STORE_FIELD_AGENT_ADDR) == 0)
			break;
		SFAILX(STORE_ERR_FLOW_INVALID, "silly agent addr af", 1);
	}

	switch(f->src_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_SRC_ADDR4) == 0)
			break;
		memcpy(&sa4.src_addr, &f->src_addr.v4,
		    sizeof(sa4.src_addr));
		fields |= STORE_FIELD_SRC_ADDR4;
		fields &= ~STORE_FIELD_SRC_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_SRC_ADDR6) == 0)
			break;
		memcpy(&sa6.src_addr, &f->src_addr.v6,
		    sizeof(sa6.src_addr));
		fields |= STORE_FIELD_SRC_ADDR6;
		fields &= ~STORE_FIELD_SRC_ADDR4;
		break;
	default:
		if ((fields & STORE_FIELD_SRC_ADDR) == 0)
			break;
		SFAILX(STORE_ERR_FLOW_INVALID, "silly src addrs af", 1);
	}

	switch(f->dst_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_DST_ADDR4) == 0)
			break;
		memcpy(&da4.dst_addr, &f->dst_addr.v4,
		    sizeof(da4.dst_addr));
		fields |= STORE_FIELD_DST_ADDR4;
		fields &= ~STORE_FIELD_DST_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_DST_ADDR6) == 0)
			break;
		memcpy(&da6.dst_addr, &f->dst_addr.v6,
		    sizeof(da6.dst_addr));
		fields |= STORE_FIELD_DST_ADDR6;
		fields &= ~STORE_FIELD_DST_ADDR4;
		break;
	default:
		if ((fields & STORE_FIELD_DST_ADDR) == 0)
			break;
		SFAILX(STORE_ERR_FLOW_INVALID, "silly dst addrs af", 1);
	}

	switch(f->gateway_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_GATEWAY_ADDR4) == 0)
			break;
		memcpy(&gwa4.gateway_addr, &f->gateway_addr.v4,
		    sizeof(gwa4.gateway_addr));
		fields |= STORE_FIELD_GATEWAY_ADDR4;
		fields &= ~STORE_FIELD_GATEWAY_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_GATEWAY_ADDR6) == 0)
			break;
		memcpy(&gwa6.gateway_addr, &f->gateway_addr.v6,
		    sizeof(gwa6.gateway_addr));
		fields |= STORE_FIELD_GATEWAY_ADDR6;
		fields &= ~STORE_FIELD_GATEWAY_ADDR4;
		break;
	default:
		if ((fields & STORE_FIELD_GATEWAY_ADDR) == 0)
			break;
		SFAILX(STORE_ERR_FLOW_INVALID, "silly gateway addr af", 1);
	}

	/* Fields have probably changes as a result of address conversion */
	f->hdr.fields = htonl(fields);

	len = store_calc_flow_len(&f->hdr);
	if ((len & 3) != 0)
		SFAILX(STORE_ERR_INTERNAL, "len & 3 != 0", 1);
	if (len > buflen)
		SFAILX(STORE_ERR_BUFFER_SIZE, "flow buffer too small", 1);
	if (len == -1)
		SFAILX(STORE_ERR_FLOW_INVALID,
		    "unsupported flow fields specified", 0);
	f->hdr.len_words = len / 4;
	f->hdr.reserved = 0;

	memcpy(buf, &f->hdr, sizeof(f->hdr));
	offset = sizeof(f->hdr);

	flowd_crc32_start(&crc);
	flowd_crc32_update((u_char *)&f->hdr, sizeof(f->hdr), &crc);

#define WFIELD(spec, what) do {						\
	if (SHASFIELD(spec)) {						\
		memcpy(buf + offset, &(what), sizeof(what));		\
		offset += sizeof(what);					\
		if (SHASFIELD(spec) && 					\
		    (STORE_FIELD_##spec != STORE_FIELD_CRC32)) {	\
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
	if (fields & (STORE_FIELD_CRC32))
		f->crc32.crc32 = htonl(crc);
	WFIELD(CRC32, f->crc32);
#undef WFIELD

	if (len + sizeof(f->hdr) != offset)
		SFAILX(STORE_ERR_INTERNAL, "len != offset", 1);

	*flowlen = offset;
	return (STORE_ERR_OK);
}

int
store_put_buf(int fd, char *buf, int len, char *ebuf, int elen)
{
	off_t startpos;
	int r, saved_errno, ispipe = 0;

	/* Remember where we started, so we can back errors out */
	if ((startpos = lseek(fd, 0, SEEK_CUR)) == -1) {
		if (errno == ESPIPE)
			ispipe = 1;
		else
			SFAIL(STORE_ERR_IO_SEEK, "lseek", 1);
	}

	r = atomicio(vwrite, fd, buf, len);
	saved_errno = errno;

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
	/* NOTREACHED */
}

int
store_flow_serialise_masked(struct store_flow_complete *f, u_int32_t mask,
    u_int8_t *buf, int buflen, int *flowlen, char *ebuf, int elen)
{
	u_int32_t fields, origfields;
	int r;

	origfields = ntohl(f->hdr.fields);
	fields = origfields & mask;
	f->hdr.fields = htonl(fields);

	r = store_flow_serialise(f, buf, buflen, flowlen, ebuf, elen);
	f->hdr.fields = htonl(origfields);

	return (r);
}

int
store_put_flow(int fd, struct store_flow_complete *flow, u_int32_t fieldmask,
    char *ebuf, int elen)
{
	u_int8_t buf[1024];
	int len, r;

	if ((r = (store_flow_serialise_masked(flow, fieldmask, buf, sizeof(buf),
	    &len, ebuf, elen))) != STORE_ERR_OK)
		return (r);

	return store_put_buf(fd, buf, len, ebuf, elen);
}

int
store_write_flow(FILE *f, struct store_flow_complete *flow, u_int32_t fieldmask,
    char *ebuf, int elen)
{
	u_int32_t fields, origfields;
	u_int8_t buf[1024];
	int len, r;

	origfields = ntohl(flow->hdr.fields);
	fields = origfields & fieldmask;
	flow->hdr.fields = htonl(fields);

	r = store_flow_serialise(flow, buf, sizeof(buf), &len, ebuf, elen);
	flow->hdr.fields = htonl(origfields);

	if (r != STORE_ERR_OK)
		return (r);
	r = fwrite(buf, len, 1, f);
	if (r == 0)
		SFAILX(STORE_ERR_EOF, "EOF on write flow", 0);
	if (r != 1)
		SFAIL(STORE_ERR_IO, "fwrite flow", 0);

	return (STORE_ERR_OK);
}

const char *
iso_time(time_t t, int utc_flag)
{
	struct tm *tm;
	static char buf[128];

	if (utc_flag)
		tm = gmtime(&t);
	else
		tm = localtime(&t);

	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);

	return (buf);
}

#define MINUTE		(60)
#define HOUR		(MINUTE * 60)
#define DAY		(HOUR * 24)
#define WEEK		(DAY * 7)
#define YEAR		(WEEK * 52)
const char *
interval_time(time_t t)
{
	static char buf[128];
	char tmp[128];
	u_long r;
	int unit_div[] = { YEAR, WEEK, DAY, HOUR, MINUTE, 1, -1 };
	char unit_sym[] = { 'y', 'w', 'd', 'h', 'm', 's' };
	int i;

	*buf = '\0';

	for (i = 0; unit_div[i] != -1; i++) {
		if ((r = t / unit_div[i]) != 0 || unit_div[i] == 1) {
			snprintf(tmp, sizeof(tmp), "%lu%c", r, unit_sym[i]);
			strlcat(buf, tmp, sizeof(buf));
			t %= unit_div[i];
		}
	}
	return (buf);
}

/*
 * Some helper functions for store_format_flow() and store_swab_flow(), 
 * so we can switch between host and network byte order easily.
 */
static u_int64_t
store_swp_ntoh64(u_int64_t v)
{
	return store_ntohll(v);
}

static u_int32_t
store_swp_ntoh32(u_int32_t v)
{
	return ntohl(v);
}

static u_int16_t
store_swp_ntoh16(u_int16_t v)
{
	return ntohs(v);
}

static u_int64_t
store_swp_hton64(u_int64_t v)
{
	return store_htonll(v);
}

static u_int32_t
store_swp_hton32(u_int32_t v)
{
	return htonl(v);
}

static u_int16_t
store_swp_hton16(u_int16_t v)
{
	return htons(v);
}

static u_int64_t
store_swp_fake64(u_int64_t v)
{
	return v;
}

static u_int32_t
store_swp_fake32(u_int32_t v)
{
	return v;
}

static u_int16_t
store_swp_fake16(u_int16_t v)
{
	return v;
}


void
store_format_flow(struct store_flow_complete *flow, char *buf, size_t len,
    int utc_flag, u_int32_t display_mask, int hostorder)
{
	char tmp[256];
	u_int32_t fields;
	u_int64_t (*fmt_ntoh64)(u_int64_t) = store_swp_ntoh64;
	u_int32_t (*fmt_ntoh32)(u_int32_t) = store_swp_ntoh32;
	u_int16_t (*fmt_ntoh16)(u_int16_t) = store_swp_ntoh16;

	if (hostorder) {
		fmt_ntoh64 = store_swp_fake64;
		fmt_ntoh32 = store_swp_fake32;
		fmt_ntoh16 = store_swp_fake16;
	}

	*buf = '\0';

	fields = fmt_ntoh32(flow->hdr.fields) & display_mask;

	strlcat(buf, "FLOW ", len);

	if (SHASFIELD(TAG)) {
		snprintf(tmp, sizeof(tmp), "tag %u ", fmt_ntoh32(flow->tag.tag));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(RECV_TIME)) {
		snprintf(tmp, sizeof(tmp), "recv_time %s.%05d ",
		    iso_time(fmt_ntoh32(flow->recv_time.recv_sec), utc_flag),
		    fmt_ntoh32(flow->recv_time.recv_usec));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(PROTO_FLAGS_TOS)) {
		snprintf(tmp, sizeof(tmp), "proto %d ", flow->pft.protocol);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "tcpflags %02x ",
		    flow->pft.tcp_flags);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "tos %02x " , flow->pft.tos);
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(AGENT_ADDR4) || SHASFIELD(AGENT_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "agent [%s] ",
		    addr_ntop_buf(&flow->agent_addr));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(SRC_ADDR4) || SHASFIELD(SRC_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "src [%s]",
		    addr_ntop_buf(&flow->src_addr));
		strlcat(buf, tmp, len);
		if (SHASFIELD(SRCDST_PORT)) {
			snprintf(tmp, sizeof(tmp), ":%d",
			    fmt_ntoh16(flow->ports.src_port));
			strlcat(buf, tmp, len);
		}
		strlcat(buf, " ", len);
	}
	if (SHASFIELD(DST_ADDR4) || SHASFIELD(DST_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "dst [%s]",
		    addr_ntop_buf(&flow->dst_addr));
		strlcat(buf, tmp, len);
		if (SHASFIELD(SRCDST_PORT)) {
			snprintf(tmp, sizeof(tmp), ":%d",
			    fmt_ntoh16(flow->ports.dst_port));
			strlcat(buf, tmp, len);
		}
		strlcat(buf, " ", len);
	}
	if (SHASFIELD(GATEWAY_ADDR4) || SHASFIELD(GATEWAY_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "gateway [%s] ",
		    addr_ntop_buf(&flow->gateway_addr));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(PACKETS)) {
		snprintf(tmp, sizeof(tmp), "packets %llu ",
		    fmt_ntoh64(flow->packets.flow_packets));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(OCTETS)) {
		snprintf(tmp, sizeof(tmp), "octets %llu ",
		    fmt_ntoh64(flow->octets.flow_octets));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(IF_INDICES)) {
		snprintf(tmp, sizeof(tmp), "in_if %d out_if %d ",
			fmt_ntoh32(flow->ifndx.if_index_in),
			fmt_ntoh32(flow->ifndx.if_index_out));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(AGENT_INFO)) {
		snprintf(tmp, sizeof(tmp), "sys_uptime_ms %s.%03u ",
		    interval_time(fmt_ntoh32(flow->ainfo.sys_uptime_ms) / 1000),
		    fmt_ntoh32(flow->ainfo.sys_uptime_ms) % 1000);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "time_sec %s ",
		    iso_time(fmt_ntoh32(flow->ainfo.time_sec), utc_flag));
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "time_nanosec %lu netflow ver %u ",
		    (u_long)fmt_ntoh32(flow->ainfo.time_nanosec),
		    fmt_ntoh16(flow->ainfo.netflow_version));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(FLOW_TIMES)) {
		snprintf(tmp, sizeof(tmp), "flow_start %s.%03u ",
		    interval_time(fmt_ntoh32(flow->ftimes.flow_start) / 1000),
		    fmt_ntoh32(flow->ftimes.flow_start) % 1000);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "flow_finish %s.%03u ",
		    interval_time(fmt_ntoh32(flow->ftimes.flow_finish) / 1000),
		    fmt_ntoh32(flow->ftimes.flow_finish) % 1000);
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(AS_INFO)) {
		snprintf(tmp, sizeof(tmp), "src_AS %u src_masklen %u ",
		    fmt_ntoh32(flow->asinf.src_as), flow->asinf.src_mask);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "dst_AS %u dst_masklen %u ",
		    fmt_ntoh32(flow->asinf.dst_as), flow->asinf.dst_mask);
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(FLOW_ENGINE_INFO)) {
		snprintf(tmp, sizeof(tmp),
		    "engine_type %u engine_id %u seq %lu source %lu ",
		    fmt_ntoh16(flow->finf.engine_type), 
		    fmt_ntoh16(flow->finf.engine_id),
		    (u_long)fmt_ntoh32(flow->finf.flow_sequence), 
		    (u_long)fmt_ntoh32(flow->finf.source_id));
		strlcat(buf, tmp, len);
	}
	if (SHASFIELD(CRC32)) {
		snprintf(tmp, sizeof(tmp), "crc32 %08x ",
		    fmt_ntoh32(flow->crc32.crc32));
		strlcat(buf, tmp, len);
	}
}

void
store_format_flow_flowtools_csv(struct store_flow_complete *flow, char *buf,
    size_t len, int utc_flag, u_int32_t display_mask, int hostorder)
{
	char tmp[256];
	u_int32_t fields;
	u_int64_t (*fmt_ntoh64)(u_int64_t) = store_swp_ntoh64;
	u_int32_t (*fmt_ntoh32)(u_int32_t) = store_swp_ntoh32;
	u_int16_t (*fmt_ntoh16)(u_int16_t) = store_swp_ntoh16;

	if (hostorder) {
		fmt_ntoh64 = store_swp_fake64;
		fmt_ntoh32 = store_swp_fake32;
		fmt_ntoh16 = store_swp_fake16;
	}

	*buf = '\0';

	fields = fmt_ntoh32(flow->hdr.fields) & display_mask;

	snprintf(tmp, sizeof(tmp), "%lu,%lu,%lu,%s,%llu,%llu,%lu,%lu,%u,%u,",
		fmt_ntoh32(flow->ainfo.time_sec),	// unix_secs
		fmt_ntoh32(flow->ainfo.time_nanosec),	// unix_nsecs
		fmt_ntoh32(flow->ainfo.sys_uptime_ms),	// sysuptime
		addr_ntop_buf(&flow->agent_addr),	// exaddr
		fmt_ntoh64(flow->packets.flow_packets),	// dpkts
		fmt_ntoh64(flow->octets.flow_octets),	// doctets
		fmt_ntoh32(flow->ftimes.flow_start),	// first
		fmt_ntoh32(flow->ftimes.flow_finish),	// last
		fmt_ntoh16(flow->finf.engine_type),	// engine_type
		fmt_ntoh16(flow->finf.engine_id)	// engine_id
	);
	strlcat(buf, tmp, len);

	// srcaddr
	snprintf(tmp, sizeof(tmp), "%s,", addr_ntop_buf(&flow->src_addr));
	strlcat(buf, tmp, len);

	// dstaddr
	snprintf(tmp, sizeof(tmp), "%s,", addr_ntop_buf(&flow->dst_addr));
	strlcat(buf, tmp, len);

	// nexthop
	snprintf(tmp, sizeof(tmp), "%s,", addr_ntop_buf(&flow->gateway_addr));
	strlcat(buf, tmp, len);

	// input
	snprintf(tmp, sizeof(tmp), "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u",
		fmt_ntoh32(flow->ifndx.if_index_in),	// input
		fmt_ntoh32(flow->ifndx.if_index_out),	// output
		fmt_ntoh16(flow->ports.src_port),	// srcport
		fmt_ntoh16(flow->ports.dst_port),	// dstport
		flow->pft.protocol,			// prot
		flow->pft.tos,				// tos
		flow->pft.tcp_flags,			// tcp_flags
		flow->asinf.src_mask,			// src_mask
		flow->asinf.dst_mask,			// dst_mask
		fmt_ntoh32(flow->asinf.src_as),		// src_as
		fmt_ntoh32(flow->asinf.dst_as)		// dst_as
	);
	strlcat(buf, tmp, len);
}

void
store_swab_flow(struct store_flow_complete *flow, int to_net)
{
	u_int64_t (*sw64)(u_int64_t) = store_swp_ntoh64;
	u_int32_t (*sw32)(u_int32_t) = store_swp_ntoh32;
	u_int16_t (*sw16)(u_int16_t) = store_swp_ntoh16;

	if (to_net) {
		sw64 = store_swp_hton64;
		sw32 = store_swp_hton32;
		sw16 = store_swp_hton16;
	}

#define FLSWAB(n,w) flow->w = sw##n(flow->w)
	FLSWAB(32, hdr.fields);
	FLSWAB(32, tag.tag);
	FLSWAB(32, recv_time.recv_sec);
	FLSWAB(32, recv_time.recv_usec);
	FLSWAB(16, ports.src_port);
	FLSWAB(16, ports.dst_port);
	FLSWAB(64, packets.flow_packets);
	FLSWAB(64, octets.flow_octets);
	FLSWAB(32, ifndx.if_index_in);
	FLSWAB(32, ifndx.if_index_out);
	FLSWAB(32, ainfo.sys_uptime_ms);
	FLSWAB(32, ainfo.time_sec);
	FLSWAB(32, ainfo.time_nanosec);
	FLSWAB(16, ainfo.netflow_version);
	FLSWAB(32, ftimes.flow_start);
	FLSWAB(32, ftimes.flow_finish);
	FLSWAB(32, asinf.src_as);
	FLSWAB(32, asinf.dst_as);
	FLSWAB(16, finf.engine_type);
	FLSWAB(16, finf.engine_id);
	FLSWAB(32, finf.flow_sequence);
	FLSWAB(16, finf.source_id);
	FLSWAB(32, crc32.crc32);
#undef FLSWAB
}

u_int64_t
store_ntohll(u_int64_t v)
{
#if defined(HAVE_BETOH64)
	v = betoh64(v);
#elif !defined(WORDS_BIGENDIAN)
        v = (v & 0xff) << 56 |
	    (v & 0xff00ULL) << 40 |
	    (v & 0xff0000ULL) << 24 |
	    (v & 0xff000000ULL) << 8 |
	    (v & 0xff00000000ULL) >> 8 |
	    (v & 0xff0000000000ULL) >> 24 |
	    (v & 0xff000000000000ULL) >> 40 |
	    (v & 0xff00000000000000ULL) >> 56;
#endif

	return (v);
}

u_int64_t
store_htonll(u_int64_t v)
{
#if defined(HAVE_BETOH64)
	v = htobe64(v);
#elif !defined(WORDS_BIGENDIAN)
        v = (v & 0xff) << 56 |
	    (v & 0xff00ULL) << 40 |
	    (v & 0xff0000ULL) << 24 |
	    (v & 0xff000000ULL) << 8 |
	    (v & 0xff00000000ULL) >> 8 |
	    (v & 0xff0000000000ULL) >> 24 |
	    (v & 0xff000000000000ULL) >> 40 |
	    (v & 0xff00000000000000ULL) >> 56;
#endif

	return (v);
}
