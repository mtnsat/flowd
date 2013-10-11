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

/* $Id: Flowd.xs,v 1.4 2005/08/21 11:17:02 djm Exp $ */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <sys/types.h>
#include <store.h>

MODULE = Flowd		PACKAGE = Flowd		

int
header_length()
	CODE:
		RETVAL = (sizeof(struct store_flow));
	OUTPUT:
		RETVAL

int flow_length(...)
	PROTOTYPE: $
	INIT:
		char *buf;
		int r;
		STRLEN len;
	CODE:
		if (items != 1)
			croak("Usage: flow_length(buffer)");
		buf = (char *)SvPV(ST(0), len);
		if (len < sizeof(struct store_flow))
			croak("Supplied header is too short");
		r = ((struct store_flow *)buf)->len_words * 4;
		RETVAL = r;
	OUTPUT:
		RETVAL

#define F_STORE(a) hv_store(fhash, a, strlen(a), field, 0)

void deserialise(...)
	PROTOTYPE: $
	INIT:
		int r;
		struct store_flow_complete flow;
		char ebuf[512], addr_buf[128], *buf;
		HV *fhash;
		STRLEN len;
		SV *field, *ret;
		u_int32_t fields;
		u_int64_t tmp;
	PPCODE:
		if (items != 1)
			croak("Usage: desearialise(buffer)");
		buf = (char *)SvPV(ST(0), len);
		r = store_flow_deserialise(buf, len, &flow, ebuf, sizeof(ebuf));
		if (r != STORE_ERR_OK)
			croak(ebuf);

		fields = ntohl(flow.hdr.fields);
		
		fhash = newHV();
		ret = newRV_noinc((SV*)fhash);

		field = newSVuv(fields);
		F_STORE("fields");
		field = newSVuv(flow.hdr.version);
		F_STORE("flow_ver");

		if (fields & STORE_FIELD_TAG) {
			field = newSVuv(ntohl(flow.tag.tag));
			F_STORE("tag");
		}
		if (fields & STORE_FIELD_RECV_TIME) {
			field = newSVuv(ntohl(flow.recv_time.recv_sec));
			F_STORE("recv_sec");
			field = newSVuv(ntohl(flow.recv_time.recv_usec));
			F_STORE("recv_usec");
		}
		if (fields & STORE_FIELD_PROTO_FLAGS_TOS) {
			field = newSViv(flow.pft.tcp_flags);
			F_STORE("tcp_flags");
			field = newSViv(flow.pft.protocol);
			F_STORE("protocol");
			field = newSViv(flow.pft.tos);
			F_STORE("tos");
		}
		if (fields & (STORE_FIELD_AGENT_ADDR4|STORE_FIELD_AGENT_ADDR6)) {
			addr_ntop(&flow.agent_addr, addr_buf, sizeof(addr_buf));
			field = newSVpv(addr_buf, 0);
			F_STORE("agent_addr");
			field = newSViv(flow.agent_addr.af);
			F_STORE("agent_addr_af");
		}
		if (fields & (STORE_FIELD_SRC_ADDR4|STORE_FIELD_SRC_ADDR6)) {
			addr_ntop(&flow.src_addr, addr_buf, sizeof(addr_buf));
			field = newSVpv(addr_buf, 0);
			F_STORE("src_addr");
			field = newSViv(flow.src_addr.af);
			F_STORE("src_addr_af");
		}
		if (fields & (STORE_FIELD_DST_ADDR4|STORE_FIELD_DST_ADDR6)) {
			addr_ntop(&flow.dst_addr, addr_buf, sizeof(addr_buf));
			field = newSVpv(addr_buf, 0);
			F_STORE("dst_addr");
			field = newSViv(flow.dst_addr.af);
			F_STORE("dst_addr_af");
		}
		if (fields & (STORE_FIELD_GATEWAY_ADDR4|STORE_FIELD_GATEWAY_ADDR6)) {
			addr_ntop(&flow.gateway_addr, addr_buf,
			    sizeof(addr_buf));
			field = newSVpv(addr_buf, 0);
			F_STORE("gateway_addr");
			field = newSViv(flow.gateway_addr.af);
			F_STORE("gateway_addr_af");
		}
		if (fields & STORE_FIELD_SRCDST_PORT) {
			field = newSViv(ntohs(flow.ports.src_port));
			F_STORE("src_port");
			field = newSViv(ntohs(flow.ports.dst_port));
			F_STORE("dst_port");
		}
		if (fields & STORE_FIELD_PACKETS) {
			tmp = store_ntohll(flow.packets.flow_packets);
			if (tmp < (1ULL << 32))
				field = newSVuv(tmp);
			else
				field = newSVnv(tmp * 1.0);
			F_STORE("flow_packets");
		}
		if (fields & STORE_FIELD_OCTETS) {
			tmp = store_ntohll(flow.octets.flow_octets);
			if (tmp < (1ULL << 32))
				field = newSVuv(tmp);
			else
				field = newSVnv(tmp * 1.0);
			F_STORE("flow_octets");
		}
		if (fields & STORE_FIELD_IF_INDICES) {
			field = newSVuv(ntohl(flow.ifndx.if_index_in));
			F_STORE("if_index_in");
			field = newSVuv(ntohl(flow.ifndx.if_index_out));
			F_STORE("if_index_out");
		}
		if (fields & STORE_FIELD_AGENT_INFO) {
			field = newSVuv(
			    ntohl(flow.ainfo.sys_uptime_ms));
			F_STORE("sys_uptime_ms");
			field = newSVuv(ntohl(flow.ainfo.time_sec));
			F_STORE("time_sec");
			field = newSVuv(ntohl(flow.ainfo.time_nanosec));
			F_STORE("time_nanosec");
			field = newSViv(ntohs(flow.ainfo.netflow_version));
			F_STORE("netflow_version");
		}
		if (fields & STORE_FIELD_FLOW_TIMES) {
			field = newSVuv(ntohl(flow.ftimes.flow_start));
			F_STORE("flow_start");
			field = newSVuv(ntohl(flow.ftimes.flow_finish));
			F_STORE("flow_finish");
		}
		if (fields & STORE_FIELD_AS_INFO) {
			field = newSVuv(ntohl(flow.asinf.src_as));
			F_STORE("src_as");
			field = newSVuv(ntohl(flow.asinf.dst_as));
			F_STORE("dst_as");
			field = newSViv(flow.asinf.src_mask);
			F_STORE("src_mask");
			field = newSViv(flow.asinf.dst_mask);
			F_STORE("dst_mask");
		}
		if (fields & STORE_FIELD_FLOW_ENGINE_INFO) {
			field = newSViv(ntohs(flow.finf.engine_type));
			F_STORE("engine_type");
			field = newSViv(ntohs(flow.finf.engine_id));
			F_STORE("engine_id");
			field = newSVuv(htonl(flow.finf.flow_sequence));
			F_STORE("flow_sequence");
			field = newSVuv(htonl(flow.finf.source_id));
			F_STORE("source_id");
		}
		if (fields & STORE_FIELD_CRC32) {
			field = newSVuv(ntohl(flow.crc32.crc32));
			F_STORE("crc");
		}

		XPUSHs(sv_2mortal(ret));

