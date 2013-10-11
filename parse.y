/* $Id: parse.y,v 1.36 2007/10/24 01:04:10 djm Exp $ */

/*
 * Copyright (c) 2004,2005 Damien Miller <djm@mindrot.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include "flowd-common.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "flowd.h"
#include "addr.h"

static struct flowd_config	*conf = NULL;

static FILE			*fin = NULL;
static int			 lineno = 1;
static int			 errors = 0;
static int			 pdebug = 1;
const char			*infile;

int	yyerror(const char *, ...);
int	yyparse(void);
int	kw_cmp(const void *, const void *);
int	lookup(char *);
int	lgetc(FILE *);
int	lungetc(int);
int	findeol(void);
int	yylex(void);
int	atoul(char *, u_long *);
int	parse_abstime(const char *s, struct tm *tp);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 symset(const char *, const char *, int);
char	*symget(const char *);

typedef struct {
	union {
		u_int32_t			number;
		char				*string;
		u_int8_t			u8;
		struct xaddr			addr;
		struct {
			struct xaddr		addr;
			unsigned int		len;
		} prefix;
		struct {
			struct xaddr		addr;
			u_int16_t		port;
		} addrport;
		struct filter_action		filter_action;
		struct filter_match		filter_match;
	} v;
	int lineno;
} YYSTYPE;

static const char *days[7] = {
    "sun", "mon", "tue", "wed", "thu", "fri", "sat"
};

static const char *longdays[7] = {
    "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"
};

%}

%token	LISTEN ON JOIN GROUP LOGFILE LOGSOCK BUFSIZE STORE PIDFILE FLOW SOURCE
%token	ALL TAG ACCEPT DISCARD QUICK AGENT SRC DST PORT PROTO TOS ANY
%token	TCP_FLAGS EQUALS MASK INET INET6 DAYS AFTER BEFORE DATE
%token  IN_IFNDX OUT_IFNDX
%token	ERROR
%token	<v.string>		STRING
%type	<v.number>		number quick logspec not octet tcp_flags tcp_mask af dayname dayrange daylist dayspec daytime abstime
%type	<v.string>		string
%type	<v.addr>		address
%type	<v.addrport>		address_port
%type	<v.prefix>		prefix prefix_or_any
%type	<v.filter_match>	match_agent match_src match_dst match_proto match_tos match_tcp_flags match_af match_day match_after match_before match_dayafter match_daybefore match_absafter match_absbefore match_if_in match_if_out
%type	<v.filter_action>	action tag
%%

grammar		: /* empty */
		| grammar '\n'
		| grammar conf_main '\n'
		| grammar varset '\n'
		| grammar filterrule '\n'
		| grammar error '\n'		{ errors++; }
		;

number		: STRING			{
			u_long	ulval;

			if (atoul($1, &ulval) == -1) {
				yyerror("\"%s\" is not a number", $1);
				free($1);
				YYERROR;
			} else
				$$ = ulval;

			free($1);
		}
		;

octet		: number			{
			$$ = $1;
			if ($$ > 0xff) {
				yyerror("octet value exceeds 0xff");
				YYERROR;
			}
		}
		;

string		: string STRING				{
			char buf[2048];
			
			snprintf(buf, sizeof(buf), "%s %s", $1, $2);
			if (($$ = strdup(buf)) == NULL)
				logerrx("string: strdup");
			free($1);
			free($2);
		}
		| STRING
		;

varset		: STRING '=' string		{
			if (conf->opts & FLOWD_OPT_VERBOSE)
				logit(LOG_DEBUG, "%s = \"%s\"", $1, $3);
			if (symset($1, $3, 0) == -1)
				logerrx("cannot store variable");
			free($1);
			free($3);
		}
		;

/*
 * Unfortunately, we can't let yacc do the host:port colon splitting for us, 
 * because it breaks IPv6 addresses
 */
address_port	: STRING		{
			char *colon, *cp;
			unsigned long port;

			cp = $1;

			if ((colon = strrchr(cp, ':')) == NULL) {
				yyerror("missing port specification \"%s\"", $1);
				free($1);
				YYERROR;
			}

			*colon++ = '\0';

			/* Allow [blah]:foo for IPv6 */
			if (*cp == '[' && *(colon - 2) == ']') {
				cp++;
				*(colon - 2) = '\0';
			}

			if (atoul(colon, &port) == -1 || port == 0 || 
			    port > 65535) {
				yyerror("Invalid port number");
				free($1);
				YYERROR;
			}

			if (addr_pton(cp, &$$.addr) == -1) {
				yyerror("could not parse address \"%s\"", cp);
				free($1);
				YYERROR;
			}
			$$.port = port;

			free($1);
		}
		;

address		: STRING		{
			char *cp;
			size_t len;

			cp = $1;
			len = strlen(cp);

			/* Allow [blah]:foo for IPv6 */
			if (cp[0] == '[' && cp[len - 1] == ']') {
				cp++;
				cp[len - 1] = '\0';
			}

			if (addr_pton(cp, &$$) == -1) {
				yyerror("could not parse address \"%s\"", cp);
				free($1);
				YYERROR;
			}

			free($1);
		}
		;

prefix		: STRING '/' number	{
			char *s, *cp, buf[2048];
			int len;

			/* Allow [blah]:foo for IPv6 */
			cp = $1;
			len = strlen(cp);
			if (*cp == '[' && cp[len - 1]  == ']') {
				cp[len - 1] = '\0';
				cp++;
			}

			snprintf(buf, sizeof(buf), "%s/%u", cp, $3);
			if ((s = strdup(buf)) == NULL)
				logerrx("string: strdup");

			free($1);

			if (addr_pton_cidr(s, &$$.addr, &$$.len) == -1) {
				yyerror("could not parse address \"%s\"", s);
				free(s);
				YYERROR;
			}
			if (addr_host_is_all0s(&$$.addr, $$.len) != 0) {
				yyerror("invalid address/masklength \"%s\"", s);
				free(s);
				YYERROR;
			}
			free(s);
		}
		| STRING		{
			char *cp;
			int len;

			/* Allow [blah]:foo for IPv6 */
			cp = $1;
			len = strlen(cp);
			if (*cp == '[' && cp[len - 1]  == ']') {
				cp[len - 1] = '\0';
				cp++;
			}

			if (addr_pton_cidr(cp, &$$.addr, &$$.len) == -1) {
				yyerror("could not parse address \"%s\"", cp);
				free($1);
				YYERROR;
			}
			free($1);
		}
		;

prefix_or_any	: ANY		{ memset(&$$, 0, sizeof($$)); }
		| prefix	{ $$ = $1; }
		;

not		: '!'		{ $$ = 1; }
		| /* empty */	{ $$ = 0; }
		;

dayname		: STRING	{
			int i;

			for (i = 0; i < 7; i++) {
				if (strcasecmp($1, days[i]) == 0 ||
				    strcasecmp($1, longdays[i]) == 0) {
					$$ = i;
					break;
				}
			}
			if (i >= 7) {
				yyerror("invalid day of week \"%s\"", $1);
				free($1);
				YYERROR;
			}
			free($1);
		}
		;

dayrange	: dayname '-' dayname	{
			int i, start, finish;

			start = $1;
			finish = $3;

			if (finish < start)
				finish += 7;

			$$ = 0;
			for (i = start; i <= finish; i++)
				$$ |= (1 << (i % 7));
		}

daylist		: dayname ',' dayname	{ $$ = (1 << $1) | (1 << $3); }
		| daylist ',' dayname	{ $$ = $1 | (1 << $3); }

dayspec		: dayname		{ $$ = (1 << $1); }
		| daylist		{ $$ = $1; }
		| dayrange		{ $$ = $1; }

daytime		: STRING	{
			int h, m, s, n;

			n = sscanf($1, "%d:%d:%d", &h, &m, &s);

			if (n < 2) {
				yyerror("invalid time spec \"%s\"", $1);
				free($1);
				YYERROR;
			}

			if (n < 3)
				s = 0;

			if (h < 0 || h > 23 || 
			    m < 0 || m > 59 || 
			    s < 0 || s > 59) {
				yyerror("invalid time of day \"%s\"", $1);
				free($1);
				YYERROR;
			}
			free($1);
			$$ = s + (m * 60) + (h * 3600);
		}
		;

abstime		: STRING	{
			time_t t;
			struct tm tm;

			$$ = 0;
			if (parse_abstime($1, &tm) != 0 ||
			    (t = mktime(&tm)) < 0) {
				yyerror("invalid time spec \"%s\"", $1);
				free($1);
				YYERROR;
			}
			$$ = t;
			free($1);
		}
		;

conf_main	: LISTEN ON address_port	{
			struct listen_addr	*la;

			if ((la = calloc(1, sizeof(*la))) == NULL)
				logerrx("listen_on: calloc");

			la->fd = -1;
			la->addr = $3.addr;
			la->port = $3.port;
			la->bufsiz = 0;
			TAILQ_INSERT_TAIL(&conf->listen_addrs, la, entry);
		}
		| LISTEN ON address_port BUFSIZE number {
			struct listen_addr	*la;

			if ((la = calloc(1, sizeof(*la))) == NULL)
				logerrx("listen_on: calloc");

			la->fd = -1;
			la->addr = $3.addr;
			la->port = $3.port;
			la->bufsiz = $5;
			TAILQ_INSERT_TAIL(&conf->listen_addrs, la, entry);

		}
		| FLOW SOURCE prefix_or_any	{
			struct allowed_device	*ad;

			if ((ad = calloc(1, sizeof(*ad))) == NULL)
				logerrx("flow_source: calloc");

			memcpy(&ad->addr, &$3.addr, sizeof(ad->addr));
			ad->masklen = $3.len;

			TAILQ_INSERT_TAIL(&conf->allowed_devices, ad, entry);
		}
		| JOIN GROUP address	{
			struct join_group	*jg;

			if ((jg = calloc(1, sizeof(*jg))) == NULL)
				logerrx("join_group: calloc");

			memcpy(&jg->addr, &$3, sizeof(jg->addr));

			TAILQ_INSERT_TAIL(&conf->join_groups, jg, entry);
		}
		| LOGFILE string		{
			conf->log_file = $2;
		}
		| LOGSOCK string		{
			conf->log_socket = $2;
		}
		| LOGSOCK string BUFSIZE number {
			conf->log_socket = $2;
			conf->log_socket_bufsiz = $4;
		}
		| PIDFILE string		{
			conf->pid_file = $2;
		}
		| STORE logspec		{ conf->store_mask |= $2; }
		;

logspec		: STRING	{
			if (strcasecmp($1, "ALL") == 0)
				$$ = STORE_FIELD_ALL;
			else if (strcasecmp($1, "TAG") == 0)
				$$ = STORE_FIELD_TAG;
			else if (strcasecmp($1, "RECV_TIME") == 0)
				$$ = STORE_FIELD_RECV_TIME;
			else if (strcasecmp($1, "PROTO_FLAGS_TOS") == 0)
				$$ = STORE_FIELD_PROTO_FLAGS_TOS;
			else if (strcasecmp($1, "AGENT_ADDR") == 0)
				$$ = STORE_FIELD_AGENT_ADDR;
			else if (strcasecmp($1, "AGENT_ADDR4") == 0)
				$$ = STORE_FIELD_AGENT_ADDR4;
			else if (strcasecmp($1, "AGENT_ADDR6") == 0)
				$$ = STORE_FIELD_AGENT_ADDR6;
			else if (strcasecmp($1, "SRCDST_ADDR") == 0)
				$$ = STORE_FIELD_SRCDST_ADDR;
			else if (strcasecmp($1, "SRC_ADDR") == 0)
				$$ = STORE_FIELD_SRC_ADDR;
			else if (strcasecmp($1, "SRC_ADDR4") == 0)
				$$ = STORE_FIELD_SRC_ADDR4;
			else if (strcasecmp($1, "DST_ADDR") == 0)
				$$ = STORE_FIELD_DST_ADDR;
			else if (strcasecmp($1, "DST_ADDR4") == 0)
				$$ = STORE_FIELD_DST_ADDR4;
			else if (strcasecmp($1, "SRC_ADDR6") == 0)
				$$ = STORE_FIELD_SRC_ADDR6;
			else if (strcasecmp($1, "DST_ADDR6") == 0)
				$$ = STORE_FIELD_DST_ADDR6;
			else if (strcasecmp($1, "GATEWAY_ADDR") == 0)
				$$ = STORE_FIELD_GATEWAY_ADDR;
			else if (strcasecmp($1, "GATEWAY_ADDR4") == 0)
				$$ = STORE_FIELD_GATEWAY_ADDR4;
			else if (strcasecmp($1, "GATEWAY_ADDR6") == 0)
				$$ = STORE_FIELD_GATEWAY_ADDR6;
			else if (strcasecmp($1, "SRCDST_PORT") == 0)
				$$ = STORE_FIELD_SRCDST_PORT;
			else if (strcasecmp($1, "PACKETS") == 0)
				$$ = STORE_FIELD_PACKETS;
			else if (strcasecmp($1, "OCTETS") == 0)
				$$ = STORE_FIELD_OCTETS;
			else if (strcasecmp($1, "IF_INDICES") == 0)
				$$ = STORE_FIELD_IF_INDICES;
			else if (strcasecmp($1, "AGENT_INFO") == 0)
				$$ = STORE_FIELD_AGENT_INFO;
			else if (strcasecmp($1, "FLOW_TIMES") == 0)
				$$ = STORE_FIELD_FLOW_TIMES;
			else if (strcasecmp($1, "AS_INFO") == 0)
				$$ = STORE_FIELD_AS_INFO;
			else if (strcasecmp($1, "FLOW_ENGINE_INFO") == 0)
				$$ = STORE_FIELD_FLOW_ENGINE_INFO;
			else if (strcasecmp($1, "CRC32") == 0)
				$$ = STORE_FIELD_CRC32;
			else {
				yyerror("unknown store field type \"%s\"", $1);
				free($1);
				YYERROR;
			}
			free($1);
		}

filterrule	: action tag quick match_agent match_if_in match_if_out match_af match_src match_dst match_proto match_tos match_tcp_flags match_day match_after match_before
		{
			struct filter_rule	*r;

			if ((r = calloc(1, sizeof(*r))) == NULL)
				logerrx("filterrule: calloc");

			r->action = $1;
			if ($2.action_what == FF_ACTION_TAG) {
				if (r->action.action_what != FF_ACTION_ACCEPT) {
					yyerror("tag not allowed in discard");
					free(r);
					YYERROR;
				}
				r->action = $2;
			}
			r->quick = $3;

			r->match.agent_addr = $4.agent_addr;
			r->match.agent_masklen = $4.agent_masklen;
			r->match.match_what |= $4.match_what;
			r->match.match_negate |= $4.match_negate;

			r->match.ifndx_in = $5.ifndx_in;
			r->match.match_what |= $5.match_what;
			r->match.match_negate |= $5.match_negate;

			r->match.ifndx_out = $6.ifndx_out;
			r->match.match_what |= $6.match_what;
			r->match.match_negate |= $6.match_negate;
			
			r->match.af = $7.af;
			r->match.match_what |= $7.match_what;
			r->match.match_negate |= $7.match_negate;

			r->match.src_addr = $8.src_addr;
			r->match.src_masklen = $8.src_masklen;
			r->match.src_port = $8.src_port;
			r->match.match_what |= $8.match_what;
			r->match.match_negate |= $8.match_negate;

			r->match.dst_addr = $9.dst_addr;
			r->match.dst_masklen = $9.dst_masklen;
			r->match.dst_port = $9.dst_port;
			r->match.match_what |= $9.match_what;
			r->match.match_negate |= $9.match_negate;

			r->match.proto = $10.proto;
			r->match.match_what |= $10.match_what;
			r->match.match_negate |= $10.match_negate;

			r->match.tos = $11.tos;
			r->match.match_what |= $11.match_what;
			r->match.match_negate |= $11.match_negate;

			r->match.tcp_flags_mask = $12.tcp_flags_mask;
			r->match.tcp_flags_equals = $12.tcp_flags_equals;
			r->match.match_what |= $12.match_what;
			r->match.match_negate |= $12.match_negate;

			r->match.day_mask = $13.day_mask;
			r->match.match_what |= $13.match_what;
			r->match.match_negate |= $13.match_negate;

			r->match.dayafter = $14.dayafter - 1;
			r->match.absafter = $14.absafter;
			r->match.match_what |= $14.match_what;
			r->match.match_negate |= $14.match_negate;

			r->match.daybefore = $15.daybefore - 1;
			r->match.absbefore = $15.absbefore;
			r->match.match_what |= $15.match_what;
			r->match.match_negate |= $15.match_negate;

			if ((r->match.match_what & FF_MATCH_DAYTIME) != 0) {
				if (r->match.dayafter != 0 && 
				    r->match.daybefore != 0 &&
				    r->match.dayafter >= r->match.daybefore) {
					yyerror("day start time is after "
					    "day finish time");
					free(r);
					YYERROR;
				}
			}

			if ((r->match.match_what & FF_MATCH_ABSTIME) != 0) {
				if (r->match.absafter != 0 && 
				    r->match.absbefore != 0 &&
				    r->match.absafter >= r->match.absbefore) {
					yyerror("date start time is after "
					    "date finish time");
					free(r);
					YYERROR;
				}
			}

			if ((r->match.match_what & 
			    (FF_MATCH_SRC_PORT|FF_MATCH_DST_PORT)) && 
			    (r->match.proto != IPPROTO_TCP &&
			    r->match.proto != IPPROTO_UDP)) {
				yyerror("port matching is only allowed for "
				    "tcp or udp protocols");
				free(r);
				YYERROR;
			}

			if ((r->match.match_what & FF_MATCH_SRC_ADDR) && 
			    (r->match.match_what & FF_MATCH_DST_ADDR) &&
			    (r->match.src_addr.af != r->match.dst_addr.af)) {
				yyerror("src and dst address families do "
				    "not match");
				free(r);
				YYERROR;
			}

			if ((r->match.match_what & FF_MATCH_AF)) {
				if ((r->match.match_what & FF_MATCH_SRC_ADDR) &&
				     (r->match.af != r->match.src_addr.af)) {
					yyerror("Rule address family does not "
					    "match src address family");
					free(r);
					YYERROR;
				}
				if ((r->match.match_what & FF_MATCH_DST_ADDR) &&
				     (r->match.af != r->match.dst_addr.af)) {
					yyerror("Rule address family does not "
					    "match dst address family");
					free(r);
					YYERROR;
				}
			}
				    
			if ((r->match.match_what & FF_MATCH_TCP_FLAGS) &&
			    (r->match.proto != IPPROTO_TCP)) {
				yyerror("tcp_flags matching is only allowed "
				    "for the tcp protocol");
				free(r);
				YYERROR;
			}

			TAILQ_INSERT_TAIL(&conf->filter_list, r, entry);
		}
		| action tag quick ALL
		{
			struct filter_rule	*r;

			if ((r = calloc(1, sizeof(*r))) == NULL)
				logerrx("filterrule: calloc");

			r->action = $1;
			if ($2.action_what == FF_ACTION_TAG) {
				if (r->action.action_what != FF_ACTION_ACCEPT) {
					yyerror("tag not allowed in discard");
					free(r);
					YYERROR;
				}
				r->action = $2;
			}
			r->quick = $3;

			TAILQ_INSERT_TAIL(&conf->filter_list, r, entry);
		}
		;

action		: ACCEPT	{
			bzero(&$$, sizeof($$));
			$$.action_what = FF_ACTION_ACCEPT;
		}
		| DISCARD	{
			bzero(&$$, sizeof($$));
			$$.action_what = FF_ACTION_DISCARD;
		}

tag		: /* empty */	{ bzero(&$$, sizeof($$)); }
		| TAG number	{
			bzero(&$$, sizeof($$));
			$$.action_what = FF_ACTION_TAG;
			$$.tag = $2;
		}
		;

quick		: /* empty */	{ $$ = 0; }
		| QUICK		{ $$ = 1; }
		;

match_agent	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| AGENT not prefix		{
			bzero(&$$, sizeof($$));
			memcpy(&$$.agent_addr, &$3.addr, sizeof($$.agent_addr));
			$$.agent_masklen = $3.len;
			$$.match_what |= FF_MATCH_AGENT_ADDR;
			$$.match_negate |= $2 ? FF_MATCH_AGENT_ADDR : 0;
		}
		;

af		: INET				{ $$ = AF_INET; }
		| INET6				{ $$ = AF_INET6; }

match_if_in	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| IN_IFNDX not number 		{
			bzero(&$$, sizeof($$));
			$$.ifndx_in = $3;
			$$.match_what |= FF_MATCH_IFNDX_IN;
			$$.match_negate |= $2 ? FF_MATCH_IFNDX_IN : 0;
			if ($$.ifndx_in <= 0 || $$.ifndx_in > 65535) {
				yyerror("invalid input interface index");
				YYERROR;
			}
		}
		;

match_if_out	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| OUT_IFNDX not number 		{
			bzero(&$$, sizeof($$));
			$$.ifndx_out = $3;
			$$.match_what |= FF_MATCH_IFNDX_OUT;
			$$.match_negate |= $2 ? FF_MATCH_IFNDX_OUT : 0;
			if ($$.ifndx_out <= 0 || $$.ifndx_out > 65535) {
				yyerror("invalid output interface index");
				YYERROR;
			}
		}
		;

match_af	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| not af		{
			bzero(&$$, sizeof($$));
			$$.af = $2;
			$$.match_what |= FF_MATCH_AF;
			$$.match_negate |= $1 ? FF_MATCH_AF : 0;
		}
		;

match_src	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| SRC not prefix_or_any			{
			bzero(&$$, sizeof($$));
			memcpy(&$$.src_addr, &$3.addr, sizeof($$.src_addr));
			$$.src_masklen = $3.len;
			$$.match_what |= FF_MATCH_SRC_ADDR;
			$$.match_negate |= $2 ? FF_MATCH_SRC_ADDR : 0;
		}
		| SRC not prefix_or_any PORT not number	{
			bzero(&$$, sizeof($$));
			memcpy(&$$.src_addr, &$3.addr, sizeof($$.src_addr));
			$$.src_masklen = $3.len;
			$$.src_port = $6;
			if ($$.src_port <= 0 || $$.src_port > 65535) {
				yyerror("invalid port number");
				YYERROR;
			}
			if ($$.src_addr.af != 0)
				$$.match_what |= FF_MATCH_SRC_ADDR;
			$$.match_what |= FF_MATCH_SRC_PORT;
			$$.match_negate |= $2 ? FF_MATCH_SRC_ADDR : 0;
			$$.match_negate |= $5 ? FF_MATCH_SRC_PORT : 0;
		}
		;

match_dst	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| DST not prefix_or_any			{
			bzero(&$$, sizeof($$));
			memcpy(&$$.dst_addr, &$3.addr, sizeof($$.dst_addr));
			$$.dst_masklen = $3.len;
			$$.match_what |= FF_MATCH_DST_ADDR;
			$$.match_negate |= $2 ? FF_MATCH_DST_ADDR : 0;
		}
		| DST not prefix_or_any PORT not number	{
			bzero(&$$, sizeof($$));
			memcpy(&$$.dst_addr, &$3.addr, sizeof($$.dst_addr));
			$$.dst_masklen = $3.len;
			$$.dst_port = $6;
			if ($$.dst_port <= 0 || $$.dst_port > 65535) {
				yyerror("invalid port number");
				YYERROR;
			}
			if ($$.dst_addr.af != 0)
				$$.match_what |= FF_MATCH_DST_ADDR;
			$$.match_what |= FF_MATCH_DST_PORT;
			$$.match_negate |= $2 ? FF_MATCH_DST_ADDR : 0;
			$$.match_negate |= $5 ? FF_MATCH_DST_PORT : 0;
		}
		;

match_proto	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| PROTO not string		{
			unsigned long proto;
			struct protoent *pe;

			bzero(&$$, sizeof($$));
			if ((pe = getprotobyname($3)) != NULL)
				proto = pe->p_proto;
			else {
				if (atoul($3, &proto) == -1 || proto == 0 || 
				    proto > 255) {
					yyerror("Invalid protocol");
					free($3);
					YYERROR;
				}
			}
			free($3);
			$$.proto = proto;
			$$.match_what |= FF_MATCH_PROTOCOL;
			$$.match_negate |= $2 ? FF_MATCH_PROTOCOL : 0;
		}
		;

match_tos	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| TOS not octet		{
			bzero(&$$, sizeof($$));
			$$.tos = $3;
			$$.match_what |= FF_MATCH_TOS;
			$$.match_negate |= $2 ? FF_MATCH_TOS : 0;
		}
		;

tcp_flags	: octet 			{ $$ = $1; }
		;

tcp_mask	: /* empty */			{ $$ = 0xff; }
		| MASK tcp_flags 		{ $$ = $2; }
		;

match_tcp_flags	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| TCP_FLAGS tcp_mask not EQUALS tcp_flags	{
			bzero(&$$, sizeof($$));
			if ($2 > 0xff) {
				yyerror("Invalid ToS");
				YYERROR;
			}
			$$.tcp_flags_mask = $2;
			$$.tcp_flags_equals = $5;
			$$.match_what |= FF_MATCH_TCP_FLAGS;
			$$.match_negate |= $3 ? FF_MATCH_TCP_FLAGS : 0;
		}
		;

match_day	: /* empty */	{ bzero(&$$, sizeof($$)); }
		| DAYS dayspec {
			bzero(&$$, sizeof($$));
			$$.day_mask = $2;
			$$.match_what |= FF_MATCH_DAYTIME;
		}
		;

match_dayafter	: AFTER daytime {
			bzero(&$$, sizeof($$));
			$$.dayafter = $2 + 1;
			$$.match_what |= FF_MATCH_DAYTIME;
		}
		;

match_daybefore	: BEFORE daytime {
			bzero(&$$, sizeof($$));
			$$.daybefore = $2 + 1;
			$$.match_what |= FF_MATCH_DAYTIME;
		}
		;

match_absafter	: AFTER DATE abstime {
			bzero(&$$, sizeof($$));
			$$.absafter = $3;
			$$.match_what |= FF_MATCH_ABSTIME;
		}
		;

match_absbefore	: BEFORE DATE abstime {
			bzero(&$$, sizeof($$));
			$$.absbefore = $3;
			$$.match_what |= FF_MATCH_ABSTIME;
		}
		;

match_after	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| match_dayafter		{ $$ = $1; }
		| match_absafter		{ $$ = $1; }

match_before	: /* empty */			{ bzero(&$$, sizeof($$)); }
		| match_daybefore		{ $$ = $1; }
		| match_absbefore		{ $$ = $1; } 

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*nfmt, buf[2048];

	errors = 1;
	va_start(ap, fmt);
	snprintf(buf, sizeof(buf), "%s:%d: %s", infile, yylval.lineno, fmt);
	if ((nfmt = strdup(buf)) == NULL)
		logerrx("yyerror strdup");
	vlogit(LOG_ERR, nfmt, ap);
	va_end(ap);
	free(nfmt);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "accept",		ACCEPT},
		{ "after",		AFTER},
		{ "agent",		AGENT},
		{ "all",		ALL},
		{ "any",		ANY},
		{ "before",		BEFORE},
		{ "bufsize",		BUFSIZE},
		{ "date",		DATE},
		{ "days",		DAYS},
		{ "discard",		DISCARD},
		{ "dst",		DST},
		{ "equals",		EQUALS},
		{ "flow",		FLOW},
		{ "group",		GROUP},
		{ "in_ifndx",		IN_IFNDX},
		{ "inet",		INET},
		{ "inet6",		INET6},
		{ "join",		JOIN},
		{ "listen",		LISTEN},
		{ "logfile",		LOGFILE},
		{ "logsock",		LOGSOCK},
		{ "mask",		MASK},
		{ "on",			ON},
		{ "out_ifndx",		OUT_IFNDX},
		{ "pidfile",		PIDFILE},
		{ "port",		PORT},
		{ "proto",		PROTO},
		{ "quick",		QUICK},
		{ "source",		SOURCE},
		{ "src",		SRC},
		{ "store",		STORE},
		{ "tag",		TAG},
		{ "tcp_flags",		TCP_FLAGS},
		{ "tos",		TOS},
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p) {
		if (pdebug > 1)
			logit(LOG_DEBUG, "%s: %d", s, p->k_val);
		return (p->k_val);
	} else {
		if (pdebug > 1)
			logit(LOG_DEBUG, "string: %s", s);
		return (STRING);
	}
}

#define MAXPUSHBACK	128

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(FILE *f)
{
	int	c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	while ((c = getc(f)) == '\\') {
		next = getc(f);
		if (next != '\n') {
			if (isspace(next))
				yyerror("whitespace after \\");
			ungetc(next, f);
			break;
		}
		yylval.lineno = lineno;
		lineno++;
	}
	if (c == '\t' || c == ' ') {
		/* Compress blanks to a single space. */
		do {
			c = getc(f);
		} while (c == '\t' || c == ' ');
		ungetc(c, f);
		c = ' ';
	}

	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;
	pushback_index = 0;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(fin);
		if (c == '\n') {
			lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 endc, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(fin)) == ' ')
		; /* nothing */

	yylval.lineno = lineno;
	if (c == '#')
		while ((c = lgetc(fin)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(fin)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = (char)c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro \"%s\" not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		endc = c;
		while (1) {
			if ((c = lgetc(fin)) == EOF)
				return (0);
			if (c == endc) {
				*p = '\0';
				break;
			}
			if (c == '\n') {
				lineno++;
				continue;
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			logerrx("yylex: strdup");
		return (STRING);
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ',' && x != '-'))

	if (isalnum(c) || c == '[' || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(fin)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				logerrx("yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = lineno;
		lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
parse_config(const char *path, FILE *f, struct flowd_config *mconf,
    int filter_only)
{
	struct sym		*sym, *next;

	conf = mconf;

	TAILQ_INIT(&conf->listen_addrs);
	TAILQ_INIT(&conf->filter_list);
	TAILQ_INIT(&conf->allowed_devices);
	TAILQ_INIT(&conf->join_groups);

	lineno = 1;
	errors = 0;
	fin = f;
	infile = path;

	yyparse();

	if (!filter_only && conf->log_file == NULL &&
	    conf->log_socket == NULL) {
		logit(LOG_ERR, "No log file or socket specified");
		return (-1);
	}
	if (!filter_only && conf->pid_file == NULL && 
	    (conf->pid_file = strdup(DEFAULT_PIDFILE)) == NULL) {
		logit(LOG_ERR, "strdup pidfile");
		return (-1);
	}

	if (!filter_only && TAILQ_EMPTY(&conf->listen_addrs)) {
		logit(LOG_ERR, "No listening addresses specified");
		return (-1);
	}
	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		if ((conf->opts & FLOWD_OPT_VERBOSE) && !sym->used)
			logit(LOG_WARNING, "warning: macro \"%s\" not used",
			    sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	return (errors ? -1 : 0);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
	    sym = TAILQ_NEXT(sym, entry))
		;	/* nothing */

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		logerrx("cmdline_symset: malloc");

	strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	return (NULL);
}

int
atoul(char *s, u_long *ulvalp)
{
	u_long	 ulval;
	char	*ep;

	errno = 0;
	ulval = strtoul(s, &ep, 0);
	if (s[0] == '\0' || *ep != '\0')
		return (-1);
	if (errno == ERANGE && ulval == ULONG_MAX)
		return (-1);
	*ulvalp = ulval;
	return (0);
}

int
parse_abstime(const char *s, struct tm *tp)
{
	const char *cp;
	
	bzero(tp, sizeof(*tp));
	if ((cp = strptime(s, "%Y%m%d%H%M%S", tp)) != NULL && *cp == '\0')
		goto good;
	if ((cp = strptime(s, "%Y%m%d%H%M", tp)) != NULL && *cp == '\0')
		goto good;
	if ((cp = strptime(s, "%Y%m%d%H", tp)) != NULL && *cp == '\0')
		goto good;
	if ((cp = strptime(s, "%Y%m%d", tp)) != NULL && *cp == '\0')
		goto good;
	if ((cp = strptime(s, "%Y%m", tp)) != NULL && *cp == '\0')
		goto good;
	if ((cp = strptime(s, "%Y", tp)) != NULL && *cp == '\0')
		goto good;

	return -1;

 good:
	tp->tm_isdst = -1;
	return 0;
}

void
dump_config(struct flowd_config *c, const char *prefix, int filter_only)
{
	struct filter_rule *fr;
	struct listen_addr *la;
	struct join_group *jg;
#define DCPR(a) ((a) == NULL ? "" : a), ((a) == NULL ? "" : ": ")
	if (!filter_only) {
		if (c->log_file != NULL) {
			logit(LOG_DEBUG, "%s%slogfile \"%s\"",
			    DCPR(prefix), c->log_file);
		}
		if (c->log_socket != NULL) {
			logit(LOG_DEBUG, "%s%slogsock \"%s\"",
			    DCPR(prefix), c->log_socket);
		}
	}
	logit(LOG_DEBUG, "%s%s# store mask %08x", DCPR(prefix), c->store_mask);
	if (!filter_only) {
		logit(LOG_DEBUG, "%s%s# opts %08x", DCPR(prefix), c->opts);
		TAILQ_FOREACH(la, &c->listen_addrs, entry) {
			logit(LOG_DEBUG, "%s%slisten on [%s]:%d # fd = %d",
			    DCPR(prefix), addr_ntop_buf(&la->addr), la->port, la->fd);
		}
		TAILQ_FOREACH(jg, &c->join_groups, entry) {
			logit(LOG_DEBUG, "%s%sjoin group [%s]",
			    DCPR(prefix), addr_ntop_buf(&jg->addr));
		}
	}
	TAILQ_FOREACH(fr, &c->filter_list, entry)
		logit(LOG_DEBUG, "%s%s%s", DCPR(prefix), format_rule(fr));
#undef DCPR
}

