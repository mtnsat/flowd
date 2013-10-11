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
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>

#include "flowd.h"
#include "privsep.h"
#include "atomicio.h"

RCSID("$Id: privsep.c,v 1.33 2008/04/23 02:01:04 djm Exp $");

#ifndef offsetof
# define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

static sig_atomic_t child_exited = 0;
static pid_t child_pid = -1;
static int monitor_to_child_sock = -1;

#define C2M_MSG_OPEN_LOG	1	/* send: nothing   ret: fdpass */
#define C2M_MSG_OPEN_SOCKET	2	/* send: nothing   ret: fdpass */
#define C2M_MSG_RECONFIGURE	3	/* send: nothing   ret: conf+fdpass */

/* Utility functions */
static char *
privsep_read_string(int fd, int nullok)
{
	size_t len;
	char buf[8192], *ret;

	if (atomicio(read, fd, &len, sizeof(len)) != sizeof(len))
		logerrx("%s: read len", __func__);
	if (nullok && len == 0)
		return (NULL);
	if (len <= 0 || len >= sizeof(buf))
		logerrx("%s: silly len: %u", __func__, len);
	if (atomicio(read, fd, buf, len) != len) {
		logitm(LOG_ERR, "%s: read str", __func__);
		return (NULL);
	}
	buf[len] = '\0';
	if ((ret = strdup(buf)) == NULL)
		logit(LOG_ERR, "%s: strdup failed", __func__);

	return (ret);
}

static int
privsep_write_string(int fd, char *s, int nullok)
{
	size_t len;

	if (s == NULL) {
		if (!nullok)
			logerrx("%s: s == NULL", s);
		len = 0;
	} else if ((len = strlen(s)) <= 0) {
		logit(LOG_ERR, "%s: silly len: %u", __func__, len);
		return (-1);
	}
	if (atomicio(vwrite, fd, &len, sizeof(len)) != sizeof(len)) {
		logitm(LOG_ERR, "%s: write len", __func__);
		return (-1);
	}
	if (len > 0 && atomicio(vwrite, fd, s, len) != len) {
		logitm(LOG_ERR, "%s: write(str)", __func__);
		return (-1);
	}

	return (0);
}

static int
write_pid_file(const char *path)
{
	FILE *pid_file;

	if ((pid_file = fopen(path, "w")) == NULL) {
		logitm(LOG_ERR, "fopen(%s)", path);
		return (-1);
	}
	if (fprintf(pid_file, "%ld\n", (long)getpid()) == -1) {
		logitm(LOG_ERR, "fprintf(%s)", path);
		return (-1);
	}
	fclose(pid_file);

	return (0);
}

int
open_listener(struct xaddr *addr, u_int16_t port, size_t bufsiz,
    struct join_groups *groups)
{
	int fd, fl, i, orig;
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	struct join_group *jg;
	struct ip_mreq v4mreq;
	struct ipv6_mreq v6mreq;

	if (addr_xaddr_to_sa(addr, (struct sockaddr *)&ss, &slen, port) == -1) {
		logit(LOG_ERR, "addr_xaddr_to_sa");
		return (-1);
	}

	if ((fd = socket(addr->af, SOCK_DGRAM, 0)) == -1) {
		logitm(LOG_ERR, "socket");
		return (-1);
	}

	/* Set non-blocking */
	if ((fl = fcntl(fd, F_GETFL, 0)) == -1) {
		logitm(LOG_ERR, "fcntl(%d, F_GETFL, 0)", fd);
		return (-1);
	}
	fl |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, fl) == -1) {
		logitm(LOG_ERR, "fcntl(%d, F_SETFL, O_NONBLOCK)", fd);
		return (-1);
	}

#ifdef IPV6_V6ONLY
	/* Set v6-only for AF_INET6 sockets (no mapped address crap) */
	fl = 1;
	if (addr->af == AF_INET6 &&
	    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &fl, sizeof(fl)) == -1) {
		logitm(LOG_ERR, "setsockopt(IPV6_V6ONLY)");
		return (-1);
	}
#endif

	if (bind(fd, (struct sockaddr *)&ss, slen) == -1) {
		logitm(LOG_ERR, "bind");
		return (-1);
	}

	logit(LOG_DEBUG, "Listener for [%s]:%d fd = %d", addr_ntop_buf(addr),
	    port, fd);

	/*
	 * Crank up socket receive buffer size to cope with bursts of flows
	 * If the config doesn't contain an explicit buffer size, we
	 * fall back to guessing.
	 */
	slen = sizeof(fl);
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &orig, &slen) == 0) {
		if (bufsiz > 0) {
			fl = bufsiz;
			if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &fl,
			    sizeof(fl)) == 0) {
				logit(LOG_DEBUG, "Adjusted socket receive "
					"buffer from %d to %d", orig, fl);
			} else
				logerr("%s: setsockopt(SO_RCVBUF)", __func__);
		} else {
		    for (i = 3; i >= 1; i--) {
			fl = (1024 * 64) << i;
			if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &fl,
			    sizeof(fl)) == 0) {
				logit(LOG_DEBUG, "Adjusted socket receive "
				    "buffer from %d to %d", orig, fl);
				break;
			} else if (i == 1)
				logitm(LOG_DEBUG, "setsockopt(SO_RCVBUF)");
		    }
		}
	}

	/* Shrink send buffer, because we never use it */
	fl = 1024;
	logit(LOG_DEBUG, "Setting socket send buf to %d", fl);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &fl, sizeof(fl)) == -1)
		logitm(LOG_DEBUG, "setsockopt(SO_SNDBUF)");

	TAILQ_FOREACH(jg, groups, entry) {
		if (jg->addr.af != addr->af)
			continue;
		logit(LOG_DEBUG, "Multicast join on fd %d to [%s]", fd,
		    addr_ntop_buf(&jg->addr));
		switch (addr->af) {
		case AF_INET:
			bzero(&v4mreq, sizeof(v4mreq));
			v4mreq.imr_multiaddr = jg->addr.v4;
			v4mreq.imr_interface.s_addr = INADDR_ANY;
			if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			    &v4mreq, sizeof(v4mreq)) == -1)
				logitm(LOG_ERR, "setsockopt(IP_ADD_MEMBERSHIP)");
			/* non-fatal for now */
			break;
		case AF_INET6:
			bzero(&v6mreq, sizeof(v6mreq));
			v6mreq.ipv6mr_multiaddr = jg->addr.v6;
			v6mreq.ipv6mr_interface = jg->addr.scope_id;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
			    &v6mreq, sizeof(v6mreq)) == -1)
				logitm(LOG_ERR, "setsockopt(IPV6_JOIN_GROUP)");
			/* non-fatal for now */
			break;
		}
	}

	return (fd);
}

static void
replace_conf(struct flowd_config *conf, struct flowd_config *newconf)
{
	struct listen_addr *la;
	struct filter_rule *fr;
	struct allowed_device *ad;
	struct join_group *jg;

	if (conf->log_file != NULL)
		free(conf->log_file);
	if (conf->log_socket != NULL)
		free(conf->log_socket);
	free(conf->pid_file);
	while ((la = TAILQ_FIRST(&conf->listen_addrs)) != NULL) {
		if (la->fd != -1)
			close(la->fd);
		TAILQ_REMOVE(&conf->listen_addrs, la, entry);
		free(la);
	}
	while ((fr = TAILQ_FIRST(&conf->filter_list)) != NULL) {
		TAILQ_REMOVE(&conf->filter_list, fr, entry);
		free(fr);
	}
	while ((ad = TAILQ_FIRST(&conf->allowed_devices)) != NULL) {
		TAILQ_REMOVE(&conf->allowed_devices, ad, entry);
		free(ad);
	}
	while ((jg = TAILQ_FIRST(&conf->join_groups)) != NULL) {
		TAILQ_REMOVE(&conf->join_groups, jg, entry);
		free(jg);
	}

	memcpy(conf, newconf, sizeof(*conf));
	TAILQ_INIT(&conf->listen_addrs);
	TAILQ_INIT(&conf->filter_list);
	TAILQ_INIT(&conf->allowed_devices);
	TAILQ_INIT(&conf->join_groups);

	while ((la = TAILQ_LAST(&newconf->listen_addrs, listen_addrs)) != NULL) {
		TAILQ_REMOVE(&newconf->listen_addrs, la, entry);
		TAILQ_INSERT_HEAD(&conf->listen_addrs, la, entry);
	}
	while ((fr = TAILQ_LAST(&newconf->filter_list, filter_list)) != NULL) {
		TAILQ_REMOVE(&newconf->filter_list, fr, entry);
		TAILQ_INSERT_HEAD(&conf->filter_list, fr, entry);
	}
	while ((ad = TAILQ_LAST(&newconf->allowed_devices,
	    allowed_devices)) != NULL) {
		TAILQ_REMOVE(&newconf->allowed_devices, ad, entry);
		TAILQ_INSERT_HEAD(&conf->allowed_devices, ad, entry);
	}
	while ((jg = TAILQ_LAST(&newconf->join_groups, join_groups)) != NULL) {
		TAILQ_REMOVE(&newconf->join_groups, jg, entry);
		TAILQ_INSERT_HEAD(&conf->join_groups, jg, entry);
	}

	bzero(newconf, sizeof(*newconf));
}

static int
recv_config(int fd, struct flowd_config *conf)
{
	u_int n, i;
	struct listen_addr *la;
	struct filter_rule *fr;
	struct allowed_device *ad;
	struct join_group *jg;
	struct flowd_config newconf;

	logit(LOG_DEBUG, "%s: entering fd = %d", __func__, fd);

	bzero(&newconf, sizeof(newconf));
	TAILQ_INIT(&newconf.listen_addrs);
	TAILQ_INIT(&newconf.filter_list);
	TAILQ_INIT(&newconf.allowed_devices);
	TAILQ_INIT(&newconf.join_groups);

	logit(LOG_DEBUG, "%s: ready to receive config", __func__);

	newconf.log_file = privsep_read_string(fd, 1);
	newconf.log_socket = privsep_read_string(fd, 1);

	if (atomicio(read, fd, &newconf.log_socket_bufsiz,
	    sizeof(newconf.log_socket_bufsiz)) !=
	    sizeof(newconf.log_socket_bufsiz)) {
		logitm(LOG_ERR, "%s: read(conf.log_socket_bufsiz)", __func__);
		return (-1);
	}

	if ((newconf.pid_file = privsep_read_string(fd, 0)) == NULL) {
		logit(LOG_ERR, "%s: Couldn't read conf.pid_file", __func__);
		return (-1);
	}

	if (atomicio(read, fd, &newconf.store_mask,
	    sizeof(newconf.store_mask)) != sizeof(newconf.store_mask)) {
		logitm(LOG_ERR, "%s: read(conf.store_mask)", __func__);
		return (-1);
	}

	if (atomicio(read, fd, &newconf.opts, sizeof(newconf.opts)) !=
	    sizeof(newconf.opts)) {
		logitm(LOG_ERR, "%s: read(conf.opts)", __func__);
		return (-1);
	}

	/* Read Listen Addrs */
	if (atomicio(read, fd, &n, sizeof(n)) != sizeof(n)) {
		logitm(LOG_ERR, "%s: read(num listen_addrs)", __func__);
		return (-1);
	}
	if (n == 0 || n > 8192) {
		logit(LOG_ERR, "%s: silly number of listen_addrs: %d",
		    __func__, n);
		return (-1);
	}
	for (i = 0; i < n; i++) {
		if ((la = calloc(1, sizeof(*la))) == NULL) {
			logit(LOG_ERR, "%s: calloc", __func__);
			return (-1);
		}
		if (atomicio(read, fd, la, sizeof(*la)) != sizeof(*la)) {
			logitm(LOG_ERR, "%s: read(listen_addr)", __func__);
			return (-1);
		}
		if (la->fd != -1 && (la->fd = receive_fd(fd)) == -1)
			return (-1);
		TAILQ_INSERT_TAIL(&newconf.listen_addrs, la, entry);
	}

	/* Read Filter Rules */
	if (atomicio(read, fd, &n, sizeof(n)) != sizeof(n)) {
		logitm(LOG_ERR, "%s: read(num filter_rules)", __func__);
		return (-1);
	}
	if (n > 1024*1024) {
		logit(LOG_ERR, "%s: silly number of filter_rules: %d",
		    __func__, n);
		return (-1);
	}
	for (i = 0; i < n; i++) {
		if ((fr = calloc(1, sizeof(*fr))) == NULL) {
			logit(LOG_ERR, "%s: calloc", __func__);
			return (-1);
		}
		if (atomicio(read, fd, fr, sizeof(*fr)) != sizeof(*fr)) {
			logitm(LOG_ERR, "%s: read(filter_rule)", __func__);
			return (-1);
		}
		TAILQ_INSERT_TAIL(&newconf.filter_list, fr, entry);
	}

	/* Read Allowed Devices */
	if (atomicio(read, fd, &n, sizeof(n)) != sizeof(n)) {
		logitm(LOG_ERR, "%s: read(num allowed_devices)", __func__);
		return (-1);
	}
	if (n > 1024*1024) {
		logit(LOG_ERR, "%s: silly number of allowed_devices: %d",
		    __func__, n);
		return (-1);
	}
	for (i = 0; i < n; i++) {
		if ((ad = calloc(1, sizeof(*ad))) == NULL) {
			logit(LOG_ERR, "%s: calloc", __func__);
			return (-1);
		}
		if (atomicio(read, fd, ad, sizeof(*ad)) != sizeof(*ad)) {
			logitm(LOG_ERR, "%s: read(allowed_device)", __func__);
			return (-1);
		}
		TAILQ_INSERT_TAIL(&newconf.allowed_devices, ad, entry);
	}

	/* Read multicast join groups */
	if (atomicio(read, fd, &n, sizeof(n)) != sizeof(n)) {
		logitm(LOG_ERR, "%s: read(num join_groups)", __func__);
		return (-1);
	}
	if (n > 1024*1024) {
		logit(LOG_ERR, "%s: silly number of join_groups: %d",
		    __func__, n);
		return (-1);
	}
	for (i = 0; i < n; i++) {
		if ((jg = calloc(1, sizeof(*jg))) == NULL) {
			logit(LOG_ERR, "%s: calloc", __func__);
			return (-1);
		}
		if (atomicio(read, fd, jg, sizeof(*jg)) != sizeof(*jg)) {
			logitm(LOG_ERR, "%s: read(join_group)", __func__);
			return (-1);
		}
		TAILQ_INSERT_TAIL(&newconf.join_groups, jg, entry);
	}

	replace_conf(conf, &newconf);

	return (0);
}

static int
send_config(int fd, struct flowd_config *conf)
{
	u_int n;
	struct listen_addr *la;
	struct filter_rule *fr;
	struct allowed_device *ad;
	struct join_group *jg;

	logit(LOG_DEBUG, "%s: entering fd = %d", __func__, fd);

	if (privsep_write_string(fd, conf->log_file, 1) == -1) {
		logit(LOG_ERR, "%s: Couldn't write conf.log_file", __func__);
		return (-1);
	}
	if (privsep_write_string(fd, conf->log_socket, 1) == -1) {
		logit(LOG_ERR, "%s: Couldn't write conf.log_socket", __func__);
		return (-1);
	}
	if (atomicio(vwrite, fd, &conf->log_socket_bufsiz,
	    sizeof(conf->log_socket_bufsiz)) !=
	    sizeof(conf->log_socket_bufsiz)) {
		logitm(LOG_ERR, "%s: write(conf.log_socket_bufsiz)", __func__);
		return (-1);
	}

	if (privsep_write_string(fd, conf->pid_file, 0) == -1) {
		logit(LOG_ERR, "%s: Couldn't write conf.pid_file", __func__);
		return (-1);
	}

	if (atomicio(vwrite, fd, &conf->store_mask,
	    sizeof(conf->store_mask)) != sizeof(conf->store_mask)) {
		logitm(LOG_ERR, "%s: write(conf.store_mask)", __func__);
		return (-1);
	}

	if (atomicio(vwrite, fd, &conf->opts,
	    sizeof(conf->opts)) != sizeof(conf->opts)) {
		logitm(LOG_ERR, "%s: write(conf.opts)", __func__);
		return (-1);
	}

	/* Write Listen Addrs */
	n = 0;
	TAILQ_FOREACH(la, &conf->listen_addrs, entry)
		n++;
	if (atomicio(vwrite, fd, &n, sizeof(n)) != sizeof(n)) {
		logitm(LOG_ERR, "%s: write(num listen_addrs)", __func__);
		return (-1);
	}
	TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
		if (atomicio(vwrite, fd, la, sizeof(*la)) != sizeof(*la)) {
			logitm(LOG_ERR, "%s: write(listen_addr)", __func__);
			return (-1);
		}
		if (la->fd != -1 && send_fd(fd, la->fd) == -1)
			return (-1);
	}

	/* Write Filter Rules */
	n = 0;
	TAILQ_FOREACH(fr, &conf->filter_list, entry)
		n++;
	if (atomicio(vwrite, fd, &n, sizeof(n)) != sizeof(n)) {
		logitm(LOG_ERR, "%s: write(num filter_rules)", __func__);
		return (-1);
	}
	TAILQ_FOREACH(fr, &conf->filter_list, entry) {
		if (atomicio(vwrite, fd, fr, sizeof(*fr)) != sizeof(*fr)) {
			logitm(LOG_ERR, "%s: write(filter_rule)", __func__);
			return (-1);
		}
	}

	/* Write Allowed Devices */
	n = 0;
	TAILQ_FOREACH(ad, &conf->allowed_devices, entry)
		n++;
	if (atomicio(vwrite, fd, &n, sizeof(n)) != sizeof(n)) {
		logitm(LOG_ERR, "%s: write(num allowed_devices)", __func__);
		return (-1);
	}
	TAILQ_FOREACH(ad, &conf->allowed_devices, entry) {
		if (atomicio(vwrite, fd, ad, sizeof(*ad)) != sizeof(*ad)) {
			logitm(LOG_ERR, "%s: write(allowed_devices)", __func__);
			return (-1);
		}
	}

	/* Write Multicast join groups */
	n = 0;
	TAILQ_FOREACH(jg, &conf->join_groups, entry)
		n++;
	if (atomicio(vwrite, fd, &n, sizeof(n)) != sizeof(n)) {
		logitm(LOG_ERR, "%s: write(num join_group)", __func__);
		return (-1);
	}
	TAILQ_FOREACH(jg, &conf->join_groups, entry) {
		if (atomicio(vwrite, fd, jg, sizeof(*jg)) != sizeof(*jg)) {
			logitm(LOG_ERR, "%s: write(join_group)", __func__);
			return (-1);
		}
	}

	logit(LOG_DEBUG, "%s: done", __func__);

	return (0);
}

static int
drop_privs(struct passwd *pw, int do_chroot)
{
	logit(LOG_DEBUG, "drop_privs: dropping privs %s chroot",
	    do_chroot ? "with" : "without");

	if (setsid() == -1) {
		logitm(LOG_ERR, "setsid");
		return (-1);
	}
	if (do_chroot) {
		if (chdir(pw->pw_dir) == -1) {
			logitm(LOG_ERR, "chdir(%s)", pw->pw_dir);
			return (-1);
		}
		if (chroot(pw->pw_dir) == -1) {
			logitm(LOG_ERR, "chroot(%s)", pw->pw_dir);
			return (-1);
		}
	}
	if (chdir("/") == -1) {
		logitm(LOG_ERR, "chdir(/)");
		return (-1);
	}
	if (setgroups(1, &pw->pw_gid) == -1) {
		logitm(LOG_ERR, "setgroups");
		return (-1);
	}
#if defined(HAVE_SETRESGID)
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
		logitm(LOG_ERR, "setresgid");
		return (-1);
	}
#elif defined(HAVE_SETREGID)
	if (setregid(pw->pw_gid, pw->pw_gid) == -1) {
		logitm(LOG_ERR, "setregid");
		return (-1);
	}
#else
# error No suitable setgid function found
#endif
#if defined(HAVE_SETRESUID)
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
		logitm(LOG_ERR, "setresuid");
		return (-1);
	}
#elif defined(HAVE_SETREUID)
	if (setreuid(pw->pw_uid, pw->pw_uid) == -1) {
		logitm(LOG_ERR, "setreuid");
		return (-1);
	}
#else
# error No suitable setuid function found
#endif
	return (0);
}

static int
child_get_config(const char *path, struct flowd_config *conf)
{
	int s[2], ok, status;
	pid_t ccpid;
	void (*oldsigchld)(int);
	FILE *cfg;
	struct passwd *pw = NULL;
	struct flowd_config newconf = {
		NULL, NULL, 0, NULL, 0, 0,
		TAILQ_HEAD_INITIALIZER(newconf.listen_addrs),
		TAILQ_HEAD_INITIALIZER(newconf.filter_list),
		TAILQ_HEAD_INITIALIZER(newconf.allowed_devices),
		TAILQ_HEAD_INITIALIZER(newconf.join_groups)
	};

	logit(LOG_DEBUG, "%s: entering", __func__);

	if ((conf->opts & FLOWD_OPT_INSECURE) == 0 &&
	    (pw = getpwnam(PRIVSEP_USER)) == NULL) {
		logit(LOG_ERR, "Privilege separation user %s doesn't exist",
		    PRIVSEP_USER);
		return(-1);
	}
	endpwent();

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, s) == -1) {
		logitm(LOG_ERR, "%s: socketpair", __func__);
		return (-1);
	}

	oldsigchld = signal(SIGCHLD, SIG_DFL);
	switch (ccpid = fork()) {
	case -1:
		logitm(LOG_ERR, "%s: fork", __func__);
		return (-1);
	case 0: /* Child */
		close(s[0]);
		setproctitle("config");

		if ((cfg = fopen(path, "r")) == NULL) {
			logitm(LOG_ERR, "fopen(%s)", path);
			exit(1);
		}

		if ((conf->opts & FLOWD_OPT_INSECURE) == 0 &&
		    drop_privs(pw, 0) == -1)
			exit(1);

		ok = (parse_config(path, cfg, &newconf, 0) == 0);
		fclose(cfg);
		if (atomicio(vwrite, s[1], &ok, sizeof(ok)) != sizeof(ok)) {
			logitm(LOG_ERR, "%s: write(ok)", __func__);
			exit(1);
		}
		if (!ok)
			exit(1);
		if (send_config(s[1], &newconf) == -1)
			exit(1);
		logit(LOG_DEBUG, "%s: child config done", __func__);

		exit(0);
	default: /* Parent */
		close(s[1]);
		break;
	}

	/* Parent */
	if (atomicio(read, s[0], &ok, sizeof(ok)) != sizeof(ok)) {
		logitm(LOG_ERR, "%s: read(ok)", __func__);
		return (-1);
	}
	if (!ok)
		return (-1);
	if (recv_config(s[0], conf) == -1)
		return (-1);
	close(s[0]);

	if (waitpid(ccpid, &status, 0) == -1) {
		logitm(LOG_ERR, "%s: waitpid", __func__);
		return (-1);
	}
	if (!WIFEXITED(status)) {
		logit(LOG_ERR, "child exited abnormally");
		return (-1);
	}
	if (WEXITSTATUS(status) != 0) {
		logit(LOG_ERR, "child exited with status %d",
		    WEXITSTATUS(status));
		return (-1);
	}

	signal(SIGCHLD, oldsigchld);

	return (0);
}

int
read_config(const char *path, struct flowd_config *conf)
{
	u_int32_t opts;

	logit(LOG_DEBUG, "%s: entering", __func__);

	/* Preserve options not set in config file */
	opts = conf->opts &
	    (FLOWD_OPT_DONT_FORK|FLOWD_OPT_VERBOSE|FLOWD_OPT_INSECURE);

	if (child_get_config(path, conf))
		return (-1);

	conf->opts |= opts;

	return (0);
}

/* Client functions */
int
client_open_log(int monitor_fd)
{
	int fd = -1;
	u_int msg = C2M_MSG_OPEN_LOG;

	logit(LOG_DEBUG, "%s: entering", __func__);

	if (atomicio(vwrite, monitor_fd, &msg, sizeof(msg)) != sizeof(msg)) {
		logitm(LOG_ERR, "%s: write", __func__);
		return (-1);
	}
	if ((fd = receive_fd(monitor_fd)) == -1)
		return (-1);

	return (fd);
}

int
client_open_socket(int monitor_fd)
{
	int fd = -1;
	u_int msg = C2M_MSG_OPEN_SOCKET;

	logit(LOG_DEBUG, "%s: entering", __func__);

	if (atomicio(vwrite, monitor_fd, &msg, sizeof(msg)) != sizeof(msg)) {
		logitm(LOG_ERR, "%s: write", __func__);
		return (-1);
	}
	if ((fd = receive_fd(monitor_fd)) == -1)
		return (-1);

	return (fd);
}

int
client_reconfigure(int monitor_fd, struct flowd_config *conf)
{
	u_int msg = C2M_MSG_RECONFIGURE, ok;
	struct listen_addr *la;

	logit(LOG_DEBUG, "%s: entering", __func__);

	TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
		if (la->fd != -1)
			close(la->fd);
		la->fd = -1;
	}

	if (atomicio(vwrite, monitor_fd, &msg, sizeof(msg)) != sizeof(msg)) {
		logitm(LOG_ERR, "%s: write", __func__);
		return (-1);
	}

	if (atomicio(read, monitor_fd, &ok, sizeof(ok)) != sizeof(ok)) {
		logitm(LOG_ERR, "%s: read(ok)", __func__);
		return (-1);
	}
	if (!ok) {
		logit(LOG_ERR, "New config is invalid");
		return (-1);
	}

	if (recv_config(monitor_fd, conf) == -1)
		return (-1);

	logit(LOG_DEBUG, "%s: done", __func__);

	return (0);
}

/* Client answer functions */
static int
answer_open_log(struct flowd_config *conf, int client_fd)
{
	int fd;

	logit(LOG_DEBUG, "%s: entering", __func__);

	if (conf->log_file == NULL)
		logerrx("%s: attempt to open NULL log", __func__);

	fd = open(conf->log_file, O_RDWR|O_APPEND|O_CREAT, 0600);
	if (fd == -1) {
		logitm(LOG_ERR, "%s: open", __func__);
		return (-1);
	}
	if (send_fd(client_fd, fd) == -1)
		return (-1);
	close(fd);
	return (0);
}

static int
answer_open_socket(struct flowd_config *conf, int client_fd)
{
	int fd, slen, orig;
	struct sockaddr_un to;
	socklen_t tolen;

	logit(LOG_DEBUG, "%s: entering", __func__);

	if (conf->log_socket == NULL)
		logerrx("%s: attempt to open NULL log", __func__);

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
		logitm(LOG_ERR, "%s: socket", __func__);
		return (-1);
	}

	bzero(&to, sizeof(to));
	if (strlcpy(to.sun_path, conf->log_socket,
	    sizeof(to.sun_path)) >= sizeof(to.sun_path))
		logerrx("Log socket path too long");
	to.sun_family = AF_UNIX;
	tolen = offsetof(struct sockaddr_un, sun_path) +
	    strlen(conf->log_socket) + 1;
#ifdef SOCK_HAS_LEN 
	to.sun_len = tolen;
#endif

	if (connect(fd, (struct sockaddr *)&to, tolen) == -1) {
		logitm(LOG_ERR, "connect to logsock");
		return (-1);
	}

	slen = sizeof(orig);
	if (conf->log_socket_bufsiz > 0 &&
	    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &orig, &slen) == 0) {
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, 
		    &conf->log_socket_bufsiz,
		    sizeof(conf->log_socket_bufsiz)) == 0) {
			logit(LOG_DEBUG, "Adjusted log_socket send "
			    "buffer from %d to %d", orig,
			    conf->log_socket_bufsiz);
		} else
			logerr("%s: setsockopt(SO_SNDBUF)", __func__);
	}

	if (send_fd(client_fd, fd) == -1)
		return (-1);

	close(fd);
	return (0);
}

static int
answer_reconfigure(struct flowd_config *conf, int client_fd,
    const char *config_path)
{
	u_int ok, rewrite_pidfile;
	struct flowd_config newconf;
	struct listen_addr *la;

	bzero(&newconf, sizeof(newconf));
	TAILQ_INIT(&newconf.listen_addrs);
	TAILQ_INIT(&newconf.filter_list);
	TAILQ_INIT(&newconf.allowed_devices);
	TAILQ_INIT(&newconf.join_groups);

	/* Transcribe flags not set in config file */
	newconf.opts |= (conf->opts &
	    (FLOWD_OPT_DONT_FORK|FLOWD_OPT_VERBOSE|FLOWD_OPT_INSECURE));

	logit(LOG_DEBUG, "%s: entering", __func__);

	ok = 1;
	if (read_config(config_path, &newconf) == -1) {
		logit(LOG_ERR, "New config has errors");
		ok = 0;
	}

	TAILQ_FOREACH(la, &newconf.listen_addrs, entry) {
		if ((la->fd = open_listener(&la->addr, la->port, la->bufsiz,
		    &conf->join_groups)) == -1) {
			logit(LOG_ERR, "Listener setup of [%s]:%d failed",
			    addr_ntop_buf(&la->addr), la->port);
			ok = 0;
			break;
		}
	}

	logit(LOG_DEBUG, "%s: post listener open, ok = %d", __func__, ok);
	if (atomicio(vwrite, client_fd, &ok, sizeof(ok)) != sizeof(ok)) {
		logitm(LOG_ERR, "%s: write(ok)", __func__);
		return (-1);
	}
	if (ok == 0)
		return (-1);

	if (send_config(client_fd, &newconf) == -1)
		return (-1);

	TAILQ_FOREACH(la, &newconf.listen_addrs, entry) {
		close(la->fd);
		la->fd = -1;
	}

	/* Cleanup old config and move new one into place */
	rewrite_pidfile = (strcmp(conf->pid_file, newconf.pid_file) != 0);

	replace_conf(conf, &newconf);

	if (rewrite_pidfile && write_pid_file(conf->pid_file) == -1)
		return (-1);

	logit(LOG_DEBUG, "%s: done", __func__);

	return (0);
}

/* Signal handlers */
static void
sighand_exit(int signo)
{
	if (monitor_to_child_sock != -1)
		shutdown(monitor_to_child_sock, SHUT_RDWR);
	if (!child_exited && child_pid > 1)
		kill(child_pid, signo);
}

static void
sighand_child(int signo)
{
	child_exited = 1;
}

static void
sighand_relay(int signo)
{
	if (!child_exited && child_pid > 1)
		if (kill(child_pid, signo) != 0)
			_exit(1);
	signal(signo, sighand_relay);
}

static void
privsep_master(struct flowd_config *conf, const char *config_path)
{
	int status, r;
	u_int what;

	for (;!child_exited;) {
		r = atomicio(read, monitor_to_child_sock, &what, sizeof(what));
		if (r == 0) {
			logit(LOG_DEBUG, "%s: child exited", __func__);
			break;
		}
		if (r != sizeof(what)) {
			logitm(LOG_ERR, "%s: read", __func__);
			unlink(conf->pid_file);
			exit(1);
		}

		switch (what) {
		case C2M_MSG_OPEN_LOG:
			if (answer_open_log(conf, monitor_to_child_sock)) {
				unlink(conf->pid_file);
				exit(1);
			}
			break;
		case C2M_MSG_OPEN_SOCKET:
			if (answer_open_socket(conf, monitor_to_child_sock)) {
				unlink(conf->pid_file);
				exit(1);
			}
			break;
		case C2M_MSG_RECONFIGURE:
			if (answer_reconfigure(conf, monitor_to_child_sock,
			    config_path)) {
				unlink(conf->pid_file);
				exit(1);
			}
			break;
		default:
			logit(LOG_ERR, "Unknown message %d", what);
			break;
		}
	}

	r = 0;
	if (child_exited) {
		if (waitpid(child_pid, &status, 0) == -1) {
			logitm(LOG_ERR, "%s: waitpid", __func__);
			r = 1;
		} else if (!WIFEXITED(status)) {
			logit(LOG_ERR, "child exited abnormally");
			r = 1;
		} else if (WEXITSTATUS(status) != 0) {
			logit(LOG_ERR, "child exited with status %d",
			    WEXITSTATUS(status));
			r = 1;
		}
	}

	unlink(conf->pid_file);
	exit(r);
}

void
privsep_init(struct flowd_config *conf, int *child_to_monitor_sock,
    const char *config_path)
{
	int s[2], devnull;
	struct passwd *pw = NULL;
	struct listen_addr *la;

	logit(LOG_DEBUG, "%s: entering", __func__);

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, s) == -1)
		logerr("socketpair");

	monitor_to_child_sock = s[0];
	*child_to_monitor_sock = s[1];

	if ((conf->opts & FLOWD_OPT_INSECURE) == 0 &&
	    (pw = getpwnam(PRIVSEP_USER)) == NULL) {
		logerrx("Privilege separation user %s doesn't exist",
		    PRIVSEP_USER);
	}
	endpwent();

	if ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		logerr("open(/dev/null)");

	if ((conf->opts & FLOWD_OPT_DONT_FORK) == 0 && daemon(0, 1) == -1)
		logerr("daemon");

	if (dup2(devnull, STDIN_FILENO) == -1 ||
	    dup2(devnull, STDOUT_FILENO) == -1)
		logerr("dup2");

	switch (child_pid = fork()) {
	case -1:
		logerr("fork");
	case 0: /* Child */
		loginit(PROGNAME, (conf->opts & FLOWD_OPT_VERBOSE),
		    (conf->opts & FLOWD_OPT_DONT_FORK));
		close(monitor_to_child_sock);

		if ((conf->opts & FLOWD_OPT_INSECURE) == 0 &&
		    drop_privs(pw, 1) == -1)
			exit(1);

		if ((conf->opts & FLOWD_OPT_DONT_FORK) == 0 &&
		    dup2(devnull, STDERR_FILENO) == -1)
			logerr("dup2");
		close(devnull);
		setproctitle("net");
		return;
	default: /* Parent */
		loginit(PROGNAME, (conf->opts & FLOWD_OPT_VERBOSE),
		    (conf->opts & FLOWD_OPT_DONT_FORK));
		if ((conf->opts & FLOWD_OPT_DONT_FORK) == 0 &&
		    dup2(devnull, STDERR_FILENO) == -1)
			logerr("dup2");
		close(devnull);
		close(*child_to_monitor_sock);
		TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
			if (la->fd != -1)
				close(la->fd);
			la->fd = -1;
		}
		setproctitle("monitor");
		if (write_pid_file(conf->pid_file) == -1)
			exit(1);

		signal(SIGINT, sighand_exit);
		signal(SIGTERM, sighand_exit);
		signal(SIGCHLD, sighand_child);
		signal(SIGHUP, sighand_relay);
#ifdef SIGINFO
		signal(SIGINFO, sighand_relay);
#endif
		signal(SIGUSR1, sighand_relay);
		signal(SIGUSR2, sighand_relay);

		privsep_master(conf, config_path);
	}
	/* NOTREACHED */
}

