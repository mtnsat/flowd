# $Id: configure.ac,v 1.27 2008/07/25 00:04:17 djm Exp $
#
# Copyright (c) 2004 Damien Miller
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

AC_INIT
AC_CONFIG_SRCDIR([flowd.c])

PROGVER=0.9.1
AC_SUBST(PROGVER)

AC_CONFIG_HEADER(flowd-config.h)
AC_CANONICAL_HOST
AC_PROG_CC

AC_PROG_INSTALL
AC_PROG_RANLIB
AC_SYS_LARGEFILE
AC_C_BIGENDIAN

if test "x$GCC" = "xyes" ; then
	CFLAGS="${CFLAGS} -fPIC"
fi

# GNU bison doesn't work for us, so try to find a Berkeley yacc
AC_PATH_PROG(YACC, yacc)
AC_PATH_PROG(BYACC, byacc)

# Prefer byacc if it is present
if test "x$BYACC" != "x" ; then
	YACC=$BYACC
	AC_SUBST(YACC)
fi

if test "x$YACC" == "x" ; then
	AC_MSG_ERROR([yacc not found])
fi
if ${YACC} -V 2>&1 | grep -i bison >/dev/null 2>&1 ; then
	AC_MSG_ERROR([missing Berkeley yacc - GNU bison not supported])
fi

# Check for some target-specific stuff
case "$host" in
*-*-linux*)
	AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV], [setproctitle replacement type])
	CFLAGS="$CFLAGS -D_GNU_SOURCE"
	case `uname -r` in
	1.*|2.0.*)
		AC_DEFINE([BROKEN_CMSG_TYPE], [], [cmsg_type is wrong])
		;;
	esac
	;;
*-*-solaris*)
	;;
esac

# Optional verbose warnings for gcc, see below
WFLAGS="-Wall -Waggregate-return -Wcast-align -Wcast-qual"
WFLAGS="$WFLAGS -Wmissing-declarations -Wmissing-prototypes"
WFLAGS="$WFLAGS -Wno-conversion -Wpointer-arith -Wshadow"
WFLAGS="$WFLAGS -Wuninitialized -Wcast-align -Wcast-qual"
WFLAGS="$WFLAGS -Wformat=2 -Wformat-nonliteral -Wwrite-strings" 

# Process flag arguments early, so they are available for tests later
AC_ARG_ENABLE(gcc-warnings,
	[  --enable-gcc-warnings   Enable verbose warnings (only for gcc)],
	[ if test "x$enableval" = "xyes" ; then CFLAGS="$CFLAGS $WFLAGS"; fi ]
)
AC_ARG_WITH(cflags,
	[  --with-cflags           Specify additional compiler flags],
	[ if test "x$withval" != "xno" ; then CFLAGS="$CFLAGS $withval"; fi ]	
)
AC_ARG_WITH(cppflags,
	[  --with-cppflags         Specify additional preprocessor flags] ,
	[ if test "x$withval" != "xno"; then CPPFLAGS="$CPPFLAGS $withval"; fi ]
)
AC_ARG_WITH(ldflags,
	[  --with-ldflags          Specify additional linker flags],
	[ if test "x$withval" != "xno" ; then LDFLAGS="$LDFLAGS $withval"; fi ]	
)
AC_ARG_WITH(libs,
	[  --with-libs             Specify additional libraries to link with],
	[ if test "x$withval" != "xno" ; then LIBS="$LIBS $withval"; fi ]	
)

AC_CHECK_HEADERS(dirent.h sys/ndir.h sys/dir.h ndir.h sys/pstat.h endian.h sys/cdefs.h paths.h strings.h sys/time.h time.h)

AC_CHECK_MEMBER([struct sockaddr.sa_len], 
	[AC_DEFINE([SOCK_HAS_LEN], 1, [struct sockaddr contains length])], ,
	[#include <sys/types.h>
	 #include <sys/socket.h>])

AC_SEARCH_LIBS(daemon, bsd)
AC_SEARCH_LIBS(socket, socket)

AC_CHECK_FUNCS(closefrom betoh64 htobe64 daemon setresuid setreuid setresgid setregid sysconf setproctitle dirfd sendmsg recvmsg tzset strlcpy strlcat)

AC_CHECK_TYPES([u_int64_t, int64_t, uint64_t, u_int32_t, int32_t, uint32_t])
AC_CHECK_TYPES([u_int16_t, int16_t, uint16_t, u_int8_t, int8_t, uint8_t])
AC_CHECK_TYPES([u_int])
AC_CHECK_SIZEOF(char, 1)
AC_CHECK_SIZEOF(unsigned char, 1)
AC_CHECK_SIZEOF(short int, 2)
AC_CHECK_SIZEOF(unsigned short int, 2)
AC_CHECK_SIZEOF(int, 4)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(long int, 4)
AC_CHECK_SIZEOF(unsigned long int, 4)
AC_CHECK_SIZEOF(long long int, 8)
AC_CHECK_SIZEOF(unsigned long long int, 8)

AC_CHECK_SIZEOF(sa_family_t, 1, [
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
])

AC_MSG_CHECKING([for /proc/pid/fd directory])
if test -d "/proc/$$/fd" ; then
	AC_DEFINE([HAVE_PROC_PID], [], [has /proc/PID/fd directory])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

dnl make sure we're using the real structure members and not defines
AC_CACHE_CHECK([for msg_accrights field in struct msghdr],
		ac_cv_have_accrights_in_msghdr, [
	AC_TRY_RUN(
		[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
int main() {
#ifdef msg_accrights
exit(1);
#endif
struct msghdr m;
m.msg_accrights = 0;
exit(0);
}
		],
		[ ac_cv_have_accrights_in_msghdr="yes" ],
		[ ac_cv_have_accrights_in_msghdr="no" ]
	)
])
if test "x$ac_cv_have_accrights_in_msghdr" = "xyes" ; then
	AC_DEFINE([HAVE_ACCRIGHTS_IN_MSGHDR], [], [msghdr.accrights exists])
fi

AC_CACHE_CHECK([for msg_control field in struct msghdr],
		ac_cv_have_control_in_msghdr, [
	AC_TRY_RUN(
		[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
int main() {
#ifdef msg_control
exit(1);
#endif
struct msghdr m;
m.msg_control = 0;
exit(0);
}
		],
		[ ac_cv_have_control_in_msghdr="yes" ],
		[ ac_cv_have_control_in_msghdr="no" ]
	)
])
if test "x$ac_cv_have_control_in_msghdr" = "xyes" ; then
	AC_DEFINE([HAVE_CONTROL_IN_MSGHDR], [], [msghdr.msg_control exists])
fi

AC_CACHE_CHECK([if libc defines __progname], ac_cv_libc_defines___progname, [
	AC_TRY_LINK([],
		[ extern char *__progname; printf("%s", __progname); ],
		[ ac_cv_libc_defines___progname="yes" ],
		[ ac_cv_libc_defines___progname="no" ]
	)
])
if test "x$ac_cv_libc_defines___progname" = "xyes" ; then
	AC_DEFINE([HAVE___PROGNAME], [], [__progname is set in libc])
fi

if test "x$ac_cv_type_uint8_t" = "xyes" ; then
	AC_DEFINE([OUR_CFG_U_INT8_T], [uint8_t], [8-bit unsigned int])
elif test "x$ac_cv_sizeof_char" = "x1" ; then
	AC_DEFINE([OUR_CFG_U_INT8_T], [unsigned char], [8-bit unsigned int])
else
	AC_MSG_ERROR([No 8-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_char" = "x1" ; then
	AC_DEFINE([OUR_CFG_INT8_T], [signed char], [8-bit signed int])
else
	AC_MSG_ERROR([No 8-bit signed int type found])
fi

if test "x$ac_cv_type_uint16_t" = "xyes" ; then
	AC_DEFINE([OUR_CFG_U_INT16_T], [uint16_t], [16-bit unsigned int])
elif test "x$ac_cv_sizeof_short_int" = "x2" ; then
	AC_DEFINE([OUR_CFG_U_INT16_T], [unsigned short int], [16-bit unsigned int])
else
	AC_MSG_ERROR([No 16-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_short_int" = "x2" ; then
	AC_DEFINE([OUR_CFG_INT16_T], [short int], [16-bit signed int])
else
	AC_MSG_ERROR([No 16-bit signed int type found])
fi

if test "x$ac_cv_type_uint32_t" = "xyes" ; then
	AC_DEFINE([OUR_CFG_U_INT32_T], [uint32_t], [32-bit unsigned int])
elif test "x$ac_cv_sizeof_int" = "x4" ; then
	AC_DEFINE([OUR_CFG_U_INT32_T], [unsigned int], [32-bit unsigned int])
else
	AC_MSG_ERROR([No 32-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_int" = "x4" ; then
	AC_DEFINE([OUR_CFG_INT32_T], [int], [32-bit signed int])
else
	AC_MSG_ERROR([No 32-bit signed int type found])
fi

if test "x$ac_cv_type_uint64_t" = "xyes" ; then
	AC_DEFINE([OUR_CFG_U_INT64_T], [uint64_t], [64-bit unsigned int])
elif test "x$ac_cv_sizeof_long_int" = "x8" ; then
	AC_DEFINE([OUR_CFG_U_INT64_T], [unsigned long int], [64-bit unsigned int])
elif test "x$ac_cv_sizeof_long_long_int" = "x8" ; then
	AC_DEFINE([OUR_CFG_U_INT64_T], [unsigned long long int], [64-bit unsigned int])
else
	AC_MSG_ERROR([No 64-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_long_int" = "x8" ; then
	AC_DEFINE([OUR_CFG_INT64_T], [long int], [64-bit signed int])
elif test "x$ac_cv_sizeof_long_long_int" = "x8" ; then
	AC_DEFINE([OUR_CFG_INT64_T], [long long int], [64-bit signed int])
else
	AC_MSG_ERROR([No 64-bit signed int type found])
fi

# Python structmember.h types
if test "x$ac_cv_sizeof_unsigned_char" = "x1" ; then
	FL_T_U8='T_UBYTE'
else
	AC_MSG_ERROR([No 8-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_unsigned_short_int" = "x2" ; then
	FL_T_U16='T_USHORT'
elif test "x$ac_cv_sizeof_unsigned_int" = "x2" ; then
	FL_T_U16='T_UINT'
else
	AC_MSG_ERROR([No 16-bit unsigned int type found])
fi
if test "x$ac_cv_sizeof_unsigned_long_int" = "x4" ; then
	FL_T_U32='T_ULONG'
elif test "x$ac_cv_sizeof_unsigned_int" = "x4" ; then
	FL_T_U32='T_UINT'
else
	AC_MSG_ERROR([No 32-bit int type found])
fi
if test "x$ac_cv_sizeof_unsigned_char" = "x$ac_cv_sizeof_sa_family_t" ; then
	FL_T_AF='T_UBYTE'
elif test "x$ac_cv_sizeof_unsigned_short_int" = "x$ac_cv_sizeof_sa_family_t" ; then
	FL_T_AF='T_USHORT'
elif test "x$ac_cv_sizeof_unsigned_int" = "x$ac_cv_sizeof_sa_family_t" ; then
	FL_T_AF='T_UINT'
else
	AC_MSG_ERROR([No 16-bit unsigned int type found])
fi
AC_SUBST(FL_T_U8)
AC_SUBST(FL_T_U16)
AC_SUBST(FL_T_U32)
AC_SUBST(FL_T_AF)

piddir="${localstatedir}/run"
AC_DEFINE_DIR(PIDPATH, piddir, [Directory to store pidfile in])
AC_DEFINE_DIR(CONFPATH, sysconfdir, [Full path to configuration file])

AC_EXEEXT
AC_CONFIG_FILES([Makefile flowd.8 flowd-reader.8 flowd.conf.5 flowd-pytypes.h])
AC_OUTPUT
