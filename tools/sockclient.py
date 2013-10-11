#!/usr/bin/env python

# Copyright (c) 2004,2005 Damien Miller <djm@mindrot.org>
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

# $Id: sockclient.py,v 1.1 2005/08/24 12:26:50 djm Exp $

# This is a tiny example client for the flowd.conf "logsock" realtime
# flow relay socket

import socket
import flowd
import os
import sys
import getopt

def usage():
	print >> sys.stderr, "sockclient.pl (flowd.py version %s)" % \
	    flowd.__version__
	print >> sys.stderr, "Usage: reader.pl [options] [flowd-socket]";
	print >> sys.stderr, "Options:";
	print >> sys.stderr, "      -h       Display this help";
	print >> sys.stderr, "      -v       Print all flow information";
	print >> sys.stderr, "      -u       Print dates in UTC timezone";
	sys.exit(1);

def main():
	verbose = 0
	utc = 0

	try:
		opts, args = getopt.getopt(sys.argv[1:], 'huv')
	except getopt.GetoptError:
		print >> sys.stderr, "Invalid commandline arguments"
		usage()

	for o, a in opts:
		if o in ('-h', '--help'):
			usage()
			sys.exit(0)
		if o in ('-v', '--verbose'):
			verbose = 1
			continue
		if o in ('-u', '--utc'):
			utc = 1
			continue

	if len(args) == 0:
		print >> sys.stderr, "No log socket specified"
		usage()
	if len(args) > 1:
		print >> sys.stderr, "Too many log sockets specified"
		usage()

	if verbose:
		mask = flowd.DISPLAY_ALL
	else:
		mask = flowd.DISPLAY_BRIEF

	s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	s.bind(args[0])
	try:
		while 1:
			flowrec = s.recv(1024)
			flow = flowd.Flow(blob = flowrec)
			print flow.format(mask = mask, utc = utc)
	except:
		os.unlink(args[0])
		raise

if __name__ == '__main__': main()
