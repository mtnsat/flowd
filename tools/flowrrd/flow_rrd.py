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

# $Id: flow_rrd.py,v 1.1.1.1 2006/03/04 04:31:37 djm Exp $

# This is a small program to populate a RRD database with summaries of
# NetFlow data recorded by flowd. It is a pretty basic example; only
# creating per-protocol (TCP, UDP, ICMP, etc.) summaries but it can be 
# easily modified to suit any summarisation system by changing the 
# FlowTrack class below

# Please note that this requires the py-rrdtool module

# How often (seconds) we update the RRD
UPDATE_RATE = 300

import socket
import time
import select
import flowd
import os
import sys
import getopt
import rrdtool

def usage():
	print >> sys.stderr, "flow_rrd.pl (flowd.py version %s)" % \
	    flowd.__version__
	print >> sys.stderr, "Usage: flow_rrd.pl [options] [flowd-log] " + \
	    "[rrd-database]";
	print >> sys.stderr, "Options:";
	print >> sys.stderr, "      -h       Display this help";
	print >> sys.stderr, "      -s       Read from a flowd log socket " + \
	    "instead of a log file"
	sys.exit(1);

def create_rrd(filename, when = None):
	args = [ filename ]
	if when is not None:
		args.append("-b%s" % when)
	args += [ "-s300",
		"DS:icmp_flows:ABSOLUTE:600:0:U",
		"DS:tcp_flows:ABSOLUTE:600:0:U",
		"DS:udp_flows:ABSOLUTE:600:0:U",
		"DS:gre_flows:ABSOLUTE:600:0:U",
		"DS:esp_flows:ABSOLUTE:600:0:U",
		"DS:other_flows:ABSOLUTE:600:0:U",
		"DS:icmp_bytes:ABSOLUTE:600:0:U",
		"DS:tcp_bytes:ABSOLUTE:600:0:U",
		"DS:udp_bytes:ABSOLUTE:600:0:U",
		"DS:gre_bytes:ABSOLUTE:600:0:U",
		"DS:esp_bytes:ABSOLUTE:600:0:U",
		"DS:other_bytes:ABSOLUTE:600:0:U",
		"DS:icmp_packets:ABSOLUTE:600:0:U",
		"DS:tcp_packets:ABSOLUTE:600:0:U",
		"DS:udp_packets:ABSOLUTE:600:0:U",
		"DS:gre_packets:ABSOLUTE:600:0:U",
		"DS:esp_packets:ABSOLUTE:600:0:U",
		"DS:other_packets:ABSOLUTE:600:0:U",
		"RRA:AVERAGE:0.75:1:4800",
		"RRA:AVERAGE:0.5:6:2400",
		"RRA:AVERAGE:0.5:24:1200",
		"RRA:AVERAGE:0.5:288:1500",
	]
	print >> sys.stderr, "Creating %s" % filename
	rrdtool.create(*args)

class FlowTrack:
	_PROTOS = {
		 1 : "icmp", 6 : "tcp", 17 : "udp", 47 : "gre", 50 : "esp",
		-1 : "other"
	}
	_FIELDS = [ "flows", "bytes", "packets" ]
	def __init__(self):
		for field in self._FIELDS:
			self.__dict__[field] = dict([(x, 0)
			    for x in self._PROTOS.keys()])
	def update(self, flow):
		proto = -1
		bytes = 0
		packets = 0
		if flow.has_field(flowd.FIELD_PROTO_FLAGS_TOS):
			proto = flow.protocol
			if not self.flows.has_key(proto):
				proto = -1
		if flow.has_field(flowd.FIELD_OCTETS):
			bytes = flow.octets
		if flow.has_field(flowd.FIELD_PACKETS):
			packets = flow.packets
		self.flows[proto] += 1
		self.bytes[proto] += bytes
		self.packets[proto] += packets
	def store_in_rrd(self, filename, when = None):
		print when
		if when is None:
			when = "N"
		all = [(x, y) for x in self._FIELDS for y in self.flows.keys()]
		template = ""
		data = "%s" % when
		for field, proto in all:
			ds = "%s_%s" % (self._PROTOS[proto], field)
			template += ":" + ds
			data += ":%u" % self.__dict__[field][proto]
		# Fix up start of template
		template = "-t" + template[1:]
		rrdtool.update(filename, template, data)

def quantise(when):
	return (when // UPDATE_RATE) * UPDATE_RATE

def process_from_socket(sockpath, rrdpath):
	if not os.access(rrdpath, os.R_OK|os.W_OK):
		create_rrd(rrdpath)
	s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	s.bind(sockpath)
	start_time = quantise(time.time())
	flows = FlowTrack()
	try:
		while 1:
			elapsed = time.time() - start_time
			if elapsed > 0:
				select.select([s], [], [],
				    UPDATE_RATE - elapsed)
			elapsed = time.time() - start_time
			if elapsed > UPDATE_RATE:
				flows.store_in_rrd(rrdpath)
				flows = FlowTrack()
				start_time = time.time()
				continue
			flowrec = s.recv(2048)
			flow = flowd.Flow(blob = flowrec)
			flows.update(flow)
	except:
		os.unlink(sockpath)
		raise

def process_from_file(logpath, rrdpath):
	flowlog = flowd.FlowLog(logpath)
	start_time = None
	flows = FlowTrack()
	for flow in flowlog:
		if not flow.has_field(flowd.FIELD_RECV_TIME):
			continue
		if start_time is None or \
		   (flow.recv_sec - start_time) > UPDATE_RATE:
			if start_time is not None:
				flows.store_in_rrd(rrdpath, start_time)
			elif not os.access(rrdpath, os.R_OK|os.W_OK):
				create_rrd(rrdpath,
				    quantise(flow.recv_sec) - 300)
			flows = FlowTrack()
			start_time = quantise(flow.recv_sec)
		flows.update(flow)

def main():
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'hs')
	except getopt.GetoptError:
		print >> sys.stderr, "Invalid commandline arguments"
		usage()

	do_sock = False
	for o, a in opts:
		if o in ('-h', '--help'):
			usage()
			sys.exit(0)
		if o in ('-s', '--socket'):
			do_sock = True

	if len(args) == 0:
		print >> sys.stderr, "No log path specified"
		usage()
	if len(args) == 1:
		print >> sys.stderr, "No RRD database specified"
		usage()
	if len(args) > 2:
		print >> sys.stderr, "Too many commandline arguments"
		usage()

	if do_sock:
		process_from_socket(args[0], args[1])
	else:
		process_from_file(args[0], args[1])

if __name__ == '__main__': main()

