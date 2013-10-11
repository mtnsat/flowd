#!/usr/bin/env python

# Copyright (c) 2004 Damien Miller <djm@mindrot.org>
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

# $Id: stats.py,v 1.7 2005/10/01 00:06:48 djm Exp $

# Example Python statistics application
# This isn't polished at all, it just writes a top-N report to stdout

# XXX TODO
# - redo charts support
# - Limit memory consumption in per-address statistics
# - Reports in UTC time or other timezones
# - Autoscale axes in charts better (particularly time)
# - Use a moving average for charting the interpolated bitmaps (rather than
#   absurdly large bins)
# - More reports
# - pretty PDF output
# - Split summarisation from presentation
#   - Save/load summary state (so you can play with presentation settings 
#     without grovelling through the flow data every time)
# - Clean up time units conversion mess in history classes
# - num unique src unique dst per unit time


import flowd
import sys
import string
import math
import getopt
import time
import datetime
import pickle
import gzip

try:
	import curses
	no_curses = False
except ImportError:
	no_curses = True	
	
class exponential_histogram:
	'''Class implementing a histogram with exponential bins'''
	def __init__(self, base = 2):
		'''Constructor for class exponential_histogram. Parameter 
		"base" specifies the base bin size. Bins are of the form 
		base**n. For example, a base of 10 will yield bins 1, 10, 
		100, 1000, ...'''
		self.n = 0
		self.d = {}
		self.base = int(base)
		if self.base < 2:
			raise ValueError, "Invalid base"

	def update(self, data):
		'''Update an exponential histogram with 'data' (which must be
		numeric)'''
		if data != 0:
			data = int(math.log(data, self.base))
		if not self.d.has_key(data):
			self.d[data] = 0
		self.d[data] += 1

	def tolist(self):
		'''Convert an exponential_histogram to a sorted list of 
		(bin_value, frequency) tuples'''
		items = self.d.items()
		items.sort(lambda x, y: cmp(x[0], y[0]))
		ret = []
		last = None
		for value, count in items:
			if last is not None and last + 1 < value:
				# Fill in the blanks
				for x in range(last + 1, value):
					ret.append((self.base ** x, 0))
			ret.append((self.base ** value, count))
			last = value
		return ret

	def report(self):
		ret = ""
		for val, count in self.tolist():
			ret += "%u:%u\n" % (val, count)
		return ret

class _base_history:
	'''Base class for time-series histories - Implements a history to
	record an event rate'''
	def __init__(self, resolution = 7200, start_time = None):
		'''Create a new history object. 'resolution' parameter
		determines the time length of a single bin in the array'''
		self.resolution = resolution * 1000
		self.samples = {}

	def _bin2dt(self, when, skew):
		secs = (self.resolution * when / 1000.0) + skew
		return datetime.datetime.fromtimestamp(secs)

	def tolist(self, skew = 0):
		'''Convert a history to a sorted list of (time, amount)
		tuples'''
		items = self.samples.items()
		items.sort(lambda x, y: cmp(x[0], y[0]))
		ret = []
		last = None
		for value, count in items:
			if last is not None and last + 1 < value:
				# Fill in the blanks
				#print "filling", last, value
				for x in range(last + 1, value):
					ret.append((self._bin2dt(x, skew), 0))
			ret.append((self._bin2dt(value, skew), count))
			last = value
		return ret

class interpolated_history(_base_history):
	'''Implements a history to estimate data throughput based on the
	information in the flow: start_time, finish_time and quantity.'''
	def _add(self, amount, when):
		if not self.samples.has_key(when):
			self.samples[when] = 0
		self.samples[when] += amount * 1000.0 / self.resolution

	def update(self, amount, start, finish):
		'''Update a interpolated_history with a flow's data. Throughtput
		is estimated over the lifetime (defined by 'start' and 'finish')
		based on total 'amount' of flow.''' 
		if finish < start:
			raise ValueError, "start lies after finish"
		mstart = int(start / self.resolution)
		mfinish = int(finish / self.resolution)
		# Easy case
		if mstart == mfinish:
			#print "easy", mstart, amount
			self._add(amount, mstart)
			return
		rate = float(amount) / float(finish - start)
		for when in range(mstart, mfinish):
			# Special-case for start and finish: estimate
			# contribution based on proportion of time in bin
			if when == mstart:
				contribution = (self.resolution - \
				    (start % self.resolution)) * rate
			elif when == mfinish - 1:
				contribution = (finish % self.resolution) * rate
			else:
				contribution = rate * self.resolution

			self._add(contribution, when)

	def crop(self, first = None, last = None):
		'''Delete records outside of specified time range'''
		delete_keys = []
		for key in self.samples.keys():
			xkey = int(key * self.resolution)
			if first is not None and xkey < first:
				delete_keys.append(key)
			elif last is not None and xkey > last:
				delete_keys.append(key)
		for key in delete_keys:
			del self.samples[key]

class simple_history(_base_history):
	'''Implements a history to record event rate based on the
	information time and quantity.'''

	def update(self, amount, when):
		'''Update a simple_history with a flow's data. Event rate is
		is recorded based on event rate ('amount') and time of
		incidence ('when')'''
		mwhen = int(when / self.resolution)
		if not self.samples.has_key(mwhen):
			self.samples[mwhen] = 0
		self.samples[mwhen] += amount * 1000.0 / self.resolution

class flow_stat_count:
	def __init__(self):
		self.flows = 0
		self.octets = 0
		self.packets = 0

	def update(self, flow):
		self.flows += 1
		if flow.has_field(flowd.FIELD_OCTETS):
			self.octets += flow.octets
		if flow.has_field(flowd.FIELD_PACKETS):
			self.packets += flow.packets		

class flow_statistic:
	'''maintain flows, packets and octet counts statistics on a particular 
	aspect of a flow (e.g. per-protocol, per-port)'''
	def __init__(self):
		'''Constructor for class flow_statistic'''
		self.num_unique = 0
		self.counts = {}

	def update(self, what, flow):
		'''Update a flow_statistic with a flow's data.'''
		try:
			count = self.counts[what]
		except:
			self.num_unique += 1
			count = flow_stat_count()
			self.counts[what] = count

		count.update(flow)

	def toplist(self, which = "octets", by_key = False, top_n = 10):
		d = [[x[0], x[1].__dict__[which]] for x in self.counts.items()]
		if by_key:
			d.sort(lambda x, y: cmp(x[0], y[0]))
		else:
			d.sort(lambda x, y: -cmp(x[1], y[1]))
		if top_n is None:
			return d
		return d[0:top_n]

	def report(self):
		ret = ""
		ret += "Total: %d\n" % len(self.counts.keys())
		ret += "Octets\n"
		for k, v in self.toplist("octets"):
			ret += "  %s: %s\n" % (k, v)
		ret += "Packets\n"
		for k, v in self.toplist("packets"):
			ret += "  %s: %s\n" % (k, v)
		ret += "Flows\n"
		for k, v in self.toplist("flows"):
			ret += "  %s: %s\n" % (k, v)
		return ret

class flow_statistics:
	def __init__(self):
		self.first = None
		self.last = None
		self.average_clockskew = None
		self.average_clockskew_samples = 0
		self.src_port = flow_statistic()
		self.dst_port = flow_statistic()
		self.src_addr = flow_statistic()
		self.dst_addr = flow_statistic()
		self.fromto = flow_statistic()
		self.protocol = flow_statistic()
		self.flows = 0;
		self.octets = None;
		self.packets = None;

		self.octets_hist = None
		self.packets_hist = None
		self.duration_hist = None
		self.packets_history = None
		self.octets_history = None
		self.flows_history = None

# These need more work, or aren't much use for many people
#		self.octets_hist = exponential_histogram(base = 10)
#		self.packets_hist = exponential_histogram(base = 10)
#		self.duration_hist = exponential_histogram(base = 10)
#		self.packets_history = interpolated_history()
#		self.octets_history = interpolated_history()
#		self.flows_history = simple_history()

	def update(self, flow):
		self.flows += 1
		
		if flow.has_field(flowd.FIELD_RECV_TIME):
			if self.flows_history is not None:
				self.flows_history.update(1, \
				    flow.recv_sec * 1000)
			if self.first is None or \
			   flow.recv_sec < self.first:
				self.first = flow.recv_sec
			if self.last is None or \
			   flow.recv_sec > self.last:
				self.last = flow.recv_sec
			if flow.has_field(flowd.FIELD_FLOW_TIMES):
				delta = flow.recv_sec - \
				    flow.flow_finish / 1000.0
				if self.average_clockskew is None:
					self.average_clockskew = delta
				self.average_clockskew_samples += 1
				new_offset = delta - self.average_clockskew
				self.average_clockskew += new_offset / \
				    self.average_clockskew_samples
		
		if flow.has_field(flowd.FIELD_OCTETS):
			if self.octets is None:
				self.octets = 0
			self.octets += flow.octets
			if self.octets_hist is not None:
				self.octets_hist.update(flow.octets)

		if flow.has_field(flowd.FIELD_PACKETS):
			if self.packets is None:
				self.packets = 0
			self.packets += flow.packets
			if self.packets_hist is not None:
				self.packets_hist.update(flow.packets)

		if flow.has_field(flowd.FIELD_FLOW_TIMES) and \
		   flow.has_field(flowd.FIELD_FLOW_TIMES):
		   	duration = flow.flow_finish - \
			    flow.flow_start
			duration = int(duration / 1000) # milliseconds
			if self.duration_hist is not None:
				self.duration_hist.update(duration)
			if flow.has_field(flowd.FIELD_OCTETS) and \
			   self.octets_history is not None:
				self.octets_history.update(\
				    flow.octets, \
				    flow.flow_start, \
				    flow.flow_finish)
			if flow.has_field(flowd.FIELD_PACKETS) and \
			   self.packets_history is not None:
				self.packets_history.update(\
				    flow.packets, \
				    flow.flow_start, \
				    flow.flow_finish)

		if flow.has_field(flowd.FIELD_SRC_ADDR):
			self.src_addr.update(flow.src_addr, flow)

		if flow.has_field(flowd.FIELD_DST_ADDR):
			self.dst_addr.update(flow.dst_addr, flow)

		if flow.has_field(flowd.FIELD_SRC_ADDR) and \
		   flow.has_field(flowd.FIELD_DST_ADDR):
		   	fromto = flow.src_addr + " -> " + \
				 flow.dst_addr
			self.fromto.update(fromto, flow)

		if flow.has_field(flowd.FIELD_SRCDST_PORT):
			self.src_port.update(flow.src_port, flow)

		if flow.has_field(flowd.FIELD_SRCDST_PORT):
			self.dst_port.update(flow.dst_port, flow)

		if flow.has_field(flowd.FIELD_PROTO_FLAGS_TOS):
			self.protocol.update(flow.protocol, flow)

	def crop(self):
		if self.first is None and self.last is None:
			return
		if self.average_clockskew is None:
			return
		first = self.first
		last = self.last
		if first is not None:
			first -= self.average_clockskew
			first *= 1000.0
		if last is not None:
			last -= self.average_clockskew
			last *= 1000.0
		if self.packets_history is not None:
			self.packets_history.crop(first, last)
		if self.octets_history is not None:
			self.octets_history.crop(first, last)

	def report(self):
		ret = ""
		ret += "total_flows: %u\n" % self.flows
		if self.octets is not None:
			ret += "total_octets: %u\n" % self.octets
		if self.packets is not None:
			ret += "total_packets: %u\n" % self.packets
		ret += "\n"
		if self.duration_hist is not None:
			ret += "duration_histogram:\n"
			ret += self.duration_hist.report()
			ret += "\n"
		if self.octets_hist is not None:
			ret += "octets_histogram:\n"
			ret += self.octets_hist.report()
			ret += "\n"
		if self.packets_hist is not None:
			ret += "packets_histogram:\n"
			ret += self.packets_hist.report()
			ret += "\n"

		ret += "src_ports:\n"
		ret += self.src_port.report()
		ret += "\n\n"
		ret += "dst_ports:\n"
		ret += self.dst_port.report()
		ret += "\n\n"
		ret += "protocols:\n"
		ret += self.protocol.report()
		ret += "\n\n"
		ret += "source address:\n"
		ret += self.src_addr.report()
		ret += "\n\n"
		ret += "destination address:\n"
		ret += self.dst_addr.report()
		ret += "\n\n"
		ret += "source / destination tuples:\n"
		ret += self.fromto.report()
		return ret

def iso_units(x):
	units = ( "", "K", "M", "G", "T", "E", None)
	last = ""
	for u in units:
		if u is None:
			break
		last = u
		if x < 1000:
			break;
		x = int(x / 1000)

	return "%u%s" % (x, last)

def usage():
	print >> sys.stderr, "stats.py (flowd.py version %s)" % \
	    flowd.__version__
	print >> sys.stderr, "Usage: stats.py [options] [flowd-store]";
	print >> sys.stderr, "Options:";
	print >> sys.stderr, "      -h       Display this help";
	sys.exit(1);

def main():
	stats = flow_statistics()

	try:
		opts, args = getopt.getopt(sys.argv[1:], 'p:hu')
	except getopt.GetoptError:
		print >> sys.stderr, "Invalid commandline arguments"
		usage()

	pickle_file = None
	for o, a in opts:
		if o in ('-h', '--help'):
			usage()
			sys.exit(0)
		if o in ('-p', '--pickle'):
			pickle_file = a

	# Get clear-to-line-end sequence for progress display
	ceol = None
	if sys.stderr.isatty() and not no_curses:
		curses.setupterm()
		ceol = curses.tigetstr("el")
		if ceol is not None:
			ceol = curses.tparm(ceol, 0, 0)
	if ceol is None:
		ceol = ""

	if len(args) == 0:
		print >> sys.stderr, "No logfiles specified"
		usage()

	i = 0;
	for ffile in args:
		j = 0
		if ffile == "-":
			flog = flowd.FlowLog_fromfile(sys.stdin)
		else:
			flog = flowd.FlowLog(ffile, "rb")
		for flow in flog:
			stats.update(flow)
			if ceol != "" and i >= 0 and j % 1000 == 0:
				print >> sys.stderr, "\r%s: %d flows" % \
				    (ffile, j),
				if i != j:
					print >> sys.stderr, " total %d" % i,
				print >> sys.stderr, ceol,
				sys.stderr.flush()
			i += 1
			j += 1
		print >> sys.stderr, "\r%s: %d flows (total %d)%s\n" % \
		    (ffile, j, i, ceol)
		sys.stderr.flush()

	stats.crop()
	print stats.report()

	if pickle_file is not None:
		out = open(pickle_file, "wb")
		pickle.dump(stats, out)
		out.close()
		print >> sys.stderr, "Statistics pickled to \"%s\"" % \
		    pickle_file

if __name__ == '__main__': main()
