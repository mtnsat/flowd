#!/usr/bin/perl

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

# An example script to insert flowd logs into an SQL database. 

# $Id: flowinsert.pl,v 1.3 2007/10/10 02:55:11 djm Exp $

use strict;
use warnings;

use DBI;
use Flowd;

# Database settings
my $DBI_DRIVER =	"SQLite"; # or one of "Pg" "mysql" "mysqlPP" 
my $DB =		"flows.sqlite";
my $TABLE =		"flows";
my $USER =		undef;
my $PASS =		undef;

die "Usage: flowinsert.pl [flowd-log]\n" unless (@ARGV);

my $db = DBI->connect("dbi:$DBI_DRIVER:dbname=$DB", $USER, $PASS)
	or die "DBI->connect error: " . $DBI::errstr;

for (my $i = 0; $i < scalar(@ARGV); $i++) {
	my $flow_log = $ARGV[$i];
	my $flow_handle = Flowd->new($flow_log);

#	print "$flow_log\n";

	while (my $flow = $flow_handle->read_flow()) {
		my $tag = $flow->{tag};
		$tag = 0 unless defined $tag;

#		print $flow->format(Flowd::Flow::BRIEF, 0) . "\n";

		my $query = sprintf( "INSERT INTO flows ".
		    "(tag, received, agent_addr, src_addr, dst_addr, ".
		    " src_port, dst_port, octets, packets, protocol) VALUES ".
		    "(%u, %s, %s, %s, %s, %u, %u, %u, %u, %u)" ,
		    $tag, 
		    $db->quote(Flowd::iso_time($flow->{recv_sec})),
		    $db->quote($flow->{agent_addr}), 
		    $db->quote($flow->{src_addr}), 
		    $db->quote($flow->{dst_addr}),
		    $flow->{src_port},
		    $flow->{dst_port},
		    $flow->{flow_octets},
		    $flow->{flow_packets},
		    $flow->{protocol} );

#		print "$query\n";
		$db->do($query) or die "db->do failed: " . $DBI::errstr;
	}
	$flow_handle->finish();
}
