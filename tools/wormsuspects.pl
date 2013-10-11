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

# A very simple script that looks for the src_host:proto:dst_port tuples that 
# have generated the greatest number of flows. This may indicate hosts that 
# are performing a large number of host connection attempts, e.g. worms
#
# Despite being horribly quick and dirty, this is surprisingly useful
#
# Warning: this is a really naive brute-force implementation: it will happily 
# exhaust memory if there are too many src_host:proto:dst_port tuples :)

# $Id: wormsuspects.pl,v 1.2 2004/10/31 06:42:57 djm Exp $

use strict;
use warnings;
use Flowd;

my $TOP = 10;
my $DOT_PER = 1000;

$| = 1;

sub usage
{
	printf STDERR "wormsuspects.pl (Flowd.pm version %s)\n", Flowd::VERSION;
	printf STDERR "Usage: wormsuspects.pl [flowd-store]\n";
	exit 1;
}

usage() unless (defined $ARGV[0]);

my %top;
my $i = 0;
foreach my $ffile (@ARGV) {
	my $log = Flowd->new($ffile);
	
	printf STDERR "LOGFILE %s started at %s\n",
	    $ffile, Flowd::iso_time($log->{start_time}, 0);
	
	while (my $flow = $log->read_flow()) {
		my $src = $flow->{src_addr};
		my $proto = $flow->{protocol};
		my $port = $flow->{dst_port};
		my $src_id;

		die "Need source address" unless defined $src;
		$src_id = "$src";
		$src_id .= "|X:$proto" if defined $proto && $proto != 0;		
		$src_id .= "|Y:$port" if defined $port && $port != 0;
		$top{$src_id} = 0 if not defined $top{$src_id};
		$top{$src_id}++;
		$i++;
		print STDERR "." if $i and ($i % $DOT_PER) == 0;
		print STDERR "\n" if $i and ($i % ($DOT_PER * 50)) == 0;
	}
	print STDERR "\n";
	$log->finish();
}

printf "%32s %8s %8s  %24s\n", "Address", "Proto", "Port", "Num Flows";
printf "%32s %8s %8s  %24s\n", "-------", "-----", "----", "---------";

my @src_ids = sort {$top{$b} <=> $top{$a}} keys %top;
my $total = 0;
foreach my $src_id (@src_ids[0 .. $TOP]) {
	my @src = $src_id =~ /^([^|]+)(?:\|X\:([^|]+))?(?:\|Y\:([^|]+))?/;
	$src[1] = "???" if not defined $src[1];	
	$src[2] = "???" if not defined $src[2];

	printf "%32s %8s %8s %16d (%05.2f%%)\n",
	    $src[0], $src[1], $src[2], $top{$src_id},
	    $top{$src_id} * 100.0 / $i;
	$total += $top{$src_id};
}
printf "%32s %8s %8s  %24s\n", "-----", "", "", "";
printf "%32s %8s %8s %16d (%05.2f%%)\n", "OTHER", "", "",
    $i - $total, ($i - $total) * 100.0 / $i;
