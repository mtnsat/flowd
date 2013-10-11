#!/usr/bin/perl

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

# $Id: reader.pl,v 1.10 2005/08/21 11:16:05 djm Exp $

# This intended to be an example of the Flowd package API more than a usable
# application

use strict;
use warnings;
use Flowd;

sub usage
{
	printf STDERR "reader.pl (Flowd.pm version %s)\n", $Flowd::VERSION;
	printf STDERR "Usage: reader.pl [flowd-store]\n";
	exit 1;
}

usage() unless (defined $ARGV[0]);

foreach my $ffile (@ARGV) {
	my $log = Flowd->new($ffile);
	
	printf "LOGFILE %s \n", $ffile;
	
	while (my $flow = $log->read_flow()) {
		print $log->format(Flowd::BRIEF, 0, $flow) . "\n";
	}
	$log->finish();
}
