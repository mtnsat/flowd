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

# $Id: Flowd.pm,v 1.7 2008/07/25 00:04:17 djm Exp $

package Flowd;

use 5.006;
use strict;
use warnings;

use constant VERSION		=> "0.9.1";

# Flowd log header fields
use constant TAG		=> 0x00000001;
use constant RECV_TIME		=> 0x00000002;
use constant PROTO_FLAGS_TOS	=> 0x00000004;
use constant AGENT_ADDR4	=> 0x00000008;
use constant AGENT_ADDR6	=> 0x00000010;
use constant SRC_ADDR4		=> 0x00000020;
use constant SRC_ADDR6		=> 0x00000040;
use constant DST_ADDR4		=> 0x00000080;
use constant DST_ADDR6		=> 0x00000100;
use constant GATEWAY_ADDR4	=> 0x00000200;
use constant GATEWAY_ADDR6	=> 0x00000400;
use constant SRCDST_PORT	=> 0x00000800;
use constant PACKETS		=> 0x00001000;
use constant OCTETS		=> 0x00002000;
use constant IF_INDICES		=> 0x00004000;
use constant AGENT_INFO		=> 0x00008000;
use constant FLOW_TIMES		=> 0x00010000;
use constant AS_INFO		=> 0x00020000;
use constant FLOW_ENGINE_INFO	=> 0x00040000;
use constant CRC32		=> 0x40000000;

# Some useful combinations
use constant AGENT_ADDR		=> 0x00000018;
use constant SRC_ADDR		=> 0x00000060;
use constant DST_ADDR		=> 0x00000180;
use constant SRCDST_ADDR	=> 0x000001e0;
use constant GATEWAY_ADDR	=> 0x00000600;
use constant BRIEF		=> 0x000039ff;
use constant ALL		=> 0x4007ffff;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Flowd ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.9.1';

require XSLoader;
XSLoader::load('Flowd', $VERSION);

# Preloaded methods go here.
sub iso_time {
	my $timet = shift;
	my $utc = 0;
	my @tm;

	Carp::confess("missing argument") if not defined $timet;

	@tm = localtime($timet) unless $utc;
	@tm = gmtime($timet) if $utc;

	return sprintf("%04u-%02u-%02uT%02u:%02u:%02u", 
	    1900 + $tm[5], 1 + $tm[4], $tm[3], $tm[2], $tm[1], $tm[0]);
}

sub interval_time {
	my $t = shift;
	my @ivs = (
		[ "m", 60 ], [ "h", 60 ], [ "d", 24 ], 
		[ "w", 7 ], [ "y", 52 ] 
	);
	my $ret = "s";

	Carp::confess("missing argument") if not defined $t;

	foreach my $iv (@ivs) {
		$ret = sprintf "%u%s", $t % @$iv[1], $ret;
		$t = int($t / @$iv[1]);
		last if $t <= 0;
		$ret = @$iv[0] . $ret;
	}
	return $ret;
}

sub interval_time_ms
{
	my $tms = shift;

	return sprintf "%s.%03u", interval_time($tms / 1000), $tms % 1000,	
}

sub new {
	my $class = shift;
	my @args = (@_);

	my $self = {};
	bless($self, $class);

	$self->init(@args);

	return $self;
}

sub init {
	my $self = shift;
	my $filename = shift;
	my $fhandle;
	my $hdr;
	my $r;

	$self->{filename} = $filename;
	open($fhandle, "<$filename") or die "open($filename): $!";
	$self->{handle} = $fhandle;
}

sub finish {
	my $self = shift;

	close($self->{handle});
	$self->{handle} = undef;
}

sub read_flow {
	my $self = shift;
	my $hdr;
	my $fdata;
	my $r;
	my $need;

	# Read initial flow header
	$need = Flowd::header_length();
	$r = read($self->{handle}, $hdr, $need);
	die "read($self->{filename}): $!" if not defined $r;
	return 0 if $r == 0;
	die "early EOF reading header on $self->{filename}" if $r < $need;

	# Calculate length of flow and read it in
	$need = Flowd::flow_length($hdr);
	$r = read($self->{handle}, $fdata, $need);
	die "read($self->{filename}): $!" if not defined $r;
	die "early EOF reading flow on $self->{filename}" if $r < $need;

	return Flowd::deserialise($hdr . $fdata);
}

sub format
{
	my $self = shift;
	my $field_mask = shift;
	my $utc_flag = shift;
	my $flowfields = shift;
	my $fields = $flowfields->{fields} & $field_mask;

	my $ret = "";

	$ret .= "FLOW ";

	if ($fields & TAG) {
		$ret .= sprintf "tag %u ", $flowfields->{tag};
	}
	if ($fields & RECV_TIME) {
		$ret .= sprintf "recv_time %s.%05d ", 
		    Flowd::iso_time($flowfields->{recv_sec}, $utc_flag),
		    $flowfields->{recv_usec};
	}
	if ($fields & PROTO_FLAGS_TOS) {
		$ret .= sprintf "proto %u ", $flowfields->{protocol};
		$ret .= sprintf "tcpflags %02x ", $flowfields->{tcp_flags};
		$ret .= sprintf "tos %02x ", $flowfields->{tos};
	}
	if ($fields & AGENT_ADDR) {
		$ret .= sprintf "agent [%s] ", $flowfields->{agent_addr};
	}
	if ($fields & SRC_ADDR) {
		$ret .= sprintf "src [%s]", $flowfields->{src_addr};
		if ($fields & SRCDST_PORT) {
			$ret .= sprintf ":%u", $flowfields->{src_port};
		}
		$ret .= " ";
	}
	if ($fields & DST_ADDR) {
		$ret .= sprintf "dst [%s]", $flowfields->{dst_addr};
		if ($fields & SRCDST_PORT) {
			$ret .= sprintf ":%u", $flowfields->{dst_port};
		}
		$ret .= " ";
	}
	if ($fields & GATEWAY_ADDR) {
		$ret .= sprintf "gateway [%s] ",
		    $flowfields->{gateway_addr};
	}
	if ($fields & PACKETS) {
		my $p = $flowfields->{flow_packets};
		$p =~ s/^\+//;
		$ret .= sprintf "packets %s ", $p;
	}
	if ($fields & OCTETS) {
		my $o = $flowfields->{flow_octets};
		$o =~ s/^\+//;
		$ret .= sprintf "octets %s ", $o;
	}
	if ($fields & IF_INDICES) {
		$ret .= sprintf "in_if %u ", $flowfields->{if_index_in};
		$ret .= sprintf "out_if %u ", $flowfields->{if_index_out};
	}
	if ($fields & AGENT_INFO) {
		$ret .= sprintf "sys_uptime_ms %s ",
		    Flowd::interval_time_ms($flowfields->{sys_uptime_ms});
		$ret .= sprintf "time_sec %s ",
		    Flowd::iso_time($flowfields->{time_sec}, $utc_flag);
		$ret .= sprintf "time_nanosec %u ",
		    $flowfields->{time_nanosec};
		$ret .= sprintf "netflow ver %u ",
			$flowfields->{netflow_version};
	}
	if ($fields & FLOW_TIMES) {
		$ret .= sprintf "flow_start %s ",
		    Flowd::interval_time_ms($flowfields->{flow_start});
		$ret .= sprintf "flow_finish %s ",
		    Flowd::interval_time_ms($flowfields->{flow_finish});
	}
	if ($fields & AS_INFO) {
		$ret .= sprintf "src_AS %u ", $flowfields->{src_as};
		$ret .= sprintf "src_masklen %u ",
		    $flowfields->{src_masklen};
		$ret .= sprintf "dst_AS %u ", $flowfields->{dst_as};
		$ret .= sprintf "dst_masklen %u ",
		    $flowfields->{dst_masklen};
	}
	if ($fields & FLOW_ENGINE_INFO) {
		$ret .= sprintf "engine_type %u ",
		    $flowfields->{engine_type};
		$ret .= sprintf "engine_id %u ", $flowfields->{engine_id};
		$ret .= sprintf "seq %u ", $flowfields->{flow_sequence};
	}
	if ($fields & CRC32) {
		$ret .= sprintf "crc32 %08x ", $flowfields->{crc};
	}

	return $ret;
}

1;
__END__
=head1 NAME

Flowd::Serialiser - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Flowd::Serialiser;

=head1 DESCRIPTION

This module isn't really intended for public consumption. It is just a thin
wrapper over the flowd C library. If you are really curious, have a look at
Flowd.pm to see how it uses it (it is very simple).

=head2 EXPORT

None by default.

=head1 SEE ALSO

Refer to Flowd.pm for usage information.

=head1 AUTHOR

Damien Miller, E<lt>djm@mindrot.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004 Damien Miller <djm@mindrot.org>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

=cut
