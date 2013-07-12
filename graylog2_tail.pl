#!/usr/bin/perl
# This is the MIT license.
# Copyright (c) 2013 bert@p3rf3ct.com
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

use IO::Socket;
use open qw( :std :encoding(UTF-8) );
use strict;
use warnings;
use Getopt::Long;
use Data::Dumper;
use POSIX qw(strftime);

our %opt;
GetOptions(
  'g|graylog=s' => \$opt{Graylog},
  'h|hosts=s' => \$opt{Hosts},
  'x|excludes=s' => \$opt{Excludes},
  's|severity=s' => \$opt{Severity},
  'f|facility=s' => \$opt{Facility},
  'j|fexculdes=s' => \$opt{FExcludes},
  'c' => \$opt{Colour},
  'p' => \$opt{Padding},
  'd' => \$opt{Debug},
);

use constant PLUGIN_PORT => 1978;
my $clr = { stop => "\x1b[00m", };

$SIG{INT} = \&close_sock; 
$SIG{TERM} = \&close_sock; 
$| = 1;

if(!$opt{Graylog}) {
    print "usage $0 -g [grayloghost|prod|uat|dev] [-h hostlist] [-x hostlist] [-s severity] [-f facilitylist] [-j exlude facilitylist] [-p auto-padded] [-c disables colour]\n";
	print "where: hostlists and facility can be simple regexes or fullnames\n";
    print "e.g: $0 -g uat -h wordpress,broker -s INFO,ERROR -f agg,user -p\n";
    exit 0;
}

my $loghosts = {
	prod => "graylog.prod.qmetric.co.uk",
	uat => "graylog.uat.qmetric.co.uk",
	dev => "graylog.dev.qmetric.co.uk",
};

my $allopts = {};
if($opt{Hosts}) { print "Hosts:"; foreach my $h ( split(/,/,$opt{Hosts}) ) { $allopts->{hosts}->{$h} = 1; print " $h"; } print "\n"; }
if($opt{FExcludes}) { print "Facility Excludes:"; foreach my $f ( split(/,/,$opt{FExcludes}) ) { $allopts->{fexcludes}->{$f} = 1; print " $f"; } print "\n"; }
if($opt{Excludes}) { print "Excludes:"; foreach my $h ( split(/,/,$opt{Excludes}) ) { $allopts->{excludes}->{$h} = 1; print " $h"; } print "\n"; }
if($opt{Facility}) { print "Facility:"; foreach my $f ( split(/,/,$opt{Facility}) ) { $allopts->{facils}->{$f} = 1; print " $f"; } print "\n"; }
if($opt{Severity}) { print "Severity:"; foreach my $s ( split(/,/,$opt{Severity}) ) { $allopts->{sevs}->{$s} = 1; print " $s"; } print "\n"; }
if($opt{Colour}) { $allopts->{colour} = 1; }
if($opt{Padding}) { $allopts->{padding} = 1; }

# for the graylog db in the env, get to the messages
my $grayloghost = $opt{'Graylog'};
$grayloghost = $loghosts->{$grayloghost} if defined $loghosts->{$grayloghost};
print "Graylog: $grayloghost\n";

my $socket = new IO::Socket::INET (
	PeerAddr => $grayloghost,
	PeerPort => PLUGIN_PORT,
	Proto => 'tcp',
);

my @lines = ();
my $host_max = 1;
my $fac_max = 1;
while(defined (my $line = <$socket>)) {
	chomp $line;
	if (($line =~ /^host:/) && (@lines)) {
		($host_max,$fac_max) = process_lines($allopts,$host_max,$fac_max,@lines);
		@lines = ();
	}
	push (@lines,$line);
}

# match simple regex to keys
sub rmatch {
	my $matchers = shift;
	my $match = shift;
	foreach my $key (keys %{$matchers}) {
		return 1 if grep { /$key/ } $match;
	}
	return 0;
}

# works on lines from socket, processing as 'groups' with a potential first line we can parse
# and subsequent lines we display. if its an excluded line/group then it isnt displayed.
sub process_lines {
	my $opts = shift;
	my $host_max = shift;
	my $fac_max = shift;
	my @lines = @_;
	my $firstline = 1;
	my $dont_ignore = 1;
	foreach my $line (@lines) {
		if ($firstline) {
			my $parts = parse($line);
			my $host = $parts->{'host'};
			my $lev = $parts->{'level'};
			$parts->{'facility'} = "sec/auth" if $parts->{'facility'} =~ 'security/authorization';
			my $fac = $parts->{'facility'};
			my $colour = !defined $opts->{'colour'};
			my $padding = defined $opts->{'padding'};
			if (		( (!defined $opts->{hosts} || rmatch($opts->{hosts},$host)) && !rmatch($opts->{excludes},$host)) 
					&&  ( (!defined $opts->{facils} || rmatch($opts->{facils},$fac)) && !rmatch($opts->{fexcludes},$fac))
					&&  ( !defined $opts->{sevs} || defined $opts->{sevs}->{severity($lev,'lev')} )
			){
				my $hostlen = length $host;
				my $faclen = length $fac;
				$host_max = $hostlen if $hostlen > $host_max;
				$fac_max = $faclen if $faclen > $fac_max;
				print transform($parts,$host_max,$fac_max,$colour,$padding);
				$dont_ignore = 1;
			} else {
				$dont_ignore = 0;
			}
		} else {
			$dont_ignore && print $line,"\n";
		}
		$firstline = 0;
	}
	return ($host_max,$fac_max);
}

# parse line into parts
sub parse {
	my $line = shift;
	my @bits = split(/,/,$line, 5);
	my $parts = {};
	foreach my $logpart (@bits) {
		my $key = "script_error";
		my $val = "script_error";
		my $odd = "";
		if ($logpart =~ /^message:/) {
			$key = 'message';
			$logpart =~ s/^message://;
			$val = $logpart;
		} else {
			($key,$val,$odd) = split(/:/,$logpart);
			if($odd) {
				$odd = "-$odd";
			} else {
				$odd = "";
			}
		}
		$parts->{$key} = $val.$odd;
	}
	return $parts;
}

# transform the line into something readable.
sub transform {
	my $parts = shift;
	my $host_max = shift;
	my $fac_max = shift;
	my $colour = shift;
	my $padding = shift;

	my $stamp = strftime("%Y-%m-%d %H:%M:%S",localtime($parts->{'date'}));
	$parts->{'date'} = $stamp;
	$parts->{'message'} =~ s/^<\d+>//;
	$parts->{'level'} = severity($parts->{'level'},'lev');
	$padding && do {
		$parts->{'level'} = sprintf "%-6s", $parts->{'level'};
		$parts->{'host'} = sprintf "%-${host_max}s", $parts->{'host'};
		$parts->{'facility'} = sprintf "%-${fac_max}s", $parts->{'facility'};
	};
	$colour && colourem($parts);
	# this host is ok and the severity is wanted ...
	my $line = "";
	$line = $line.$parts->{'host'}. ": ";
	$line = $line.$parts->{'date'}. ": ";
	$line = $line.$parts->{'level'}.": ";
	$line = $line.$parts->{'facility'}. ": "; 
	$line = $line.$parts->{'message'};
	$line = $line."\n";
	return $line;
}

# ascii key for colour
sub colour {
	my $col = shift;
	my $colours = {
	  black       => "\x1b[0;30m",
	  red         => "\x1b[0;31m",
	  green       => "\x1b[0;32m",
	  yellow      => "\x1b[0;33m",
	  blue        => "\x1b[0;34m",
	  magenta     => "\x1b[0;35m",
	  cyan        => "\x1b[0;36m",
	  white       => "\x1b[0;37m",
	  bblack       => "\x1b[1;30m",
	  bred         => "\x1b[1;31m",
	  bgreen       => "\x1b[1;32m",
	  byellow      => "\x1b[1;33m",
	  bblue        => "\x1b[1;34m",
	  bmagenta     => "\x1b[1;35m",
	  bcyan        => "\x1b[1;36m",
	  bwhite       => "\x1b[1;37m",
	  rev         => "\x1b[00m\x1b[07m",
	  ired        => "\x1b[00m\x1b[41m",
	  igreen      => "\x1b[00m\x1b[42m",
	  iyellow     => "\x1b[1;30m\x1b[43m",
	  iblue       => "\x1b[1;30m\x1b[44m",
	  imagenta    => "\x1b[1;30m\x1b[45m",
	  icyan       => "\x1b[1;30m\x1b[46m",
	  stop        => "\x1b[00m",
	};
	if(defined $colours->{$col}) { return $colours->{$col};}
	return 0;
}

# nice name for severity level and associated colour 
# taking into account padded version of nicename
sub severity {
	my $level = shift;
	my $key = shift;
	my $severities = {
	  'NONE  ' => { col => colour('blue') },
	  'DEBUG ' => { col => colour('cyan'), },
	  'INFO  ' => { col => colour('magenta'), },
	  'NOTICE' => { col => colour('bblue'), },
	  'WARN  ' => { col => colour('yellow'), },
	  'ERROR ' => { col => colour('red'), },
	  'CRIT  ' => { col => colour('ired'), },
	  'ALERT ' => { col => colour('iyellow'), },
	  'EMERG ' => { col => colour('igreen'), },
	  'NONE' => { col => colour('blue') },
	  'DEBUG' => { col => colour('cyan'), },
	  'INFO' => { col => colour('magenta'), },
	  'NOTICE' => { col => colour('bblue'), },
	  'WARN' => { col => colour('yellow'), },
	  'ERROR' => { col => colour('red'), },
	  'CRIT' => { col => colour('ired'), },
	  'ALERT' => { col => colour('iyellow'), },
	  'EMERG' => { col => colour('igreen'), },
	  '8' => { lev => 'NONE', col => colour('blue') },
	  '7' => { lev => 'DEBUG', col => colour('cyan'), },
	  '6' => { lev => 'INFO', col => colour('magenta'), },
	  '5' => { lev => 'NOTICE', col => colour('green'), },
	  '4' => { lev => 'WARN', col => colour('yellow'), },
	  '3' => { lev => 'ERROR', col => colour('red'), },
	  '2' => { lev => 'CRIT', col => colour('ired'), },
	  '1' => { lev => 'ALERT', col => colour('iyellow'), },
	  '0' => { lev => 'EMERG', col => colour('igreen'), },
	};
	if(defined $severities->{$level}->{$key}) { return $severities->{$level}->{$key}; }
	return 0;
}


# add colour to the line components
sub colourem {
	my $parts = shift;
	$parts->{'host'}  = colour('cyan').$parts->{'host'}.colour('stop');
	$parts->{'date'}  = colour('green').$parts->{'date'}.colour('stop');
	$parts->{'level'} = severity($parts->{'level'},'col').$parts->{'level'}.colour('stop');
	$parts->{'facility'} = colour('green').$parts->{'facility'}.colour('stop');
	defined $parts->{'file'} && ($parts->{'file'} = colour('cyan').$parts->{'file'}.colour('stop'));
}

# catch the ctrl-c or term
sub close_sock {
	close($socket);
    print "\nClosing socket connection".colour('stop')."\n";
    exit 1;
}
