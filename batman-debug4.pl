#!/usr/bin/perl

use strict;
use utf8;


my ( %myself_hash, %receive_hash, $last_orig, $last_neigh, $orig_interval, $total_seconds );

$orig_interval = 1000;


if ( ! -e $ARGV[0] ) {

	print "B.A.T.M.A.N log file could not be found: $ARGV[0]\n";
	exit;

}


open(BATMANLOG, "< $ARGV[0]");

while (<BATMANLOG>) {


	if ( m/Received\ BATMAN\ packet\ from\ ([\d]+\.[\d]+\.[\d]+\.[\d]+).*?originator\ ([\d]+\.[\d]+\.[\d]+\.[\d]+)/ ) {

		$receive_hash{ $2 }{ $1 }{ "num_recv" }++;
		$last_orig = $2;
		$last_neigh = $1;

	} elsif ( m/Forwarding\ packet\ \(originator\ ([\d]+\.[\d]+\.[\d]+\.[\d]+)/ ) {

		if ( $1 eq $last_orig ) {

			$receive_hash{ $last_orig }{ $last_neigh }{ "num_forw" }++;

		} elsif ( $myself_hash{ $1 } ) {

			$myself_hash{ $1 }{ "sent" }++

		} else {

			print "Not equal: $_\n"

		}

	} elsif ( m/not\ my\ best\ neighbour/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "not_best" }++;

	} elsif ( m/ttl\ exceeded/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "ttl" }++;

	} elsif ( m/Packet\ with\ unidirectional\ flag/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "uni" }++;

	} elsif ( m/received\ via\ bidirectional\ link/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "bi" }++;

	} elsif ( m/neighbour\ thinks\ connection\ is\ bidirectional\ -\ I\ disagree/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "disagree" }++;

	} elsif ( m/Duplicate\ packet/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "dup" }++;

	} elsif ( m/Incompatible\ batman\ version/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "incom" }++;

	} elsif ( m/Using\ interface\ (.*?)\ with\ address\ ([\d]+\.[\d]+\.[\d]+\.[\d]+)/ ) {

		$myself_hash{ $2 }{ "if" } = $1;

	} elsif ( m/orginator interval: ([\d]+)/ ) {

		$orig_interval = $1;

	}

}


close(BATMANLOG);


print "\nSent:\n^^^^\n";

foreach my $my_ip ( keys %myself_hash ) {

	$total_seconds = ( $myself_hash{ $my_ip }{ "sent" } * $orig_interval ) / 1000;
	print " => $my_ip (" . $myself_hash{ $my_ip }{ "if" } . "): send " . $myself_hash{ $my_ip }{ "sent" } . " packets in $total_seconds seconds\n";

}


print "\n\nReceived:\n^^^^^^^^";

foreach my $orginator ( keys %receive_hash ) {

	my $sum = 0;
	my $string = "";

	foreach my $neighbour ( keys %{ $receive_hash{ $orginator } } ) {

		$sum += $receive_hash{ $orginator }{ $neighbour }{ "num_recv" };
		$string .= " => $neighbour" . ( $myself_hash{ $neighbour } ? " (myself):\t" : ":\t\t" );
		$string .= " recv = " . $receive_hash{ $orginator }{ $neighbour }{ "num_recv" };
		$string .= " <> forw = " . ( $receive_hash{ $orginator }{ $neighbour }{ "num_forw" } ? $receive_hash{ $orginator }{ $neighbour }{ "num_forw" } : "0" );
		$string .= " \t [ uni = " . ( $receive_hash{ $orginator }{ $neighbour }{ "uni" } ? $receive_hash{ $orginator }{ $neighbour }{ "uni" } : "0" );
		$string .= "; bi = " . ( $receive_hash{ $orginator }{ $neighbour }{ "bi" } ? $receive_hash{ $orginator }{ $neighbour }{ "bi" } : "0" );
		$string .= "; uni/bi = " . ( $receive_hash{ $orginator }{ $neighbour }{ "disagree" } ? $receive_hash{ $orginator }{ $neighbour }{ "disagree" } : "0" ) . " ]";
		$string .= " [ not best = " . ( $receive_hash{ $orginator }{ $neighbour }{ "not_best" } ? $receive_hash{ $orginator }{ $neighbour }{ "not_best" } : "0" );
		$string .= "; uni = " . ( $receive_hash{ $orginator }{ $neighbour }{ "uni" } ? $receive_hash{ $orginator }{ $neighbour }{ "uni" } : "0" );
		$string .= "; incom = " . ( $receive_hash{ $orginator }{ $neighbour }{ "incom" } ? $receive_hash{ $orginator }{ $neighbour }{ "incom" } : "0" );
		$string .= "; ttl = " . ( $receive_hash{ $orginator }{ $neighbour }{ "ttl" } ? $receive_hash{ $orginator }{ $neighbour }{ "ttl" } : "0" );
		$string .= "; dup = " . ( $receive_hash{ $orginator }{ $neighbour }{ "dup" } ? $receive_hash{ $orginator }{ $neighbour }{ "dup" } : "0" ) . " ]\n";

	}

	print "\norginator $orginator" . ( $myself_hash{ $orginator } ? " (myself)" : "" ) . ": total recv = $sum\n";
	print $string;

}

print "\n\nHelp:\n^^^^\n";
print "\tuni      = received packet with unidirectional flag (won't be forwarded)\n";
print "\tbi       = received packet via bidirectional link\n";
print "\tuni/bi   = neighbour thinks connection is bidirectional - I disagree\n";
print "\tnot best = received packet didn't came via my best neighbor (won't be forwarded)\n";
print "\tincom    = received packet indicated incompatible batman version (will be ignored)\n";
print "\tttl      = ttl of packet exceeded (won't be forwarded)\n";
print "\tdup      = received packet is a duplicate\n";
