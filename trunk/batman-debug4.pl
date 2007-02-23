#!/usr/bin/perl

use strict;
use utf8;


my ( %myself_hash, %receive_hash, %forward_hash, $last_orig, $last_neigh, $last_seq, $last_ttl, $orig_interval, $total_seconds, %to_do_hash, %seq_hash );

$orig_interval = 1000;


if ( ( $ARGV[0] ne "-s" ) && ( $ARGV[0] ne "-p" ) && ( $ARGV[0] ne "-r" ) ) {

	print "Usage: batman-debug4.pl option <file>\n";
	print "\t-p    packet statistic\n";
	print "\t-s    sequence number statistic\n";
	print "\t-r    routing statistic (not implemented yet)\n";
	exit;

}

if ( ! -e $ARGV[1] ) {

	print "B.A.T.M.A.N log file could not be found: $ARGV[1]\n";
	exit;

}


open(BATMANLOG, "< $ARGV[1]");

while ( <BATMANLOG> ) {

	if ( m/Received\ BATMAN\ packet\ from\ ([\d]+\.[\d]+\.[\d]+\.[\d]+).*?originator\ ([\d]+\.[\d]+\.[\d]+\.[\d]+),\ seqno ([\d]+),\ TTL ([\d]+)/ ) {

		$receive_hash{ $2 }{ $1 }{ "num_recv" }++;
		$last_orig = $2;
		$last_neigh = $1;
		$last_seq = $3;
		$last_ttl = $4;

	} elsif ( m/Forwarding\ packet\ \(originator\ ([\d]+\.[\d]+\.[\d]+\.[\d]+)/ ) {

		if ( $1 eq $last_orig ) {

# 			$receive_hash{ $last_orig }{ $last_neigh }{ "num_forw" }++;

		} elsif ( $myself_hash{ $1 } ) {

			$myself_hash{ $1 }{ "sent" }++

		} else {

			print "Not equal: $_ <> $1\n"

		}

	} elsif ( m/Drop\ packet:/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "num_drop" }++;

		if ( m/incompatible\ batman\ version/ ) {

			$receive_hash{ $last_orig }{ $last_neigh }{ "version" }++;

		} elsif ( m/received\ my\ own\ broadcast/ ) {

			$receive_hash{ $last_orig }{ $last_neigh }{ "own_broad" }++;

		} elsif ( m/originator\ packet\ from\ myself/ ) {

			$receive_hash{ $last_orig }{ $last_neigh }{ "own_rebroad" }++;

		} elsif ( m/originator\ packet\ with\ unidirectional\ flag/ ) {

			$receive_hash{ $last_orig }{ $last_neigh }{ "uni_flag" }++;

		} elsif ( m/received\ via\ unidirectional\ link/ ) {

			$receive_hash{ $last_orig }{ $last_neigh }{ "uni_link" }++;

		} elsif ( m/duplicate\ packet/ ) {

			$receive_hash{ $last_orig }{ $last_neigh }{ "dup" }++;

		}

	} elsif ( m/Forward packet:/ ) {

		$forward_hash{ $last_orig }{ $last_neigh }{ "num_forw" }++;

		if ( m/rebroadcast\ neighbour\ packet\ with\ direct\ link\ flag/ ) {

			$forward_hash{ $last_orig }{ $last_neigh }{ "direct_link" }++;

		} elsif ( m/rebroadcast\ neighbour\ packet\ with\ direct\ link\ and\ unidirectional\ flag/ ) {

			$forward_hash{ $last_orig }{ $last_neigh }{ "direct_uni" }++;

		} elsif ( m/rebroadcast\ orginator\ packet/ ) {

			$forward_hash{ $last_orig }{ $last_neigh }{ "rebroad" }++;

		} elsif ( m/duplicate\ packet\ received\ via\ best\ neighbour\ with\ best\ ttl/ ) {

			$forward_hash{ $last_orig }{ $last_neigh }{ "dup" }++;

		}

	} elsif ( m/update_originator/ ) {

		push( @{ $seq_hash{ $last_orig }{ $last_neigh } }, "$last_seq [$last_ttl]" );

	} elsif ( m/ttl\ exceeded/ ) {

		$receive_hash{ $last_orig }{ $last_neigh }{ "ttl" }++;

	} elsif ( m/Using\ interface\ (.*?)\ with\ address\ ([\d]+\.[\d]+\.[\d]+\.[\d]+)/ ) {

		$myself_hash{ $2 }{ "if" } = $1;

	} elsif ( m/orginator interval: ([\d]+)/ ) {

		$orig_interval = $1;

	} elsif ( m/\[.*\](.*)/ ) {

		$to_do_hash{ $1 }++;

	}

}


close( BATMANLOG );


if ( $ARGV[0] eq "-p" ) {

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
			$string .= " => $neighbour" . ( $myself_hash{ $neighbour } ? " (myself):\t" : ": \t\t" );
			$string .= " recv = " . $receive_hash{ $orginator }{ $neighbour }{ "num_recv" };
			$string .= " <> forw = " . ( $forward_hash{ $orginator }{ $neighbour }{ "num_forw" } ? $forward_hash{ $orginator }{ $neighbour }{ "num_forw" } : "0" );
			$string .= " <> drop = " . ( $receive_hash{ $orginator }{ $neighbour }{ "num_drop" } ? $receive_hash{ $orginator }{ $neighbour }{ "num_drop" } : "0" );
			$string .= " \t [ version = " . ( $receive_hash{ $orginator }{ $neighbour }{ "version" } ? $receive_hash{ $orginator }{ $neighbour }{ "version" } : "0" );
			$string .= "; own_broad = " . ( $receive_hash{ $orginator }{ $neighbour }{ "own_broad" } ? $receive_hash{ $orginator }{ $neighbour }{ "own_broad" } : "0" );
			$string .= "; own_rebroad = " . ( $receive_hash{ $orginator }{ $neighbour }{ "own_rebroad" } ? $receive_hash{ $orginator }{ $neighbour }{ "own_rebroad" } : "0" );
			$string .= "; uni_flag = " . ( $receive_hash{ $orginator }{ $neighbour }{ "uni_flag" } ? $receive_hash{ $orginator }{ $neighbour }{ "uni_flag" } : "0" );
			$string .= "; uni_link = " . ( $receive_hash{ $orginator }{ $neighbour }{ "uni_link" } ? $receive_hash{ $orginator }{ $neighbour }{ "uni_link" } : "0" );
			$string .= "; dup = " . ( $receive_hash{ $orginator }{ $neighbour }{ "dup" } ? $receive_hash{ $orginator }{ $neighbour }{ "dup" } : "0" );
			$string .= "; ttl = " . ( $receive_hash{ $orginator }{ $neighbour }{ "ttl" } ? $receive_hash{ $orginator }{ $neighbour }{ "ttl" } : "0" ) . " ]";
			$string .= " [ direct_link = " . ( $forward_hash{ $orginator }{ $neighbour }{ "direct_link" } ? $forward_hash{ $orginator }{ $neighbour }{ "direct_link" } : "0" );
			$string .= "; direct_uni = " . ( $forward_hash{ $orginator }{ $neighbour }{ "direct_uni" } ? $forward_hash{ $orginator }{ $neighbour }{ "direct_uni" } : "0" );
			$string .= "; rebroad = " . ( $forward_hash{ $orginator }{ $neighbour }{ "rebroad" } ? $forward_hash{ $orginator }{ $neighbour }{ "rebroad" } : "0" );
			$string .= "; dup = " . ( $forward_hash{ $orginator }{ $neighbour }{ "dup" } ? $forward_hash{ $orginator }{ $neighbour }{ "dup" } : "0" ) . " ]\n";

		}

		print "\norginator $orginator" . ( $myself_hash{ $orginator } ? " (myself)" : "" ) . ": total recv = $sum\n";
		print $string;

	}

	print "\n\nHelp:\n^^^^\n";
	print " Dropped packets:\n";
	print "\tversion     = received packet indicated incompatible batman version\n";
	print "\town_broad   = received my own broadcast\n";
	print "\town_rebroad = received rebroadcast of my packet via neighbour\n";
	print "\tuni_flag    = received packet with unidrectional flag\n";
	print "\tuni_link    = received packet via unidirectional link\n";
	print "\tdup         = received packet is a duplicate\n\n";
	print "\tttl         = ttl of packet exceeded\n\n";

	print " Forwarded packets:\n";
	print "\tdirect_link = forwarded packet with direct_link flag\n";
	print "\tdirect_uni  = forwarded packet with direct_link and unidirectional flag\n";
	print "\trebroad     = just rebroadcast packet\n";
	print "\tdup         = rebroadcast packet allthough it is a duplicate\n";

} elsif ( $ARGV[0] eq "-s" ) {

	foreach my $orginator ( keys %seq_hash ) {

		print "\n\nOrginator: $orginator\n^^^^^^^^^\n";

		foreach my $neighbour ( keys %{ $seq_hash{ $orginator } } ) {

			print "\nNeighbour: $neighbour\n";

			foreach my $seqno ( @{ $seq_hash{ $orginator }{ $neighbour } } ) {

				print "$seqno ";

			}

			print "\n";

		}

	}

}



foreach my $todo ( keys %to_do_hash ) {

	print "ToDo: $todo -> $to_do_hash{ $todo }\n" if ( $to_do_hash{ $todo } > 2 );

}
