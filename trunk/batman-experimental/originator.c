/* Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Simon Wunderlich, Marek Lindner, Axel Neumann
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "os.h"
#include "batman.h"
#include "originator.h"



/* needed for hash, compares 2 struct orig_node, but only their ip-addresses. assumes that
 * the ip address is the first field in the struct */
int compare_orig( void *data1, void *data2 ) {

	return ( memcmp( data1, data2, 4 ) );

}



/* hashfunction to choose an entry in a hash table of given size */
/* hash algorithm from http://en.wikipedia.org/wiki/Hash_table */
int choose_orig( void *data, int32_t size ) {

	unsigned char *key= data;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < 4; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return (hash%size);

}



/* this function finds or creates an originator entry for the given address if it does not exits */
struct orig_node *get_orig_node( uint32_t addr ) {

	prof_start( PROF_get_orig_node );
	struct orig_node *orig_node;
	struct hashtable_t *swaphash;
	static char orig_str[ADDR_STR_LEN];
	size_t i;


	orig_node = ((struct orig_node *)hash_find( orig_hash, &addr ));

	if ( orig_node != NULL ) {

		prof_stop( PROF_get_orig_node );
		return orig_node;

	}


	addr_to_string( addr, orig_str, ADDR_STR_LEN );
	debug_output( 4, "Creating new originator: %s \n", orig_str );

	orig_node = debugMalloc( sizeof(struct orig_node), 401 );
	memset(orig_node, 0, sizeof(struct orig_node));
	INIT_LIST_HEAD_FIRST( orig_node->neigh_list );

	orig_node->orig = addr;
	orig_node->router = NULL;
	orig_node->batman_if = NULL;

	orig_node->bidirect_link = debugMalloc( found_ifs * sizeof(uint16_t), 402 );
	memset( orig_node->bidirect_link, 0, found_ifs * sizeof(uint16_t) );
	
	orig_node->bi_link_bits = NULL;
	orig_node->last_bi_link_seqno = NULL;	
	orig_node->lq_bits = NULL;
	
	
	/*TODO: 
	this actually just postpones the problem to the moment of wrap-arounds but its probably less confusing in the beginning!
	if orig_node->bidirect_link[i] is regulary updated with
	 ((uint16_t) (if_incoming->out.bat_packet.seqno - OUT_SEQNO_OFFSET - bidirect_link_to)); 
	it may work !
	*/
	for ( i=0; i<found_ifs; i++ ) {
		orig_node->bidirect_link[i] = ((uint16_t) (0 - OUT_SEQNO_OFFSET - bidirect_link_to)); 
	}
	
	hash_add( orig_hash, orig_node );

	if ( orig_hash->elements * 4 > orig_hash->size ) {

		swaphash = hash_resize( orig_hash, orig_hash->size * 2 );

		if ( swaphash == NULL ) {

			debug_output( 0, "Couldn't resize hash table \n" );
			restore_and_exit(0);

		}

		orig_hash = swaphash;

	}

	prof_stop( PROF_get_orig_node );
	return orig_node;

}



void update_orig( struct orig_node *orig_node, struct bat_packet *in, uint32_t neigh, struct batman_if *if_incoming, unsigned char *hna_recv_buff, int16_t hna_buff_len, uint32_t rcvd_time ) {

	prof_start( PROF_update_originator );
	struct list_head *neigh_pos;
	struct neigh_node *neigh_node = NULL, *tmp_neigh_node = NULL, *best_neigh_node = NULL;
	uint8_t max_packet_count = 0, is_new_seqno = 0; // TBD: check max_packet_count for overflows if MAX_SEQ_RANGE > 256
	

	debug_output( 4, "update_originator(): Searching and updating originator entry of received packet,  \n" );


	list_for_each( neigh_pos, &orig_node->neigh_list ) {

		tmp_neigh_node = list_entry( neigh_pos, struct neigh_node, list );

		if ( ( tmp_neigh_node->addr == neigh ) && ( tmp_neigh_node->if_incoming == if_incoming ) ) {

			neigh_node = tmp_neigh_node;

		} else {

			bit_get_packet( tmp_neigh_node->seq_bits, in->seqno - orig_node->last_seqno, 0 );
			tmp_neigh_node->packet_count = bit_packet_count( tmp_neigh_node->seq_bits, sequence_range );

			/* if we got more packets via this neighbour or same amount of packets if it is currently our best neighbour (to avoid route flipping) */
			if ( ( tmp_neigh_node->packet_count > max_packet_count ) || ( ( orig_node->router == tmp_neigh_node ) && ( tmp_neigh_node->packet_count >= max_packet_count ) ) ) {

				max_packet_count = tmp_neigh_node->packet_count;
				best_neigh_node = tmp_neigh_node;

			}

		}

	}

	if ( neigh_node == NULL ) {

		debug_output( 4, "Creating new last-hop neighbour of originator\n" );

		neigh_node = debugMalloc( sizeof (struct neigh_node), 403 );
		memset( neigh_node, 0, sizeof(struct neigh_node) );
		INIT_LIST_HEAD( &neigh_node->list );

		neigh_node->addr = neigh;
		neigh_node->if_incoming = if_incoming;

		list_add_tail( &neigh_node->list, &orig_node->neigh_list );

	} else {

		debug_output( 4, "Updating existing last-hop neighbour of originator\n" );

	}

	is_new_seqno = bit_get_packet( neigh_node->seq_bits, in->seqno - orig_node->last_seqno, 1 );
	neigh_node->packet_count = bit_packet_count( neigh_node->seq_bits, sequence_range );

	if ( neigh_node->packet_count > max_packet_count ) {

		max_packet_count = neigh_node->packet_count;
		best_neigh_node = neigh_node;

	}

	/* this is for remembering the actual re-broadcasted non-unidirectional OGMs */
	bit_get_packet( orig_node->send_old_seq_bits, in->seqno - orig_node->last_seqno, 0 );

	
	orig_node->last_valid = rcvd_time;
	neigh_node->last_valid = rcvd_time;

	if ( is_new_seqno ) {

		debug_output( 4, "updating last_seqno: old %d, new %d \n", orig_node->last_seqno, in->seqno  );

		orig_node->last_seqno = in->seqno;
		neigh_node->last_ttl = in->ttl;

	}

	
	if( penalty_min > 0 ) {
		
		uint16_t max_penalty_count, challenger_penalty_count, penalty_round;
		struct neigh_node *max_penalty_neigh;
		
		for( penalty_round = 0; penalty_round < sequence_range; penalty_round++ ) {
		
			max_penalty_count = challenger_penalty_count = 0;
			max_penalty_neigh = NULL;
			
			list_for_each( neigh_pos, &orig_node->neigh_list ) {
		
				tmp_neigh_node = list_entry( neigh_pos, struct neigh_node, list );
		
				if ( penalty_round == 0 )
					tmp_neigh_node->penalty_count = 0;
				
//				if ( tmp_neigh_node->penalty_count < tmp_neigh_node->packet_count ) {
					
					if ( get_bit_status( tmp_neigh_node->seq_bits, orig_node->last_seqno, (orig_node->last_seqno - penalty_round) ) )
						tmp_neigh_node->penalty_count++;
						
					if ( tmp_neigh_node->penalty_count > max_penalty_count ) {
						
						challenger_penalty_count = max_penalty_count;
							
						max_penalty_count = tmp_neigh_node->penalty_count;
						max_penalty_neigh = tmp_neigh_node;
					
					} else if ( tmp_neigh_node->penalty_count > challenger_penalty_count ) {
				
						challenger_penalty_count = tmp_neigh_node->penalty_count;
						
					}
//				}
			}
			
			if ( orig_node->router == NULL ) {
				
				best_neigh_node = max_penalty_neigh;
				break;
			
			} else if ( ( max_penalty_neigh == orig_node->router && max_penalty_count > challenger_penalty_count) || orig_node->router->penalty_count >= penalty_min ) {
				
				best_neigh_node = orig_node->router;
				break;
				
			} else if ( max_penalty_count >= penalty_min && max_penalty_count >= orig_node->router->penalty_count + penalty_exceed ) {
				
				best_neigh_node = max_penalty_neigh;
				break;
				
			}
		}
	}
	
	
	
	
	
	/* update routing table and check for changed hna announcements */
	update_routes( orig_node, best_neigh_node, hna_recv_buff, hna_buff_len );

	if ( orig_node->gwflags != in->gwflags )
		update_gw_list( orig_node, in->gwflags );

	orig_node->gwflags = in->gwflags;

	prof_stop( PROF_update_originator );

}



void purge_orig( uint32_t curr_time ) {

	prof_start( PROF_purge_originator );
	struct hash_it_t *hashit = NULL;
	struct list_head *neigh_pos, *neigh_temp, *prev_list_head;
	struct list_head *gw_pos, *gw_pos_tmp;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node, *best_neigh_node;
	struct gw_node *gw_node;
	uint8_t gw_purged = 0, neigh_purged;
	static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];
	struct list_head *if_pos;
	struct batman_if *batman_if;
	uint8_t free_bi_link_bits, free_lq_bits;
	
	/* for all origins... */
	while ( NULL != ( hashit = hash_iterate( orig_hash, hashit ) ) ) {

		orig_node = hashit->bucket->data;
		
		if ( orig_node->bi_link_bits != NULL ) {
			
			free_bi_link_bits = YES;
			
			list_for_each( if_pos, &if_list ) {
				
				batman_if = list_entry( if_pos, struct batman_if, list );
				
				if ( update_bi_link_bits ( orig_node, batman_if, NO, sequence_range ) > 0 ) {
					free_bi_link_bits = NO;
					break;
				}
			}
			
			if ( free_bi_link_bits == YES ) {

				if( orig_node->bi_link_bits != NULL ) { 
					debugFree( orig_node->bi_link_bits, 1406 );
					orig_node->bi_link_bits = NULL;
				}
				
				if( orig_node->last_bi_link_seqno != NULL ) {
					debugFree( orig_node->last_bi_link_seqno, 1407 );
					orig_node->last_bi_link_seqno = NULL;
				}
			}

		}
		
		if ( orig_node->lq_bits != NULL ) {
			
			free_lq_bits = YES;
			
			list_for_each( if_pos, &if_list ) {
				
				batman_if = list_entry( if_pos, struct batman_if, list );
				
				if ( update_lq_bits( orig_node, NO, NO, batman_if, NO, sequence_range ) > 0 ) {
					free_lq_bits = NO;
					break;
				}
			}
			
			if ( free_lq_bits == YES ) {

				if( orig_node->lq_bits != NULL ) { 
					debugFree( orig_node->lq_bits, 1408 );
					orig_node->lq_bits = NULL;
				}
			}			
			
		}
		
		if ( (int)( ( orig_node->last_valid + PURGE_TIMEOUT ) < curr_time ) ) {

			addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
			debug_output( 4, "Originator timeout: originator %s, last_valid %u \n", orig_str, orig_node->last_valid );

			hash_remove_bucket( orig_hash, hashit );

			/* for all neighbours towards this originator ... */
			list_for_each_safe( neigh_pos, neigh_temp, &orig_node->neigh_list ) {

				neigh_node = list_entry(neigh_pos, struct neigh_node, list);

				list_del( (struct list_head *)&orig_node->neigh_list, neigh_pos, &orig_node->neigh_list );
				debugFree( neigh_node, 1401 );

			}

			list_for_each( gw_pos, &gw_list ) {

				gw_node = list_entry( gw_pos, struct gw_node, list );

				if ( gw_node->deleted )
					continue;

				if ( gw_node->orig_node == orig_node ) {

					addr_to_string( gw_node->orig_node->orig, orig_str, ADDR_STR_LEN );
					debug_output( 3, "Removing gateway %s from gateway list \n", orig_str );

					gw_node->deleted = get_time();

					gw_purged = 1;

					break;

				}

			}

			update_routes( orig_node, NULL, NULL, 0 );
			
			if( orig_node->bi_link_bits != NULL ) { 
				debugFree( orig_node->bi_link_bits, 1406 );
				orig_node->bi_link_bits = NULL;
			}
				
			if( orig_node->last_bi_link_seqno != NULL ) {
				debugFree( orig_node->last_bi_link_seqno, 1407 );
				orig_node->last_bi_link_seqno = NULL;
			}
			
			if( orig_node->lq_bits != NULL ) {
				debugFree( orig_node->lq_bits, 1408 );
				orig_node->lq_bits = NULL;
			}
			
			debugFree( orig_node->bidirect_link, 1402 );
			debugFree( orig_node, 1403 );

		} else {

			best_neigh_node = NULL;
			neigh_purged = 0;
			prev_list_head = (struct list_head *)&orig_node->neigh_list;

			/* for all neighbours towards this originator ... */
			list_for_each_safe( neigh_pos, neigh_temp, &orig_node->neigh_list ) {

				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if ( (int)( ( neigh_node->last_valid + PURGE_TIMEOUT ) < curr_time ) ) {

					addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
					addr_to_string( neigh_node->addr, neigh_str, ADDR_STR_LEN );
					debug_output( 4, "Neighbour timeout: originator %s, neighbour: %s, last_valid %u \n", orig_str, neigh_str, neigh_node->last_valid );

					if ( orig_node->router == neigh_node ) {

						/* we have to delete the route towards this node before it gets purged */
						debug_output( 4, "Deleting previous route \n" );

						/* remove old announced network(s) */
						if ( orig_node->hna_buff_len > 0 )
							add_del_hna( orig_node, 1 );

						add_del_route( orig_node->orig, 32, orig_node->router->addr, orig_node->batman_if->if_index, orig_node->batman_if->dev, BATMAN_RT_TABLE_HOSTS, 0, 1 );

						orig_node->router = NULL;

					}

					neigh_purged = 1;
					list_del( prev_list_head, neigh_pos, &orig_node->neigh_list );
					debugFree( neigh_node, 1404 );

				} else {

					if ( ( best_neigh_node == NULL ) || ( neigh_node->packet_count > best_neigh_node->packet_count ) )
						best_neigh_node = neigh_node;

					prev_list_head = &neigh_node->list;

				}

			}

			if ( ( neigh_purged ) && ( ( best_neigh_node == NULL ) || ( orig_node->router == NULL ) || ( best_neigh_node->packet_count > orig_node->router->packet_count ) ) )
				update_routes( orig_node, best_neigh_node, orig_node->hna_buff, orig_node->hna_buff_len );

		}

	}


	prev_list_head = (struct list_head *)&gw_list;

	list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

		gw_node = list_entry(gw_pos, struct gw_node, list);

		if ( ( gw_node->deleted ) && ( (int)((gw_node->deleted + (2 * PURGE_TIMEOUT)) < curr_time) ) ) {

			list_del( prev_list_head, gw_pos, &gw_list );
			debugFree( gw_pos, 1405 );

		} else {

			prev_list_head = &gw_node->list;

		}

	}

	prof_stop( PROF_purge_originator );

	if ( gw_purged )
		choose_gw();

}


/* set update to YES only with new valid in_seqno */
int update_lq_bits( struct orig_node *orig_node, uint8_t update, uint16_t in_seqno, struct batman_if *this_if, uint8_t direct_undupl_neigh_ogm, uint16_t read_range ) {
	
	uint8_t is_new_lq_seqno = 0;
	int i, ret_pcnt;
	
	
	debug_output( 4, "update_lq_bits(): \n" );
	
	if ( direct_undupl_neigh_ogm && orig_node->lq_bits == NULL ) {
		orig_node->lq_bits = debugMalloc( found_ifs * MAX_NUM_WORDS * sizeof( TYPE_OF_WORD ), 408 );
		memset( orig_node->lq_bits, 0, found_ifs * MAX_NUM_WORDS * sizeof( TYPE_OF_WORD ) );
	}
	
	if ( orig_node->lq_bits != NULL ) {
		
		if ( update ) {
		
			for( i=0; i < found_ifs; i++ ) {
				is_new_lq_seqno = 
//						bit_get_packet( (orig_node->lq_bits + ( i * MAX_NUM_WORDS * sizeof( TYPE_OF_WORD ))),
						bit_get_packet( (&orig_node->lq_bits[ i * MAX_NUM_WORDS ]),
								( in_seqno - orig_node->last_lq_seqno ),
						( ( direct_undupl_neigh_ogm && this_if->if_num == i ) ? 1 : 0 ) );
			}
			
			if ( is_new_lq_seqno ) 
				orig_node->last_lq_seqno = in_seqno;
			
		}
		
		if ( read_range > 0 ) {
			
//			ret_pcnt = bit_packet_count( (orig_node->lq_bits + (this_if->if_num * MAX_NUM_WORDS * sizeof( TYPE_OF_WORD )) ), read_range  ); /* not perfect until sequence_range OGMs have been send by neighbor */
			ret_pcnt = bit_packet_count( ( &orig_node->lq_bits[ this_if->if_num * MAX_NUM_WORDS ] ), read_range  ); /* not perfect until sequence_range OGMs have been send by neighbor */
			
			return ret_pcnt;
		}
		
	}
	
	return -1;

}



int update_bi_link_bits ( struct orig_node *orig_neigh_node, struct batman_if * this_if, uint8_t write, uint16_t read_range ) {
	
	uint8_t is_new_bi_link_seqno;				
	int rcvd_bi_link_packets = -1;
	
	debug_output( 4, "update_bi_link_bits(): \n" );

	if( write ) { 
		if ( orig_neigh_node->bi_link_bits == NULL ) {
			orig_neigh_node->bi_link_bits = debugMalloc( found_ifs * MAX_NUM_WORDS * sizeof( TYPE_OF_WORD ), 406 );
			memset( orig_neigh_node->bi_link_bits, 0, found_ifs * MAX_NUM_WORDS * sizeof( TYPE_OF_WORD ) );
		}
		
		if ( orig_neigh_node->last_bi_link_seqno == NULL ) {
			orig_neigh_node->last_bi_link_seqno = debugMalloc( found_ifs * sizeof(uint16_t), 407 );
			memset( orig_neigh_node->last_bi_link_seqno, 0, found_ifs * sizeof(uint16_t) );
		}
	}
	
	if ( orig_neigh_node->bi_link_bits != NULL && orig_neigh_node->last_bi_link_seqno != NULL ) {
	
		is_new_bi_link_seqno = bit_get_packet( 
				( &orig_neigh_node->bi_link_bits[ this_if->if_num * MAX_NUM_WORDS ] ),
				( ( this_if->out.bat_packet.seqno - OUT_SEQNO_OFFSET ) - orig_neigh_node->last_bi_link_seqno[this_if->if_num] ),
					( ( write ) ? 1 : 0) );
	
		if ( is_new_bi_link_seqno ) 
			orig_neigh_node->last_bi_link_seqno[this_if->if_num] = ( this_if->out.bat_packet.seqno - OUT_SEQNO_OFFSET );
		
		if ( read_range > 0 ) {
			
			rcvd_bi_link_packets = bit_packet_count( ( &orig_neigh_node->bi_link_bits[ this_if->if_num * MAX_NUM_WORDS ] ), read_range ); /*TBD: not perfect until sequence_range OGMs have been send */
			
		}
		
		return rcvd_bi_link_packets;
	
	}	

	return -1;
	
}

int nlq_rate( struct orig_node *orig_neigh_node, struct batman_if *if_incoming ) {
	
	int l2q, lq, nlq;
	
	l2q = update_bi_link_bits( orig_neigh_node, if_incoming, NO, sequence_range );

	lq = update_lq_bits( orig_neigh_node, YES, orig_neigh_node->last_seqno, if_incoming, NO, sequence_range );
	
	if ( l2q <= 0 || lq <= 0 ) return 0;
	
	nlq = ( (sequence_range * l2q ) / lq ) - 1;
	
	return ( (nlq >= (sequence_range - 1)) ? (sequence_range - 1) : nlq );
	
}


int nlq_power( int nlq_rate_value ) {
	
	int nlq_power_value = sequence_range;
	int exp_counter;
	for ( exp_counter = 0; exp_counter <= asymmetric_exp; exp_counter++ )
		nlq_power_value = ((nlq_power_value * nlq_rate_value) / sequence_range);

	return nlq_power_value;

}
					

int acceptance( int nlq_assumption, uint16_t lq_assumtion ) {
	
	return ( nlq_power( nlq_assumption ) * lq_assumtion / sequence_range );

}


void debug_orig() {

	struct hash_it_t *hashit = NULL;
	struct list_head *forw_pos, *orig_pos, *neigh_pos;
	struct forw_node *forw_node;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct gw_node *gw_node;
	uint16_t batman_count = 0;
	uint32_t uptime_sec;
	static char str[ADDR_STR_LEN], str2[ADDR_STR_LEN], orig_str[ADDR_STR_LEN];
	int dbg_ogm_out = 0, lq, nlq;
	static char dbg_ogm_str[MAX_DBG_STR_SIZE + 1]; // TBD: must be checked for overflow when using with sprintf


	if ( debug_clients.clients_num[1] > 0 ) {

		debug_output( 2, "BOD\n" );

		if ( list_empty( &gw_list ) ) {

			debug_output( 2, "No gateways in range ... \n" );

		} else {

			debug_output( 2, "%12s     %15s (%s/%i) \n", "Gateway", "Router", "#", sequence_range );  

			list_for_each( orig_pos, &gw_list ) {

				gw_node = list_entry( orig_pos, struct gw_node, list );

				if ( gw_node->deleted )
					continue;

				addr_to_string( gw_node->orig_node->orig, str, sizeof (str) );
				addr_to_string( gw_node->orig_node->router->addr, str2, sizeof (str2) );

				if ( curr_gateway == gw_node ) {
					debug_output( 2, "=> %-15s %15s (%3i), gw_class %2i - %s, reliability: %i \n", str, str2, gw_node->orig_node->router->packet_count, gw_node->orig_node->gwflags, gw2string[gw_node->orig_node->gwflags], gw_node->unavail_factor );
				} else {
					debug_output( 2, "   %-15s %15s (%3i), gw_class %2i - %s, reliability: %i \n", str, str2, gw_node->orig_node->router->packet_count, gw_node->orig_node->gwflags, gw2string[gw_node->orig_node->gwflags], gw_node->unavail_factor );
				}

				batman_count++;

			}

			if ( batman_count == 0 )
				debug_output( 2, "No gateways in range ... \n" );

		}

		debug_output( 2, "EOD\n" );

	}

	if ( ( debug_clients.clients_num[0] > 0 ) || ( debug_clients.clients_num[3] > 0 ) ) {

		addr_to_string( ((struct batman_if *)if_list.next)->addr.sin_addr.s_addr, orig_str, sizeof(orig_str) );
		uptime_sec = (uint32_t)( get_time() / 1000 );

		debug_output( 1, "BOD \n" );
		
		debug_output( 1, "  %-12s %11s (%3i/new/old plcy l2q lq  nlq lseq lvld): %20s... [B.A.T.M.A.N. %s%s, MainIF/IP: %s %s, BLT: %i, OGI: %i, UT: %id%2ih%2im] \n",
			      "Originator", "Router", 
			      sequence_range, "Potential routers", 
			      SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), 
			      ((struct batman_if *)if_list.next)->dev, orig_str, 
			      bidirect_link_to, originator_interval,
			      uptime_sec/86400, ((uptime_sec%86400)/3600), ((uptime_sec)%3600)/60  );
		
		
		
		if ( debug_clients.clients_num[3] > 0 ) {

			debug_output( 4, "------------------ DEBUG ------------------ \n" );
			debug_output( 4, "Forward list \n" );

			list_for_each( forw_pos, &forw_list ) {
				forw_node = list_entry( forw_pos, struct forw_node, list );
				addr_to_string( ((struct orig_packet *)forw_node->pack_buff)->bat_packet.orig, str, sizeof (str) );
				debug_output( 4, "    %s at %u \n", str, forw_node->send_time );
			}

			debug_output( 4, "Originator list \n" );
			debug_output( 4, "  %-12s %14s (%s/%3i %9s): %20s\n", "Originator", "Router", "#", sequence_range, "lastvalid", "Potential routers" );

		}

		while ( NULL != ( hashit = hash_iterate( orig_hash, hashit ) ) ) {

			orig_node = hashit->bucket->data;

			if ( orig_node->router == NULL )
				continue;

			batman_count++;

			addr_to_string( orig_node->orig, str, sizeof (str) );
			addr_to_string( orig_node->router->addr, str2, sizeof (str2) );
			
			lq = update_lq_bits( orig_node, YES, orig_node->last_seqno, orig_node->router->if_incoming, NO, sequence_range ), /* lq */
							
			nlq = nlq_rate( orig_node, orig_node->router->if_incoming ), /* nlq */
			
			
			dbg_ogm_out = snprintf( dbg_ogm_str, MAX_DBG_STR_SIZE, "%-15s %15s (%3i %2i %3i %3i %3i %3i %5i %5i):", str, str2, 
					orig_node->router->packet_count, /* new */
					bit_packet_count( orig_node->send_old_seq_bits, sequence_range ), /* old  */
					
					acceptance( nlq, lq ),	
					
					update_bi_link_bits( orig_node, orig_node->router->if_incoming, NO, sequence_range ), /* l2q */
					
					lq, nlq,
					
					orig_node->last_seqno,
					( get_time() - orig_node->last_valid ) );
//			debug_output( 1, "%-15s %''15s (%3i):", str, str2, orig_node->router->packet_count );
//			debug_output( 4, "%''15s %''15s (%3i), last_valid: %u: \n", str, str2, orig_node->router->packet_count, orig_node->last_valid );

			list_for_each( neigh_pos, &orig_node->neigh_list ) {
				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if( neigh_node->addr != orig_node->router->addr ) {
					addr_to_string( neigh_node->addr, str, sizeof (str) );

					dbg_ogm_out = dbg_ogm_out + snprintf( (dbg_ogm_str + dbg_ogm_out), (MAX_DBG_STR_SIZE - dbg_ogm_out), " %15s (%3i)", str, neigh_node->packet_count );
//					debug_output( 1, " %''15s (%3i)", str, neigh_node->packet_count );
//					debug_output( 4, "\t\t%''15s (%3i) \n", str, neigh_node->packet_count );
				}
			}

			debug_output( 1, "%s \n", dbg_ogm_str );
			debug_output( 4, "%s \n", dbg_ogm_str );
//			debug_output( 1, " \n" );

		}

		if ( batman_count == 0 ) {

			debug_output( 1, "No batman nodes in range ... \n" );
			debug_output( 4, "No batman nodes in range ... \n" );

		}

		debug_output( 1, "EOD\n" );
		debug_output( 4, "---------------------------------------------- END DEBUG \n" );

	}

}


