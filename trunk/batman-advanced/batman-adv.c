/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann,
 * Felix Fietkau, Marek Lindner, Simon Wunderlich
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



#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "os.h"
#include "list.h"
#include "batman-adv.h"
#include "allocate.h"
#include "hash.h"

/* "-d" is the command line switch for the debug level,
 * specify it multiple times to increase verbosity
 * 0 gives a minimum of messages to save CPU-Power
 * 1 normal
 * 2 verbose
 * 3 very verbose
 * Beware that high debugging levels eat a lot of CPU-Power
 */

uint8_t debug_level = 0;

/* "-g" is the command line switch for the gateway class,
 * 0 no gateway
 * 1 modem
 * 2 ISDN
 * 3 Double ISDN
 * 3 256 KBit
 * 5 UMTS/ 0.5 MBit
 * 6 1 MBit
 * 7 2 MBit
 * 8 3 MBit
 * 9 5 MBit
 * 10 6 MBit
 * 11 >6 MBit
 * this option is used to determine packet path
 */

char *gw2string[] = { "No Gateway",
                      "56 KBit (e.g. Modem)",
                      "64 KBit (e.g. ISDN)",
                      "128 KBit (e.g. double ISDN)",
                      "256 KBit",
                      "512 KBit (e.g. UMTS)",
                      "1 MBit",
                      "2 MBit",
                      "3 MBit",
                      "5 MBit",
                      "6 MBit",
                      ">6 MBit" };

uint8_t gateway_class = 0;

/* "-r" is the command line switch for the routing class,
 * 0 set no default route
 * 1 use fast internet connection
 * 2 use stable internet connection
 * 3 use use best statistic (olsr style)
 * this option is used to set the routing behaviour
 */

uint8_t routing_class = 0;


int16_t orginator_interval = 1000;   /* orginator message interval in miliseconds */

uint32_t bidirectional_timeout = 0;   /* bidirectional neighbour reply timeout in ms */

struct gw_node *curr_gateway = NULL;
pthread_t curr_gateway_thread_id = 0;

uint32_t pref_gateway = 0;

uint8_t found_ifs = 0;
int32_t receive_max_sock = 0;
fd_set receive_wait_set;
int32_t tap_sock = 0;
uint8_t my_hw_addr[6];

unsigned char broadcastAddr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


/* static LIST_HEAD(orig_list); 		XXX: obsolete with hashing */
struct hashtable_t *orig_hash;

static LIST_HEAD(forw_list);
static LIST_HEAD(gw_list);
LIST_HEAD(if_list);

// struct vis_if vis_if;
struct unix_if unix_if;
struct debug_clients debug_clients;



void usage( void ) {

	fprintf( stderr, "Usage: batman [options] interface [interface interface]\n" );
	fprintf( stderr, "       -b run connection in batch mode\n" );
	fprintf( stderr, "       -c connect via unix socket\n" );
	fprintf( stderr, "       -d debug level\n" );
	fprintf( stderr, "       -g gateway class\n" );
	fprintf( stderr, "       -h this help\n" );
	fprintf( stderr, "       -H verbose help\n" );
	fprintf( stderr, "       -o orginator interval in ms\n" );
	fprintf( stderr, "       -p preferred gateway\n" );
	fprintf( stderr, "       -r routing class\n" );
	fprintf( stderr, "       -s visualisation server\n" );
	fprintf( stderr, "       -v print version\n" );

}



void verbose_usage( void ) {

	fprintf( stderr, "Usage: batman [options] interface [interface interface]\n\n" );
	fprintf( stderr, "       -b run connection in batch mode\n" );
	fprintf( stderr, "       -c connect to running batmand via unix socket\n" );
	fprintf( stderr, "       -d debug level\n" );
	fprintf( stderr, "          default:         0 -> debug disabled\n" );
	fprintf( stderr, "          allowed values:  1 -> list neighbours\n" );
	fprintf( stderr, "                           2 -> list gateways\n" );
	fprintf( stderr, "                           3 -> observe batman\n" );
	fprintf( stderr, "                           4 -> observe batman (very verbose)\n\n" );
	fprintf( stderr, "       -g gateway class\n" );
	fprintf( stderr, "          default:         0 -> this is not an internet gateway\n" );
	fprintf( stderr, "          allowed values:  1 -> modem line\n" );
	fprintf( stderr, "                           2 -> ISDN line\n" );
	fprintf( stderr, "                           3 -> double ISDN\n" );
	fprintf( stderr, "                           4 -> 256 KBit\n" );
	fprintf( stderr, "                           5 -> UMTS / 0.5 MBit\n" );
	fprintf( stderr, "                           6 -> 1 MBit\n" );
	fprintf( stderr, "                           7 -> 2 MBit\n" );
	fprintf( stderr, "                           8 -> 3 MBit\n" );
	fprintf( stderr, "                           9 -> 5 MBit\n" );
	fprintf( stderr, "                          10 -> 6 MBit\n" );
	fprintf( stderr, "                          11 -> >6 MBit\n\n" );
	fprintf( stderr, "       -h shorter help\n" );
	fprintf( stderr, "       -H this help\n" );
	fprintf( stderr, "       -o orginator interval in ms\n" );
	fprintf( stderr, "          default: 1000, allowed values: >0\n\n" );
	fprintf( stderr, "       -p preferred gateway\n" );
	fprintf( stderr, "          default: none, allowed values: IP\n\n" );
	fprintf( stderr, "       -r routing class (only needed if gateway class = 0)\n" );
	fprintf( stderr, "          default:         0 -> set no default route\n" );
	fprintf( stderr, "          allowed values:  1 -> use fast internet connection\n" );
	fprintf( stderr, "                           2 -> use stable internet connection\n" );
	fprintf( stderr, "                           3 -> use best statistic internet connection (olsr style)\n\n" );
	fprintf( stderr, "       -s visualisation server\n" );
	fprintf( stderr, "          default: none, allowed values: IP\n\n" );
	fprintf( stderr, "       -v print version\n" );

}
/* needed for hash, compares 2 struct orig_node, but only their mac-addresses. assumes that
 * the mac address is the first field in the struct */
int orig_comp(void *data1, void *data2) {
	return(memcmp(data1, data2, 6));
}

/* hashfunction to choose an entry in a hash table of given size */
/* hash algorithm from http://en.wikipedia.org/wiki/Hash_table */
int orig_choose(void *data, int size) {
	unsigned char *key= data;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < 6; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return (hash%size);
}

/* free the data when hash_delete is called. */
void orig_free(void *data) {
	/* TODO: free nodes when destroying the hash, or leak the memory. :( */
}

struct orig_node *find_orig_node( uint8_t *addr ) {
	return((struct orig_node *) hash_find( orig_hash, addr ));
		/* addr is supposed to be the first entry in the struct orig_node entry, so
		 * we don't allocate and copy into a new struct orig_node. should be enough for comparing. */

}
/* XXX: obsolete with hash structure */
/*
struct orig_node *find_orig_node( uint8_t *addr ) {
	struct list_head *pos;
	struct orig_node *orig_node;

	list_for_each( pos, &orig_list ) {

		orig_node = list_entry( pos, struct orig_node, list );

		if ( memcmp( &orig_node->orig, addr, sizeof(orig_node->orig) ) == 0 )
			return orig_node;

	}

	return NULL;

}
*/


/* this function finds or creates an originator entry for the given address if it does not exits */
struct orig_node *get_orig_node( uint8_t *addr ) {

	struct orig_node *orig_node = find_orig_node( addr );

	if ( orig_node != NULL )
		return orig_node;

	debug_output( 4, "Creating new originator\n" );

	orig_node = debugMalloc( sizeof(struct orig_node), 1 );
	memset(orig_node, 0, sizeof(struct orig_node));
	INIT_LIST_HEAD(&orig_node->list);
	INIT_LIST_HEAD(&orig_node->neigh_list);

	memcpy( &orig_node->orig, addr, sizeof(orig_node->orig) );
	orig_node->router = NULL;
	orig_node->batman_if = NULL;

	orig_node->bidirect_link = debugMalloc( found_ifs * sizeof(uint32_t), 2 );
	memset( orig_node->bidirect_link, 0, found_ifs * sizeof(uint32_t) );

	hash_add(orig_hash, orig_node);
	if (orig_hash->elements * 4 > orig_hash->size) {
		struct hashtable_t *swaphash;
		swaphash = hash_resize(orig_hash, orig_hash->size*2);
		if (swaphash == NULL)
			debug_output( 0, "Couldn't resize hash table\n" );
		else
			orig_hash = swaphash;

	}
/*	list_add_tail( &orig_node->list, &orig_list );		XXX: obsolete wiht hash structure */

	return orig_node;

}



// static void choose_gw() {
//
// 	struct list_head *pos;
// 	struct gw_node *gw_node, *tmp_curr_gw = NULL;
// 	uint8_t max_gw_class = 0, max_packets = 0, max_gw_factor = 0;
// 	static char orig_str[ADDR_STR_LEN];
//
//
// 	if ( routing_class == 0 )
// 		return;
//
// 	if ( list_empty(&gw_list) ) {
//
// 		if ( curr_gateway != NULL ) {
//
// 			debug_output( 3, "Removing default route - no gateway in range\n" );
//
// 			del_default_route();
//
// 		}
//
// 		return;
//
// 	}
//
//
// 	list_for_each(pos, &gw_list) {
//
// 		gw_node = list_entry(pos, struct gw_node, list);
//
// 		/* ignore this gateway if recent connection attempts were unsuccessful */
// 		if ( ( gw_node->unavail_factor * gw_node->unavail_factor * 30000 ) + gw_node->last_failure > get_time() )
// 			continue;
//
// 		if ( gw_node->orig_node->router == NULL )
// 			continue;
//
// 		if ( gw_node->deleted )
// 			continue;
//
// 		switch ( routing_class ) {
//
// 			case 1:   /* fast connection */
// 				if ( ( ( gw_node->orig_node->router->packet_count * gw_node->orig_node->gwflags ) > max_gw_factor ) || ( ( ( gw_node->orig_node->router->packet_count * gw_node->orig_node->gwflags ) == max_gw_factor ) && ( gw_node->orig_node->router->packet_count > max_packets ) ) )
// 					tmp_curr_gw = gw_node;
// 				break;
//
// 			case 2:   /* stable connection */
// 				/* FIXME - not implemented yet */
// 				if ( ( ( gw_node->orig_node->router->packet_count * gw_node->orig_node->gwflags ) > max_gw_factor ) || ( ( ( gw_node->orig_node->router->packet_count * gw_node->orig_node->gwflags ) == max_gw_factor ) && ( gw_node->orig_node->router->packet_count > max_packets ) ) )
// 					tmp_curr_gw = gw_node;
// 				break;
//
// 			default:  /* use best statistic (olsr style) */
// 				if ( gw_node->orig_node->router->packet_count > max_packets )
// 					tmp_curr_gw = gw_node;
// 				break;
//
// 		}
//
// 		if ( gw_node->orig_node->gwflags > max_gw_class )
// 			max_gw_class = gw_node->orig_node->gwflags;
//
// 		if ( gw_node->orig_node->router->packet_count > max_packets )
// 			max_packets = gw_node->orig_node->router->packet_count;
//
// 		if ( ( gw_node->orig_node->router->packet_count * gw_node->orig_node->gwflags ) > max_gw_class )
// 			max_gw_factor = ( gw_node->orig_node->router->packet_count * gw_node->orig_node->gwflags );
//
// 		if ( ( pref_gateway != 0 ) && ( pref_gateway == gw_node->orig_node->orig ) ) {
//
// 			tmp_curr_gw = gw_node;
//
// 			debug_output( 3, "Preferred gateway found: %s (%i,%i,%i)\n", addr_to_string( tmp_curr_gw->orig_node->orig ), gw_node->orig_node->gwflags, gw_node->orig_node->router->packet_count, ( gw_node->orig_node->router->packet_count * gw_node->orig_node->gwflags ) );
//
// 			break;
//
// 		}
//
// 	}
//
//
// 	if ( curr_gateway != tmp_curr_gw ) {
//
// 		if ( curr_gateway != NULL ) {
//
// 			debug_output( 3, "Removing default route - better gateway found\n" );
//
// 			del_default_route();
//
// 		}
//
// 		curr_gateway = tmp_curr_gw;
//
// 		/* may be the last gateway is now gone */
// 		if ( ( curr_gateway != NULL ) && ( !is_aborted() ) ) {
//
// 			addr_to_string( curr_gateway->orig_node->orig, orig_str, ADDR_STR_LEN );
// 			debug_output( 3, "Adding default route to %s (%i,%i,%i)\n", orig_str, max_gw_class, max_packets, max_gw_factor );
//
// 			add_default_route();
//
// 		}
//
// 	}
//
// }



static void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node ) {

	debug_output( 4, "update_routes() \n" );


	if ( ( orig_node != NULL ) && ( orig_node->router != neigh_node ) ) {

		if ( ( orig_node != NULL ) && ( neigh_node != NULL ) )
			debug_output( 4, "Route to %s via %s\n", addr_to_string( orig_node->orig ), addr_to_string( neigh_node->addr ) );

		/* route altered or deleted */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( neigh_node == NULL ) ) {

			if ( neigh_node == NULL ) {
				debug_output( 4, "Deleting previous route\n" );
			} else {
				debug_output( 4, "Route changed\n" );
			}

//			add_del_route( orig_node->orig, 32, orig_node->router->addr, 1, orig_node->batman_if->dev, orig_node->batman_if->udp_send_sock );

		}

		/* route altered or new route added */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( orig_node->router == NULL ) ) {

			if ( orig_node->router == NULL ) {
				debug_output( 4, "Adding new route\n" );
			} else {
				debug_output( 4, "Route changed\n" );
			}

//			add_del_route( orig_node->orig, 32, neigh_node->addr, 0, neigh_node->if_incoming->dev, neigh_node->if_incoming->udp_send_sock );

			orig_node->batman_if = neigh_node->if_incoming;
			orig_node->router = neigh_node;

		}

		orig_node->router = neigh_node;

	}

}



static void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags ) {

	struct list_head *gw_pos, *gw_pos_tmp;
	struct gw_node *gw_node;

	list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

		gw_node = list_entry(gw_pos, struct gw_node, list);

		if ( gw_node->orig_node == orig_node ) {

			debug_output( 3, "Gateway class of originator %s changed from %i to %i\n", addr_to_string( gw_node->orig_node->orig ), gw_node->orig_node->gwflags, new_gwflags );

			if ( new_gwflags == 0 ) {

				gw_node->deleted = get_time();

				debug_output( 3, "Gateway %s removed from gateway list\n", addr_to_string( gw_node->orig_node->orig ) );

			} else {

				gw_node->deleted = 0;
				gw_node->orig_node->gwflags = new_gwflags;

			}

// 			choose_gw();
			return;

		}

	}

	debug_output( 3, "Found new gateway %s -> class: %i - %s\n", addr_to_string( gw_node->orig_node->orig ), new_gwflags, gw2string[new_gwflags] );

	gw_node = debugMalloc( sizeof(struct gw_node), 5 );
	memset( gw_node, 0, sizeof(struct gw_node) );
	INIT_LIST_HEAD( &gw_node->list );

	gw_node->orig_node = orig_node;
	gw_node->unavail_factor = 0;
	gw_node->last_failure = get_time();

	list_add_tail( &gw_node->list, &gw_list );

// 	choose_gw();

}



void debug() {

	struct hash_it_t *hashit;
	struct list_head *forw_pos, *orig_pos, *neigh_pos;
	struct forw_node *forw_node;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct gw_node *gw_node;
	uint16_t batman_count = 0;


	if ( debug_clients.clients_num[1] > 0 ) {

		debug_output( 2, "BOD\n" );

		if ( list_empty( &gw_list ) ) {

			debug_output( 2, "No gateways in range ...\n" );

		} else {

			list_for_each( orig_pos, &gw_list ) {

				gw_node = list_entry( orig_pos, struct gw_node, list );

				if ( gw_node->deleted )
					continue;

				if ( curr_gateway == gw_node ) {
					debug_output( 2, "=> %s via: %s(%i), gw_class %i - %s, reliability: %i\n", addr_to_string( gw_node->orig_node->orig ), addr_to_string( gw_node->orig_node->router->addr ), gw_node->orig_node->router->packet_count, gw_node->orig_node->gwflags, gw2string[gw_node->orig_node->gwflags], gw_node->unavail_factor );
				} else {
					debug_output( 2, "%s via: %s(%i), gw_class %i - %s, reliability: %i\n", addr_to_string( gw_node->orig_node->orig ), addr_to_string( gw_node->orig_node->router->addr ), gw_node->orig_node->router->packet_count, gw_node->orig_node->gwflags, gw2string[gw_node->orig_node->gwflags], gw_node->unavail_factor );
				}

			}

			if ( batman_count == 0 )
				debug_output( 2, "No gateways in range ...\n" );

		}

	}

	if ( ( debug_clients.clients_num[0] > 0 ) || ( debug_clients.clients_num[3] > 0 ) ) {

		debug_output( 1, "BOD\n" );

		if ( debug_clients.clients_num[3] > 0 ) {

			debug_output( 4, "------------------ DEBUG ------------------\n" );
			debug_output( 4, "Forward list\n" );

			list_for_each( forw_pos, &forw_list ) {
				forw_node = list_entry( forw_pos, struct forw_node, list );
				debug_output( 4, "    %s at %u\n", addr_to_string( ((struct packet *)forw_node->pack_buff)->orig ), forw_node->send_time );
			}

			debug_output( 4, "Originator list\n" );

		}
		hashit=NULL;
		while (NULL != (hashit = hash_iterate(orig_hash, hashit))) {
/*		list_for_each( orig_pos, &orig_list ) {
			orig_node = list_entry( orig_pos, struct orig_node, list ); XXX: obsoleted by hash */
			orig_node = hashit->bucket->data;

			if ( orig_node->router == NULL )
				continue;

			batman_count++;

			debug_output( 1, "%s, GW: %s(%i) via:", addr_to_string( orig_node->orig ), addr_to_string( orig_node->router->addr ), orig_node->router->packet_count );
			debug_output( 4, "%s, GW: %s(%i), last_aware:%u via:\n", addr_to_string( orig_node->orig ), addr_to_string( orig_node->router->addr ), orig_node->router->packet_count, orig_node->last_aware );

			list_for_each( neigh_pos, &orig_node->neigh_list ) {
				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				debug_output( 1, " %s(%i)", addr_to_string( neigh_node->addr ), neigh_node->packet_count );
				debug_output( 4, "\t\t%s (%d)\n", addr_to_string( neigh_node->addr ), neigh_node->packet_count );

			}

			debug_output( 1, "\n" );

		}

		if ( batman_count == 0 ) {

			debug_output( 1, "No batman nodes in range ...\n" );
			debug_output( 4, "    No batman nodes in range ...\n" );

		}

		debug_output( 4, "---------------------------------------------- END DEBUG\n" );

	}

}



int isDuplicate( uint8_t *orig, uint16_t seqno ) {

	struct list_head /* XXX: *orig_pos,*/ *neigh_pos;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct hash_it_t *hashit;

	hashit=NULL;
	while (NULL != (hashit = hash_iterate(orig_hash, hashit))) {
	/*list_for_each( orig_pos, &orig_list ) {
		orig_node = list_entry( orig_pos, struct orig_node, list ); XXX: obsoleted by hash */
		orig_node = hashit->bucket->data;

		if ( orig_comp( &orig_node->orig, orig ) == 0 ) {

			list_for_each( neigh_pos, &orig_node->neigh_list ) {
				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if ( get_bit_status( neigh_node->seq_bits, orig_node->last_seqno, seqno ) )
					return 1;

			}

			return 0;

		}

	}

	return 0;

}



int isBidirectionalNeigh( struct orig_node *orig_neigh_node, struct batman_if *if_incoming ) {

	if( orig_neigh_node->bidirect_link[if_incoming->if_num] > 0 && ( orig_neigh_node->bidirect_link[if_incoming->if_num] + (bidirectional_timeout) ) >= get_time() )
		return 1;
	else
		return 0;

}



void update_originator( struct orig_node *orig_node, struct packet *in, uint8_t *neigh, struct batman_if *if_incoming, unsigned char *pay_buff ) {

	struct list_head *neigh_pos;
	struct neigh_node *neigh_node = NULL, *tmp_neigh_node, *best_neigh_node;
	uint8_t max_packet_count = 0, is_new_seqno = 0;


	debug_output( 4, "update_originator(): Searching and updating originator entry of received packet,  \n" );


	list_for_each( neigh_pos, &orig_node->neigh_list ) {

		tmp_neigh_node = list_entry( neigh_pos, struct neigh_node, list );

		if ( ( orig_comp( &tmp_neigh_node->addr, neigh ) == 0 ) && ( tmp_neigh_node->if_incoming == if_incoming ) ) {

			neigh_node = tmp_neigh_node;

		} else {

			bit_get_packet( tmp_neigh_node->seq_bits, in->seqno - orig_node->last_seqno, 0 );
			tmp_neigh_node->packet_count = bit_packet_count( tmp_neigh_node->seq_bits );

			if ( tmp_neigh_node->packet_count > max_packet_count ) {

				max_packet_count = tmp_neigh_node->packet_count;
				best_neigh_node = tmp_neigh_node;

			}

		}

	}

	if ( neigh_node == NULL ) {

		debug_output( 4, "Creating new last-hop neighbour of originator\n" );

		neigh_node = debugMalloc( sizeof (struct neigh_node), 6 );
		memset( neigh_node, 0, sizeof(struct neigh_node) );
		INIT_LIST_HEAD( &neigh_node->list );

		memcpy( &neigh_node->addr, neigh, sizeof(neigh_node->addr) );
		neigh_node->if_incoming = if_incoming;

		list_add_tail( &neigh_node->list, &orig_node->neigh_list );

	} else {

		debug_output( 4, "Updating existing last-hop neighbour of originator\n" );

	}


	is_new_seqno = bit_get_packet( neigh_node->seq_bits, in->seqno - orig_node->last_seqno, 1 );
	neigh_node->packet_count = bit_packet_count( neigh_node->seq_bits );

	if ( neigh_node->packet_count > max_packet_count ) {

		max_packet_count = neigh_node->packet_count;
		best_neigh_node = neigh_node;

	}


	neigh_node->last_aware = get_time();

	if ( is_new_seqno ) {

		debug_output( 4, "updating last_seqno: old %d, new %d \n", orig_node->last_seqno, in->seqno  );

		orig_node->last_seqno = in->seqno;
		neigh_node->last_ttl = in->ttl;

	}

	/* update routing table */
	update_routes( orig_node, best_neigh_node );

	if ( orig_node->gwflags != in->gwflags )
		update_gw_list( orig_node, in->gwflags );

	orig_node->gwflags = in->gwflags;

	/* ethernet broadcasts for the kernel */
	if ( in->pay_len > 0 )
		tap_write( tap_sock, pay_buff, in->pay_len );

}



void schedule_own_packet( struct batman_if *batman_if, unsigned char *pay_buff, int16_t pay_buff_len ) {

	struct forw_node *forw_node_new, *forw_packet_tmp = NULL;
	struct list_head *list_pos;


	forw_node_new = debugMalloc( sizeof(struct forw_node), 11 );

	INIT_LIST_HEAD( &forw_node_new->list );

	forw_node_new->if_outgoing = batman_if;
	forw_node_new->own = 1;

	if ( pay_buff_len > 0 ) {

		/* batman packets with payload are send immediately */
		forw_node_new->send_time = get_time();

		forw_node_new->pack_buff = debugMalloc( sizeof(struct packet) + pay_buff_len, 12 );
		memcpy( forw_node_new->pack_buff, (unsigned char *)&batman_if->out, sizeof(struct packet) );
		memcpy( forw_node_new->pack_buff + sizeof(struct packet), pay_buff, pay_buff_len );
		forw_node_new->pack_buff_len = sizeof(struct packet) + pay_buff_len;

		((struct packet *)forw_node_new->pack_buff)->pay_len = pay_buff_len;

	} else {

		forw_node_new->send_time = get_time() + orginator_interval - JITTER + rand_num( 2 * JITTER );

		forw_node_new->pack_buff = debugMalloc( sizeof(struct packet), 13 );
		memcpy( forw_node_new->pack_buff, &batman_if->out, sizeof(struct packet) );
		forw_node_new->pack_buff_len = sizeof(struct packet);

	}

	list_for_each( list_pos, &forw_list ) {

		forw_packet_tmp = list_entry( list_pos, struct forw_node, list );

		if ( forw_packet_tmp->send_time > forw_node_new->send_time ) {

			list_add_before( &forw_list, list_pos, &forw_node_new->list );
			break;

		}

	}

	if ( ( forw_packet_tmp == NULL ) || ( forw_packet_tmp->send_time <= forw_node_new->send_time ) )
		list_add_tail( &forw_node_new->list, &forw_list );

	batman_if->out.seqno++;

}


void reschedule_own_packet( unsigned char *pay_buff, int16_t pay_buff_len ) {

	struct forw_node *forw_packet;
	struct list_head *list_pos, *list_pos_tmp;


	/* TODO: too many packets from primary interface ?! */
	list_for_each_safe( list_pos, list_pos_tmp, &forw_list ) {

		forw_packet = list_entry( list_pos, struct forw_node, list );

		if ( ( forw_packet->own ) && ( forw_packet->if_outgoing->if_num == 0 ) ) {

			list_del( list_pos );

			schedule_own_packet( forw_packet->if_outgoing, pay_buff, pay_buff_len );

			debugFree( forw_packet->pack_buff, 503 );
			debugFree( forw_packet, 504 );

			break;

		}

	}

}



void schedule_forward_packet( struct packet *in, uint8_t unidirectional, uint8_t directlink, struct batman_if *if_outgoing ) {

	struct forw_node *forw_node_new;

	debug_output( 4, "schedule_forward_packet():  \n" );

	if ( in->ttl <= 1 ) {

		debug_output( 4, "ttl exceeded \n" );

	} else {

		forw_node_new = debugMalloc( sizeof(struct forw_node), 8 );

		INIT_LIST_HEAD(&forw_node_new->list);

		if ( in->pay_len > 0 ) {

			forw_node_new->pack_buff = debugMalloc( sizeof(struct packet) + in->pay_len, 9 );
			memcpy( forw_node_new->pack_buff, in, sizeof(struct packet) + in->pay_len );
			forw_node_new->pack_buff_len = sizeof(struct packet) + in->pay_len;

		} else {

			forw_node_new->pack_buff = debugMalloc( sizeof(struct packet), 10 );
			memcpy( forw_node_new->pack_buff, in, sizeof(struct packet) );
			forw_node_new->pack_buff_len = sizeof(struct packet);

		}

		((struct packet *)forw_node_new->pack_buff)->ttl--;

		forw_node_new->send_time = get_time();
		forw_node_new->own = 0;

		forw_node_new->if_outgoing = if_outgoing;

		if ( unidirectional ) {

			((struct packet *)forw_node_new->pack_buff)->flags = ( UNIDIRECTIONAL | DIRECTLINK );

		} else if ( directlink ) {

			((struct packet *)forw_node_new->pack_buff)->flags = DIRECTLINK;

		} else {

			((struct packet *)forw_node_new->pack_buff)->flags = 0x00;

		}

		list_add( &forw_node_new->list, &forw_list );

	}

}



void send_outstanding_packets() {

	struct forw_node *forw_node;
	struct list_head *forw_pos, *if_pos, *temp;
	struct batman_if *batman_if;
	uint8_t directlink;
	uint32_t curr_time;


	if ( list_empty( &forw_list ) )
		return;

	curr_time = get_time();

	list_for_each_safe( forw_pos, temp, &forw_list ) {
		forw_node = list_entry( forw_pos, struct forw_node, list );

		if ( forw_node->send_time <= curr_time ) {

			directlink = ( ( ((struct packet *)forw_node->pack_buff)->flags & DIRECTLINK ) ? 1 : 0 );

			((struct packet *)forw_node->pack_buff)->seqno = htons( ((struct packet *)forw_node->pack_buff)->seqno ); /* change sequence number to network order */
			((struct packet *)forw_node->pack_buff)->pay_len = htons( ((struct packet *)forw_node->pack_buff)->pay_len ); /* change payload length to network order */


			if ( ((struct packet *)forw_node->pack_buff)->flags & UNIDIRECTIONAL ) {

				if ( forw_node->if_outgoing != NULL ) {

					debug_output( 4, "Forwarding packet (originator %s, seqno %d, TTL %d) on interface %s\n", addr_to_string( ((struct packet *)forw_node->pack_buff)->orig ), ntohs( ((struct packet *)forw_node->pack_buff)->seqno ), ((struct packet *)forw_node->pack_buff)->ttl, forw_node->if_outgoing->dev );

					if ( send_packet( forw_node->pack_buff, forw_node->pack_buff_len, broadcastAddr, forw_node->if_outgoing->raw_sock ) < 0 )
						exit(EXIT_FAILURE);

				} else {

					debug_output( 0, "Error - can't forward packet with UDF: outgoing iface not specified \n" );

				}

			/* multihomed peer assumed */
			} else if ( ( directlink ) && ( ((struct packet *)forw_node->pack_buff)->ttl == 1 ) ) {

				if ( ( forw_node->if_outgoing != NULL ) ) {

					if ( send_packet( forw_node->pack_buff, forw_node->pack_buff_len, broadcastAddr, forw_node->if_outgoing->raw_sock ) < 0 )
						exit(EXIT_FAILURE);

				} else {

					debug_output( 0, "Error - can't forward packet with IDF: outgoing iface not specified (multihomed) \n" );

				}

			} else {

				if ( ( directlink ) && ( forw_node->if_outgoing == NULL ) ) {

					debug_output( 0, "Error - can't forward packet with IDF: outgoing iface not specified \n" );

				} else {

					list_for_each(if_pos, &if_list) {

						batman_if = list_entry(if_pos, struct batman_if, list);

						if ( ( directlink ) && ( forw_node->if_outgoing == batman_if ) ) {
							((struct packet *)forw_node->pack_buff)->flags = DIRECTLINK;
						} else {
							((struct packet *)forw_node->pack_buff)->flags = 0x00;
						}

						debug_output( 4, "Forwarding packet (originator %s, seqno %d, TTL %d) on interface %s\n", addr_to_string( ((struct packet *)forw_node->pack_buff)->orig ), ntohs( ((struct packet *)forw_node->pack_buff)->seqno ), ((struct packet *)forw_node->pack_buff)->ttl, batman_if->dev );

						if ( send_packet( forw_node->pack_buff, forw_node->pack_buff_len, broadcastAddr, batman_if->raw_sock ) < 0 )
							exit(EXIT_FAILURE);

					}

				}

			}

			list_del( forw_pos );

			if ( forw_node->own )
				schedule_own_packet( forw_node->if_outgoing, NULL, 0 );

			debugFree( forw_node->pack_buff, 103 );
			debugFree( forw_node, 104 );

		} else {

			break;

		}

	}

}



void purge( uint32_t curr_time ) {

	struct list_head /**orig_pos, */*neigh_pos, /**orig_temp,*/ *neigh_temp;
	struct list_head *gw_pos, *gw_pos_tmp;
	struct orig_node *orig_node;
	struct neigh_node *neigh_node;
	struct gw_node *gw_node;
	struct hash_it_t *hashit;
	uint8_t gw_purged = 0;

	debug_output( 4, "purge() \n" );

	/* for all origins... */

	hashit=NULL;
	while (NULL != (hashit = hash_iterate(orig_hash, hashit))) {
/*
	list_for_each_safe( orig_pos, orig_temp, &orig_list ) {

		orig_node = list_entry( orig_pos, struct orig_node, list ); XXX: obsoleted by hash */
		orig_node = hashit->bucket->data;

		if ( (int)( ( orig_node->last_aware + ( 2 * TIMEOUT ) ) < curr_time ) ) {

			debug_output( 4, "Orginator timeout: originator %s, last_aware %u)\n", addr_to_string( orig_node->orig ), orig_node->last_aware );

			/* for all neighbours towards this orginator ... */
			list_for_each_safe( neigh_pos, neigh_temp, &orig_node->neigh_list ) {
				neigh_node = list_entry(neigh_pos, struct neigh_node, list);

				list_del( neigh_pos );
				debugFree( neigh_node, 107 );

			}

			list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

				gw_node = list_entry( gw_pos, struct gw_node, list );

				if ( gw_node->deleted )
					continue;

				if ( gw_node->orig_node == orig_node ) {

					debug_output( 3, "Removing gateway %s from gateway list\n", addr_to_string( gw_node->orig_node->orig ) );

					gw_node->deleted = get_time();

					gw_purged = 1;

					break;

				}

			}

			/* XXX: list_del( orig_pos ); */
			hash_remove( orig_hash, orig_node);

			update_routes( orig_node, NULL );

			debugFree( orig_node->bidirect_link, 109 );
			debugFree( orig_node, 110 );

		} else {

			/* for all neighbours towards this orginator ... */
			list_for_each_safe( neigh_pos, neigh_temp, &orig_node->neigh_list ) {

				neigh_node = list_entry( neigh_pos, struct neigh_node, list );

				if ( (int)( ( neigh_node->last_aware + ( 2 * TIMEOUT ) ) < curr_time ) ) {

					list_del( neigh_pos );
					debugFree( neigh_node, 108 );

				}

			}

		}

	}

	list_for_each_safe(gw_pos, gw_pos_tmp, &gw_list) {

		gw_node = list_entry(gw_pos, struct gw_node, list);

		if ( ( gw_node->deleted ) && ( (int)((gw_node->deleted + 3 * TIMEOUT) < curr_time) ) ) {

			list_del( gw_pos );
			debugFree( gw_pos, 107 );

		}

	}

// 	if ( gw_purged )
// 		choose_gw();

}



// void send_vis_packet()
// {
// 	struct list_head *pos;
// 	struct orig_node *orig_node;
// 	unsigned char *packet=NULL;
//
// 	int step = 5, size=0,cnt=0;
//
// 	list_for_each(pos, &orig_list) {
// 		orig_node = list_entry(pos, struct orig_node, list);
// 		if ( ( orig_node->router != NULL ) && ( orig_node->orig == orig_node->router->addr ) )
// 		{
// 			if(cnt >= size)
// 			{
// 				size += step;
// 				packet = debugRealloc(packet, size * sizeof(unsigned char), 14);
// 			}
// 			memmove(&packet[cnt], (unsigned char*)&orig_node->orig,4);
// 			 *(packet + cnt + 4) = (unsigned char) orig_node->router->packet_count;
// 			cnt += step;
// 		}
// 	}
// 	if(packet != NULL)
// 	{
// 		send_packet(packet, size * sizeof(unsigned char), &vis_if.addr, vis_if.sock);
// 	 	debugFree( packet, 111 );
// 	}
// }

int8_t batman() {

	struct list_head *if_pos, *neigh_pos, *forw_pos, *forw_pos_tmp;
	struct orig_node *orig_neigh_node, *orig_node;
	struct batman_if *batman_if, *if_incoming;
	struct neigh_node *neigh_node;
	struct forw_node *forw_node;
	uint32_t debug_timeout, select_timeout, time_count = 0, curr_time;
	unsigned char in[2000];
	int16_t in_len;
	uint8_t neigh[6], is_duplicate, is_bidirectional, forward_duplicate_packet;
	int8_t res;

	debug_timeout = get_time();
	bidirectional_timeout = orginator_interval * 3;

	list_for_each( if_pos, &if_list ) {

		batman_if = list_entry( if_pos, struct batman_if, list );

		memcpy( batman_if->out.orig, my_hw_addr, 6 );
		batman_if->out.flags = 0x00;
		batman_if->out.ttl = ( batman_if->if_num == 0 ? TTL : 2 );
		batman_if->out.seqno = 1;
		batman_if->out.gwflags = gateway_class;
		batman_if->out.version = COMPAT_VERSION;
		batman_if->out.pay_len = 0;

		schedule_own_packet( batman_if, NULL, 0 );

	}

	if (NULL == (orig_hash = hash_new( 128, orig_comp, orig_choose)))
		return(-1);

	while ( !is_aborted() ) {

		debug_output( 4, " \n \n" );

// 		if(vis_if.sock && time_count == 50)
// 		{
// 			time_count = 0;
// 			send_vis_packet();
// 		}

		/* harden select_timeout against sudden time change (e.g. ntpdate) */
		curr_time = get_time();
		select_timeout = ( curr_time < ((struct forw_node *)forw_list.next)->send_time ? ((struct forw_node *)forw_list.next)->send_time - curr_time : 10 );

		res = receive_packet( ( unsigned char *)&in, sizeof(in), &in_len, neigh, select_timeout, &if_incoming );

		if ( res < 0 )
			return -1;

		if ( res > 0 ) {

			debug_output( 4, "Received BATMAN packet from %s (originator %s, seqno %d, TTL %d, payload: %s)\n", addr_to_string( neigh ), addr_to_string( ((struct packet *)&in)->orig ), ((struct packet *)&in)->seqno, ((struct packet *)&in)->ttl, ( ((struct packet *)&in)->pay_len > 0 ? "yes" : "no" ) );

			is_duplicate = is_bidirectional = forward_duplicate_packet = 0;

// 			list_for_each( if_pos, &if_list ) {
//
// 				batman_if = list_entry(if_pos, struct batman_if, list);
//
// 				if ( neigh == batman_if->addr.sin_addr.s_addr )
// 					is_my_addr = 1;
//
// 				if ( ((struct packet *)&in)->orig == batman_if->addr.sin_addr.s_addr )
// 					is_my_orig = 1;
//
// 				if ( neigh == batman_if->broad.sin_addr.s_addr )
// 					is_broadcast = 1;
//
// 			}


// 			addr_to_string( ((struct packet *)&in)->orig );
// 			addr_to_string( neigh );
// 			debug_output( 4, "new packet - orig: %s, sender: %s\n", addr_to_string( ((struct packet *)&in)->orig ), addr_to_string( neigh ) );

			/*if ( is_duplicate )
				output("Duplicate packet \n");

			if ( in.orig == neigh )
				output("Originator packet from neighbour \n");

			if ( is_my_orig == 1 )
				output("Originator packet from myself (via neighbour) \n");

			if ( in.flags & UNIDIRECTIONAL )
				output("Packet with unidirectional flag \n");

			if ( is_bidirectional )
				output("received via bidirectional link \n");

			if ( !( in.flags & UNIDIRECTIONAL ) && ( !is_bidirectional ) )
				output("neighbour thinks connection is bidirectional - I disagree \n");*/

			if ( ((struct packet *)&in)->gwflags != 0 )
				debug_output( 4, "Is an internet gateway (class %i) \n", ((struct packet *)&in)->gwflags );

			/*if ( ( ! is_my_addr ) && ( ! is_my_orig ) )
				debug_output( 3, "IP: %s send packet with sequence number: %i from %s\n", neigh_str, ((struct packet *)&in)->seqno, orig_str );*/


			if ( ((struct packet *)&in)->version != COMPAT_VERSION ) {

				debug_output( 4, "Drop packet: incompatible batman version (%i) \n", ((struct packet *)&in)->version );

			} else if ( orig_comp( my_hw_addr, neigh ) == 0 ) {

				debug_output( 4, "Drop packet: received my own broadcast (sender: %s)\n", addr_to_string( neigh ) );

			} else if ( orig_comp( neigh, broadcastAddr ) == 0 ) {

				debug_output( 4, "Drop packet: ignoring all packets with broadcast source IP (sender: %s)\n", addr_to_string( neigh ) );

			} else if ( orig_comp( my_hw_addr, ((struct packet *)&in)->orig ) == 0 ) {

				orig_neigh_node = get_orig_node( neigh );

				orig_neigh_node->last_aware = get_time();

				/* neighbour has to indicate direct link and it has to come via the corresponding interface */
// TODO: we only have one address ...
// 				if ( ( ((struct packet *)&in)->flags & DIRECTLINK ) && ( if_incoming->addr.sin_addr.s_addr == ((struct packet *)&in)->orig ) ) {
				if ( ((struct packet *)&in)->flags & DIRECTLINK ) {

					orig_neigh_node->bidirect_link[if_incoming->if_num] = get_time();

					debug_output( 4, "received my own packet from neighbour indicating bidirectional link, updating bidirect_link timestamp \n");

				}

				debug_output( 4, "Drop packet: originator packet from myself (via neighbour) \n" );

			} else if ( ((struct packet *)&in)->flags & UNIDIRECTIONAL ) {

				debug_output( 4, "Drop packet: originator packet with unidirectional flag \n" );

			} else {

				orig_node = get_orig_node( ((struct packet *)&in)->orig );
				orig_node->last_aware = get_time();

				orig_neigh_node = get_orig_node( neigh );

				is_duplicate = isDuplicate( ((struct packet *)&in)->orig, ((struct packet *)&in)->seqno );
				is_bidirectional = isBidirectionalNeigh( orig_neigh_node, if_incoming );

				/* update ranking */
				if ( ( is_bidirectional ) && ( !is_duplicate ) )
					update_originator( orig_node, (struct packet *)&in, neigh, if_incoming, in + sizeof(struct packet) );

				/* is single hop (direct) neighbour */
				if ( orig_comp( ((struct packet *)&in)->orig, neigh ) == 0 ) {

					/* it is our best route towards him */
					if ( ( is_bidirectional ) && ( orig_node->router != NULL ) && ( orig_comp( orig_node->router->addr, neigh ) == 0 ) ) {

						/* mark direct link on incoming interface */
						schedule_forward_packet( (struct packet *)&in, 0, 1, if_incoming );

						debug_output( 4, "Forward packet: rebroadcast neighbour packet with direct link flag \n" );

					/* if an unidirectional neighbour sends us a packet - retransmit it with unidirectional flag to tell him that we get its packets */
					/* if a bidirectional neighbour sends us a packet - retransmit it with unidirectional flag if it is not our best link to it in order to prevent routing problems */
					} else if ( ( ( is_bidirectional ) && ( ( orig_node->router == NULL ) || ( orig_comp( orig_node->router->addr, neigh ) != 0 ) ) ) || ( !is_bidirectional ) ) {

						schedule_forward_packet( (struct packet *)&in, 1, 1, if_incoming );

						debug_output( 4, "Forward packet: rebroadcast neighbour packet with direct link and unidirectional flag \n" );

					}

				/* multihop orginator */
				} else {

					if ( is_bidirectional ) {

						if ( !is_duplicate ) {

							schedule_forward_packet( (struct packet *)&in, 0, 0, if_incoming );

							debug_output( 4, "Forward packet: rebroadcast orginator packet \n" );

						} else if ( ( orig_node->router != NULL ) && ( orig_comp( orig_node->router->addr, neigh ) == 0 ) ) {

							list_for_each( neigh_pos, &orig_node->neigh_list ) {

								neigh_node = list_entry(neigh_pos, struct neigh_node, list);

								if ( ( orig_comp( neigh_node->addr, neigh ) == 0 ) && ( neigh_node->if_incoming == if_incoming ) ) {

									if ( neigh_node->last_ttl == ((struct packet *)&in)->ttl )
										forward_duplicate_packet = 1;

									break;

								}

							}

							/* we are forwarding duplicate o-packets if they come via our best neighbour and ttl is valid */
							if ( forward_duplicate_packet ) {

								schedule_forward_packet( (struct packet *)&in, 0, 0, if_incoming );

								debug_output( 4, "Forward packet: duplicate packet received via best neighbour with best ttl \n" );

							} else {

								debug_output( 4, "Drop packet: duplicate packet received via best neighbour but not best ttl \n" );

							}

						} else {

							debug_output( 4, "Drop packet: duplicate packet (not received via best neighbour) \n" );

						}

					} else {

						debug_output( 4, "Drop packet: received via unidirectional link \n" );

					}

				}

			}

		}

		send_outstanding_packets();

		purge( get_time() );

		if ( debug_timeout + 1000 < get_time() ) {

			debug_timeout = get_time();

			debug();

			checkIntegrity();

// 			if ( ( routing_class != 0 ) && ( curr_gateway == NULL ) )
// 				choose_gw();

		}

		time_count++;

	}

	hash_delete(orig_hash, orig_free);

	if ( debug_level > 0 )
		printf( "Deleting all BATMAN routes\n" );

	purge( get_time() + ( 5 * TIMEOUT ) + orginator_interval );


	list_for_each_safe( forw_pos, forw_pos_tmp, &forw_list ) {
		forw_node = list_entry( forw_pos, struct forw_node, list );

		list_del( forw_pos );

		debugFree( forw_node->pack_buff, 112 );
		debugFree( forw_node, 113 );

	}


	return 0;

}
