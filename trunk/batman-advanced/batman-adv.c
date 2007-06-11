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
#include "batman-adv.h"
#include "originator.h"
#include "schedule.h"



uint8_t debug_level = 0;


#ifdef PROFILE_DATA

uint8_t debug_level_max = 5;

#elif DEBUG_MALLOC && MEMORY_USAGE

uint8_t debug_level_max = 5;

#else

uint8_t debug_level_max = 4;

#endif


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


int16_t originator_interval = 1000;   /* originator message interval in miliseconds */

struct gw_node *curr_gateway = NULL;
pthread_t curr_gateway_thread_id = 0;

uint32_t pref_gateway = 0;

uint8_t found_ifs = 0;
int32_t receive_max_sock = 0;
fd_set receive_wait_set;
int32_t tap_sock = 0;
uint8_t my_hw_addr[6];

unsigned char broadcastAddr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

uint8_t unix_client = 0;

struct unix_client *unix_packet[256];


struct hashtable_t *orig_hash;

struct list_head_first forw_list;
struct list_head_first gw_list;
struct list_head_first if_list;

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
	fprintf( stderr, "       -o originator interval in ms\n" );
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
	fprintf( stderr, "       -o originator interval in ms\n" );
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



void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node ) {

	debug_output( 4, "update_routes() \n" );


	if ( ( orig_node != NULL ) && ( orig_node->router != neigh_node ) ) {

		if ( ( orig_node != NULL ) && ( neigh_node != NULL ) )
			debug_output( 4, "Route to %s via %s\n", addr_to_string( orig_node->orig ), addr_to_string( neigh_node->addr ) );

		/* route altered or deleted */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( neigh_node == NULL ) ) {

			if ( neigh_node == NULL ) {
				debug_output( 4, "Deleting previous route \n" );
			} else {
				debug_output( 4, "Route changed \n" );
			}

//			add_del_route( orig_node->orig, 32, orig_node->router->addr, 1, orig_node->batman_if->dev, orig_node->batman_if->udp_send_sock );

		}

		/* route altered or new route added */
		if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( orig_node->router == NULL ) ) {

			if ( orig_node->router == NULL ) {
				debug_output( 4, "Adding new route \n" );
			} else {
				debug_output( 4, "Route changed \n" );
			}

//			add_del_route( orig_node->orig, 32, neigh_node->addr, 0, neigh_node->if_incoming->dev, neigh_node->if_incoming->udp_send_sock );

			orig_node->batman_if = neigh_node->if_incoming;
			orig_node->router = neigh_node;

		}

		orig_node->router = neigh_node;

	}

}



void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags ) {

	struct list_head *gw_pos, *gw_pos_tmp;
	struct gw_node *gw_node = NULL;

	list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

		gw_node = list_entry(gw_pos, struct gw_node, list);

		if ( gw_node->orig_node == orig_node ) {

			debug_output( 3, "Gateway class of originator %s changed from %i to %i \n", addr_to_string( gw_node->orig_node->orig ), gw_node->orig_node->gwflags, new_gwflags );

			if ( new_gwflags == 0 ) {

				gw_node->deleted = get_time();

				debug_output( 3, "Gateway %s removed from gateway list \n", addr_to_string( gw_node->orig_node->orig ) );

			} else {

				gw_node->deleted = 0;
				gw_node->orig_node->gwflags = new_gwflags;

			}

// 			choose_gw();
			return;

		}

	}

	debug_output( 3, "Found new gateway %s -> class: %i - %s \n", addr_to_string( gw_node->orig_node->orig ), new_gwflags, gw2string[new_gwflags] );

	gw_node = debugMalloc( sizeof(struct gw_node), 103 );
	memset( gw_node, 0, sizeof(struct gw_node) );
	INIT_LIST_HEAD( &gw_node->list );

	gw_node->orig_node = orig_node;
	gw_node->unavail_factor = 0;
	gw_node->last_failure = get_time();

	list_add_tail( &gw_node->list, &gw_list );

// 	choose_gw();

}



int isDuplicate( struct orig_node *orig_node, uint16_t seqno ) {

	struct list_head *neigh_pos;
	struct neigh_node *neigh_node;


	list_for_each( neigh_pos, &orig_node->neigh_list ) {
		neigh_node = list_entry( neigh_pos, struct neigh_node, list );

		if ( get_bit_status( neigh_node->seq_bits, orig_node->last_seqno, seqno ) )
			return 1;

	}

	return 0;

}



int isBntog( uint8_t *neigh, struct orig_node *orig_tog_node ) {

	if ( ( orig_tog_node->router != NULL ) && ( compare_orig( orig_tog_node->router->addr, neigh ) == 0 ) )
		return 1;

	return 0;

}



int isBidirectionalNeigh( struct orig_node *orig_neigh_node, struct batman_if *if_incoming ) {

	if ( ( if_incoming->out.seqno - 2 - orig_neigh_node->bidirect_link[if_incoming->if_num] ) < BIDIRECT_TIMEOUT )
		return 1;

	return 0;

}



int isMyMac( uint8_t *addr ) {

	struct list_head *if_pos;
	struct batman_if *batman_if;


	list_for_each( if_pos, &if_list ) {

		batman_if = list_entry(if_pos, struct batman_if, list);

		if ( compare_orig( batman_if->hw_addr, addr ) == 0 )
			return 1;

	}

	return 0;

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
	uint32_t debug_timeout, select_timeout, curr_time;
	unsigned char in[2000];
	int16_t in_len;
	uint8_t neigh[6], is_my_addr, is_my_orig, is_broadcast, is_duplicate, is_bidirectional, is_bntog, forward_duplicate_packet, has_unidirectional_flag, has_directlink_flag, has_version;
	int8_t res;

	debug_timeout = get_time();

	list_for_each( if_pos, &if_list ) {

		batman_if = list_entry( if_pos, struct batman_if, list );

		memcpy( batman_if->out.orig, batman_if->hw_addr, 6 );
		batman_if->out.packet_type = 0;
		batman_if->out.flags = 0x00;
		batman_if->out.ttl = TTL;
		batman_if->out.seqno = 1;
		batman_if->out.gwflags = gateway_class;
		batman_if->out.version = COMPAT_VERSION;

		batman_if->bcast_seqno = 1;

		schedule_own_packet( batman_if );

	}

	if ( NULL == ( orig_hash = hash_new( 128, compare_orig, choose_orig ) ) )
		return(-1);

	while ( !is_aborted() ) {

		debug_output( 4, " \n \n" );

		/* harden select_timeout against sudden time change (e.g. ntpdate) */
		curr_time = get_time();
		select_timeout = ( curr_time < ((struct forw_node *)forw_list.next)->send_time ? ((struct forw_node *)forw_list.next)->send_time - curr_time : 10 );

		res = receive_packet( ( unsigned char *)&in, sizeof(in), &in_len, neigh, select_timeout, &if_incoming );

		if ( res < 0 )
			return -1;

		if ( res > 0 ) {

			curr_time = get_time();

			is_my_addr = is_my_orig = is_broadcast = is_duplicate = is_bidirectional = is_bntog = forward_duplicate_packet = 0;

			has_unidirectional_flag = ((struct batman_packet *)&in)->flags & UNIDIRECTIONAL ? 1 : 0;
			has_directlink_flag = ((struct batman_packet *)&in)->flags & DIRECTLINK ? 1 : 0;
			has_version = ((struct batman_packet *)&in)->version;

			debug_output( 4, "Received BATMAN packet via NB: %s ,IF: %s %s (from OG: %s, seqno %d, TTL %d, V %d, UDF %d, IDF %d) \n", addr_to_string( neigh ), if_incoming->dev, addr_to_string( if_incoming->hw_addr ), addr_to_string( ((struct batman_packet *)&in)->orig ), ((struct batman_packet *)&in)->seqno, ((struct batman_packet *)&in)->ttl, has_version, has_unidirectional_flag, has_directlink_flag );

			list_for_each( if_pos, &if_list ) {

				batman_if = list_entry(if_pos, struct batman_if, list);

				if ( compare_orig( neigh, batman_if->hw_addr ) == 0 )
					is_my_addr = 1;

				if ( compare_orig( ((struct batman_packet *)&in)->orig, batman_if->hw_addr ) == 0 )
					is_my_orig = 1;

				if ( compare_orig( neigh, broadcastAddr ) == 0 )
					is_broadcast = 1;

			}

			if ( ((struct batman_packet *)&in)->gwflags != 0 )
				debug_output( 4, "Is an internet gateway (class %i) \n", ((struct batman_packet *)&in)->gwflags );


			if ( ((struct batman_packet *)&in)->version != COMPAT_VERSION ) {

				debug_output( 4, "Drop packet: incompatible batman version (%i) \n", ((struct batman_packet *)&in)->version );

			} else if ( is_my_addr ) {

				debug_output( 4, "Drop packet: received my own broadcast (sender: %s)\n", addr_to_string( neigh ) );

			} else if ( is_broadcast ) {

				debug_output( 4, "Drop packet: ignoring all packets with broadcast source IP (sender: %s)\n", addr_to_string( neigh ) );

			} else if ( is_my_orig ) {

				orig_neigh_node = get_orig_node( neigh );

				debug_output( 4, "received my own OGM via NB lastTxIfSeqno: %d, currRxSeqno: %d, prevRxSeqno: %d, currRxSeqno-prevRxSeqno %d \n", ( if_incoming->out.seqno - 2 ), ((struct batman_packet *)&in)->seqno, orig_neigh_node->bidirect_link[if_incoming->if_num], ((struct batman_packet *)&in)->seqno - orig_neigh_node->bidirect_link[if_incoming->if_num] );

				/* neighbour has to indicate direct link and it has to come via the corresponding interface */
				/* if received seqno equals last send seqno save new seqno for bidirectional check */
				if ( ( ((struct batman_packet *)&in)->flags & DIRECTLINK ) && ( compare_orig( if_incoming->hw_addr, ((struct batman_packet *)&in)->orig ) == 0 ) && ( ((struct batman_packet *)&in)->seqno + 2 == if_incoming->out.seqno ) ) {

					orig_neigh_node->bidirect_link[if_incoming->if_num] = ((struct batman_packet *)&in)->seqno;

					debug_output( 4, "indicating bidirectional link - updating bidirect_link seqno \n");

				} else {

					debug_output( 4, "NOT indicating bidirectional link - NOT updating bidirect_link seqno \n");

				}

				debug_output( 4, "Drop packet: originator packet from myself (via neighbour) \n" );

			} else if ( ((struct batman_packet *)&in)->flags & UNIDIRECTIONAL ) {

				debug_output( 4, "Drop packet: originator packet with unidirectional flag \n" );

			} else {

				orig_node = get_orig_node( ((struct batman_packet *)&in)->orig );

				orig_neigh_node = get_orig_node( neigh );

				is_duplicate = isDuplicate( orig_node, ((struct batman_packet *)&in)->seqno );
				is_bidirectional = isBidirectionalNeigh( orig_neigh_node, if_incoming );

				/* update ranking */
				if ( ( is_bidirectional ) && ( !is_duplicate ) )
					update_orig( orig_node, (struct batman_packet *)&in, neigh, if_incoming, curr_time );

				is_bntog = isBntog( neigh, orig_node );

				/* is single hop (direct) neighbour */
				if ( compare_orig( ((struct batman_packet *)&in)->orig, neigh ) == 0 ) {

					/* it is our best route towards him */
					if ( is_bidirectional && is_bntog ) {

						/* mark direct link on incoming interface */
						schedule_forward_packet( (struct batman_packet *)&in, 0, 1, if_incoming );

						debug_output( 4, "Forward packet: rebroadcast neighbour packet with direct link flag \n" );

					/* if an unidirectional neighbour sends us a packet - retransmit it with unidirectional flag to tell him that we get its packets */
					/* if a bidirectional neighbour sends us a packet - retransmit it with unidirectional flag if it is not our best link to it in order to prevent routing problems */
					} else if ( ( is_bidirectional && !is_bntog ) || ( !is_bidirectional ) ) {

						schedule_forward_packet( (struct batman_packet *)&in, 1, 1, if_incoming );

						debug_output( 4, "Forward packet: rebroadcast neighbour packet with direct link and unidirectional flag \n" );

					}

				/* multihop originator */
				} else {

					if ( is_bidirectional && is_bntog ) {

						if ( !is_duplicate ) {

							schedule_forward_packet( (struct batman_packet *)&in, 0, 0, if_incoming );

							debug_output( 4, "Forward packet: rebroadcast originator packet \n" );

						} else { /* is_bntog anyway */

							list_for_each( neigh_pos, &orig_node->neigh_list ) {

								neigh_node = list_entry(neigh_pos, struct neigh_node, list);

								if ( ( compare_orig( neigh_node->addr, neigh ) == 0 ) && ( neigh_node->if_incoming == if_incoming ) ) {

									if ( neigh_node->last_ttl == ((struct batman_packet *)&in)->ttl ) {

										forward_duplicate_packet = 1;

										/* also update only last_valid time if arrived (and rebroadcasted because best neighbor) */
										orig_node->last_valid = curr_time;
										neigh_node->last_valid = curr_time;

									}

									break;

								}

							}

							/* we are forwarding duplicate o-packets if they come via our best neighbour and ttl is valid */
							if ( forward_duplicate_packet ) {

								schedule_forward_packet( (struct batman_packet *)&in, 0, 0, if_incoming );

								debug_output( 4, "Forward packet: duplicate packet received via best neighbour with best ttl \n" );

							} else {

								debug_output( 4, "Drop packet: duplicate packet received via best neighbour but not best ttl \n" );

							}

						}

					} else {

						debug_output( 4, "Drop packet: received via bidirectional link: %s, BNTOG: %s !\n", ( is_bidirectional ? "YES" : "NO" ), ( is_bntog ? "YES" : "NO" ) );

					}

				}

			}

		}


		send_outstanding_packets();

		if ( debug_timeout + 1000 < curr_time ) {

			debug_timeout = curr_time;

			purge_orig( curr_time );

			debug_orig();

			checkIntegrity();

// 			if ( ( routing_class != 0 ) && ( curr_gateway == NULL ) )
// 				choose_gw();

// 			if ( vis_if.sock )
// 				send_vis_packet();

		}

	}


	if ( debug_level > 0 )
		printf( "Deleting all BATMAN routes\n" );

	purge_orig( get_time() + ( 5 * PURGE_TIMEOUT ) + originator_interval );

	hash_destroy( orig_hash );


	list_for_each_safe( forw_pos, forw_pos_tmp, &forw_list ) {
		forw_node = list_entry( forw_pos, struct forw_node, list );

		list_del( (struct list_head *)&forw_list, forw_pos, &forw_list );

		debugFree( forw_node->pack_buff, 1110 );
		debugFree( forw_node, 1111 );

	}


	return 0;

}
