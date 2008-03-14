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
#include "trans_table.h"



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
int32_t tap_mtu = 2000;

unsigned char broadcastAddr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

uint8_t unix_client = 0;


struct unix_client *unix_packet[256];


struct hashtable_t *orig_hash;

struct list_head_first forw_list;
struct list_head_first gw_list;
struct list_head_first if_list;

struct vis_if vis_if;
struct unix_if unix_if;
struct debug_clients debug_clients;

uint32_t curr_time = 0;
unsigned char *vis_packet = NULL;
uint16_t vis_packet_size = 0;


void usage( void ) {

	fprintf( stderr, "Usage: batman [options] interface [interface interface]\n" );
	fprintf( stderr, "       -b run connection in batch mode\n" );
	fprintf( stderr, "       -c connect via unix socket\n" );
	fprintf( stderr, "       -d debug level\n" );
/*	fprintf( stderr, "       -g gateway class\n" );*/
	fprintf( stderr, "       -h this help\n" );
	fprintf( stderr, "       -H verbose help\n" );
	fprintf( stderr, "       -o originator interval in ms\n" );
/*	fprintf( stderr, "       -p preferred gateway\n" );
	fprintf( stderr, "       -r routing class\n" );*/
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
/*	fprintf( stderr, "       -g gateway class\n" );
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
	fprintf( stderr, "                          11 -> >6 MBit\n\n" );*/
	fprintf( stderr, "       -h shorter help\n" );
	fprintf( stderr, "       -H this help\n" );
	fprintf( stderr, "       -o originator interval in ms\n" );
	fprintf( stderr, "          default: 1000, allowed values: >0\n\n" );
/*	fprintf( stderr, "       -p preferred gateway\n" );
	fprintf( stderr, "          default: none, allowed values: IP\n\n" );
	fprintf( stderr, "       -r routing class (only needed if gateway class = 0)\n" );
	fprintf( stderr, "          default:         0 -> set no default route\n" );
	fprintf( stderr, "          allowed values:  1 -> use fast internet connection\n" );
	fprintf( stderr, "                           2 -> use stable internet connection\n" );
	fprintf( stderr, "                           3 -> use best statistic internet connection (olsr style)\n\n" );*/
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
//



void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node, unsigned char *hna_recv_buff, int16_t hna_buff_len )
{
	char str1[ETH_STR_LEN], str2[ETH_STR_LEN];

	debug_output( 4, "update_routes() \n" );


	if ( ( orig_node != NULL ) && ( orig_node->router != neigh_node ) ) {



		if ((orig_node != NULL) && (neigh_node != NULL)) {

			addr_to_string(str1, orig_node->orig);
			addr_to_string(str2, neigh_node->addr);
			debug_output( 4, "Route to %s via %s\n", str1, str2);

		}

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


	if ((hna_recv_buff == NULL) && (orig_node->hna_buff == NULL)) {
		/* great, nothing to do. */
	} else if ((hna_recv_buff != NULL) && (orig_node->hna_buff == NULL)) {
		orig_node->hna_buff = debugMalloc( hna_buff_len, 102 );
		orig_node->hna_buff_len = hna_buff_len;
		memcpy( orig_node->hna_buff, hna_recv_buff, hna_buff_len );

		hna_add_buff(orig_node); /* only things to add */
	} else if ((hna_recv_buff == NULL) && (orig_node->hna_buff != NULL)) {
		hna_del_buff(orig_node); /* only things to delete */

	} else {
		int changed=0;

		if (hna_buff_len != orig_node->hna_buff_len)
			changed=1;
		else if(memcmp(hna_recv_buff, orig_node->hna_buff, hna_buff_len) == 0)
			changed=1;
		if (changed) {
			/* need to update table */
			hna_del_buff(orig_node);
			orig_node->hna_buff = debugMalloc( hna_buff_len, 102 );
			orig_node->hna_buff_len = hna_buff_len;

			memcpy( orig_node->hna_buff, hna_recv_buff, hna_buff_len );

			hna_add_buff(orig_node);
		}
	}
}



void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags ) {

	struct list_head *gw_pos, *gw_pos_tmp;
	struct gw_node *gw_node = NULL;

	list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

		gw_node = list_entry(gw_pos, struct gw_node, list);

		if ( gw_node->orig_node == orig_node ) {

			debug_output(3, "Gateway class of originator %s changed from %i to %i \n", addr_to_string_static(gw_node->orig_node->orig), gw_node->orig_node->gwflags, new_gwflags);

			if ( new_gwflags == 0 ) {

				gw_node->deleted = get_time();

				debug_output(3, "Gateway %s removed from gateway list \n", addr_to_string_static(gw_node->orig_node->orig));

			} else {

				gw_node->deleted = 0;
				gw_node->orig_node->gwflags = new_gwflags;

			}

// 			choose_gw();
			return;

		}

	}

	debug_output(3, "Found new gateway %s -> class: %i - %s \n", addr_to_string_static(orig_node->orig), new_gwflags, gw2string[new_gwflags]);

	gw_node = debugMalloc( sizeof(struct gw_node), 103 );
	memset( gw_node, 0, sizeof(struct gw_node) );
	INIT_LIST_HEAD( &gw_node->list );

	gw_node->orig_node = orig_node;
	gw_node->unavail_factor = 0;
	gw_node->last_failure = get_time();

	list_add_tail( &gw_node->list, &gw_list );

// 	choose_gw();

}



/*int isDuplicate( struct orig_node *orig_node, uint16_t seqno ) {

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

}*/



int isBidirectionalNeigh(struct orig_node *orig_node, struct orig_node *orig_neigh_node, struct batman_packet *in, uint32_t recv_time, struct batman_if *if_incoming)
{
	struct list_head *list_pos;
	struct neigh_node *neigh_node = NULL, *tmp_neigh_node = NULL;
	uint8_t total_count;
	char str1[ETH_STR_LEN], str2[ETH_STR_LEN];


	if (orig_node == orig_neigh_node) {

		list_for_each(list_pos, &orig_node->neigh_list) {
			tmp_neigh_node = list_entry(list_pos, struct neigh_node, list);

			if ((compare_orig(tmp_neigh_node->addr, orig_neigh_node->orig) == 0) && (tmp_neigh_node->if_incoming == if_incoming) )
				neigh_node = tmp_neigh_node;
		}

		if (neigh_node == NULL)
			neigh_node = create_neighbor(orig_node, orig_neigh_node, orig_neigh_node->orig, if_incoming);

		neigh_node->last_valid = recv_time;
	} else {
		/* find packet count of corresponding one hop neighbor */
		list_for_each(list_pos, &orig_neigh_node->neigh_list) {
			tmp_neigh_node = list_entry(list_pos, struct neigh_node, list);

			if ((compare_orig(tmp_neigh_node->addr, orig_neigh_node->orig) == 0) && (tmp_neigh_node->if_incoming == if_incoming))
				neigh_node = tmp_neigh_node;
		}

		if ( neigh_node == NULL )
			neigh_node = create_neighbor(orig_neigh_node, orig_neigh_node, orig_neigh_node->orig, if_incoming);
	}

	orig_node->last_valid = recv_time;

	/* pay attention to not get a value bigger than 100 % */
	total_count = (orig_neigh_node->bcast_own_sum[if_incoming->if_num] > neigh_node->real_packet_count ? neigh_node->real_packet_count : orig_neigh_node->bcast_own_sum[if_incoming->if_num]);

	/* if we have too few packets (too less data) we set tq_own to zero */
	/* if we receive too few packets it is not considered bidirectional */
	if ((total_count < TQ_LOCAL_BIDRECT_SEND_MINIMUM) || (neigh_node->real_packet_count < TQ_LOCAL_BIDRECT_RECV_MINIMUM))
		orig_neigh_node->tq_own = 0;
	else
		/* neigh_node->real_packet_count is never zero as we only purge old information when getting new information */
		orig_neigh_node->tq_own = (TQ_MAX_VALUE * total_count) / neigh_node->real_packet_count;

	/* 1 - ((1-x)** 3), normalized to TQ_MAX_VALUE */
	/* this does affect the nearly-symmetric links only a little,
	* but punishes asymetric links more. */
	/* this will give a value between 0 and TQ_MAX_VALUE */
	orig_neigh_node->tq_asym_penalty = TQ_MAX_VALUE - (TQ_MAX_VALUE *
			(TQ_LOCAL_WINDOW_SIZE - neigh_node->real_packet_count) *
			(TQ_LOCAL_WINDOW_SIZE - neigh_node->real_packet_count) *
			(TQ_LOCAL_WINDOW_SIZE - neigh_node->real_packet_count)) /
			(TQ_LOCAL_WINDOW_SIZE * TQ_LOCAL_WINDOW_SIZE * TQ_LOCAL_WINDOW_SIZE);

	in->tq = ((in->tq * orig_neigh_node->tq_own * orig_neigh_node->tq_asym_penalty) / (TQ_MAX_VALUE *  TQ_MAX_VALUE));

	/*static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];
	addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
	addr_to_string( orig_neigh_node->orig, neigh_str, ADDR_STR_LEN );*/

	/*debug_output( 3, "bidirectional: orig = %-15s neigh = %-15s => own_bcast = %2i, real recv = %2i, local tq: %3i, asym_penality: %3i, total tq: %3i \n",
	orig_str, neigh_str, total_count, neigh_node->real_packet_count, orig_neigh_node->tq_own, orig_neigh_node->tq_asym_penalty, in->tq );*/
	addr_to_string(str1, orig_node->orig);
	addr_to_string(str2, orig_neigh_node->orig);
	debug_output( 4, "bidirectional: orig = %-15s neigh = %-15s => own_bcast = %2i, real recv = %2i, local tq: %3i, asym_penality: %3i, total tq: %3i \n",
		      str1, str2, total_count, neigh_node->real_packet_count, orig_neigh_node->tq_own, orig_neigh_node->tq_asym_penalty, in->tq );

	/* if link has the minimum required transmission quality consider it bidirectional */
	if (in->tq >= TQ_TOTAL_BIDRECT_LIMIT)
		return 1;

	return 0;
}



int is_my_mac( uint8_t *addr ) {

	struct list_head *if_pos;
	struct batman_if *batman_if;


	list_for_each( if_pos, &if_list ) {

		batman_if = list_entry(if_pos, struct batman_if, list);

		if ( compare_orig( batman_if->hw_addr, addr ) == 0 )
			return 1;

	}

	return 0;

}


void generate_vis_packet() {

	struct hash_it_t *hashit = NULL;
	struct orig_node *orig_node;
	struct vis_data *vis_data;
	struct list_head *list_pos;
	struct batman_if *batman_if;
	int i;


	if ( vis_packet != NULL ) {

		debugFree( vis_packet, 1102 );
		vis_packet = NULL;
		vis_packet_size = 0;

	}

	vis_packet_size = sizeof(struct vis_packet);
	vis_packet = debugMalloc( vis_packet_size, 104 );

	memcpy( ((struct vis_packet *)vis_packet)->sender_mac, (unsigned char *)&(((struct batman_if *)if_list.next)->hw_addr), 6 );

	((struct vis_packet *)vis_packet)->version = VIS_COMPAT_VERSION;
	((struct vis_packet *)vis_packet)->gw_class = gateway_class;
	((struct vis_packet *)vis_packet)->seq_range = TQ_MAX_VALUE;

	/* neighbor list */
	while ( NULL != ( hashit = hash_iterate( orig_hash, hashit ) ) ) {

		orig_node = hashit->bucket->data;

		/* we interested in 1 hop neighbours only */
		if ( ( orig_node->router != NULL ) && ( memcmp(orig_node->orig, orig_node->router->addr, 6) == 0 ) && ( orig_node->router->tq_avg > 0 ) ) {

			vis_packet_size += sizeof(struct vis_data);

			vis_packet = debugRealloc( vis_packet, vis_packet_size, 105 );

			vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

			memcpy( vis_data->mac, (unsigned char *)&orig_node->orig, 6 );

			vis_data->data = orig_node->router->tq_avg;
			vis_data->type = DATA_TYPE_NEIGH;

		}

	}

	/* secondary interfaces */
	if ( found_ifs > 1 ) {

		list_for_each( list_pos, &if_list ) {

			batman_if = list_entry( list_pos, struct batman_if, list );

			if ( memcmp(((struct vis_packet *)vis_packet)->sender_mac, batman_if->hw_addr, 6))
				continue;

			vis_packet_size += sizeof(struct vis_data);

			vis_packet = debugRealloc( vis_packet, vis_packet_size, 106 );

			vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

			memcpy( vis_data->mac, (unsigned char *)&batman_if->hw_addr, 6 );

			vis_data->data = 0;
			vis_data->type = DATA_TYPE_SEC_IF;

		}

	}

	/* hna announcements */
	if ( num_hna > 0 ) {

		vis_packet_size += sizeof(struct vis_data)* num_hna;

		vis_packet = debugRealloc( vis_packet, vis_packet_size, 107 );

		for (i = 0 ; i < (int)num_hna; i++) {

			vis_data = (struct vis_data *)(vis_packet + vis_packet_size - (num_hna-i) * sizeof(struct vis_data));

			memcpy( vis_data->mac, &hna_buff[6*i], 6 );

			vis_data->data = 0;	/* batman advanced does not use a netmask */
			vis_data->type = DATA_TYPE_HNA;
		}

	}


	if ( vis_packet_size == sizeof(struct vis_packet) ) {

		debugFree( vis_packet, 1107 );
		vis_packet = NULL;
		vis_packet_size = 0;

	}

}



void send_vis_packet() {

	generate_vis_packet();

	if ( vis_packet != NULL )
		send_udp_packet( vis_packet, vis_packet_size, &vis_if.addr, vis_if.sock );

}

uint8_t count_real_packets(uint8_t *neigh, struct batman_packet *in, struct batman_if *if_incoming)
{
	struct list_head *list_pos;
	struct orig_node *orig_node;
	struct neigh_node *tmp_neigh_node;
	uint8_t is_duplicate = 0;


	orig_node = get_orig_node(in->orig);

	/*static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];

	addr_to_string( in->orig, orig_str, ADDR_STR_LEN );
	addr_to_string( neigh, neigh_str, ADDR_STR_LEN );

	debug_output( 3, "count_real_packets: orig = %s, neigh = %s, seq = %i, last seq = %i\n", orig_str, neigh_str, in->seqno, orig_node->last_real_seqno );*/

	list_for_each(list_pos, &orig_node->neigh_list) {
		tmp_neigh_node = list_entry(list_pos, struct neigh_node, list);

		if (!is_duplicate)
			is_duplicate = get_bit_status(tmp_neigh_node->real_bits, orig_node->last_real_seqno, in->seqno);

		if ((compare_orig(tmp_neigh_node->addr, neigh) == 0) && (tmp_neigh_node->if_incoming == if_incoming))
			bit_get_packet(tmp_neigh_node->real_bits, in->seqno - orig_node->last_real_seqno, 1);
		else
			bit_get_packet(tmp_neigh_node->real_bits, in->seqno - orig_node->last_real_seqno, 0);

		tmp_neigh_node->real_packet_count = bit_packet_count(tmp_neigh_node->real_bits);
	}

	if (!is_duplicate) {
		debug_output( 4, "updating last_seqno: old %d, new %d \n", orig_node->last_real_seqno, in->seqno );
		orig_node->last_real_seqno = in->seqno;
	}

	return is_duplicate;
}

int8_t batman() {

	struct list_head *if_pos, *forw_pos, *forw_pos_tmp;
	struct orig_node *orig_neigh_node, *orig_node;
	struct batman_if *batman_if, *if_incoming;
	struct forw_node *forw_node;
	uint32_t debug_timeout, select_timeout;
	unsigned char in[2000];
	char str1[ETH_STR_LEN], str2[ETH_STR_LEN], str3[ETH_STR_LEN];
	int16_t in_len;
	int16_t in_hna_len;
	uint8_t *in_hna_buff;
	uint8_t neigh[6], is_my_addr, is_my_orig, is_my_oldorig, is_broadcast, is_duplicate, is_bidirectional, is_single_hop_neigh, has_directlink_flag;
	int8_t res;

	debug_timeout = get_time();

	if ( NULL == ( orig_hash = hash_new( 128, compare_orig, choose_orig ) ) )
		return(-1);

	list_for_each( if_pos, &if_list ) {

		batman_if = list_entry( if_pos, struct batman_if, list );

		batman_if->out.packet_type = BAT_PACKET;
		batman_if->out.version = COMPAT_VERSION;
		batman_if->out.flags = 0x00;
		batman_if->out.ttl = TTL;
		batman_if->out.gwflags = gateway_class;
		batman_if->out.tq = TQ_MAX_VALUE;
		batman_if->out.seqno = 1;
		batman_if->out.num_hna = 0;

		memcpy(batman_if->out.orig, batman_if->hw_addr, 6);
		memcpy(batman_if->out.old_orig, batman_if->hw_addr, 6);

		batman_if->bcast_seqno = 1;

		schedule_own_packet( batman_if );

	}

	if ( -1 == transtable_init())
		return(-1);

	while ( !is_aborted() ) {

		debug_output( 4, " \n \n" );

		/* harden select_timeout against sudden time change (e.g. ntpdate) */
		curr_time = get_time();
		select_timeout = ( curr_time < ((struct forw_node *)forw_list.next)->send_time ? ((struct forw_node *)forw_list.next)->send_time - curr_time : 10 );

		res = receive_packet( in, sizeof(in), &in_len, neigh, select_timeout, &if_incoming );

		if ( res < 0 )
			return -1;

		if ( res > 0 ) {

			curr_time = get_time();

			is_my_addr = is_my_orig = is_my_oldorig = is_broadcast = is_duplicate = is_bidirectional = 0;

			has_directlink_flag = ((struct batman_packet *)&in)->flags & DIRECTLINK ? 1 : 0;

			is_single_hop_neigh = (compare_orig(neigh, ((struct batman_packet *)&in)->orig) == 0 ? 1 : 0);

			in_hna_buff = in + sizeof(struct batman_packet);
			in_hna_len = in_len - sizeof(struct batman_packet);

			addr_to_string(str1, neigh);
			addr_to_string(str2, if_incoming->hw_addr);
			addr_to_string(str3, ((struct batman_packet *)&in)->orig);

			debug_output( 4, "Received BATMAN packet via NB: %s ,IF: %s %s (from OG: %s, seqno %d, TTL %d, V %d, IDF %d) \n",
					str1,
					if_incoming->dev,
					str2,
					str3,
					((struct batman_packet *)&in)->seqno,
					((struct batman_packet *)&in)->ttl,
					((struct batman_packet *)&in)->version,
					has_directlink_flag );

			list_for_each( if_pos, &if_list ) {

				batman_if = list_entry(if_pos, struct batman_if, list);

				if ( compare_orig( neigh, batman_if->hw_addr ) == 0 )
					is_my_addr = 1;

				if ( compare_orig( ((struct batman_packet *)&in)->orig, batman_if->hw_addr ) == 0 )
					is_my_orig = 1;

				if (compare_orig(((struct batman_packet *)&in)->old_orig, batman_if->hw_addr) == 0)
					is_my_oldorig = 1;

				if ( compare_orig( neigh, broadcastAddr ) == 0 )
					is_broadcast = 1;

			}

			if ( ((struct batman_packet *)&in)->gwflags != 0 )
				debug_output( 4, "Is an internet gateway (class %i) \n", ((struct batman_packet *)&in)->gwflags );


			if ( ((struct batman_packet *)&in)->version != COMPAT_VERSION ) {

				debug_output( 4, "Drop packet: incompatible batman version (%i) \n", ((struct batman_packet *)&in)->version );

			} else if ( is_my_addr ) {

				debug_output(4, "Drop packet: received my own broadcast (sender: %s)\n", str1);

			} else if ( is_broadcast ) {

				debug_output( 4, "Drop packet: ignoring all packets with broadcast source IP (sender: %s)\n", str1);

			} else if ( is_my_orig ) {

				orig_neigh_node = get_orig_node( neigh );

				/* neighbour has to indicate direct link and it has to come via the corresponding interface */
				/* if received seqno equals last send seqno save new seqno for bidirectional check */
				if (has_directlink_flag && (((struct batman_packet *)&in)->seqno - if_incoming->out.seqno + 2 == 0)) {
					bit_mark((TYPE_OF_WORD *)&(orig_neigh_node->bcast_own[if_incoming->if_num * NUM_WORDS]), 0);
					orig_neigh_node->bcast_own_sum[if_incoming->if_num] = bit_packet_count((TYPE_OF_WORD *)&(orig_neigh_node->bcast_own[if_incoming->if_num * NUM_WORDS]));
				}

				debug_output( 4, "Drop packet: originator packet from myself (via neighbour) \n" );

			} else if (((struct batman_packet *)&in)->tq == 0) {

				count_real_packets(neigh, (struct batman_packet *)&in, if_incoming);

				debug_output(4, "Drop packet: originator packet with tq equal 0 \n");

			} else if (is_my_oldorig) {

				debug_output(4, "Drop packet: ignoring all rebroadcast echos (sender: %s) \n", str1);

			} else {
				is_duplicate = count_real_packets(neigh, (struct batman_packet *)&in, if_incoming);

				orig_node = get_orig_node( ((struct batman_packet *)&in)->orig );

				/* if sender is a direct neighbor the sender mac equals originator mac */
				orig_neigh_node = (is_single_hop_neigh ? orig_node : get_orig_node(neigh));

				/* drop packet if sender is not a direct neighbor and if we no route towards it */
				if (!is_single_hop_neigh && (orig_neigh_node->router == NULL)) {

					debug_output( 4, "Drop packet: OGM via unkown neighbor! \n" );

				} else {

					is_bidirectional = isBidirectionalNeigh(orig_node, orig_neigh_node, (struct batman_packet *)&in, curr_time, if_incoming);

					/* update ranking if it is not a duplicate or has the same seqno and similar ttl as the non-duplicate */
					if (is_bidirectional && (!is_duplicate || ((orig_node->last_real_seqno == ((struct batman_packet *)&in)->seqno) && (orig_node->last_ttl - 3 <= ((struct batman_packet *)&in)->ttl))))
						update_orig(orig_node, neigh, (struct batman_packet *)&in, if_incoming, in_hna_buff, in_hna_len, is_duplicate, curr_time);

					/* is single hop (direct) neighbour */
					if (is_single_hop_neigh) {

						/* mark direct link on incoming interface */
						schedule_forward_packet(orig_node, neigh, (struct batman_packet *)&in, 1, in_len, if_incoming);

						debug_output(4, "Forward packet: rebroadcast neighbour packet with direct link flag \n" );

					/* multihop originator */
					} else {

						if (is_bidirectional) {

							if (!is_duplicate) {

								schedule_forward_packet(orig_node, neigh, (struct batman_packet *)&in, 0, in_len, if_incoming);

								debug_output(4, "Forward packet: rebroadcast originator packet \n" );

							} else {

								debug_output(4, "Drop packet: duplicate packet received\n" );

							}

						} else {

							debug_output(4, "Drop packet: not received via bidirectional link\n" );

						}

					}

				}
			}
		}


		hna_update(curr_time);
		send_outstanding_packets();

		if (debug_timeout+1000 < curr_time) {

			debug_timeout = curr_time;
			purge_orig(curr_time);
			debug_orig();
			checkIntegrity();

// 			if ( ( routing_class != 0 ) && ( curr_gateway == NULL ) )
// 				choose_gw();

 			if ( vis_if.sock )
 				send_vis_packet();

		}

	}


	if ( debug_level > 0 )
		printf( "Deleting all BATMAN routes\n" );

	purge_orig( get_time() + ( 5 * PURGE_TIMEOUT ) + originator_interval );

	hash_destroy( orig_hash );
	transtable_quit();


	list_for_each_safe( forw_pos, forw_pos_tmp, &forw_list ) {
		forw_node = list_entry( forw_pos, struct forw_node, list );

		list_del( (struct list_head *)&forw_list, forw_pos, &forw_list );

		debugFree( forw_node->pack_buff, 1110 );
		debugFree( forw_node, 1111 );

	}


	return 0;

}
