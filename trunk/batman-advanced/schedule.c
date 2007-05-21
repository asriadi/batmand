/* Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Simon Wunderlich, Marek Lindner
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



#include <string.h>
#include <stdlib.h>
#include "os.h"
#include "batman-adv.h"



void schedule_own_packet( struct batman_if *batman_if ) {

	struct forw_node *forw_node_new, *forw_packet_tmp = NULL;
	struct list_head *list_pos, *prev_list_head;


	forw_node_new = debugMalloc( sizeof(struct forw_node), 501 );

	INIT_LIST_HEAD( &forw_node_new->list );

	forw_node_new->if_outgoing = batman_if;
	forw_node_new->own = 1;
	forw_node_new->send_time = get_time() + originator_interval - JITTER + rand_num( 2 * JITTER );

	forw_node_new->pack_buff = debugMalloc( sizeof(struct batman_packet), 502 );
	memcpy( forw_node_new->pack_buff, &batman_if->out, sizeof(struct batman_packet) );
	forw_node_new->pack_buff_len = sizeof(struct batman_packet);

	prev_list_head = (struct list_head *)&forw_list;

	list_for_each( list_pos, &forw_list ) {

		forw_packet_tmp = list_entry( list_pos, struct forw_node, list );

		if ( forw_packet_tmp->send_time > forw_node_new->send_time ) {

			list_add_before( prev_list_head, list_pos, &forw_node_new->list );
			break;

		}

		prev_list_head = &forw_packet_tmp->list;

	}

	if ( ( forw_packet_tmp == NULL ) || ( forw_packet_tmp->send_time <= forw_node_new->send_time ) )
		list_add_tail( &forw_node_new->list, &forw_list );

	batman_if->out.seqno++;

}



void schedule_forward_packet( struct batman_packet *in, uint8_t unidirectional, uint8_t directlink, struct batman_if *if_outgoing ) {

	struct forw_node *forw_node_new;

	debug_output( 4, "schedule_forward_packet():  \n" );

	if ( in->ttl <= 1 ) {

		debug_output( 4, "ttl exceeded \n" );

	} else {

		forw_node_new = debugMalloc( sizeof(struct forw_node), 503 );

		INIT_LIST_HEAD(&forw_node_new->list);

		forw_node_new->pack_buff = debugMalloc( sizeof(struct batman_packet), 504 );
		memcpy( forw_node_new->pack_buff, in, sizeof(struct batman_packet) );
		forw_node_new->pack_buff_len = sizeof(struct batman_packet);

		((struct batman_packet *)forw_node_new->pack_buff)->ttl--;

		forw_node_new->send_time = get_time();
		forw_node_new->own = 0;

		forw_node_new->if_outgoing = if_outgoing;

		if ( unidirectional ) {

			((struct batman_packet *)forw_node_new->pack_buff)->flags = ( UNIDIRECTIONAL | DIRECTLINK );

		} else if ( directlink ) {

			((struct batman_packet *)forw_node_new->pack_buff)->flags = DIRECTLINK;

		} else {

			((struct batman_packet *)forw_node_new->pack_buff)->flags = 0x00;

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

			directlink = ( ( ((struct batman_packet *)forw_node->pack_buff)->flags & DIRECTLINK ) ? 1 : 0 );

			((struct batman_packet *)forw_node->pack_buff)->seqno = htons( ((struct batman_packet *)forw_node->pack_buff)->seqno ); /* change sequence number to network order */


			if ( ((struct batman_packet *)forw_node->pack_buff)->flags & UNIDIRECTIONAL ) {

				if ( forw_node->if_outgoing != NULL ) {

					debug_output( 4, "Forwarding packet (originator %s, seqno %d, TTL %d) on interface %s\n", addr_to_string( ((struct batman_packet *)forw_node->pack_buff)->orig ), ntohs( ((struct batman_packet *)forw_node->pack_buff)->seqno ), ((struct batman_packet *)forw_node->pack_buff)->ttl, forw_node->if_outgoing->dev );

					if ( send_packet( forw_node->pack_buff, forw_node->pack_buff_len, forw_node->if_outgoing->hw_addr, broadcastAddr, forw_node->if_outgoing->raw_sock ) < 0 )
						restore_and_exit(0);

				} else {

					debug_output( 0, "Error - can't forward packet with UDF: outgoing iface not specified \n" );

				}

			/* multihomed peer assumed */
			} else if ( ( directlink ) && ( ((struct batman_packet *)forw_node->pack_buff)->ttl == 1 ) ) {

				if ( ( forw_node->if_outgoing != NULL ) ) {

					if ( send_packet( forw_node->pack_buff, forw_node->pack_buff_len, forw_node->if_outgoing->hw_addr, broadcastAddr, forw_node->if_outgoing->raw_sock ) < 0 )
						restore_and_exit(0);

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
							((struct batman_packet *)forw_node->pack_buff)->flags = DIRECTLINK;
						} else {
							((struct batman_packet *)forw_node->pack_buff)->flags = 0x00;
						}

						debug_output( 4, "Forwarding packet (originator %s, seqno %d, TTL %d) on interface %s \n", addr_to_string( ((struct batman_packet *)forw_node->pack_buff)->orig ), ntohs( ((struct batman_packet *)forw_node->pack_buff)->seqno ), ((struct batman_packet *)forw_node->pack_buff)->ttl, batman_if->dev );

						if ( send_packet( forw_node->pack_buff, forw_node->pack_buff_len, batman_if->hw_addr, broadcastAddr, batman_if->raw_sock ) < 0 )
							restore_and_exit(0);

					}

				}

			}

			list_del( (struct list_head *)&forw_list, forw_pos, &forw_list );

			if ( forw_node->own )
				schedule_own_packet( forw_node->if_outgoing );

			debugFree( forw_node->pack_buff, 1501 );
			debugFree( forw_node, 1502 );

		} else {

			break;

		}

	}

}
