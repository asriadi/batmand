/*
 * vis.c
 *
 * Copyright (C) 2006 Andreas Langer <a.langer@q-dsl.de>:
 *
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
#include <stdio.h>


#include "vis.h"



static void add_neighbour_node( struct node *orig_node, struct node *orig_neigh_node, unsigned char packet_count ) {

	struct list_head *list_pos;
	struct neighbour *neigh = NULL;


	/* find neighbor in neighbour list of originator */
	list_for_each( list_pos, &orig_node->neigh_list ) {

		neigh = list_entry( list_pos, struct neighbour, list );

		if ( orig_neigh_node->addr == neigh->node->addr )
			break;
		else
			neigh = NULL;

	}

	/* if neighbour does not exist create it */
	if ( neigh == NULL ) {

		neigh = debugMalloc( sizeof(struct neighbour), 401 );
		memset( neigh, 0, sizeof( struct neighbour ) );
		neigh->node = orig_neigh_node;

		list_add_tail( &neigh->list, &orig_node->neigh_list );

	}

	/* save new packet count */
	neigh->packet_count = packet_count;


	neigh = NULL;

	/* find originator in neighbour list of neighbour (for faster deleting) */
	list_for_each( list_pos, &orig_neigh_node->rev_neigh_list ) {

		neigh = list_entry( list_pos, struct neighbour, list );

		if ( orig_node->addr == neigh->node->addr )
			break;
		else
			neigh = NULL;

	}

	/* if originator does not exist create it */
	if ( neigh == NULL ) {

		neigh = debugMalloc( sizeof(struct neighbour), 413 );
		memset( neigh, 0, sizeof( struct neighbour ) );
		neigh->node = orig_node;

		list_add_tail( &neigh->list, &orig_neigh_node->rev_neigh_list );

	}

	return;

}



void handle_node( unsigned int sender_ip, unsigned int neigh_ip, unsigned char neigh_packet_count, unsigned char gw_class, unsigned char seq_range ) {

	struct node *orig_node, *orig_neigh_node;
	struct hashtable_t *swaphash;

	/*char from_str[16];
	char to_str[16];

	addr_to_string( sender_ip, from_str, sizeof(from_str) );
	addr_to_string( neigh_ip, to_str, sizeof(to_str) );
	printf( "UDP data from %s: %s \n", from_str, to_str );*/

	if ( node_hash->elements * 4 > node_hash->size ) {

		swaphash = hash_resize( node_hash, node_hash->size * 2 );

		if ( swaphash == NULL )
			exit_error( "Couldn't resize hash table \n" );

		node_hash = swaphash;

	}

	/* the neighbour */
	orig_neigh_node = (struct node *)hash_find( node_hash, &neigh_ip );

	/* node not found */
	if ( orig_neigh_node == NULL ) {

		orig_neigh_node = (struct node *)debugMalloc( sizeof(struct node), 402 );
		orig_neigh_node->addr = neigh_ip;
		orig_neigh_node->last_seen = 10;

		INIT_LIST_HEAD_FIRST( orig_neigh_node->neigh_list );
		INIT_LIST_HEAD_FIRST( orig_neigh_node->rev_neigh_list );

		hash_add( node_hash, orig_neigh_node );

	} else {

		orig_neigh_node->last_seen = 10;

	}

	/* the node which send the packet */
	orig_node = (struct node *)hash_find( node_hash, &sender_ip );

	/* node not found */
	if ( orig_node == NULL ) {

		orig_node = (struct node *)debugMalloc( sizeof(struct node), 403 );
		orig_node->addr = sender_ip;
		orig_node->last_seen = 10;
		orig_node->gw_class = gw_class;
		orig_node->seq_range = seq_range;

		INIT_LIST_HEAD_FIRST( orig_node->neigh_list );
		INIT_LIST_HEAD_FIRST( orig_node->rev_neigh_list );

		hash_add( node_hash, orig_node );

	} else {

		orig_node->last_seen = 10;
		orig_node->gw_class = gw_class;

	}

// 	add_neighbour_node( orig_neigh_node, neigh_packet_count, &orig_node->neighbour );
// 	add_is_neighbour_node( orig_node, orig_neigh_node );

	add_neighbour_node( orig_node, orig_neigh_node, neigh_packet_count );

	return;

}



void *udp_server() {

	struct vis_if *vis_if;
	struct list_head *list_pos;
	struct sockaddr_in client;
	struct timeval tv;
	unsigned char receive_buff[MAXCHAR], *payload_ptr;
	int max_sock = 0, packet_count, i, buff_len;
	int orig_neigh_node, orig_node;
	fd_set wait_sockets, tmp_wait_sockets;
	socklen_t len;


	FD_ZERO(&wait_sockets);

	list_for_each( list_pos, &vis_if_list ) {

		vis_if = list_entry( list_pos, struct vis_if, list );

		if ( vis_if->udp_sock > max_sock )
			max_sock = vis_if->udp_sock;

		FD_SET(vis_if->udp_sock, &wait_sockets);

	}


	while ( !is_aborted() ) {

		len = sizeof(client);

		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof(fd_set) );

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if ( select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv ) > 0 ) {

			list_for_each( list_pos, &vis_if_list ) {

				vis_if = list_entry( list_pos, struct vis_if, list );

				if ( FD_ISSET( vis_if->udp_sock, &tmp_wait_sockets ) ) {

					buff_len = recvfrom( vis_if->udp_sock, receive_buff, sizeof(receive_buff), 0, (struct sockaddr*)&client, &len );

					/* 11 bytes is minumum packet size: sender ip, gateway class, seq range, neighbour ip, neighbour packet count */
					if ( buff_len > 10 ) {

						if ( pthread_mutex_trylock( &hash_mutex ) == 0 ) {

							packet_count = buff_len - 6 / PACKET_FIELD_LENGTH;
							memmove( &orig_node, &receive_buff, 4 );
							payload_ptr = receive_buff + 6;

							if ( orig_node != 0 ) {

								for( i = 0; i < packet_count; i++ ) {

									memmove( &orig_neigh_node, payload_ptr + i * PACKET_FIELD_LENGTH, 4 );

									if ( orig_neigh_node != 0 )
										handle_node( orig_node, orig_neigh_node, payload_ptr[i*PACKET_FIELD_LENGTH+4], receive_buff[4], receive_buff[5] );

								}

							}

							if ( pthread_mutex_unlock( &hash_mutex ) < 0 )
								printf( "Error - could not unlock mutex (udp server): %s \n", strerror( errno ) );

						} else {

							printf( "Warning - dropping UDP packet: hash mutext is locked (%s)\n", strerror( EBUSY ) );

						}

					}

				}

			}

		}

	}

	return NULL;

}

