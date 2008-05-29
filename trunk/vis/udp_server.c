/*
 * udp_server.c
 *
 * Copyright (C) 2006 Marek Lindner:
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



void handle_node( unsigned int sender_ip, unsigned char *buff, int buff_len, unsigned char gw_class, uint16_t tq_max ) {

	struct node *orig_node;
	struct secif *secif;
	struct secif_lst *secif_lst;
	struct hashtable_t *swaphash;
	struct neighbour *neigh;
	struct hna *hna;
	struct list_head *list_pos;
	struct vis_data *vis_data;
	int packet_count, i;

	/*char from_str[16];
	char to_str[16];

	addr_to_string( sender_ip, from_str, sizeof(from_str) );
// 	addr_to_string( neigh_ip, to_str, sizeof(to_str) );
	printf( "UDP data from %s \n", from_str );*/

	if ( node_hash->elements * 4 > node_hash->size ) {

		swaphash = hash_resize( node_hash, node_hash->size * 2 );

		if ( swaphash == NULL )
			exit_error( "Couldn't resize node hash table \n" );

		node_hash = swaphash;

	}


	/* the node which send the packet */
	orig_node = (struct node *)hash_find( node_hash, &sender_ip );

	/* node not found */
	if ( orig_node == NULL ) {

		orig_node = (struct node *)debugMalloc( sizeof(struct node), 1100 );
		memset( orig_node, 0, sizeof(struct node) );

		orig_node->addr = sender_ip;

		INIT_LIST_HEAD_FIRST( orig_node->neigh_list );
		INIT_LIST_HEAD_FIRST( orig_node->secif_list );
		INIT_LIST_HEAD_FIRST( orig_node->hna_list );

		hash_add( node_hash, orig_node );

	}

	orig_node->last_seen = 20;
	orig_node->gw_class = gw_class;
	orig_node->tq_max = tq_max;

	packet_count = buff_len / sizeof(struct vis_data);

	for( i = 0; i < packet_count; i++ ) {
		vis_data = (struct vis_data *)(buff + i * sizeof(struct vis_data));

		if ( vis_data->ip != 0 ) {

			/* is neighbour */
			if ( vis_data->type == DATA_TYPE_NEIGH ) {


				if ( vis_data->data > orig_node->tq_max )
					continue;

				neigh = NULL;

				/* find neighbor in neighbour list of originator */
				list_for_each( list_pos, &orig_node->neigh_list ) {

					neigh = list_entry( list_pos, struct neighbour, list );

					if ( vis_data->ip == neigh->addr )
						break;
					else
						neigh = NULL;

				}

				/* if neighbour does not exist create it */
				if ( neigh == NULL ) {

					neigh = debugMalloc( sizeof(struct neighbour), 1101 );
					memset( neigh, 0, sizeof(struct neighbour) );
					neigh->addr = vis_data->ip;

					INIT_LIST_HEAD( &neigh->list );

					list_add_tail( &neigh->list, &orig_node->neigh_list );

				}

				/* save new tq value */
				neigh->tq_avg = vis_data->data;
				neigh->last_seen = 20;

			/* is secondary interface */
			} else if ( vis_data->type == DATA_TYPE_SEC_IF ) {

				if ( secif_hash->elements * 4 > secif_hash->size ) {

					swaphash = hash_resize( secif_hash, secif_hash->size * 2 );

					if ( swaphash == NULL )
						exit_error( "Couldn't resize secif hash table \n" );

					secif_hash = swaphash;

				}

				/* use hash for fast processing of secondary interfaces in write_data_in_buffer() */
				secif = (struct secif *)hash_find( secif_hash, &vis_data->ip );

				if ( secif == NULL ) {

					secif = (struct secif *)debugMalloc( sizeof(struct secif), 1102 );

					secif->addr = vis_data->ip;
					secif->orig = orig_node;

					hash_add( secif_hash, secif );

				}

				/* maintain list of own secondary interfaces which must be removed from the hash if the originator is purged */
				secif_lst = NULL;

				/* find secondary interface in secondary if list of originator */
				list_for_each( list_pos, &orig_node->secif_list ) {

					secif_lst = list_entry( list_pos, struct secif_lst, list );

					if ( vis_data->ip == secif_lst->addr )
						break;
					else
						secif_lst = NULL;

				}

				/* if secondary interface does not exist create it */
				if ( secif_lst == NULL ) {

					secif_lst = debugMalloc( sizeof(struct secif_lst), 1103 );
					memset( secif_lst, 0, sizeof(struct secif_lst) );

					secif_lst->addr = vis_data->ip;

					INIT_LIST_HEAD( &secif_lst->list );

					list_add_tail( &secif_lst->list, &orig_node->secif_list );

				}

				secif_lst->last_seen = 20;

			} else if ( vis_data->type == DATA_TYPE_HNA ) {

				if ( vis_data->data > 32 )
					continue;

				hna = NULL;

				/* find hna in hna list of originator */
				list_for_each( list_pos, &orig_node->hna_list ) {

					hna = list_entry( list_pos, struct hna, list );

					if ( ( vis_data->ip == hna->addr ) && ( vis_data->data == hna->netmask ) )
						break;
					else
						hna = NULL;

				}

				/* if hna does not exist create it */
				if ( hna == NULL ) {

					hna = debugMalloc( sizeof(struct hna), 1104 );
					memset( hna, 0, sizeof(struct hna) );
					hna->addr = vis_data->ip;
					hna->netmask = vis_data->data;

					INIT_LIST_HEAD( &hna->list );

					list_add_tail( &hna->list, &orig_node->hna_list );

				}

				hna->last_seen = 20;

			}

		}

	}

	return;

}



void *udp_server() {

	struct vis_if *vis_if;
	struct list_head *list_pos;
	struct sockaddr_in client;
	struct timeval tv;
	unsigned char receive_buff[MAXCHAR];
	int max_sock = 0, buff_len;
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

					/* drop packet if it has not minumum packet size or not the correct version */
					if ( ( buff_len >= sizeof(struct vis_packet) + sizeof(struct vis_data) ) && ( ((struct vis_packet *)receive_buff)->version == VIS_COMPAT_VERSION ) ) {

						if ( ((struct vis_packet *)receive_buff)->sender_ip != 0 ) {

							if ( pthread_mutex_trylock( &hash_mutex ) == 0 ) {

								handle_node( ((struct vis_packet *)receive_buff)->sender_ip, receive_buff + sizeof(struct vis_packet), buff_len - sizeof(struct vis_packet), ((struct vis_packet *)receive_buff)->gw_class, ((struct vis_packet *)receive_buff)->tq_max );

								if ( pthread_mutex_unlock( &hash_mutex ) < 0 )
									debug_output( "Error - could not unlock mutex (udp server): %s \n", strerror( errno ) );

							} else {

								debug_output( "Warning - dropping UDP packet: hash mutext is locked (%s)\n", strerror( EBUSY ) );

							}

						}

					}

				}

			}

		}

	}

	return NULL;

}

