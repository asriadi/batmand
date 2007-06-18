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

#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <getopt.h>


#include "hash.h"
#include "allocate.h"
#include "vis.h"



struct list_head_first udp_if_list;

pthread_t udp_server_thread = 0;
pthread_t master_thread = 0;

struct node *root = NULL;

buffer_t *current = NULL;
buffer_t *first = NULL;
buffer_t *fillme = NULL;

static int8_t stop, sd;
struct hashtable_t *node_hash;

void handler( int32_t sig ) {
	switch( sig ) {
		case SIGINT:
		case SIGTERM:
			stop =1;
			break;
		default:
			break;
	}
}

int8_t is_aborted() {
	return stop != 0;
}

int32_t orig_comp(void *data1, void *data2) {
	return(memcmp(data1, data2, 4));
}

/* hashfunction to choose an entry in a hash table of given size */
/* hash algorithm from http://en.wikipedia.org/wiki/Hash_table */
int32_t orig_choose(void *data, int32_t size) {
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



void restore_defaults() {

	struct udp_if *udp_if;
	struct list_head *list_pos, *list_pos_tmp;


	if ( udp_server_thread != 0 )
		pthread_join( udp_server_thread, NULL );

	if ( master_thread != 0 )
		pthread_join( master_thread, NULL );

	list_for_each_safe( list_pos, list_pos_tmp, &udp_if_list ) {

		udp_if = list_entry( list_pos, struct udp_if, list );

		if ( udp_if->sock )
			close( udp_if->sock );

		debugFree( udp_if, 1200 );

	}

	clean_hash();
	hash_destroy( node_hash );

	clean_buffer();

}



void exit_error(char *format, ...) {

	va_list args;


	va_start(args, format);
	vprintf(format, args);
	va_end(args);

	restore_defaults();

	exit( EXIT_FAILURE );

}



void addr_to_string(unsigned int addr, char *str, int len)
{
	inet_ntop(AF_INET, &addr, str, len);
	return;
}

static int calc_packet_count_average(struct node *node)
{
	struct neighbour *neigh;
	int pc = 0, cnt = 0;

	if(node->neighbour == NULL)
		return(0);

	for(neigh = node->neighbour; neigh != NULL; neigh = neigh->next)
	{
		pc += neigh->packet_count;
		cnt++;
	}
	return(pc/cnt);
}

void clean_hash() {

	struct neighbour *neigh, *neigh_delete, *is_neigh, *is_neigh_delete;
	struct node *node;
	struct hash_it_t *hashit;

	if( node_hash->elements == 0 )
		return;

	hashit = NULL;
	while ( NULL != ( hashit = hash_iterate( node_hash, hashit ) ) )
	{
		node = (struct node *) hashit->bucket->data;
		hash_remove_bucket( node_hash, hashit );

		neigh = node->neighbour;
		while( NULL != neigh  )
		{
			neigh_delete = neigh;
			neigh = neigh->next;
			debugFree( neigh_delete, 1404 );
		}
		is_neigh = node->is_neighbour;
		while( NULL != is_neigh  )
		{
			is_neigh_delete = is_neigh;
			is_neigh = is_neigh->next;
			debugFree( is_neigh_delete, 1414 );
		}
		debugFree( node, 1410 );
	}

	return;

}



void clean_buffer() {

	buffer_t *i = first , *rm;


	while ( i != NULL ) {

		rm = i;
		i = i->next;
		debugFree( rm->buffer, 1410 );
		debugFree( rm, 1405 );

	}

}



static void add_neighbour_node(struct node *orig, unsigned char packet_count, struct neighbour **neigh)
{
	struct neighbour *prev = NULL;

	while( (*neigh) != NULL)
	{
		if( (*neigh)->node == orig)
		{
			(*neigh)->packet_count = packet_count;
			return;
		}
		prev = (*neigh);
		neigh = &(*neigh)->next;
	}

	(*neigh) = (struct neighbour*) debugMalloc( sizeof(struct neighbour), 401 );
	memset( (*neigh), 0, sizeof( struct neighbour ) );
	(*neigh)->node = orig;
	(*neigh)->packet_count = packet_count;
	(*neigh)->next = NULL;
	if(prev != NULL)
		prev->next = (*neigh);
	return;
}

static void add_is_neighbour_node(struct node *node, struct neighbour **is_neigh)
{
	struct neighbour *prev = NULL;

	while( (*is_neigh) != NULL)
	{
		if( (*is_neigh)->node == node)
			return;
		prev = (*is_neigh);
		is_neigh = &(*is_neigh)->next;
	}

	(*is_neigh) = (struct neighbour*) debugMalloc( sizeof(struct neighbour), 413 );
	memset( (*is_neigh), 0, sizeof( struct neighbour ) );
	(*is_neigh)->node = node;
	(*is_neigh)->packet_count = 0;
	(*is_neigh)->next = NULL;
	if(prev != NULL)
		prev->next = (*is_neigh);
	return;
}



void handle_node( unsigned int sender_ip, unsigned int neigh_ip, unsigned char neigh_packet_count, unsigned char gw_class ) {

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
		orig_neigh_node->neighbour = NULL;
		orig_neigh_node->is_neighbour = NULL;
		orig_neigh_node->packet_count_average = 0;
		orig_neigh_node->last_seen = 10;

		if ( pthread_mutex_init( &orig_neigh_node->mutex, NULL ) != 0 )
			exit_error( "Error - can't init mutex for orig neigh node\n");

		hash_add( node_hash, orig_neigh_node );

	} else {

		pthread_mutex_lock( &orig_neigh_node->mutex );
		orig_neigh_node->last_seen = 10;
		pthread_mutex_unlock( &orig_neigh_node->mutex );

	}

	/* the node which send the packet */
	orig_node = (struct node *)hash_find( node_hash, &sender_ip );

	/* node not found */
	if( orig_node == NULL ) {

		orig_node = (struct node *)debugMalloc( sizeof(struct node), 403 );
		orig_node->addr = sender_ip;
		orig_node->neighbour = NULL;
		orig_neigh_node->is_neighbour = NULL;
		orig_node->packet_count_average = 0;
		orig_node->last_seen = 10;
		orig_node->gw_class = gw_class;

		if ( pthread_mutex_init(&orig_node->mutex, NULL) != 0 )
			exit_error( "Error - can't init mutex for orig node\n");

		hash_add( node_hash, orig_node );

	} else {

		pthread_mutex_lock( &orig_node->mutex );
		orig_node->last_seen = 10;
		orig_node->gw_class = gw_class;
		pthread_mutex_unlock( &orig_node->mutex );

	}

	add_neighbour_node( orig_neigh_node, neigh_packet_count, &orig_node->neighbour );
	add_is_neighbour_node( orig_node, &orig_neigh_node->is_neighbour );
	orig_node->packet_count_average = calc_packet_count_average( orig_node );

	return;

}



void write_data_in_buffer()
{
	struct neighbour *neigh;
	struct node *node;
	struct hash_it_t *hashit;

	char from_str[16];
	char to_str[16];
	char tmp[100];

	if( node_hash->elements == 0 )
		return;
	memset( tmp, '\0', sizeof( tmp ) );
	hashit = NULL;
	while ( NULL != ( hashit = hash_iterate( node_hash, hashit ) ) )
	{
		node = (struct node *) hashit->bucket->data;
		addr_to_string( node->addr, from_str, sizeof( from_str ) );
		for( neigh = node->neighbour; neigh != NULL; neigh = neigh->next )
		{
			addr_to_string( neigh->node->addr, to_str, sizeof( to_str ) );
			snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"%s\"[label=\"%.2f\"]\n", from_str, to_str, (float)( 64 / ( int )neigh->packet_count ) );
			fillme->buffer = (char *)debugRealloc( fillme->buffer, strlen( tmp ) + strlen( fillme->buffer ) + 1, 408 );

			strncat( fillme->buffer, tmp, strlen( tmp ) );
		}
		/*printf("gw_class %d\n",(unsigned int)node->gw_class);*/
		if( node->gw_class != 0 ) {
			snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"0.0.0.0/0.0.0.0\"[label=\"HNA\"]\n", from_str );
			fillme->buffer = (char *)debugRealloc( fillme->buffer, strlen( tmp ) + strlen( fillme->buffer ) + 1, 409 );
			strncat( fillme->buffer, tmp, strlen( tmp ) );
		}

	}
	return;
}



void *udp_server() {

	struct udp_if *udp_if;
	struct list_head *list_pos;
	struct sockaddr_in client;
	struct timeval tv;
	unsigned char receive_buff[MAXCHAR];
	int max_sock = 0, packet_count, i, buff_len;
	int orig_neigh_node, orig_node;
	fd_set wait_sockets, tmp_wait_sockets;
	socklen_t len;


	FD_ZERO(&wait_sockets);

	list_for_each( list_pos, &udp_if_list ) {

		udp_if = list_entry( list_pos, struct udp_if, list );

		if ( udp_if->sock > max_sock )
			max_sock = udp_if->sock;

		FD_SET(udp_if->sock, &wait_sockets);

	}


	while ( !is_aborted() ) {

		len = sizeof(client);

		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof(fd_set) );

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if ( select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv ) > 0 ) {

			list_for_each( list_pos, &udp_if_list ) {

				udp_if = list_entry( list_pos, struct udp_if, list );

				if ( FD_ISSET( udp_if->sock, &tmp_wait_sockets ) ) {

					buff_len = recvfrom( udp_if->sock, receive_buff, sizeof(receive_buff), 0, (struct sockaddr*)&client, &len );

					/* 10 bytes is minumum packet size: sender ip, gateway class, neighbour ip, neighbour packet count */
					if ( buff_len > 9 ) {

						packet_count = buff_len / PACKET_FIELD_LENGTH;
						memmove( &orig_node, &receive_buff, 4 );

						for( i = 1; i < packet_count; i++ ) {

							memmove( &orig_neigh_node, &receive_buff[i*PACKET_FIELD_LENGTH], 4 );
							handle_node( orig_node, orig_neigh_node, receive_buff[i*PACKET_FIELD_LENGTH+4], receive_buff[4] );

						}

					}

				}

			}

		}

	}

	return NULL;

}



void *tcp_server( void *arg ) {

	struct thread_data *thread_data = ((struct thread_data*) arg);
	buffer_t *last_send = NULL;
	ssize_t ret;


	signal( SIGPIPE, SIG_IGN );

	while( !is_aborted() ) {

		if ( current != NULL && current != last_send ) {

			pthread_mutex_lock( &current->mutex );
			current->counter = current->counter == -1 ? 1 : current->counter + 1;
			pthread_mutex_unlock( &current->mutex );
			ret = write( thread_data->socket, current->buffer, strlen( current->buffer ) );
			if( ret != strlen( current->buffer ) )
			{

				pthread_mutex_lock( &current->mutex );
				current->counter--;
				pthread_mutex_unlock( &current->mutex );
				break;
			}
			pthread_mutex_lock( &current->mutex );
			current->counter--;
			pthread_mutex_unlock( &current->mutex );
			last_send = current;

		}

		sleep(5);

	}

	printf( "TCP client has left: %s \n", thread_data->ip );

	close( thread_data->socket );
	debugFree( arg, 1400 );

	return NULL;

}



void *master() {

	buffer_t *new, *tmp;
	char begin[] = "digraph topology\n{\n";
	char end[] = "}\n";

	while ( !is_aborted() ) {

		tmp = first;

		while ( tmp != NULL ) {

			if ( tmp->counter > 0 || tmp == current )
				break;

			first = tmp->next;
			debugFree( tmp->buffer, 1402 );
			debugFree( tmp, 1403 );
			tmp = first;

		}

		new = debugMalloc( sizeof( buffer_t ), 404 );
		new->counter = -1;
		new->next = NULL;
		pthread_mutex_init( &new->mutex, NULL );

		new->buffer = (char *) debugMalloc( strlen( begin ) + 1, 405 );
		memset( new->buffer, '\0', strlen( begin ) );
		strncpy( new->buffer, begin, strlen( begin ) + 1);

		/* printf( "vis.c buffer: %s\n-----Ende-----\n", new->buffer ); */
		fillme = new;

		write_data_in_buffer();

		new->buffer = (char *)debugRealloc( new->buffer, strlen( new->buffer ) + strlen( end ) + 1, 407 );
		strncat( new->buffer, end, strlen( end ) );

		if ( first == NULL )
			first = new;
		else
			current->next = new;

		current = new;

		sleep(3);

	}

	return NULL;

}

void *cleaner( void *arg)
{
	struct neighbour *tmp, *rm, *rm_neigh, *tmp_neigh, *prev;
	struct node *node, *tmp_node;
	struct hash_it_t *hashit;
	char str1[ADDR_STR_LEN];

	sd++;
	while( !is_aborted() )
	{
		hashit = NULL;
		while ( NULL != ( hashit = hash_iterate( node_hash, hashit ) ) )
		{
			node = (struct node *) hashit->bucket->data;
			addr_to_string( node->addr, str1, sizeof (str1));
			/*printf( "node %s....", str1);*/
			if( node->last_seen > 0 )
			{
				pthread_mutex_lock(&node->mutex);
				node->last_seen--;
				pthread_mutex_unlock(&node->mutex);
				/*printf("last_seen = %d\n",node->last_seen);*/
			} else {
				/*printf("start delete\n");*/
				tmp = node->is_neighbour;

				while( tmp != NULL )
				{
					char str1[ADDR_STR_LEN];
					addr_to_string( tmp->node->addr, str1, sizeof(str1));
					/*printf("is_neighbour %s\n", str1);*/

					rm = tmp;
					tmp_node = tmp->node;
					tmp_neigh = tmp_node->neighbour;
					prev = NULL;
					while( tmp_neigh != NULL )
					{
						addr_to_string( tmp_neigh->node->addr, str1, sizeof(str1));
						/*printf("\tin is_neighbour %s %d\n", str1, (int) tmp_neigh->next);*/
						rm_neigh = NULL;

						if( tmp_neigh->node == node )
						{
							/*printf( "\ttmp->node == node\n");*/
							rm_neigh = tmp_neigh;
							if( prev != NULL )
								prev->next = tmp_neigh->next;
						} else {
							/*printf( "\ttmp->node != node\n");*/
							prev = tmp_neigh;
						}

						tmp_neigh = tmp_neigh->next;

						if( rm_neigh != NULL )
						{
							addr_to_string( rm_neigh->node->addr, str1, sizeof(str1));
							/*printf( "\t\tremove %s\n", str1);*/
							debugFree( rm_neigh, 1412 );
							rm_neigh = NULL;
						}
					}
					tmp = tmp->next;
					debugFree( rm, 1413 );
					rm = NULL;
				}
				hash_remove_bucket( node_hash, hashit );
				debugFree( node, 1414 );
			}
			sleep(2);
		}
	}
	printf("shutdown cleaner....");
	printf("ok\n");
	sd--;
	return NULL;
}

void print_usage() {

	printf( "B.A.T.M.A.N. visualisation server %s\n", VERSION );
	printf("Usage: vis -l <tcp interface for dot draw connections> <udp interface(s) for incoming vis packets> \n");
	printf("\t-h help\n");
	printf("\t-v Version\n\n");
	printf("Olsrs3d / Meshs3d is an application to visualize a mesh network.\nIt is a part of s3d, have a look at s3d.berlios.de\n\n");

}

int main( int argc, char **argv ) {

	char *listen_if = NULL, ip_str[ADDR_STR_LEN];
	int optchar, tcp_sock, on = 1;
	uint8_t found_args = 1;
	struct sockaddr_in tcp_addr, addr_client;
	struct ifreq int_req;
	struct udp_if *udp_if;
	struct thread_data *thread_data;
	struct timeval tv;
	fd_set wait_sockets;
	socklen_t len_inet;
	pthread_t tcp_server_thread;

	/*int sock;
	struct sockaddr_in tcp_addr, addr_client;
	struct ifreq int_req;
	char str1[ADDR_STR_LEN];
	socklen_t len_inet;
	struct thread_data t_data;
	struct timeval tv;
	fd_set wait_sockets;
	pthread_t udp_server_thread, tcp_server_thread, master_thread, cleaner_thread;*/

	while ( ( optchar = getopt ( argc, argv, "hl:v" ) ) != -1 ) {

		switch( optchar ) {

			case 'h':
				print_usage();
				exit(EXIT_SUCCESS);
				break;

			case 'l':
				listen_if = optarg;
				found_args += 2;
				break;

			case 'v':
				printf( "B.A.T.M.A.N. visualisation server %s\n", VERSION );
				exit(EXIT_SUCCESS);
				break;

			default:
				print_usage();
				exit(EXIT_SUCCESS);
				break;

		}

	}


	stop = 0;

	signal( SIGINT, handler );
	signal( SIGTERM, handler );
	signal( SIGPIPE, SIG_IGN );

	/* init hashtable for node struct */
	if ( NULL == ( node_hash = hash_new( 1600, orig_comp, orig_choose ) ) )
		exit_error( "Error - can't create hashtable\n");

	INIT_LIST_HEAD_FIRST( udp_if_list );

	if ( listen_if == NULL ) {

		print_usage();
		exit_error( "Error - no TCP listen interface specified \n" );

	} else {

		if ( strlen( listen_if ) > IFNAMSIZ - 1 )
			exit_error( "Error - interface name too long: %s\n", listen_if );

		if ( ( tcp_sock = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
			exit_error( "Error - could not create tcp socket for interface %s: %s\n", listen_if, strerror( errno ) );

		memset( &int_req, 0, sizeof(struct ifreq) );
		strncpy( int_req.ifr_name, listen_if, IFNAMSIZ - 1 );

		if ( ioctl( tcp_sock, SIOCGIFADDR, &int_req ) < 0 ) {

			close( tcp_sock );
			exit_error( "Error - can't get IP address of interface %s\n", listen_if );

		}

		memset( &tcp_addr, 0, sizeof(tcp_addr) );
		tcp_addr.sin_family = AF_INET;
		tcp_addr.sin_port = htons(DOT_DRAW_PORT);
		tcp_addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

		if ( setsockopt( tcp_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int) ) < 0 ) {

			close( tcp_sock );
			exit_error( "Error - ioctl SO_REUSEADDR on interface %s failed: %s\n", listen_if, strerror( errno ) );

		}

		if ( bind( tcp_sock, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr) ) < 0 ) {

			close( tcp_sock );
			exit_error( "Error - could not bind to interface %s: %s\n", listen_if, strerror( errno ) );

		}

	}

	if ( argc <= found_args ) {

		close( tcp_sock );
		exit_error( "Error - no UDP listen interface specified\n" );

	}


	while ( argc > found_args ) {

		udp_if = debugMalloc( sizeof(struct udp_if), 206 );
		memset( udp_if, 0, sizeof(struct udp_if) );
		INIT_LIST_HEAD( &udp_if->list );

		udp_if->dev = argv[found_args];

		if ( strlen( udp_if->dev ) > IFNAMSIZ - 1 )
			exit_error( "Error - interface name too long: %s\n", udp_if->dev );

		if ( ( udp_if->sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 )
			exit_error( "Error - could not create udp socket for interface %s: %s\n", udp_if->dev, strerror( errno ) );

		memset( &int_req, 0, sizeof ( struct ifreq ) );
		strncpy( int_req.ifr_name, udp_if->dev, IFNAMSIZ - 1 );

		if ( ioctl( udp_if->sock, SIOCGIFADDR, &int_req ) < 0 )
			exit_error( "Error - can't get IP address of interface %s\n", udp_if->dev );

		udp_if->addr.sin_family = AF_INET;
		udp_if->addr.sin_port = htons(VIS_PORT);
		udp_if->addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

		addr_to_string( udp_if->addr.sin_addr.s_addr, ip_str, sizeof (ip_str) );

		if ( udp_if->addr.sin_addr.s_addr == INADDR_NONE )
			exit_error( "Error - interface %s has invalid address: %s\n", udp_if->dev, ip_str );

		if ( setsockopt( udp_if->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int) ) < 0 )
			exit_error( "Error - ioctl SO_REUSEADDR on interface %s failed: %s\n", udp_if->dev, strerror( errno ) );

		if( bind( udp_if->sock, (struct sockaddr*)&udp_if->addr, sizeof(struct sockaddr_in) ) < 0 )
			exit_error( "Error - could not bind to interface %s: %s\n", udp_if->dev, strerror( errno ) );

		list_add_tail( &udp_if->list, &udp_if_list );

		found_args++;

	}


	pthread_create( &udp_server_thread, NULL, &udp_server, NULL );
	pthread_create( &master_thread, NULL, &master, NULL );
// 	pthread_create( &cleaner_thread, NULL, &cleaner, NULL );


	if ( listen( tcp_sock, 32 ) < 0 ) {

		close( tcp_sock );
		exit_error( "Error - could not start listening on interface %s: %s\n", listen_if, strerror( errno ) );

	}

	while ( !is_aborted() ) {

		FD_ZERO(&wait_sockets);
		FD_SET(tcp_sock, &wait_sockets);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		len_inet = sizeof(addr_client);

		if ( select( tcp_sock + 1, &wait_sockets, NULL, NULL, &tv ) > 0 ) {

			thread_data = debugMalloc( sizeof(struct thread_data), 1200 );

			thread_data->socket = accept( tcp_sock, (struct sockaddr*)&addr_client, &len_inet );

			addr_to_string( addr_client.sin_addr.s_addr, thread_data->ip, sizeof(thread_data->ip) );
			printf( "New TCP client connected: %s \n", thread_data->ip );

			pthread_create( &tcp_server_thread, NULL, &tcp_server, thread_data );
			pthread_detach( tcp_server_thread );

		}

	}

	printf( "Shutting down visualisation server ... \n" );

	close( tcp_sock );
	restore_defaults();
	checkLeak();

	return EXIT_SUCCESS;

}

