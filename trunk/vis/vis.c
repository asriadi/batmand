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
#include "hash.h"
#include "allocate.h"

#define MAXCHAR 4096
#define PORT 1967
#define S3D_PORT 2004
#define ADDR_STR_LEN 16
#define PACKET_FIELDS 5

struct neighbour {
	struct node *node;
	unsigned char packet_count;
	struct neighbour *next;	
};

struct node {
	unsigned int addr;
	unsigned char packet_count_average;
	unsigned char last_seen;
	struct neighbour *neighbour;
	pthread_mutex_t mutex;
};

typedef struct _buffer {
	char *buffer;
	int counter;
	struct _buffer *next;
	pthread_mutex_t mutex;
} buffer_t;

static int on = 1;
struct node *root = NULL;

buffer_t *current = NULL;
buffer_t *first = NULL;
buffer_t *fillme = NULL;

static int8_t stop, sd;
struct hashtable_t *node_hash;

void handler( int32_t sig ) {
	stop = 1;
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

void exit_error(char *format, ...)
{
	va_list args;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
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

void clean_hash()
{
	struct neighbour *neigh, *neigh_delete;
	struct node *node;
	struct hash_it_t *hashit;
	
	if( node_hash->elements == 0 )
		return;

	hashit = NULL;
	while ( NULL != ( hashit = hash_iterate( node_hash, hashit ) ) )
	{
		node = (struct node *) hashit->bucket->data;
		hash_remove_bucket( node_hash, hashit->bucket );
		
		neigh = node->neighbour;
		while( NULL != neigh  )
		{
			neigh_delete = neigh;
			neigh = neigh->next;
			debugFree( neigh_delete, 1404 );
		}
		debugFree( node, 1410 );
	}
	return;
}

void clean_buffer()
{
	buffer_t *i , *rm ;
	i = first;		
	while( i != NULL )
	{
		rm = i;
		i = i->next;
		debugFree( rm->buffer, 1410 );
		debugFree( rm, 1405 );
		rm = NULL;
	}
	if( first != NULL ) debugFree( first, 1406 );
	first = NULL;
	if( current != NULL ) debugFree( current, 1407 );
	current = NULL;
	if( fillme != NULL ) debugFree( fillme, 1408 );
	fillme = NULL;
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

void handle_node(unsigned int addr,unsigned int sender, unsigned char packet_count )
{
	struct node *src_node, *orig_node;
	
	/* the neighbour */
	orig_node = (struct node *) hash_find( node_hash, &addr );
	
	if( NULL == orig_node )			/* node not found */
	{
		orig_node = (struct node *)debugMalloc( sizeof(struct node), 402 );
		orig_node->addr = addr;
		orig_node->neighbour = NULL;
		orig_node->packet_count_average = 0;
		orig_node->last_seen = 50;

		if(pthread_mutex_init(&orig_node->mutex, NULL) != 0)
			exit_error( "can't create mutex.\n");
			
		hash_add( node_hash, orig_node );

	} else {
		pthread_mutex_lock(&orig_node->mutex);
		orig_node->last_seen = 50;
		pthread_mutex_unlock(&orig_node->mutex);
	}

	/* the node which send the packet */
	src_node  = (struct node *) hash_find( node_hash, &sender );
	
	if( NULL == src_node )			/* node not found */
	{
		src_node = (struct node *)debugMalloc( sizeof(struct node), 403 );
		src_node->addr = sender;
		src_node->neighbour = NULL;
		src_node->packet_count_average = 0;
		src_node->last_seen = 50;

		if(pthread_mutex_init(&src_node->mutex, NULL) != 0)
			exit_error( "can't create mutex.\n");
			
		hash_add( node_hash, src_node );
		
	} else {
		pthread_mutex_lock(&src_node->mutex);
		src_node->last_seen = 50;
		pthread_mutex_unlock(&src_node->mutex);
	}
	add_neighbour_node( orig_node, packet_count, &src_node->neighbour );
	src_node->packet_count_average = calc_packet_count_average( src_node );
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
		
		for( neigh = node->neighbour; neigh != NULL; neigh = neigh->next )
		{
			addr_to_string( node->addr, from_str, sizeof( from_str ) );
			addr_to_string( neigh->node->addr, to_str, sizeof( to_str ) );
			snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"%s\"[label=\"%d\"]\n", from_str, to_str, ( int )neigh->packet_count );
			fillme->buffer = (char *)debugRealloc( fillme->buffer, strlen( tmp ) + strlen( fillme->buffer ) + 1, 408 );

			strncat( fillme->buffer, tmp, strlen( tmp ) );
		}
	}
	return;
}

void *udp_server( void *srv_dev )
{
	char recive_dgram[MAXCHAR];
	char str1[ADDR_STR_LEN];
	struct ifreq int_req;
	struct sockaddr_in server, client;
	int sock, n, packet_count,i;
	socklen_t len;
	
	sock = socket(PF_INET, SOCK_DGRAM,0 );
	memset( &server, 0, sizeof (server));

	memset( &int_req, 0, sizeof ( struct ifreq ) );
	strncpy( int_req.ifr_name, srv_dev, IFNAMSIZ - 1 );

	if( ioctl( sock, SIOCGIFADDR, &int_req ) < 0 )
		exit_error( "Error - can't get IP address of interface %s\n", srv_dev );

	server.sin_family = AF_INET;
	server.sin_port = htons( PORT );
	server.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

	addr_to_string( server.sin_addr.s_addr, str1, sizeof (str1));

	if(server.sin_addr.s_addr == INADDR_NONE)
		exit_error( "invalid adress %s\n", str1 );

	if( sock < 0 )
	{
		close( sock );
		exit_error( "Cannot create socket => %s\n", strerror(errno) );
	}
	
	if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof( int ) ) < 0 )
	{
		close( sock );
		exit_error( "Cannot enable ip: %s\n", strerror( errno ) );
	}
	
	if( bind( sock, ( struct sockaddr*)&server, sizeof( server ) ) < 0 )
	{
		close(sock);
		exit_error( "Error by bind => %s\n", strerror( errno ) );
	}
	
	printf( "receiver listen on ip %s port %d\n", str1, ntohs( server.sin_port ) );
	while( !is_aborted() )
	{
		int orig;
		len = sizeof(client);

		n = recvfrom(sock, recive_dgram, sizeof(recive_dgram), 0, (struct sockaddr*) &client, &len);
		packet_count = n / PACKET_FIELDS;
		for( i=0;i < packet_count; i++)
		{
			memmove(&orig,(unsigned int*)&recive_dgram[i*PACKET_FIELDS],4);
			handle_node(orig,client.sin_addr.s_addr,(unsigned char)recive_dgram[i*PACKET_FIELDS+4]);

		}
	}
	printf( "shutdown udp server.....");
	close(sock);
	clean_hash();
	hash_destroy(node_hash);
	printf( "ok\n");
	sd--;
	return( NULL );
}

static void *tcp_server( void *arg )
{
	int con = *( ( int *) arg );
	buffer_t *last_send = NULL;

	debugFree( arg, 1401 );

	while( !is_aborted() )
	{
		if( current != NULL && current != last_send )
		{
			pthread_mutex_lock( &current->mutex );
			current->counter = current->counter == -1 ? 1 : current->counter + 1;
			pthread_mutex_unlock( &current->mutex );
			if( write( con, current->buffer, strlen( current->buffer ) ) != strlen( current->buffer ) )
			{
				close( con );
				pthread_mutex_lock( &current->mutex );
				current->counter--;
				pthread_mutex_unlock( &current->mutex );
				return( NULL );
			}
			pthread_mutex_lock( &current->mutex );
			current->counter--; 
			pthread_mutex_unlock( &current->mutex );
			last_send = current;
		}
		sleep(5);
	}
	printf( "shutdown tcp server....");
	close( con );
	printf( "ok\n");
	sd--;
	return( NULL );
}

void *master( void *arg )
{
	buffer_t *new, *tmp;
	char begin[] = "digraph topology\n{\n";
	char end[] = "}\n";
	
	while( !is_aborted() )
	{
		tmp = first;
		while( tmp != NULL )
		{
			if( tmp->counter > 0 || tmp == current )
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
		
		if( first == NULL )
			first = new;
		else
			current->next = new;
		current = new;
		sleep( 3 );
	}
	printf( "shutdown buffer writer....");
	clean_buffer();
	printf( "ok\n");
	sd--;
	return NULL;
}

int main( int argc, char **argv )
{
	int sock, *clnt_socket;
	struct sockaddr_in sa, adr_client;
	struct ifreq int_req;
	char str1[ADDR_STR_LEN], client_ip[ADDR_STR_LEN];
	socklen_t len_inet;
	
	struct timeval tv;
	fd_set wait_sockets;
	
	stop = 0;
	sd = 3;
	signal( SIGINT, handler );
	signal( SIGTERM, handler );
	
	pthread_t udp_server_thread, tcp_server_thread, master_thread;

	if(argc < 3)
		exit_error( "Usage: vis <receive interface> <send interface>\n" );

	/* init hashtable for node struct */
	if ( NULL == ( node_hash = hash_new( 1600, orig_comp, orig_choose ) ) )
		exit_error( "Can't create hashtable\n");

	pthread_create( &udp_server_thread, NULL, &udp_server, argv[1] );
	pthread_create( &master_thread, NULL, &master, NULL );

	if( ( sock = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
		exit_error( "socket() failed: %s\n", strerror( errno ) );

	memset( &int_req, 0, sizeof ( struct ifreq ) );
	strncpy( int_req.ifr_name, argv[2], IFNAMSIZ - 1 );

	if( ioctl( sock, SIOCGIFADDR, &int_req ) < 0 )
		exit_error( "Error - can't get IP address of interface %s\n", argv[2] );

	memset( &sa, 0, sizeof( sa ) );
	sa.sin_family = AF_INET;
	sa.sin_port = htons( S3D_PORT );
	sa.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

	addr_to_string( sa.sin_addr.s_addr, str1, sizeof ( str1 ) );

	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof( int ) ) < 0 )
	{
		close( sock );
		exit_error( "Cannot enable ip: %s\n", strerror( errno ) );
	}
	
	if( bind( sock, ( struct sockaddr *)&sa, sizeof( sa ) ) < 0 )
	{
		close( sock );
		exit_error( "bind() failed: %s\n", strerror( errno ) );
	}

	if( listen( sock, 32 ) < 0 )
	{
		close( sock );
		exit_error( "listen() failed: %s\n", strerror( errno ) );
	}
	
	printf("sender listen on ip %s port %d\n", str1, ntohs( sa.sin_port ) );

	FD_ZERO(&wait_sockets);
	FD_SET(sock, &wait_sockets);

	clnt_socket = NULL;
	while( !is_aborted() )
	{
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		len_inet = sizeof( adr_client );
		if( clnt_socket == NULL )
			clnt_socket = debugMalloc( sizeof( int ), 406 );
		if( select( sock + 1, &wait_sockets, NULL, NULL, &tv) > 0 ) {
			*clnt_socket = accept( sock, (struct sockaddr*)&adr_client, &len_inet );
			pthread_create( &tcp_server_thread, NULL, &tcp_server, clnt_socket );
			pthread_detach( tcp_server_thread );
			addr_to_string( adr_client.sin_addr.s_addr, client_ip, sizeof( client_ip ) );
			printf("sender: client %s connected\n",client_ip);
		}
	}
	debugFree( clnt_socket, 1403 );
	while( sd ) {}
	printf( "shutdown mainloop %d\n",sd);
	checkLeak();
	return EXIT_SUCCESS;
}

