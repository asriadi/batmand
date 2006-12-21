/*
 * vis.c
 *
 * Copyright (C) 2006 Andreas Langer <andreas_lbg@gmx.de>:
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
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>

#include "rb_tree.h"

#define MAXCHAR 4096
#define PORT 1967
#define S3D_PORT 1968
#define ADDR_STR_LEN 16
#define PACKET_FIELDS 5

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


void exit_error(char *format, ...)
{
	va_list args;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	exit( EXIT_FAILURE );
}


/*void generate_buffer( char **buffer )*/
/*{*/
	/*size_t len;*/
	/*char test[] = "digraph topology\n{\n";*/
	/*char end[] = "}\n";*/

	/*if( *buffer != NULL )*/
		/*free( *buffer );*/

	/*len = strlen( test ) + 1;*/

	/**buffer = malloc( len * sizeof( char ) );*/

	/*strncpy( *buffer, test, strlen( test ) );*/

	/*write_data_in_buffer( root, &(*buffer) );*/

	/**buffer = realloc( *buffer, strlen( *buffer ) + strlen( end ) + 1 );*/

	/*strncat( *buffer, end, strlen( end ) );*/

	/*return;*/
/*}*/

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
	while(1)
	{
		int orig;
		len = sizeof(client);

		n = recvfrom(sock, recive_dgram, sizeof(recive_dgram), 0, (struct sockaddr*) &client, &len);
		packet_count = n / PACKET_FIELDS;
		for( i=0;i < packet_count; i++)
		{
			memmove(&orig,(unsigned int*)&recive_dgram[i*PACKET_FIELDS],4);
			handle_node(orig,client.sin_addr.s_addr,(unsigned char)recive_dgram[i*PACKET_FIELDS+4], &root);

		}
	}
	close(sock);
	return( NULL );
}

static void *tcp_server( void *arg )
{
	int con = *( ( int *) arg );
	buffer_t *last_send = NULL;

	free( arg );

	for( ; ; )
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

	close( con );
	return( NULL );
}

void *master( void *arg )
{
	buffer_t *new, *tmp;
	char begin[] = "digraph topology\n{\n";
	char end[] = "}\n";
	
	for( ; ; )
	{
		tmp = first;
		while( tmp != NULL )
		{
			if( tmp->counter > 0 || tmp == current )
				break;
			
			first = tmp->next;
			free( tmp->buffer );
			free( tmp );
			tmp = first;

		}

		new = malloc( sizeof( buffer_t ) );
		new->counter = -1;
		new->next = NULL;
		pthread_mutex_init( &new->mutex, NULL );

		new->buffer = malloc( strlen( begin ) );
		strncpy( new->buffer, begin, strlen( begin ) );
		write_data_in_buffer( root, new->buffer );
		
		new->buffer = realloc( new->buffer, strlen( new->buffer ) + strlen( end ) + 1 );
		strncat( new->buffer, end, strlen( end ) );
		
		if( first == NULL )
			first = new;
		else
			current->next = new;
		current = new;
		sleep( 3 );
	}

	return NULL;
}

int main( int argc, char **argv )
{
	int sock, *clnt_socket;
	struct sockaddr_in sa, adr_client;
	struct ifreq int_req;
	char str1[ADDR_STR_LEN], client_ip[ADDR_STR_LEN];
	socklen_t len_inet;
	
	pthread_t udp_server_thread, tcp_server_thread, master_thread;

	if(argc < 3)
		exit_error( "Usage: vis <receive interface> <send interface>\n" );

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

	for( ; ; )
	{
		len_inet = sizeof( adr_client );
		clnt_socket = malloc( sizeof( int ) );
		*clnt_socket = accept( sock, (struct sockaddr*)&adr_client, &len_inet );
		pthread_create( &tcp_server_thread, NULL, &tcp_server, clnt_socket );
		pthread_detach( tcp_server_thread );
		addr_to_string( adr_client.sin_addr.s_addr, client_ip, sizeof( client_ip ) );
		printf("sender: client %s connected\n",client_ip);
	}

	return EXIT_SUCCESS;
}

