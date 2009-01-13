/*
 * vis.c
 *
 * Copyright (C) 2006 Andreas Langer <a.langer@q-dsl.de>, Marek Lindner:
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
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <getopt.h>
#include <paths.h>
#include <syslog.h>


#include "vis.h"



struct list_head_first vis_if_list;

pthread_t udp_server_thread = 0;
pthread_t master_thread = 0;

pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;

buffer_t *current = NULL;
buffer_t *first = NULL;
buffer_t *fillme = NULL;

static int8_t stop;
uint8_t debug_level = 0;

struct hashtable_t *node_hash;
struct hashtable_t *secif_hash;

int my_daemon()
{
	int fd;

	switch( fork() ) {

		case -1:
			return -1;

		case 0:
			break;

		default:
			exit(EXIT_SUCCESS);

	}

	if ( setsid() == -1 )
		return(-1);

	/* Make certain we are not a session leader, or else we might reacquire a controlling terminal */
	if ( fork() )
		exit(EXIT_SUCCESS);

	chdir( "/" );

	if ( ( fd = open(_PATH_DEVNULL, O_RDWR, 0) ) != -1 ) {

		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if ( fd > 2 )
			close(fd);

	}

	return 0;
}

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

	struct vis_if *vis_if;
	struct list_head *list_pos, *list_pos_tmp;


	if ( udp_server_thread != 0 )
		pthread_join( udp_server_thread, NULL );

	if ( master_thread != 0 )
		pthread_join( master_thread, NULL );

	list_for_each_safe( list_pos, list_pos_tmp, &vis_if_list ) {

		vis_if = list_entry( list_pos, struct vis_if, list );

		if ( vis_if->udp_sock )
			close( vis_if->udp_sock );

		if ( vis_if->tcp_sock )
			close( vis_if->tcp_sock );

		debugFree( vis_if, 2000 );

	}

	if ( debug_level == 0 )
		closelog();

	clean_secif_hash();
	hash_destroy( secif_hash );

	clean_node_hash();
	hash_destroy( node_hash );

	clean_buffer();

}

void debug_output(char *format, ...)
{
	va_list args;

	if ( debug_level == 0 ) {

		va_start( args, format );
		vsyslog( LOG_ERR, format, args );
		va_end( args );

	} else {

		va_start( args, format );
		vprintf( format, args );
		va_end( args );

	}
}

void exit_error(char *format, ...)
{
	va_list args;


	va_start(args, format);
	vprintf(format, args);
	va_end(args);

	restore_defaults();

	exit(EXIT_FAILURE);
}

void ip_to_string(unsigned int addr, char *str, int len)
{
	inet_ntop(AF_INET, &addr, str, len);
	return;
}

void addr_to_string(unsigned char *addr, char *str, int len)
{
	snprintf(str, len, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1],addr[2],addr[3],addr[4],addr[5]); 
	return;
}



void clean_secif_hash() {

	struct secif *secif;
	struct hash_it_t *hashit = NULL;


	if ( secif_hash->elements == 0 )
		return;

	while ( NULL != ( hashit = hash_iterate( secif_hash, hashit ) ) ) {

		secif = (struct secif *)hashit->bucket->data;
		hash_remove_bucket( secif_hash, hashit );

		debugFree( secif, 2001 );

	}

	return;

}



void clean_node_hash() {

	struct node *orig_node;
	struct neighbour *neigh;
	struct list_head *list_pos, *list_pos_tmp;
	struct hash_it_t *hashit = NULL;
	struct hna *hna;


	if ( node_hash->elements == 0 )
		return;

	while ( NULL != ( hashit = hash_iterate( node_hash, hashit ) ) ) {

		orig_node = (struct node *)hashit->bucket->data;
		hash_remove_bucket( node_hash, hashit );

		list_for_each_safe( list_pos, list_pos_tmp, &orig_node->neigh_list ) {

			neigh = list_entry( list_pos, struct neighbour, list );

			debugFree( neigh, 2002 );

		}

		list_for_each_safe( list_pos, list_pos_tmp, &orig_node->hna_list ) {

			hna = list_entry( list_pos, struct hna, list );

			debugFree( hna, 2016 );

		}

		debugFree( orig_node, 2003 );

	}

	return;

}






void clean_buffer() {

	buffer_t *i = first , *rm;


	while ( i != NULL ) {

		rm = i;
		i = i->next;
		debugFree( rm->buffer, 2004 );
		debugFree( rm, 2005 );

	}

}



void write_data_in_buffer() {

	struct neighbour *neigh;
	struct node *orig_node;
	struct secif *secif;
	struct secif_lst *secif_lst;
	struct hna *hna;
	struct list_head *list_pos, *list_pos_tmp, *prev_list_head;
	struct hash_it_t *hashit = NULL;
	char from_str[ADDR_STR_LEN], to_str[ADDR_STR_LEN], /*hna_str[ADDR_STR_LEN], */tmp[100];


	memset( tmp, 0, sizeof(tmp) );

	if ( pthread_mutex_lock( &hash_mutex ) != 0 )
		debug_output( "Error - could not lock hash mutex (write_data_in_buffer): %s \n", strerror( errno ) );

	if ( node_hash->elements > 0 ) {

		while ( NULL != ( hashit = hash_iterate( node_hash, hashit ) ) ) {

			orig_node = (struct node *)hashit->bucket->data;
			addr_to_string( orig_node->addr, from_str, sizeof( from_str ) );

			if ( orig_node->last_seen > 0 ) {

				orig_node->last_seen--;

				list_for_each( list_pos, &orig_node->neigh_list ) {

					neigh = list_entry( list_pos, struct neighbour, list );

					/* never ever divide by zero */
					if ( neigh->packet_count > 0 ) {

						/* find out if neighbour is a secondary interface of another neighbour */
						secif = (struct secif *)hash_find( secif_hash, &neigh->addr );

						/* neighbour is a secondary interface */
						if ( secif != NULL )
							addr_to_string( secif->orig->addr, to_str, sizeof( to_str ) );
						else
							addr_to_string( neigh->addr, to_str, sizeof( to_str ) );

						snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"%s\"[label=\"%.2f\"]\n", from_str, to_str, (float)( orig_node->seq_range / (float)neigh->packet_count ) );
						fillme->buffer = (char *)debugRealloc( fillme->buffer, strlen( tmp ) + strlen( fillme->buffer ) + 1, 408 );

						strncat( fillme->buffer, tmp, strlen( tmp ) );

					}

				}

				list_for_each( list_pos, &orig_node->hna_list ) {

					hna = list_entry( list_pos, struct hna, list );

					addr_to_string( hna->addr, to_str, sizeof( to_str ) );
/*					addr_to_string( ( hna->netmask == 32 ? 0xffffffff : htonl( ~ ( 0xffffffff >> hna->netmask ) ) ), hna_str, sizeof( hna_str ) );*/

					snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"%s\"[label=\"HNA\"]\n", from_str, to_str );
/*					snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"%s/%s\"[label=\"HNA\"]\n", from_str, to_str, hna_str );*/
					fillme->buffer = (char *)debugRealloc( fillme->buffer, strlen( tmp ) + strlen( fillme->buffer ) + 1, 409 );

					strncat( fillme->buffer, tmp, strlen( tmp ) );

				}

				/*printf("gw_class %d\n",(unsigned int)orig_node->gw_class);*/
				if ( orig_node->gw_class != 0 ) {

					snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"0.0.0.0/0.0.0.0\"[label=\"HNA\"]\n", from_str );
					fillme->buffer = (char *)debugRealloc( fillme->buffer, strlen( tmp ) + strlen( fillme->buffer ) + 1, 410 );
					strncat( fillme->buffer, tmp, strlen( tmp ) );

				}

				/* remove outdated neighbours */
				prev_list_head = (struct list_head *)&orig_node->neigh_list;

				list_for_each_safe( list_pos, list_pos_tmp, &orig_node->neigh_list ) {

					neigh = list_entry( list_pos, struct neighbour, list );

					if ( neigh->last_seen > 0 ) {

						neigh->last_seen--;

						prev_list_head = &neigh->list;

					} else {

						list_del( prev_list_head, list_pos, &orig_node->neigh_list );

						debugFree( neigh, 2006 );

					}

				}

				/* remove outdated secondary interfaces */
				prev_list_head = (struct list_head *)&orig_node->secif_list;

				list_for_each_safe( list_pos, list_pos_tmp, &orig_node->secif_list ) {

					secif_lst = list_entry( list_pos, struct secif_lst, list );

					if ( secif_lst->last_seen > 0 ) {

						secif_lst->last_seen--;

						prev_list_head = &secif_lst->list;

					} else {

						/* remove secondary interface from hash */
						hash_remove( secif_hash, &secif_lst->addr );

						list_del( prev_list_head, list_pos, &orig_node->secif_list );

						debugFree( secif_lst, 2007 );

					}

				}

				/* remove outdated hna entries */
				prev_list_head = (struct list_head *)&orig_node->hna_list;

				list_for_each_safe( list_pos, list_pos_tmp, &orig_node->hna_list ) {

					hna = list_entry( list_pos, struct hna, list );

					if ( hna->last_seen > 0 ) {

						hna->last_seen--;

						prev_list_head = &hna->list;

					} else {

						list_del( prev_list_head, list_pos, &orig_node->hna_list );

						debugFree( hna, 2014 );

					}

				}

			/* delete orig node */
			} else {

				list_for_each_safe( list_pos, list_pos_tmp, &orig_node->neigh_list ) {

					neigh = list_entry( list_pos, struct neighbour, list );

					debugFree( neigh, 2008 );

				}

				list_for_each_safe( list_pos, list_pos_tmp, &orig_node->secif_list ) {

					secif_lst = list_entry( list_pos, struct secif_lst, list );

					/* remove secondary interface from hash */
					hash_remove( secif_hash, &secif_lst->addr );

					debugFree( secif_lst, 2009 );

				}

				list_for_each_safe( list_pos, list_pos_tmp, &orig_node->hna_list ) {

					hna = list_entry( list_pos, struct hna, list );

					debugFree( hna, 2015 );

				}

				hash_remove_bucket( node_hash, hashit );

				debugFree( orig_node, 2010 );

			}

		}

	}

	if ( pthread_mutex_unlock( &hash_mutex ) != 0 )
		debug_output( "Error - could not unlock hash mutex (write_data_in_buffer): %s \n", strerror( errno ) );

	return;

}



void *tcp_server( void *arg ) {

	struct thread_data *thread_data = ((struct thread_data*) arg);
	buffer_t *last_send = NULL;
	ssize_t ret;


	while ( !is_aborted() ) {

		if ( current != NULL && current != last_send ) {

			pthread_mutex_lock( &current->mutex );
			current->counter = current->counter == -1 ? 1 : current->counter + 1;
			pthread_mutex_unlock( &current->mutex );
			ret = write( thread_data->socket, current->buffer, strlen( current->buffer ) );
			if( ret != (int)strlen( current->buffer ) )
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

	if ( debug_level > 0 )
		debug_output( "TCP client has left: %s \n", thread_data->ip );

	close( thread_data->socket );
	debugFree( arg, 2011 );

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
			debugFree( tmp->buffer, 2012 );
			debugFree( tmp, 2013 );
			tmp = first;

		}

		new = debugMalloc( sizeof(buffer_t), 1000 );
		new->counter = -1;
		new->next = NULL;
		pthread_mutex_init( &new->mutex, NULL );

		new->buffer = (char *)debugMalloc( strlen( begin ) + 1, 1001 );
		memset( new->buffer, 0, strlen( begin ) );
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



void print_usage() {

	printf( "B.A.T.M.A.N. visualisation server %s\n", VERSION );
	printf( "Usage: vis <interface(s)> \n" );
	printf( "\t-d debug level\n" );
	printf( "\t-h help\n" );
	printf( "\t-v Version\n\n" );
	printf( "Olsrs3d / Meshs3d is an application to visualize a mesh network.\nIt is a part of s3d, have a look at s3d.berlios.de\n\n" );

}



int main( int argc, char **argv ) {

	char ip_str[ADDR_STR_LEN];
	int max_sock = 0, optchar, on = 1, debug_level_max = 1;
	uint8_t found_args = 1;
	int32_t unix_opts;
	struct sockaddr_in addr_client;
	struct ifreq int_req;
	struct vis_if *vis_if;
	struct list_head *list_pos;
	struct thread_data *thread_data;
	struct timeval tv;
	fd_set wait_sockets, tmp_wait_sockets;
	socklen_t len_inet;
	pthread_t tcp_server_thread;


	while ( ( optchar = getopt ( argc, argv, "d:hv" ) ) != -1 ) {

		switch( optchar ) {

			case 'd':

				debug_level = strtol( optarg, NULL, 10 );

				if ( ( errno == ERANGE ) || ( errno != 0 && debug_level == 0 ) ) {

					perror("strtol");
					exit(EXIT_FAILURE);

				}

				if ( debug_level > debug_level_max )
					exit_error( "Invalid debug level: %i\nDebug level has to be between 0 and %i.\n", debug_level, debug_level_max );

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'h':
				print_usage();
				exit(EXIT_SUCCESS);
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

	/* init hashtable for nodes */
	if ( NULL == ( node_hash = hash_new( 128, orig_comp, orig_choose ) ) )
		exit_error( "Error - can't create node hashtable\n");

	/* init hashtable for secondary interfaces */
	if ( NULL == ( secif_hash = hash_new( 128, orig_comp, orig_choose ) ) )
		exit_error( "Error - can't create secif hashtable\n");

	INIT_LIST_HEAD_FIRST( vis_if_list );

	FD_ZERO(&wait_sockets);


	if ( argc <= found_args )
		exit_error( "Error - no listen interface specified\n" );

	while ( argc > found_args ) {

		vis_if = debugMalloc( sizeof(struct vis_if), 1002 );
		memset( vis_if, 0, sizeof(struct vis_if) );
		INIT_LIST_HEAD( &vis_if->list );

		vis_if->dev = argv[found_args];

		if ( strlen( vis_if->dev ) > IFNAMSIZ - 1 )
			exit_error( "Error - interface name too long: %s\n", vis_if->dev );

		if ( ( vis_if->udp_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 )
			exit_error( "Error - could not create udp socket for interface %s: %s\n", vis_if->dev, strerror( errno ) );

		if ( ( vis_if->tcp_sock = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
			exit_error( "Error - could not create tcp socket for interface %s: %s\n", vis_if->dev, strerror( errno ) );

		memset( &int_req, 0, sizeof ( struct ifreq ) );
		strncpy( int_req.ifr_name, vis_if->dev, IFNAMSIZ - 1 );

		if ( ioctl( vis_if->udp_sock, SIOCGIFADDR, &int_req ) < 0 )
			exit_error( "Error - can't get IP address of interface %s\n", vis_if->dev );

		vis_if->udp_addr.sin_family = AF_INET;
		vis_if->udp_addr.sin_port = htons(VIS_PORT);
		vis_if->udp_addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

		vis_if->tcp_addr.sin_family = AF_INET;
		vis_if->tcp_addr.sin_port = htons(DOT_DRAW_PORT);
		vis_if->tcp_addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

		ip_to_string( vis_if->udp_addr.sin_addr.s_addr, ip_str, sizeof (ip_str) );

		if ( vis_if->udp_addr.sin_addr.s_addr == INADDR_NONE )
			exit_error( "Error - interface %s has invalid address: %s\n", vis_if->dev, ip_str );

		if ( setsockopt( vis_if->tcp_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int) ) < 0 )
			exit_error( "Error - ioctl SO_REUSEADDR on interface %s failed: %s\n", vis_if->dev, strerror( errno ) );

		if ( bind( vis_if->udp_sock, (struct sockaddr*)&vis_if->udp_addr, sizeof(struct sockaddr_in) ) < 0 )
			exit_error( "Error - could not bind to interface (udp) %s: %s\n", vis_if->dev, strerror( errno ) );

		if ( bind( vis_if->tcp_sock, (struct sockaddr*)&vis_if->tcp_addr, sizeof(struct sockaddr_in) ) < 0 )
			exit_error( "Error - could not bind to interface (tcp) %s: %s\n", vis_if->dev, strerror( errno ) );

		if ( listen( vis_if->tcp_sock, 32 ) < 0 )
			exit_error( "Error - could not start listening on interface %s: %s\n", vis_if->dev, strerror( errno ) );

		if ( vis_if->tcp_sock > max_sock )
			max_sock = vis_if->tcp_sock;

		FD_SET(vis_if->tcp_sock, &wait_sockets);

		list_add_tail( &vis_if->list, &vis_if_list );

		found_args++;

	}


	/* daemonize */
	if ( debug_level == 0 ) {

		if ( my_daemon() < 0 )
			exit_error( "Error - can't fork to background: %s\n", strerror(errno) );

		openlog( "vis_server", LOG_PID, LOG_DAEMON );

	}


	debug_output( "B.A.T.M.A.N. visualisation server %s successfully started ... \n", VERSION );


	pthread_create( &udp_server_thread, NULL, &udp_server, NULL );
	pthread_create( &master_thread, NULL, &master, NULL );


	while ( !is_aborted() ) {

		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof(fd_set) );

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		len_inet = sizeof(addr_client);

 		/*checkIntegrity();*/

		if ( select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv ) > 0 ) {

			list_for_each( list_pos, &vis_if_list ) {

				vis_if = list_entry( list_pos, struct vis_if, list );

				if ( FD_ISSET( vis_if->tcp_sock, &tmp_wait_sockets ) ) {

					thread_data = debugMalloc( sizeof(struct thread_data), 1003 );

					thread_data->socket = accept( vis_if->tcp_sock, (struct sockaddr*)&addr_client, &len_inet );

					ip_to_string( addr_client.sin_addr.s_addr, thread_data->ip, sizeof(thread_data->ip) );
 
 					if ( debug_level > 0 )
 						debug_output( "New TCP client connected: %s \n", thread_data->ip );

					/* make tcp socket non blocking */
					unix_opts = fcntl( thread_data->socket, F_GETFL, 0 );
					fcntl( thread_data->socket, F_SETFL, unix_opts | O_NONBLOCK );

					pthread_create( &tcp_server_thread, NULL, &tcp_server, thread_data );
					pthread_detach( tcp_server_thread );

				}

			}

		}

	}

	debug_output( "Shutting down visualisation server ... \n" );

	restore_defaults();
	checkLeak();

	return EXIT_SUCCESS;

}

