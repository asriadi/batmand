/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Marek Lindner, Simon Wunderlich
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



#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/if.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <paths.h>

#include "os.h"
#include "batman-adv.h"
#include "originator.h"
#include "trans_table.h"



static int8_t stop;



int8_t is_aborted() {

	return stop != 0;

}



void handler( int32_t BATUNUSED(sig) ) {

	stop = 1;

}



int my_daemon() {

	int fd;

	switch( fork() ) {

		case -1:
			return(-1);

		case 0:
			break;

		default:
			exit(EXIT_SUCCESS);

	}

	if ( setsid() == -1 )
		return(-1);

	/* Make certain we are not a session leader, or else we
	* might reacquire a controlling terminal */
	if ( fork() )
		exit(EXIT_SUCCESS);

	chdir("/");

	if ( ( fd = open(_PATH_DEVNULL, O_RDWR, 0) ) != -1 ) {

		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if (fd > 2)
			close(fd);

	}

	return(0);

}



void debug_output( int8_t debug_prio, char *format, ... ) {

	struct list_head *debug_pos;
	struct debug_level_info *debug_level_info;
	int8_t debug_prio_intern;
	va_list args;


	if ( debug_prio == 0 ) {

		if ( debug_level == 0 ) {

			va_start( args, format );
			vsyslog( LOG_ERR, format, args );
			va_end( args );

		} else if ( ( debug_level == 3 ) || ( debug_level == 4 ) ) {

			if ( debug_level == 4 )
				printf( "[%10u] ", get_time() );

			va_start( args, format );
			vprintf( format, args );
			va_end( args );

		}

		debug_prio_intern = 3;

	} else {

		debug_prio_intern = debug_prio - 1;

	}

	if ( debug_clients.clients_num[debug_prio_intern] > 0 ) {

		if ( pthread_mutex_trylock( (pthread_mutex_t *)debug_clients.mutex[debug_prio_intern] ) == 0 ) {

			va_start( args, format );

			list_for_each( debug_pos, (struct list_head *)debug_clients.fd_list[debug_prio_intern] ) {

				debug_level_info = list_entry(debug_pos, struct debug_level_info, list);

				if ( debug_prio_intern == 3 )
					dprintf( debug_level_info->fd, "[%10u] ", get_time() );

				if ( ( ( debug_level == 1 ) || ( debug_level == 2 ) ) && ( debug_level_info->fd == 1 ) && ( strncmp( format, "BOD", 3 ) == 0 ) ) {

					system( "clear" );

				} else {

					if ( ( ( debug_level != 1 ) && ( debug_level != 2 ) ) || ( debug_level_info->fd != 1 ) || ( strncmp( format, "EOD", 3 ) != 0 ) )
						vdprintf( debug_level_info->fd, format, args );

				}

			}

			va_end( args );

			if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[debug_prio_intern] ) < 0 )
				debug_output( 0, "Error - could not unlock mutex (debug_output): %s \n", strerror( errno ) );

		} else {

			debug_output( 0, "Error - could not trylock mutex (debug_output): %s \n", strerror( errno ) );

		}

	}

}



void handle_packet( unsigned char *buff, int32_t buff_len, struct unix_client *unix_client ) {

	struct ether_header ether_header;
	struct orig_node *orig_node;
	struct icmp_packet *icmp_packet;

	if ( ( ((struct icmp_packet *)buff)->packet_type == BAT_ICMP ) && ( ((struct icmp_packet *)buff)->msg_type == ECHO_REQUEST ) ) {

		icmp_packet = (struct icmp_packet *)buff;
		/* get routing information */
		orig_node = find_orig_node( icmp_packet->dst );

		if ( ( orig_node != NULL ) && ( orig_node->batman_if != NULL ) && ( orig_node->router != NULL ) && ( icmp_packet->ttl > 0 ) ) {

			memcpy( ether_header.ether_shost, orig_node->batman_if->hw_addr, ETH_ALEN );
			memcpy( ether_header.ether_dhost, orig_node->router->addr, ETH_ALEN );

			icmp_packet->uid = unix_client->uid;
			memcpy( icmp_packet->orig, orig_node->batman_if->hw_addr, ETH_ALEN );

			if ( rawsock_write( orig_node->batman_if->raw_sock, &ether_header, buff, buff_len ) < 0 ) {

				debug_output( 0, "Error - can't send data from unix socket through raw socket: %s \n", strerror(errno) );

			}

		} else {

			icmp_packet->msg_type = DESTINATION_UNREACHABLE;

			write( unix_client->sock, buff, buff_len );

		}

	} else {

		debug_output( 0, "Error - can't send data from unix socket: got bogus packet \n" );

	}

}



void *unix_listen( void BATUNUSED(*arg) ) {

	struct unix_client *unix_client;
	struct debug_level_info *debug_level_info;
	struct list_head *unix_pos, *unix_pos_tmp, *debug_pos, *debug_pos_tmp, *prev_list_head, *prev_list_head_unix;
	struct timeval tv;
	struct sockaddr_un sun_addr;
	int32_t status, max_sock, unix_opts;
	int8_t res;
	uint8_t i;
	unsigned char buff[50];
	fd_set wait_sockets, tmp_wait_sockets;
	socklen_t sun_size = sizeof(struct sockaddr_un);


	INIT_LIST_HEAD_FIRST( unix_if.client_list );

	FD_ZERO(&wait_sockets);
	FD_SET(unix_if.unix_sock, &wait_sockets);

	max_sock = unix_if.unix_sock;

	for ( i = 0; i < 255; i++ ) {
		unix_packet[i] = NULL;
	}

	while ( !is_aborted() ) {

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof(fd_set) );

		res = select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv );

		if ( res > 0 ) {

			/* new client */
			if ( FD_ISSET( unix_if.unix_sock, &tmp_wait_sockets ) ) {

				unix_client = debugMalloc( sizeof(struct unix_client), 201 );
				memset( unix_client, 0, sizeof(struct unix_client) );

				if ( ( unix_client->sock = accept( unix_if.unix_sock, (struct sockaddr *)&sun_addr, &sun_size) ) == -1 ) {
					debug_output( 0, "Error - can't accept unix client: %s\n", strerror(errno) );
					continue;
				}

				INIT_LIST_HEAD( &unix_client->list );

				FD_SET( unix_client->sock, &wait_sockets );
				if ( unix_client->sock > max_sock )
					max_sock = unix_client->sock;

				/* make unix socket non blocking */
				unix_opts = fcntl( unix_client->sock, F_GETFL, 0 );
				fcntl( unix_client->sock, F_SETFL, unix_opts | O_NONBLOCK );

				list_add_tail( &unix_client->list, &unix_if.client_list );

				debug_output( 3, "Unix socket: got connection\n" );

			/* client sent data */
			} else {

				max_sock = unix_if.unix_sock;

				prev_list_head_unix = (struct list_head *)&unix_if.client_list;

				list_for_each_safe( unix_pos, unix_pos_tmp, &unix_if.client_list ) {

					unix_client = list_entry( unix_pos, struct unix_client, list );

					if ( FD_ISSET( unix_client->sock, &tmp_wait_sockets ) ) {

						status = read( unix_client->sock, buff, sizeof( buff ) );

						if ( status > 0 ) {

							if ( unix_client->sock > max_sock )
								max_sock = unix_client->sock;

							/* debug_output( 3, "gateway: client sent data via unix socket: %s\n", buff ); */

							if ( buff[0] == 'p' ) {

								if ( status == sizeof(struct icmp_packet) + 2 ) {

									if ( unix_client->uid == 0 ) {

										for ( i = 0; i < 255; i++ ) {

											if ( unix_packet[i] == NULL ) {

												unix_packet[i] = unix_client;
												unix_client->uid = i;
												break;

											}

										}

									}

									if ( unix_packet[unix_client->uid] == unix_client ) {

										handle_packet( buff + 2, status - 2, unix_client );

									} else {

										debug_output( 0, "Error - can't add another packet client: maximum number of clients reached \n" );

									}

								}

							} else if ( buff[0] == 'd' ) {

								if ( ( status > 2 ) && ( ( buff[2] > 48 ) && ( buff[2] <= debug_level_max + 48 ) ) ) {

									if ( unix_client->debug_level != 0 ) {

										prev_list_head = (struct list_head *)debug_clients.fd_list[(int)unix_client->debug_level - '1'];

										if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[(int)unix_client->debug_level - '1'] ) != 0 )
											debug_output( 0, "Error - could not lock mutex (unix_listen => 1): %s \n", strerror( errno ) );

										list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[(int)unix_client->debug_level - '1'] ) {

											debug_level_info = list_entry( debug_pos, struct debug_level_info, list );

											if ( debug_level_info->fd == unix_client->sock ) {

												list_del( prev_list_head, debug_pos, debug_clients.fd_list[(int)unix_client->debug_level - '1'] );
												debug_clients.clients_num[(int)unix_client->debug_level - '1']--;

												debugFree( debug_pos, 1201 );

												break;

											}

											prev_list_head = &debug_level_info->list;

										}

										if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[(int)unix_client->debug_level - '1'] ) != 0 )
											debug_output( 0, "Error - could not unlock mutex (unix_listen => 1): %s \n", strerror( errno ) );

									}

									if ( unix_client->debug_level != buff[2] ) {

										if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[(int)buff[2] - '1'] ) != 0 )
											debug_output( 0, "Error - could not lock mutex (unix_listen => 2): %s \n", strerror( errno ) );

										debug_level_info = debugMalloc( sizeof(struct debug_level_info), 202 );
										INIT_LIST_HEAD( &debug_level_info->list );
										debug_level_info->fd = unix_client->sock;
										list_add( &debug_level_info->list, (struct list_head_first *)debug_clients.fd_list[(int)buff[2] - '1'] );
										debug_clients.clients_num[(int)buff[2] - '1']++;

										unix_client->debug_level = (int)buff[2];

										if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[(int)buff[2] - '1'] ) != 0 )
											debug_output( 0, "Error - could not unlock mutex (unix_listen => 2): %s \n", strerror( errno ) );

									} else {

										unix_client->debug_level = 0;

									}



								}

							}

						} else {

							if ( status < 0 )
								debug_output( 0, "Error - can't read unix message: %s\n", strerror(errno) );

							if ( unix_client->debug_level != 0 ) {

								prev_list_head = (struct list_head *)debug_clients.fd_list[(int)unix_client->debug_level - '1'];

								if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[(int)unix_client->debug_level - '1'] ) != 0 )
									debug_output( 0, "Error - could not lock mutex (unix_listen => 3): %s \n", strerror( errno ) );

								list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[(int)unix_client->debug_level - '1'] ) {

									debug_level_info = list_entry( debug_pos, struct debug_level_info, list );

									if ( debug_level_info->fd == unix_client->sock ) {

										list_del( prev_list_head, debug_pos, debug_clients.fd_list[(int)unix_client->debug_level - '1'] );
										debug_clients.clients_num[(int)unix_client->debug_level - '1']--;

										debugFree( debug_pos, 1202 );

										break;

									}

									prev_list_head = &debug_level_info->list;

								}

								if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[(int)unix_client->debug_level - '1'] ) != 0 )
									debug_output( 0, "Error - could not unlock mutex (unix_listen => 3): %s \n", strerror( errno ) );

							}

							if ( unix_client->uid != 0 )
								unix_packet[unix_client->uid] = NULL;

							debug_output( 3, "Unix client closed connection ...\n" );

							FD_CLR(unix_client->sock, &wait_sockets);
							close( unix_client->sock );

							list_del( prev_list_head_unix, unix_pos, &unix_if.client_list );
							debugFree( unix_pos, 1203 );

						}

					} else {

						if ( unix_client->sock > max_sock )
							max_sock = unix_client->sock;

					}

				}

			}

		} else if ( ( res < 0 ) && ( errno != EINTR ) ) {

			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			break;

		}

	}

	list_for_each_safe(unix_pos, unix_pos_tmp, &unix_if.client_list) {

		unix_client = list_entry(unix_pos, struct unix_client, list);

		if ( unix_client->debug_level != 0 ) {

			list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[(int)unix_client->debug_level - '1'] ) {

				debug_level_info = list_entry( debug_pos, struct debug_level_info, list );

				if ( debug_level_info->fd == unix_client->sock ) {

					list_del( (struct list_head *)debug_clients.fd_list[(int)unix_client->debug_level - '1'], debug_pos, debug_clients.fd_list[(int)unix_client->debug_level - '1'] );
					debug_clients.clients_num[(int)unix_client->debug_level - '1']--;

					debugFree( debug_pos, 1204 );

					break;

				}

			}

		}

		list_del( (struct list_head *)&unix_if.client_list, unix_pos, &unix_if.client_list );
		debugFree( unix_pos, 1205 );

	}

	return NULL;

}



void apply_init_args( int argc, char *argv[] ) {

	struct in_addr tmp_ip_holder;
	struct batman_if *batman_if;
	struct debug_level_info *debug_level_info;
	uint8_t found_args = 1, batch_mode = 0;
	uint16_t tmp_mtu;
	int8_t res;

	int32_t optchar, recv_buff_len, bytes_written;
	char *unix_buff, *buff_ptr, *cr_ptr;
	uint32_t vis_server = 0;

	tap_mtu = 2000;
	memset( &tmp_ip_holder, 0, sizeof (struct in_addr) );
	stop = 0;


	printf( "WARNING: You are using the unstable batman-advanced branch. If you are interested in *using* batman-advanced get the latest stable release !\n" );

	while ( ( optchar = getopt ( argc, argv, "bcd:hHo:g:p:r:s:vV" ) ) != -1 ) {

		switch ( optchar ) {

			case 'b':
				batch_mode++;
				break;

			case 'c':
				unix_client++;
				break;

			case 'd':

				errno = 0;
				debug_level = strtol (optarg, NULL , 10);

				if ( ( errno == ERANGE ) || ( errno != 0 && debug_level == 0 ) ) {
					perror("strtol");
					exit(EXIT_FAILURE);
				}

				if ( debug_level > debug_level_max ) {
					printf( "Invalid debug level: %i\nDebug level has to be between 0 and %i.\n", debug_level, debug_level_max );
					exit(EXIT_FAILURE);
				}

				found_args += 2;
				break;

			case 'g':

				errno = 0;
				gateway_class = strtol(optarg, NULL , 10);

				if ( ( errno == ERANGE ) || ( errno != 0 && gateway_class == 0 ) ) {
					perror("strtol");
					exit(EXIT_FAILURE);
				}

				if ( gateway_class > 11 ) {
					printf( "Invalid gateway class specified: %i.\nThe class is a value between 0 and 11.\n", gateway_class );
					exit(EXIT_FAILURE);
				}

				found_args += 2;
				break;

			case 'H':
				verbose_usage();
				exit(0);

			case 'o':

				errno = 0;
				originator_interval = strtol (optarg, NULL, 10);

				if ( originator_interval < 1 ) {

					printf( "Invalid originator interval specified: %i.\nThe Interval has to be greater than 0.\n", originator_interval );
					exit(EXIT_FAILURE);

				}

				found_args += 2;
				break;

			case 'p':

				errno = 0;
				if ( inet_pton(AF_INET, optarg, &tmp_ip_holder) < 1 ) {

					printf( "Invalid preferred gateway IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				pref_gateway = tmp_ip_holder.s_addr;

				found_args += 2;
				break;

			case 'r':

				errno = 0;
				routing_class = strtol (optarg, NULL , 10);

				if ( routing_class > 3 ) {

					printf( "Invalid routing class specified: %i.\nThe class is a value between 0 and 3.\n", routing_class );
					exit(EXIT_FAILURE);

				}

				found_args += 2;
				break;

			case 's':

				errno = 0;
				if ( inet_pton(AF_INET, optarg, &tmp_ip_holder) < 1 ) {

					printf( "Invalid preferred visualation server IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				vis_server = tmp_ip_holder.s_addr;


				found_args += 2;
				break;

			case 'v':

				printf( "B.A.T.M.A.N. Advanced %s%s (compability version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
				exit(0);

			case 'V':

				print_animation();

				printf( "\x1B[0;0HB.A.T.M.A.N. Advanced %s%s (compability version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
				printf( "\x1B[9;0H \t May the bat guide your path ...\n\n\n" );

				exit(0);

			case 'h':
			default:
				usage();
				exit(0);

		}

	}


	if ( ( gateway_class != 0 ) && ( routing_class != 0 ) ) {
		fprintf( stderr, "Error - routing class can't be set while gateway class is in use !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	if ( ( gateway_class != 0 ) && ( pref_gateway != 0 ) ) {
		fprintf( stderr, "Error - preferred gateway can't be set while gateway class is in use !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	if ( ( routing_class == 0 ) && ( pref_gateway != 0 ) ) {
		fprintf( stderr, "Error - preferred gateway can't be set without specifying routing class !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	if ( ! tap_probe() )
		exit(EXIT_FAILURE);

	if ( ! unix_client ) {

		if ( argc <= found_args ) {
			fprintf( stderr, "Error - no interface specified\n" );
			usage();
			restore_defaults();
			exit(EXIT_FAILURE);
		}

		signal( SIGINT, handler );
		signal( SIGTERM, handler );
		signal( SIGPIPE, SIG_IGN );
		signal( SIGSEGV, segmentation_fault );

		debug_clients.fd_list = debugMalloc( sizeof(struct list_head_first *) * debug_level_max, 203 );
		debug_clients.mutex = debugMalloc( sizeof(pthread_mutex_t *) * debug_level_max, 204 );
		debug_clients.clients_num = debugMalloc( sizeof(int16_t) * debug_level_max, 204 );

		for ( res = 0; res < debug_level_max; res++ ) {

			debug_clients.fd_list[res] = debugMalloc( sizeof(struct list_head_first), 203 );
			((struct list_head_first *)debug_clients.fd_list[res])->next = debug_clients.fd_list[res];
			((struct list_head_first *)debug_clients.fd_list[res])->prev = debug_clients.fd_list[res];

			debug_clients.mutex[res] = debugMalloc( sizeof(pthread_mutex_t), 204 );
			pthread_mutex_init( (pthread_mutex_t *)debug_clients.mutex[res], NULL );

			debug_clients.clients_num[res] = 0;

		}

		/* daemonize */
		if ( debug_level == 0 ) {

			if ( my_daemon() < 0 ) {

				printf( "Error - can't fork to background: %s\n", strerror(errno) );
				restore_defaults();
				exit(EXIT_FAILURE);

			}

			openlog( "batmand", LOG_PID, LOG_DAEMON );

		} else {

			printf( "B.A.T.M.A.N. Advanced %s%s (compability version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );

			debug_clients.clients_num[ debug_level - 1 ]++;
			debug_level_info = debugMalloc( sizeof(struct debug_level_info), 205 );
			INIT_LIST_HEAD( &debug_level_info->list );
			debug_level_info->fd = 1;
			list_add( &debug_level_info->list, (struct list_head_first *)debug_clients.fd_list[debug_level - 1] );

		}

		FD_ZERO( &receive_wait_set );

		while ( argc > found_args ) {

			batman_if = debugMalloc( sizeof(struct batman_if), 206 );
			memset( batman_if, 0, sizeof(struct batman_if) );
			INIT_LIST_HEAD( &batman_if->list );
			INIT_LIST_HEAD_FIRST( batman_if->client_list );

			batman_if->dev = argv[found_args];
			batman_if->if_num = found_ifs;

			list_add_tail( &batman_if->list, &if_list );

			tmp_mtu = init_interface ( batman_if );

			if ( tmp_mtu < tap_mtu )
				tap_mtu = tmp_mtu;

			if ( batman_if->raw_sock > receive_max_sock )
				receive_max_sock = batman_if->raw_sock;

			FD_SET( batman_if->raw_sock, &receive_wait_set );

			if ( debug_level > 0 )
				printf( "Using interface %s \n", batman_if->dev );

// 			if ( gateway_class != 0 ) {
//
// 				init_interface_gw( batman_if );
//
// 			}

			found_ifs++;
			found_args++;

		}

		if ( ( tap_sock = tap_create( tap_mtu ) ) < 0 ) {

			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( tap_sock > receive_max_sock )
			receive_max_sock = tap_sock;

		FD_SET( tap_sock, &receive_wait_set );

 		if (vis_server)
 		{
 			memset(&vis_if.addr, 0, sizeof(vis_if.addr));
 			vis_if.addr.sin_family = AF_INET;
 			vis_if.addr.sin_port = htons(VIS_PORT);
 			vis_if.addr.sin_addr.s_addr = vis_server;
			if ( (vis_if.sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
				printf( "Error - can't create send socket: %s", strerror(errno) );
				restore_defaults();
				exit(EXIT_FAILURE);
			}

/* 			vis_if.sock = ((struct batman_if *)if_list.next)->udp_send_sock;*/
 		} else {
 			memset(&vis_if, 0, sizeof(vis_if));
 		}


		unlink( UNIX_PATH );
		unix_if.unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);

		memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );
		unix_if.addr.sun_family = AF_LOCAL;
		strcpy( unix_if.addr.sun_path, UNIX_PATH );

		if ( bind ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof (struct sockaddr_un) ) < 0 ) {
			debug_output( 0, "Error - can't bind unix socket: %s\n", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);
		}

		if ( listen( unix_if.unix_sock, 10 ) < 0 ) {
			debug_output( 0, "Error - can't listen unix socket: %s\n", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);
		}

		pthread_create( &unix_if.listen_thread_id, NULL, &unix_listen, NULL );


		if ( debug_level > 0 ) {

			printf( "debug level: %i\n", debug_level );

			if ( originator_interval != 1000 )
				printf( "originator interval: %i\n", originator_interval );

			if ( gateway_class > 0 )
				printf( "gateway class: %i\n", gateway_class );

			if ( routing_class > 0 )
				printf( "routing class: %i\n", routing_class );

// 			if ( pref_gateway > 0 ) {
// 				addr_to_string(pref_gateway, str1, sizeof (str1));
// 				printf( "preferred gateway: %s\n", str1 );
// 			}
/*
			if ( vis_server > 0 ) {
				addr_to_string(vis_server, str1, sizeof (str1));
				printf( "visualisation server: %s\n", str1 );
			}*/

		}

	/* connect to running batmand via unix socket */
	} else {

		if ( ( debug_level > 0 ) && ( debug_level <= debug_level_max ) ) {

			if ( ( debug_level > 2 ) && ( batch_mode ) )
				printf( "WARNING: Your chosen debug level (%i) does not support batch mode !\n", debug_level );

			unix_if.unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);

			memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );
			unix_if.addr.sun_family = AF_LOCAL;
			strcpy( unix_if.addr.sun_path, UNIX_PATH );

			if ( connect ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof(struct sockaddr_un) ) < 0 ) {

				printf( "Error - can't connect to unix socket '%s': %s ! Is batmand running on this host ?\n", UNIX_PATH, strerror(errno) );
				close( unix_if.unix_sock );
				exit(EXIT_FAILURE);

			}

			unix_buff = debugMalloc( 1501, 5001 );
			snprintf( unix_buff, 10, "d:%i", debug_level );

			if ( write( unix_if.unix_sock, unix_buff, 10 ) < 0 ) {

				printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
				close( unix_if.unix_sock );
				debugFree( unix_buff, 5101 );
				exit(EXIT_FAILURE);

			}

			while ( ( recv_buff_len = read( unix_if.unix_sock, unix_buff, 1500 ) ) > 0 ) {

				unix_buff[recv_buff_len] = '\0';

				buff_ptr = unix_buff;
				bytes_written = 0;

				while ( ( cr_ptr = strchr( buff_ptr, '\n' ) ) != NULL ) {

					*cr_ptr = '\0';

					if ( strncmp( buff_ptr, "EOD", 3 ) == 0 ) {

						if ( batch_mode ) {

							close( unix_if.unix_sock );
							debugFree( unix_buff, 5102 );
							exit(EXIT_SUCCESS);

						}

					} else if ( strncmp( buff_ptr, "BOD", 3 ) == 0 ) {

						if ( !batch_mode )
							system( "clear" );

					} else {

						printf( "%s\n", buff_ptr );

					}

					bytes_written += strlen( buff_ptr ) + 1;
					buff_ptr = cr_ptr + 1;

				}

				if ( bytes_written != recv_buff_len )
					printf( "%s", buff_ptr );

			}

			close( unix_if.unix_sock );
			debugFree( unix_buff, 5103 );

			if ( recv_buff_len < 0 ) {

				printf( "Error - can't read from unix socket: %s\n", strerror(errno) );
				exit(EXIT_FAILURE);

			} else {

				printf( "Connection terminated by remote host\n" );

			}

		}

		exit(EXIT_SUCCESS);

	}

}



int16_t init_interface ( struct batman_if *batman_if ) {

	struct ifreq int_req;
	int32_t tmp_socket, raw_sock_opts;


	if ( strlen( batman_if->dev ) > IFNAMSIZ - 1 ) {
		debug_output( 0, "Error - interface name too long: %s\n", batman_if->dev );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	if ( ( tmp_socket = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

		debug_output( 0, "Error - can't create tmp socket: %s", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	memset( &int_req, 0, sizeof (struct ifreq) );
	strncpy( int_req.ifr_name, batman_if->dev, IFNAMSIZ - 1 );

	if ( ioctl( tmp_socket, SIOCGIFHWADDR, &int_req ) < 0 ) {

		debug_output( 0, "Error - can't get hardware address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		close( tmp_socket );
		exit(EXIT_FAILURE);

	}

	memcpy( batman_if->hw_addr, int_req.ifr_hwaddr.sa_data, 6 );

	if ( ( batman_if->raw_sock = rawsock_create( batman_if->dev ) ) < 0 ) {

		restore_defaults();
		close( tmp_socket );
		exit(EXIT_FAILURE);

	}

	/* make raw socket non blocking */
	raw_sock_opts = fcntl( batman_if->raw_sock, F_GETFL, 0 );
	fcntl( batman_if->raw_sock, F_SETFL, raw_sock_opts | O_NONBLOCK );

	/* get MTU from real interface */
	if ( ioctl( tmp_socket, SIOCGIFMTU, &int_req ) < 0 ) {

		debug_output( 0, "Error - can't get mtu of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		close( tmp_socket );
		exit(EXIT_FAILURE);

	}

	close( tmp_socket );

	return int_req.ifr_mtu;

}




/*void init_interface_gw ( struct batman_if *batman_if )
{
	short on = 1;

	batman_if->addr.sin_port = htons(PORT + 1);
	batman_if->tcp_gw_sock = socket(PF_INET, SOCK_STREAM, 0);

	if ( batman_if->tcp_gw_sock < 0 ) {
		debug_output( 0, "Error - can't create socket: %s", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	if ( setsockopt( batman_if->tcp_gw_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int) ) < 0 ) {
		debug_output( 0, "Error - can't enable reuse of address: %s\n", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	if ( bind( batman_if->tcp_gw_sock, (struct sockaddr*)&batman_if->addr, sizeof(struct sockaddr_in) ) < 0 ) {
		debug_output( 0, "Error - can't bind socket: %s\n", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	if ( listen( batman_if->tcp_gw_sock, 10 ) < 0 ) {
		debug_output( 0, "Error - can't listen socket: %s\n", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	batman_if->tunnel_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if ( batman_if->tunnel_sock < 0 ) {
		debug_output( 0, "Error - can't create tunnel socket: %s", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	if ( bind( batman_if->tunnel_sock, (struct sockaddr *)&batman_if->addr, sizeof (struct sockaddr_in) ) < 0 ) {
		debug_output( 0, "Error - can't bind tunnel socket: %s\n", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	batman_if->addr.sin_port = htons(PORT);

	pthread_create( &batman_if->listen_thread_id, NULL, &gw_listen, batman_if );

}*/



// void *client_to_gw_tun( void *arg ) {
//
// 	struct curr_gw_data *curr_gw_data = (struct curr_gw_data *)arg;
// 	struct sockaddr_in gw_addr, my_addr, sender_addr;
// 	struct timeval tv;
// 	int32_t res, max_sock, status, buff_len, curr_gateway_tcp_sock, curr_gateway_tun_sock, curr_gateway_tun_fd, server_keep_alive_timeout;
// 	uint32_t addr_len;
// 	char curr_gateway_tun_if[IFNAMSIZ], keep_alive_string[] = "ping\0";
// 	unsigned char buff[1500];
// 	fd_set wait_sockets, tmp_wait_sockets;
//
//
// 	addr_len = sizeof (struct sockaddr_in);
//
// 	memset( &gw_addr, 0, sizeof(struct sockaddr_in) );
// 	memset( &my_addr, 0, sizeof(struct sockaddr_in) );
//
// 	gw_addr.sin_family = AF_INET;
// 	gw_addr.sin_port = htons(PORT + 1);
// 	gw_addr.sin_addr.s_addr = curr_gw_data->orig;
//
// 	my_addr.sin_family = AF_INET;
// 	my_addr.sin_port = htons(PORT + 1);
// 	my_addr.sin_addr.s_addr = curr_gw_data->batman_if->addr.sin_addr.s_addr;
//
//
// 	/* connect to server (ask permission) */
// 	if ( ( curr_gateway_tcp_sock = socket(PF_INET, SOCK_STREAM, 0) ) < 0 ) {
//
// 		debug_output( 0, "Error - can't create tcp socket: %s\n", strerror(errno) );
// 		curr_gateway = NULL;
// 		debugFree( arg, 248 );
// 		return NULL;
//
// 	}
//
// 	if ( connect ( curr_gateway_tcp_sock, (struct sockaddr *)&gw_addr, sizeof(struct sockaddr) ) < 0 ) {
//
// 		debug_output( 0, "Error - can't connect to gateway: %s\n", strerror(errno) );
// 		close( curr_gateway_tcp_sock );
//
// 		curr_gw_data->gw_node->last_failure = get_time();
// 		curr_gw_data->gw_node->unavail_factor++;
//
// 		curr_gateway = NULL;
// 		debugFree( arg, 248 );
// 		return NULL;
//
// 	}
//
// 	server_keep_alive_timeout = get_time();
//
//
// 	/* connect to server (establish udp tunnel) */
// 	if ( ( curr_gateway_tun_sock = socket(PF_INET, SOCK_DGRAM, 0) ) < 0 ) {
//
// 		debug_output( 0, "Error - can't create udp socket: %s\n", strerror(errno) );
// 		close( curr_gateway_tcp_sock );
// 		curr_gateway = NULL;
// 		debugFree( arg, 248 );
// 		return NULL;
//
// 	}
//
// 	if ( bind( curr_gateway_tun_sock, (struct sockaddr *)&my_addr, sizeof (struct sockaddr_in) ) < 0) {
//
// 		debug_output( 0, "Error - can't bind tunnel socket: %s\n", strerror(errno) );
// 		close( curr_gateway_tcp_sock );
// 		close( curr_gateway_tun_sock );
// 		curr_gateway = NULL;
// 		debugFree( arg, 248 );
// 		return NULL;
//
// 	}
//
//
// 	if ( add_dev_tun( curr_gw_data->batman_if, curr_gw_data->batman_if->addr.sin_addr.s_addr, curr_gateway_tun_if, sizeof(curr_gateway_tun_if), &curr_gateway_tun_fd ) > 0 ) {
//
// 		add_del_route( 0, 0, 0, 0, curr_gateway_tun_if, curr_gw_data->batman_if->udp_send_sock );
//
// 	} else {
//
// 		close( curr_gateway_tcp_sock );
// 		close( curr_gateway_tun_sock );
// 		curr_gateway = NULL;
// 		debugFree( arg, 248 );
// 		return NULL;
//
// 	}
//
//
// 	FD_ZERO(&wait_sockets);
// 	FD_SET(curr_gateway_tcp_sock, &wait_sockets);
// 	FD_SET(curr_gateway_tun_sock, &wait_sockets);
// 	FD_SET(curr_gateway_tun_fd, &wait_sockets);
//
// 	max_sock = curr_gateway_tcp_sock;
// 	if ( curr_gateway_tun_sock > max_sock )
// 		max_sock = curr_gateway_tun_sock;
// 	if ( curr_gateway_tun_fd > max_sock )
// 		max_sock = curr_gateway_tun_fd;
//
// 	while ( ( !is_aborted() ) && ( curr_gateway != NULL ) && ( ! curr_gw_data->gw_node->deleted ) ) {
//
//
// 		if ( server_keep_alive_timeout + 30000 < get_time() ) {
//
// 			server_keep_alive_timeout = get_time();
//
// 			if ( write( curr_gateway_tcp_sock, keep_alive_string, sizeof( keep_alive_string ) ) < 0 ) {
//
// 				debug_output( 3, "server_keepalive failed: %s\n", strerror(errno) );
//
// 				curr_gw_data->gw_node->last_failure = get_time();
// 				curr_gw_data->gw_node->unavail_factor++;
//
// 				break;
//
// 			}
//
// 		}
//
//
// 		tv.tv_sec = 0;
// 		tv.tv_usec = 250;
//
// 		tmp_wait_sockets = wait_sockets;
//
// 		res = select(max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv);
//
// 		if ( res > 0 ) {
//
// 			/* tcp message from server */
// 			if ( FD_ISSET( curr_gateway_tcp_sock, &tmp_wait_sockets ) ) {
//
// 				status = read( curr_gateway_tcp_sock, buff, sizeof( buff ) );
//
// 				if ( status > 0 ) {
//
// 					debug_output( 3, "server message ?\n" );
//
// 				} else if ( status < 0 ) {
//
// 					debug_output( 3, "Cannot read message from gateway: %s\n", strerror(errno) );
//
// 					break;
//
// 				} else if (status == 0) {
//
// 					debug_output( 3, "Gateway closed connection - timeout ?\n" );
//
// 					curr_gw_data->gw_node->last_failure = get_time();
// 					curr_gw_data->gw_node->unavail_factor++;
//
// 					break;
//
// 				}
//
// 			/* udp message (tunnel data) */
// 			} else if ( FD_ISSET( curr_gateway_tun_sock, &tmp_wait_sockets ) ) {
//
// 				if ( ( buff_len = recvfrom( curr_gateway_tun_sock, buff, sizeof( buff ), 0, (struct sockaddr *)&sender_addr, &addr_len ) ) < 0 ) {
//
// 					debug_output( 0, "Error - can't receive packet: %s\n", strerror(errno) );
//
// 				} else {
//
// 					if ( write( curr_gateway_tun_fd, buff, buff_len ) < 0 ) {
//
// 						debug_output( 0, "Error - can't write packet: %s\n", strerror(errno) );
//
// 					}
//
// 				}
//
// 			} else if ( FD_ISSET( curr_gateway_tun_fd, &tmp_wait_sockets ) ) {
//
// 				if ( ( buff_len = read( curr_gateway_tun_fd, buff, sizeof( buff ) ) ) < 0 ) {
//
// 					debug_output( 0, "Error - couldn't read data: %s\n", strerror(errno) );
//
// 				} else {
//
// 					if ( sendto(curr_gateway_tun_sock, buff, buff_len, 0, (struct sockaddr *)&gw_addr, sizeof (struct sockaddr_in) ) < 0 ) {
// 						debug_output( 0, "Error - can't send to gateway: %s\n", strerror(errno) );
// 					}
//
// 				}
//
// 			}
//
// 		} else if ( ( res < 0 ) && (errno != EINTR) ) {
//
// 			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
// 			break;
//
// 		}
//
// 	}
//
// 	/* cleanup */
// 	add_del_route( 0, 0, 0, 1, curr_gateway_tun_if, curr_gw_data->batman_if->udp_send_sock );
//
// 	close( curr_gateway_tcp_sock );
// 	close( curr_gateway_tun_sock );
//
// 	del_dev_tun( curr_gateway_tun_fd );
//
// 	curr_gateway = NULL;
// 	debugFree( arg, 248 );
//
// 	return NULL;
//
// }


void del_default_route() {

	curr_gateway = NULL;

	if ( curr_gateway_thread_id != 0 )
		pthread_join( curr_gateway_thread_id, NULL );

}



int8_t add_default_route() {

// 	struct curr_gw_data *curr_gw_data;
//
//
// 	curr_gw_data = debugMalloc( sizeof(struct curr_gw_data), 47 );
// 	curr_gw_data->orig = curr_gateway->orig_node->orig;
// 	curr_gw_data->gw_node = curr_gateway;
// 	curr_gw_data->batman_if = curr_gateway->orig_node->batman_if;
//
//
// 	if ( pthread_create( &curr_gateway_thread_id, NULL, &client_to_gw_tun, curr_gw_data ) != 0 ) {
//
// 		debug_output( 0, "Error - couldn't spawn thread: %s\n", strerror(errno) );
// 		debugFree( curr_gw_data, 247 );
// 		curr_gateway = NULL;
//
// 	}

	return 1;

}



void restore_defaults() {

	struct list_head *if_pos, *if_pos_tmp;
	struct batman_if *batman_if;

	list_for_each_safe( if_pos, if_pos_tmp, &if_list ) {

		batman_if = list_entry( if_pos, struct batman_if, list );

		if ( batman_if->listen_thread_id != 0 ) {

			pthread_join( batman_if->listen_thread_id, NULL );

		}

		close( batman_if->raw_sock );

		list_del( (struct list_head *)&if_list, if_pos, &if_list );
		debugFree( if_pos, 1206 );

	}

	if ( ( routing_class != 0 ) && ( curr_gateway != NULL ) )
		del_default_route();

	if ( tap_sock )
		tap_destroy( tap_sock );

// 	if ( vis_if.sock )
// 		close( vis_if.sock );

	if ( unix_if.unix_sock )
		close( unix_if.unix_sock );

	if ( unix_if.listen_thread_id != 0 )
		pthread_join( unix_if.listen_thread_id, NULL );

	if ( debug_level == 0 )
		closelog();

}



int8_t is_broadcast_address( uint8_t *dst_addr ) {

	if ( memcmp( dst_addr, broadcastAddr, ETH_ALEN ) == 0 )
		return 1;

	return 0;

}

/* check multicast range: address range 01:00:5e:00:00:00 - 01:00:5e:7f:ff:ff */
int8_t is_multicast_address( uint8_t *dst_addr ) {
	if ((dst_addr[0] == 0x01) && (dst_addr[1] == 0x00) && (dst_addr[2] == 0x5e) && (!(dst_addr[3] & 0x80)))
		return 1;
	return 0;
}




int8_t receive_packet_tap(unsigned char *packet_buff, int16_t packet_buff_len, int16_t *pay_buff_len)
{
	struct unicast_packet 	*unicast_packet;
	struct bcast_packet 	*bcast_packet;
	unsigned char 			*dhost = NULL;
	unsigned char 			*payload_ptr;
	struct list_head 		*if_pos;
	struct batman_if 		*batman_if;
	struct orig_node 		*orig_node;
	int 					 i;

	payload_ptr = packet_buff + BATMAN_MAXPACKETSIZE;

	/* save data from kernel into a buffer but spare space for the header information */
	for (i=0; i< PACKETS_PER_CYCLE; i++) {
		errno=EWOULDBLOCK;
		if ( ( *pay_buff_len = read( tap_sock, payload_ptr, packet_buff_len - 1 - BATMAN_MAXPACKETSIZE ) ) > 0 ) {

			hna_add( ((struct ether_header *)payload_ptr)->ether_shost, ((struct batman_if *)if_list.next)->hw_addr);
			dhost = transtable_search(((struct ether_header *) payload_ptr)->ether_dhost);
			if (dhost == NULL)
				debug_output(4, "HNA: Could not look up destination %s :(\n", addr_to_string_static(((struct ether_header *) payload_ptr)->ether_dhost));


#ifdef BROADCAST_UNKNOWN_DEST
			if ( dhost == NULL )
				dhost = broadcastAddr;

#else
			if ( dhost == NULL )
				dhost = ((struct ether_header *)payload_ptr)->ether_dhost;
#endif

			/* ethernet packet should be broadcasted */
			if (is_broadcast_address(dhost) || is_multicast_address(dhost)) {

				bcast_packet = (struct bcast_packet *)(payload_ptr - sizeof(struct bcast_packet));

				bcast_packet->version = COMPAT_VERSION;
				/* batman packet type: broadcast */
				bcast_packet->packet_type = BAT_BCAST;
				/* hw address of first interface is the orig mac because only this mac is known throughout the mesh */
				memcpy( bcast_packet->orig, ((struct batman_if *)if_list.next)->hw_addr, 6 );
				/* set broadcast sequence number */
				bcast_packet->seqno = htons( ((struct batman_if *)if_list.next)->bcast_seqno );

				((struct batman_if *)if_list.next)->bcast_seqno++;

				/* broadcast packet */
				list_for_each(if_pos, &if_list) {

					batman_if = list_entry(if_pos, struct batman_if, list);

					if ( send_packet( (unsigned char *)bcast_packet, *pay_buff_len + sizeof(struct bcast_packet), batman_if->hw_addr, broadcastAddr, batman_if->raw_sock ) < 0 )
						return -1;

				}

			/* unicast packet */
			} else {

				/* get routing information */
				orig_node = find_orig_node( dhost );

				if ( ( orig_node != NULL ) && ( orig_node->batman_if != NULL ) && ( orig_node->router != NULL ) ) {

					unicast_packet = (struct unicast_packet *)(payload_ptr - sizeof(struct unicast_packet) );

					unicast_packet->version = COMPAT_VERSION;
					/* batman packet type: unicast */
					unicast_packet->packet_type = BAT_UNICAST;
					/* set unicast ttl */
					unicast_packet->ttl = TTL;
					/* copy the destination for faster routing */
					memcpy( unicast_packet->dest, dhost, 6 );


					if ( send_packet( (unsigned char *)unicast_packet, *pay_buff_len + sizeof(struct unicast_packet), orig_node->batman_if->hw_addr, orig_node->router->addr, orig_node->batman_if->raw_sock ) < 0 )
						return -1;

				} else {
					debug_output(4, "found no destination for the MAC %s\n", addr_to_string_static(dhost));
					/*unsigned char *pay_buff = (unsigned char *)packet_buff + sizeof(struct batman_packet);
					printf( "not found: %s\n", addr_to_string( ((struct ether_header *)payload_ptr)->ether_dhost ) ); */

				}

			}

		} else
			break;		/* can't receive anymore? jump out! */
	}

	/* TODO: sometimes there are "illegal seek" errors on high throughput scenarios, but they are not fatal. */
	if ((errno != EWOULDBLOCK)  && (errno != ESPIPE)) {
		debug_output( 0, "Error - couldn't read data from tap interface: %s\n", strerror(errno) );
		return -1;

	}
	return(0);
}
int8_t receive_packet_batiface( unsigned char *packet_buff, int16_t packet_buff_len, int16_t *pay_buff_len,
								uint8_t *neigh, struct batman_if **if_incoming, struct batman_if *batman_if )
{
	struct ether_header 	 ether_header;
	unsigned char 			*dhost = NULL;
	struct orig_node 		*orig_node;
	struct list_head 		*if_pos;
	int 					 i;
	char str1[ETH_STR_LEN], str2[ETH_STR_LEN];
	struct icmp_packet		*icmp_packet;
	struct batman_packet	*batman_packet;
	struct bcast_packet		*bcast_packet;
	struct unicast_packet 	*unicast_packet;

	for (i=0; i<PACKETS_PER_CYCLE; i++) {
		if ((*pay_buff_len = rawsock_read(batman_if->raw_sock, &ether_header, packet_buff, packet_buff_len-1)) > -1) {

			/* drop packet if it has no batman packet type field */
			if (*pay_buff_len < 2)
				continue;

			if (packet_buff[1] != COMPAT_VERSION) {
			    debug_output( 4, "Drop packet: incompatible batman version (%i) \n", packet_buff[1]);

			}

			/* batman packet */
			switch (packet_buff[0]) {
			case BAT_PACKET:

				/* drop packet if it has no batman packet payload */
				if ( *pay_buff_len < (int)sizeof(struct batman_packet) )
					continue;

				batman_packet = ((struct batman_packet *)packet_buff);

				batman_packet->seqno = ntohs( batman_packet->seqno ); /* network to host order for our 16bit seqno. */

				(*if_incoming) = batman_if;
				memcpy( neigh, ether_header.ether_shost, ETH_ALEN );

				return 1;
			/* unicast packet */
			case BAT_UNICAST:
				/* packet with unicast indication but broadcast recipient */
				if ( memcmp( &ether_header.ether_dhost, broadcastAddr, ETH_ALEN ) == 0 )
					continue;

				/* packet with broadcast sender address */
				if ( memcmp( &ether_header.ether_shost, broadcastAddr, ETH_ALEN ) == 0 )
					continue;

				/* drop packet if it has not neccessary minimum size - 1 byte ttl, 1 byte payload */
				if ( *pay_buff_len < (int)sizeof(struct unicast_packet) )
					continue;

				unicast_packet = (struct unicast_packet *)packet_buff;

				dhost = unicast_packet->dest;
	/*
				dhost = transtable_search( ((struct ether_header *)(packet_buff + sizeof(struct unicast_packet)))->ether_dhost);
				if (dhost == NULL)
					dhost = ((struct ether_header *)(packet_buff + sizeof(struct unicast_packet)))->ether_dhost;
					*/

				/* packet for me */
				if ( is_my_mac( dhost ) == 1 ) {

					tap_write( tap_sock, packet_buff + sizeof(struct unicast_packet), *pay_buff_len - sizeof(struct unicast_packet) );


				/* route it */
				} else {

					/* TTL exceeded */
					if (unicast_packet->ttl < 2 ) {

						addr_to_string(str1, ((struct ether_header *)(packet_buff + sizeof(struct unicast_packet)))->ether_shost);
						addr_to_string(str2, ((struct ether_header *)(packet_buff + sizeof(struct unicast_packet)))->ether_dhost);

						debug_output(0, "Error - can't send packet from %s to %s: ttl exceeded\n", str1, str2);

						continue;

					}

					/* get routing information */
					orig_node = find_orig_node( dhost );

					if ( ( orig_node != NULL ) && ( orig_node->batman_if != NULL ) && ( orig_node->router != NULL ) ) {

						memcpy( ether_header.ether_dhost, orig_node->router->addr, ETH_ALEN );
						memcpy( ether_header.ether_shost, orig_node->batman_if->hw_addr, ETH_ALEN );

						/* decrement ttl */
						unicast_packet->ttl--;

						if ( rawsock_write( orig_node->batman_if->raw_sock, &ether_header, packet_buff, *pay_buff_len ) < 0 ) {

							debug_output( 0, "Error - can't send data through raw socket: %s\n", strerror(errno) );
							return -1;

						}

					}

				}
				break;

			/* batman icmp packet */
			case BAT_ICMP:

				/* packet with unicast indication but broadcast recipient */
				if ( memcmp( &ether_header.ether_dhost, broadcastAddr, ETH_ALEN ) == 0 )
					continue;

				/* packet with broadcast sender address */
				if ( memcmp( &ether_header.ether_shost, broadcastAddr, ETH_ALEN ) == 0 )
					continue;

				/* drop packet if it has not neccessary minimum size */
				if ( *pay_buff_len < (int)sizeof(struct icmp_packet) )
					continue;

				icmp_packet = (struct icmp_packet *)packet_buff;

				/* packet for me */
				if ( is_my_mac( icmp_packet->dst ) == 1 ) {

						/* answer ping request (ping) */
						if ( icmp_packet->msg_type == ECHO_REQUEST ) {

							/* get routing information */
							orig_node = find_orig_node( icmp_packet->orig );

							if ( ( orig_node != NULL ) && ( orig_node->batman_if != NULL ) && ( orig_node->router != NULL ) ) {

								memcpy( icmp_packet->dst, icmp_packet->orig, ETH_ALEN );
								memcpy( icmp_packet->orig, ether_header.ether_dhost, ETH_ALEN );
								icmp_packet->msg_type = ECHO_REPLY;
								icmp_packet->ttl = TTL;

								memcpy( ether_header.ether_shost, orig_node->batman_if->hw_addr, ETH_ALEN );
								memcpy( ether_header.ether_dhost, orig_node->router->addr, ETH_ALEN );

								if ( rawsock_write( orig_node->batman_if->raw_sock, &ether_header, packet_buff, *pay_buff_len ) < 0 ) {

									debug_output( 0, "Error - can't send data through raw socket: %s\n", strerror(errno) );
									return -1;

								}
							}


						} else {

							/* give data to unix client */
							if ( unix_packet[icmp_packet->uid] != NULL )
								write( ((struct unix_client *)(unix_packet[icmp_packet->uid]))->sock, packet_buff, sizeof(struct icmp_packet) );

						}

				/* route it */
				} else {

					/* TTL exceeded */
					if ( icmp_packet->ttl < 2 )   {

						addr_to_string(str1, icmp_packet->orig);
						addr_to_string(str2, icmp_packet->dst);

						debug_output( 0, "Error - can't send packet from %s to %s: ttl exceeded\n", str1, str2);

						/* send TTL exceed if packet is an echo request (traceroute) */
						if (icmp_packet->msg_type == ECHO_REQUEST ) {

							/* get routing information */
							orig_node = find_orig_node( icmp_packet->orig );

							if ( ( orig_node != NULL ) && ( orig_node->batman_if != NULL ) && ( orig_node->router != NULL ) ) {

								memcpy( icmp_packet->dst, icmp_packet->orig, ETH_ALEN );
								memcpy( icmp_packet->orig, ether_header.ether_dhost, ETH_ALEN );
								icmp_packet->msg_type = TTL_EXCEEDED;
								icmp_packet->ttl = TTL;

								memcpy( ether_header.ether_shost, orig_node->batman_if->hw_addr, ETH_ALEN );
								memcpy( ether_header.ether_dhost, orig_node->router->addr, ETH_ALEN );

								if ( rawsock_write( orig_node->batman_if->raw_sock, &ether_header, packet_buff, *pay_buff_len ) < 0 ) {

									debug_output( 0, "Error - can't send data through raw socket: %s\n", strerror(errno) );
									return -1;

								}

							}

						}

						continue;

					}

					/* get routing information */
					orig_node = find_orig_node( icmp_packet->dst );

					if ( ( orig_node != NULL ) && ( orig_node->batman_if != NULL ) && ( orig_node->router != NULL ) ) {

						memcpy( ether_header.ether_dhost, orig_node->router->addr, ETH_ALEN );
						memcpy( ether_header.ether_shost, orig_node->batman_if->hw_addr, ETH_ALEN );

						/* decrement ttl */
						icmp_packet->ttl--;

						if ( rawsock_write( orig_node->batman_if->raw_sock, &ether_header, packet_buff, *pay_buff_len ) < 0 ) {

							debug_output( 0, "Error - can't send data through raw socket: %s\n", strerror(errno) );
							return -1;

						}

					}

				}
				break;

			/* broadcast */
			case BAT_BCAST:
#ifndef BROADCAST_UNKNOWN_DEST
				/* packet with broadcast indication but not broadcast recipient */
				if ( memcmp( &ether_header.ether_dhost, broadcastAddr, ETH_ALEN ) != 0 )
					continue;
#endif

				/* packet with broadcast sender address */
				if ( memcmp( &ether_header.ether_shost, broadcastAddr, ETH_ALEN ) == 0 )
					continue;

				/* drop packet if it has not neccessary minimum size - orig source mac, 2 byte seqno, 1 byte padding, 1 byte payload */
				if ( *pay_buff_len < (int)sizeof(struct bcast_packet) )
					continue;

				/* ignore broadcasts sent by myself */
				if ( is_my_mac( ether_header.ether_shost ) == 1 )
					continue;

				bcast_packet = (struct bcast_packet *)packet_buff;

				orig_node = find_orig_node( bcast_packet->orig );

				if ( orig_node != NULL ) {

					/* check flood history */
					if (get_bit_status(orig_node->seq_bits, orig_node->last_bcast_seqno, ntohs( bcast_packet->seqno)))
						continue;

					/* mark broadcast in flood history */
					if (bit_get_packet( orig_node->seq_bits, ntohs(bcast_packet->seqno) - orig_node->last_bcast_seqno, 1))
						orig_node->last_bcast_seqno= ntohs( bcast_packet->seqno );

					/* broadcast for me */
					tap_write( tap_sock, packet_buff + sizeof(struct bcast_packet), *pay_buff_len - sizeof(struct bcast_packet) );

					/* rebroadcast packet */
					list_for_each(if_pos, &if_list) {

						batman_if = list_entry(if_pos, struct batman_if, list);

						memcpy( ether_header.ether_shost, batman_if->hw_addr, ETH_ALEN );
						/* TODO: always rebroadcasting on orig_node->batman_if? that seems wrong ... should be rebroadcastet on every interface! */
	/*							if ( rawsock_write( orig_node->batman_if->raw_sock, &ether_header, packet_buff, *pay_buff_len ) < 0 ) { */
						if ( rawsock_write( batman_if->raw_sock, &ether_header, packet_buff, *pay_buff_len ) < 0 ) {
							debug_output( 0, "Error - can't send rebroadcast data through raw socket: %s\n", strerror(errno) );
							return -1;
						}
					}

				}
				break;

			}

		} else {

			if ( errno != EWOULDBLOCK ) {

				debug_output( 0, "Error - couldn't read data from raw socket(%s): %s\n", batman_if->dev, strerror(errno) );
				return -1;

			} else break;
		}
	}
	return(0);
}

int8_t receive_packet( unsigned char *packet_buff, int16_t packet_buff_len, int16_t *pay_buff_len, uint8_t *neigh, uint32_t timeout, struct batman_if **if_incoming )
{

	struct timeval 			 tv;
	struct batman_if 		*batman_if;
	struct list_head 		*if_pos;
	int8_t 					 res;
	int						 ret;
	fd_set 					 tmp_wait_set;


	memcpy( &tmp_wait_set, &receive_wait_set, sizeof(fd_set) );

	while (1) {

		tv.tv_sec = timeout / 1000;
		tv.tv_usec = ( timeout % 1000 ) * 1000;

		res = select( receive_max_sock + 1, &tmp_wait_set, NULL, NULL, &tv );

		if ( res >= 0 )
			break;

		if ( errno != EINTR ) {

			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			return -1;

		}

	}

	if (res == 0)
		return 0;

	if (FD_ISSET(tap_sock, &tmp_wait_set)) {
		ret = receive_packet_tap(packet_buff, packet_buff_len, pay_buff_len);
		if (ret != 0)
			return(ret);

	}

	list_for_each(if_pos, &if_list) {
		batman_if = list_entry(if_pos, struct batman_if, list);

		if (FD_ISSET(batman_if->raw_sock, &tmp_wait_set)) {
			ret = receive_packet_batiface(packet_buff, packet_buff_len, pay_buff_len, neigh, if_incoming, batman_if);
			if (ret != 0)
				return(ret);
		}

	}

	return 0;

}



int8_t send_packet( unsigned char *packet_buff, int16_t packet_buff_len, uint8_t *send_addr, uint8_t *recv_addr, int32_t send_sock ) {

	int i;
	struct ether_header ether_header;

	memcpy( ether_header.ether_dhost, recv_addr, ETH_ALEN );
	memcpy( ether_header.ether_shost, send_addr, ETH_ALEN );

//	debug_output( 4, "send packet: send addr %s,", addr_to_string( send_addr ) );
//	debug_output( 4, "recv addr %s,", addr_to_string( recv_addr ) );
//	debug_output( 4, "%02x %02x %02x %02x %02x \n", packet_buff[0], packet_buff[1], packet_buff[2], packet_buff[3], packet_buff[4] );

	/* Try sending PACKETS_PER_CYCLE times to send the packet, and drop it otherwise. */
	for (i=0; i< PACKETS_PER_CYCLE; i++) {
		if ( rawsock_write( send_sock, &ether_header, packet_buff, packet_buff_len ) < 0 ) {
			if (errno == EAGAIN || errno == ESPIPE){
				debug_output( 4, "send packet failed, but we retry\n" );
				continue;
			} else {
				debug_output( 0, "send packet failed.\n" );
				return -1;
			}
		} else break;
	}
	return 0;

}



// void *gw_listen( void *arg ) {
//
// 	struct batman_if *batman_if = (struct batman_if *)arg;
// 	struct gw_client *gw_client;
// 	struct list_head *client_pos, *client_pos_tmp;
// 	struct timeval tv;
// 	struct sockaddr_in addr;
// 	struct in_addr tmp_ip_holder;
// 	socklen_t sin_size = sizeof(struct sockaddr_in);
// 	char gw_addr[16], str2[16], tun_dev[IFNAMSIZ], tun_ip[] = "104.255.255.254\0";
// 	int32_t res, status, max_sock_min, max_sock, buff_len, tun_fd;
// 	uint32_t addr_len, client_timeout;
// 	unsigned char buff[1500];
// 	fd_set wait_sockets, tmp_wait_sockets;
//
//
// 	addr_to_string(batman_if->addr.sin_addr.s_addr, gw_addr, sizeof (gw_addr));
// 	addr_len = sizeof (struct sockaddr_in);
// 	client_timeout = get_time();
//
// 	if ( inet_pton(AF_INET, tun_ip, &tmp_ip_holder) < 1 ) {
//
// 		debug_output( 0, "Error - invalid tunnel IP specified: %s\n", tun_ip );
// 		exit(EXIT_FAILURE);
//
// 	}
//
// 	if ( add_dev_tun( batman_if, tmp_ip_holder.s_addr, tun_dev, sizeof(tun_dev), &tun_fd ) < 0 ) {
// 		return NULL;
// 	}
//
//
// 	FD_ZERO(&wait_sockets);
// 	FD_SET(batman_if->tcp_gw_sock, &wait_sockets);
// 	FD_SET(batman_if->tunnel_sock, &wait_sockets);
// 	FD_SET(tun_fd, &wait_sockets);
//
// 	max_sock_min = batman_if->tcp_gw_sock;
// 	if ( batman_if->tunnel_sock > max_sock_min )
// 		max_sock_min = batman_if->tunnel_sock;
// 	if ( tun_fd > max_sock_min )
// 		max_sock_min = tun_fd;
//
// 	max_sock = max_sock_min;
//
// 	while (!is_aborted()) {
//
// 		tv.tv_sec = 1;
// 		tv.tv_usec = 0;
// 		tmp_wait_sockets = wait_sockets;
//
// 		res = select(max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv);
//
// 		if (res > 0) {
//
// 			/* new client */
// 			if ( FD_ISSET( batman_if->tcp_gw_sock, &tmp_wait_sockets ) ) {
//
// 				gw_client = debugMalloc( sizeof(struct gw_client), 18 );
// 				memset( gw_client, 0, sizeof(struct gw_client) );
//
// 				if ( ( gw_client->sock = accept(batman_if->tcp_gw_sock, (struct sockaddr *)&gw_client->addr, &sin_size) ) == -1 ) {
// 					debug_output( 0, "Error - can't accept client packet: %s\n", strerror(errno) );
// 					continue;
// 				}
//
// 				INIT_LIST_HEAD(&gw_client->list);
// 				gw_client->batman_if = batman_if;
// 				gw_client->last_keep_alive = get_time();
//
// 				FD_SET(gw_client->sock, &wait_sockets);
// 				if ( gw_client->sock > max_sock )
// 					max_sock = gw_client->sock;
//
// 				list_add_tail(&gw_client->list, &batman_if->client_list);
//
// 				addr_to_string(gw_client->addr.sin_addr.s_addr, str2, sizeof (str2));
// 				debug_output( 3, "gateway: %s (%s) got connection from %s (internet via %s)\n", gw_addr, batman_if->dev, str2, tun_dev );
//
// 			/* tunnel activity */
// 			} else if ( FD_ISSET( batman_if->tunnel_sock, &tmp_wait_sockets ) ) {
//
// 				if ( ( buff_len = recvfrom( batman_if->tunnel_sock, buff, sizeof( buff ), 0, (struct sockaddr *)&addr, &addr_len ) ) < 0 ) {
//
// 					debug_output( 0, "Error - can't receive packet: %s\n", strerror(errno) );
//
// 				} else {
//
// 					if ( write( tun_fd, buff, buff_len ) < 0 ) {
//
// 						debug_output( 0, "Error - can't write packet: %s\n", strerror(errno) );
//
// 					}
//
// 				}
//
// 			/* /dev/tunX activity */
// 			} else if ( FD_ISSET( tun_fd, &tmp_wait_sockets ) ) {
//
// 				/* not needed - kernel knows client adress and routes traffic directly */
//
// 				debug_output( 0, "Warning - data coming through tun device: %s\n", tun_dev );
//
// 				/*if ( ( buff_len = read( tun_fd, buff, sizeof( buff ) ) ) < 0 ) {
//
// 					fprintf(stderr, "Could not read data from %s: %s\n", tun_dev, strerror(errno));
//
// 				} else {
//
// 					if ( sendto(curr_gateway_tun_sock, buff, buff_len, 0, (struct sockaddr *)&gw_addr, sizeof (struct sockaddr_in) ) < 0 ) {
// 						fprintf(stderr, "Cannot send to client: %s\n", strerror(errno));
// 					}
//
// 				}*/
//
// 			/* client sent keep alive */
// 			} else {
//
// 				max_sock = max_sock_min;
//
// 				list_for_each_safe(client_pos, client_pos_tmp, &batman_if->client_list) {
//
// 					gw_client = list_entry(client_pos, struct gw_client, list);
//
// 					if ( FD_ISSET( gw_client->sock, &tmp_wait_sockets ) ) {
//
// 						addr_to_string(gw_client->addr.sin_addr.s_addr, str2, sizeof (str2));
//
// 						status = read( gw_client->sock, buff, sizeof( buff ) );
//
// 						if ( status > 0 ) {
//
// 							gw_client->last_keep_alive = get_time();
//
// 							if ( gw_client->sock > max_sock )
// 								max_sock = gw_client->sock;
//
// 							debug_output( 3, "gateway: client %s sent keep alive on interface %s\n", str2, batman_if->dev );
//
// 						} else {
//
// 							if ( status < 0 ) {
//
// 								debug_output( 0, "Error - can't read message: %s\n", strerror(errno) );
//
// 							} else {
//
// 								debug_output( 3, "Client %s closed connection ...\n", str2 );
//
// 							}
//
// 							FD_CLR(gw_client->sock, &wait_sockets);
// 							close( gw_client->sock );
//
// 							list_del( client_pos );
// 							debugFree( client_pos, 201 );
//
// 						}
//
// 					} else {
//
// 						if ( gw_client->sock > max_sock )
// 							max_sock = gw_client->sock;
//
// 					}
//
// 				}
//
// 			}
//
// 		} else if ( ( res < 0 ) && (errno != EINTR) ) {
//
// 			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
// 			break;
//
// 		}
//
//
// 		/* close unresponsive client connections */
// 		if ( ( client_timeout + 59000 ) < get_time() ) {
//
// 			client_timeout = get_time();
//
// 			max_sock = max_sock_min;
//
// 			list_for_each_safe(client_pos, client_pos_tmp, &batman_if->client_list) {
//
// 				gw_client = list_entry(client_pos, struct gw_client, list);
//
// 				if ( ( gw_client->last_keep_alive + 120000 ) < client_timeout ) {
//
// 					FD_CLR(gw_client->sock, &wait_sockets);
// 					close( gw_client->sock );
//
// 					addr_to_string(gw_client->addr.sin_addr.s_addr, str2, sizeof (str2));
// 					debug_output( 3, "gateway: client %s timeout on interface %s\n", str2, batman_if->dev );
//
// 					list_del( client_pos );
// 					debugFree( client_pos, 202 );
//
// 				} else {
//
// 					if ( gw_client->sock > max_sock )
// 						max_sock = gw_client->sock;
//
// 				}
//
// 			}
//
// 		}
//
// 	}
//
// 	/* delete tun devices on exit */
// 	del_dev_tun( tun_fd );
//
// 	list_for_each_safe(client_pos, client_pos_tmp, &batman_if->client_list) {
//
// 		gw_client = list_entry(client_pos, struct gw_client, list);
//
// 		list_del( client_pos );
// 		debugFree( client_pos, 297 );
//
// 	}
//
// 	return NULL;
//
// }



void tap_write( int32_t tap_fd, unsigned char *buff, int16_t buff_len ) {

	if ( write( tap_fd, buff, buff_len ) < 0 )
		debug_output( 0, "Error - can't write broadcast data to tap interface: %s\n", strerror(errno) );

}



// int8_t set_hw_addr( char *dev, uint8_t *hw_addr ) {
//
// 	struct ifreq int_req;
// 	int32_t tmp_socket;
//
//
// 	strncpy( int_req.ifr_name, dev, IFNAMSIZ - 1 );
//
// 	if ( ( tmp_socket = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
//
// 		debug_output( 0, "Error - can't create tmp socket: %s", strerror(errno) );
// 		return -1;
//
// 	}
//
// 	if ( ioctl( tmp_socket, SIOCGIFFLAGS, &int_req ) < 0 ) {
//
// 		debug_output( 0, "Error - can't set hardware address of interface %s (SIOCGIFFLAGS): %s\n", dev, strerror(errno) );
// 		close( tmp_socket );
// 		return -1;
//
// 	}
//
// 	int_req.ifr_flags &= ~IFF_UP;
// 	int_req.ifr_flags &= ~IFF_RUNNING;
//
// 	if ( ioctl( tmp_socket, SIOCSIFFLAGS, &int_req ) < 0 ) {
//
// 		debug_output( 0, "Error - can't set hardware address of interface %s (SIOCSIFFLAGS): %s\n", dev, strerror(errno) );
// 		close( tmp_socket );
// 		return -1;
//
// 	}
//
// 	if ( ioctl( tmp_socket, SIOCGIFHWADDR, &int_req ) < 0 ) {
//
// 		debug_output( 0, "Error - can't set hardware address of interface %s (SIOCGIFHWADDR): %s\n", dev, strerror(errno) );
// 		close( tmp_socket );
// 		return -1;
//
// 	}
//
// 	memcpy( int_req.ifr_hwaddr.sa_data, hw_addr, 6 );
//
// 	if ( ioctl( tmp_socket, SIOCSIFHWADDR, &int_req ) < 0 ) {
//
// 		debug_output( 0, "Error - can't set hardware address of interface %s (SIOCSIFHWADDR): %s\n", dev, strerror(errno) );
// 		close( tmp_socket );
// 		return -1;
//
// 	}
//
// 	int_req.ifr_flags |= IFF_UP;
// 	int_req.ifr_flags |= IFF_RUNNING;
//
// 	if ( ioctl( tmp_socket, SIOCSIFFLAGS, &int_req ) < 0 ) {
//
// 		debug_output( 0, "Error - can't set hardware address of interface %s (SIOCSIFFLAGS): %s\n", dev, strerror(errno) );
// 		close( tmp_socket );
// 		return -1;
//
// 	}
//
// 	return 0;
//
// }



void restore_and_exit( uint8_t is_sigsegv ) {

	if ( !unix_client ) {

		/* remove tap interface first */
		stop = 1;

		if ( tap_sock ) {

			tap_destroy( tap_sock );
			tap_sock = 0;

		}

		restore_defaults();

	}

	if ( !is_sigsegv )
		exit(EXIT_FAILURE);

}



void segmentation_fault( int32_t BATUNUSED(sig) ) {

	signal( SIGSEGV, SIG_DFL );

	debug_output( 0, "Error - SIGSEGV received, trying to clean up ... \n" );

	restore_and_exit(1);

	raise( SIGSEGV );

}



void cleanup() {

	int8_t i;
	struct debug_level_info *debug_level_info;
	struct list_head *debug_pos, *debug_pos_tmp;


	for ( i = 0; i < debug_level_max; i++ ) {

		if ( debug_clients.clients_num[i] > 0 ) {

			list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[i] ) {

				debug_level_info = list_entry( debug_pos, struct debug_level_info, list );

				list_del( (struct list_head *)debug_clients.fd_list[i], debug_pos, (struct list_head_first *)debug_clients.fd_list[i] );
				debugFree( debug_pos, 1207 );

			}

		}

		debugFree( debug_clients.fd_list[i], 1208 );
		debugFree( debug_clients.mutex[i], 1209 );

	}

	debugFree( debug_clients.fd_list, 1210 );
	debugFree( debug_clients.mutex, 1211 );
	debugFree( debug_clients.clients_num, 1212 );

}

