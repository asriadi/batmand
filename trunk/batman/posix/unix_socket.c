/*
 * Copyright (C) 2006 BATMAN contributors:
 * Marek Lindner
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
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include "../os.h"
#include "../batman.h"



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

			debug_output( 0, "Warning - could not trylock mutex (debug_output): %s \n", strerror( EBUSY ) );

		}

	}

}



void *unix_listen( void *arg ) {

	struct unix_client *unix_client;
	struct debug_level_info *debug_level_info;
	struct list_head *list_pos, *unix_pos_tmp, *debug_pos, *debug_pos_tmp, *prev_list_head, *prev_list_head_unix;
	struct hna_node *hna_node;
	struct batman_if *batman_if;
	struct timeval tv;
	struct sockaddr_un sun_addr;
	struct in_addr tmp_ip_holder;
	int32_t status, max_sock, unix_opts, download_speed, upload_speed;
	int8_t res;
	char buff[100], str[16], was_gateway, tmp_unix_value;
	fd_set wait_sockets, tmp_wait_sockets;
	socklen_t sun_size = sizeof(struct sockaddr_un);


	INIT_LIST_HEAD_FIRST(unix_if.client_list);

	FD_ZERO(&wait_sockets);
	FD_SET(unix_if.unix_sock, &wait_sockets);

	max_sock = unix_if.unix_sock;

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

				list_for_each_safe( list_pos, unix_pos_tmp, &unix_if.client_list ) {

					unix_client = list_entry( list_pos, struct unix_client, list );

					if ( FD_ISSET( unix_client->sock, &tmp_wait_sockets ) ) {

						status = read( unix_client->sock, buff, sizeof( buff ) );

						if ( status > 0 ) {

							if ( unix_client->sock > max_sock )
								max_sock = unix_client->sock;

							/* debug_output( 3, "gateway: client sent data via unix socket: %s\n", buff ); */

							if ( buff[0] == 'd' ) {

								if ( ( status > 2 ) && ( ( buff[2] > 0 ) && ( buff[2] <= debug_level_max ) ) ) {

									if ( unix_client->debug_level != 0 ) {

										prev_list_head = (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1];

										if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
											debug_output( 0, "Error - could not lock mutex (unix_listen => 1): %s \n", strerror( errno ) );

										list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1] ) {

											debug_level_info = list_entry( debug_pos, struct debug_level_info, list );

											if ( debug_level_info->fd == unix_client->sock ) {

												list_del( prev_list_head, debug_pos, debug_clients.fd_list[unix_client->debug_level - 1] );
												debug_clients.clients_num[unix_client->debug_level - 1]--;

												debugFree( debug_pos, 1201 );

												break;

											}

											prev_list_head = &debug_level_info->list;

										}

										if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
											debug_output( 0, "Error - could not unlock mutex (unix_listen => 1): %s \n", strerror( errno ) );

									}

									if ( unix_client->debug_level != buff[2] ) {

										if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[buff[2] - 1] ) != 0 )
											debug_output( 0, "Error - could not lock mutex (unix_listen => 2): %s \n", strerror( errno ) );

										debug_level_info = debugMalloc( sizeof(struct debug_level_info), 202 );
										INIT_LIST_HEAD( &debug_level_info->list );
										debug_level_info->fd = unix_client->sock;
										list_add( &debug_level_info->list, (struct list_head_first *)debug_clients.fd_list[buff[2] - 1] );
										debug_clients.clients_num[buff[2] - 1]++;

										unix_client->debug_level = buff[2];

										if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[buff[2] - 1] ) != 0 )
											debug_output( 0, "Error - could not unlock mutex (unix_listen => 2): %s \n", strerror( errno ) );

									} else {

										unix_client->debug_level = 0;

									}

								}

							} else if ( buff[0] == 'i' ) {

								dprintf( unix_client->sock, "%s", prog_name );

								if ( routing_class > 0 )
									dprintf( unix_client->sock, " -r %i", routing_class );

								if ( pref_gateway > 0 ) {

									addr_to_string( pref_gateway, str, sizeof (str) );

									dprintf( unix_client->sock, " -p %s", str );

								}

								if ( gateway_class > 0 ) {

									get_gw_speeds( gateway_class, &download_speed, &upload_speed );

									dprintf( unix_client->sock, " -g %i%s/%i%s", ( download_speed > 2048 ? download_speed / 1024 : download_speed ), ( download_speed > 2048 ? "MBit" : "KBit" ), ( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ), ( upload_speed > 2048 ? "MBit" : "KBit" ) );

								}

								list_for_each( list_pos, &hna_list ) {

									hna_node = list_entry( list_pos, struct hna_node, list );

									addr_to_string( hna_node->addr, str, sizeof (str) );

									dprintf( unix_client->sock, " -a %s/%i", str, hna_node->netmask );

								}

								list_for_each( list_pos, &if_list ) {

									batman_if = list_entry( list_pos, struct batman_if, list );

									dprintf( unix_client->sock, " %s", batman_if->dev );

								}

								dprintf( unix_client->sock, "\nEOD\n" );

							} else if ( buff[0] == 'g' ) {

								if ( status > 2 ) {

									was_gateway = ( gateway_class > 0 ? 1 : 0 );

									gateway_class = buff[2];

									list_for_each( list_pos, &if_list ) {

										batman_if = list_entry( list_pos, struct batman_if, list );

										batman_if->out.gwflags = gateway_class;

										if ( ( ! was_gateway ) && ( gateway_class > 0 ) )
											init_interface_gw( batman_if );

									}

									if ( ( gateway_class > 0 ) && ( routing_class > 0 ) ) {

										routing_class = 0;

										if ( curr_gateway != NULL )
											curr_gateway = NULL;

									}

								}

								dprintf( unix_client->sock, "EOD\n" );

							} else if ( buff[0] == 'r' ) {

								if ( status > 2 ) {

									tmp_unix_value = buff[2];

									if ( ( tmp_unix_value >= 0 ) && ( tmp_unix_value <= 3 ) ) {

										routing_class = tmp_unix_value;

										if ( curr_gateway != NULL )
											curr_gateway = NULL;

										if ( ( routing_class > 0 ) && ( gateway_class > 0 ) ) {

											gateway_class = 0;

											list_for_each( list_pos, &if_list ) {

												batman_if = list_entry( list_pos, struct batman_if, list );

												batman_if->out.gwflags = gateway_class;

											}

										}

									}

								}

								dprintf( unix_client->sock, "EOD\n" );

							} else if ( buff[0] == 'p' ) {

								if ( status > 2 ) {

									if ( inet_pton( AF_INET, buff + 2, &tmp_ip_holder ) > 0 ) {

										pref_gateway = tmp_ip_holder.s_addr;

										if ( curr_gateway != NULL )
											curr_gateway = NULL;

									} else {

										debug_output( 3, "Unix socket: rejected new preferred gw (%s) - invalid IP specified\n", buff + 2 );

									}

								}

								dprintf( unix_client->sock, "EOD\n" );

							}

						} else {

							if ( status < 0 )
								debug_output( 0, "Error - can't read unix message: %s\n", strerror(errno) );

							if ( unix_client->debug_level != 0 ) {

								prev_list_head = (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1];

								if ( pthread_mutex_lock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
									debug_output( 0, "Error - could not lock mutex (unix_listen => 3): %s \n", strerror( errno ) );

								list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[unix_client->debug_level - 1] ) {

									debug_level_info = list_entry( debug_pos, struct debug_level_info, list );

									if ( debug_level_info->fd == unix_client->sock ) {

										list_del( prev_list_head, debug_pos, debug_clients.fd_list[unix_client->debug_level - 1] );
										debug_clients.clients_num[unix_client->debug_level - 1]--;

										debugFree( debug_pos, 1202 );

										break;

									}

									prev_list_head = &debug_level_info->list;

								}

								if ( pthread_mutex_unlock( (pthread_mutex_t *)debug_clients.mutex[unix_client->debug_level - 1] ) != 0 )
									debug_output( 0, "Error - could not unlock mutex (unix_listen => 3): %s \n", strerror( errno ) );

							}

							debug_output( 3, "Unix client closed connection ...\n" );

							FD_CLR(unix_client->sock, &wait_sockets);
							close( unix_client->sock );

							list_del( prev_list_head_unix, list_pos, &unix_if.client_list );
							debugFree( list_pos, 1203 );

						}

					} else {

						if ( unix_client->sock > max_sock )
							max_sock = unix_client->sock;

					}

					prev_list_head_unix = &unix_client->list;

				}

			}

		} else if ( ( res < 0 ) && ( errno != EINTR ) ) {

			debug_output( 0, "Error - can't select: %s\n", strerror(errno) );
			break;

		}

	}

	list_for_each_safe( list_pos, unix_pos_tmp, &unix_if.client_list ) {

		unix_client = list_entry( list_pos, struct unix_client, list );

		if ( unix_client->debug_level != 0 ) {

			list_for_each_safe( debug_pos, debug_pos_tmp, (struct list_head *)debug_clients.fd_list[(int)unix_client->debug_level - '1'] ) {

				debug_level_info = list_entry(debug_pos, struct debug_level_info, list);

				if ( debug_level_info->fd == unix_client->sock ) {

					list_del( (struct list_head *)debug_clients.fd_list[(int)unix_client->debug_level - '1'], debug_pos, debug_clients.fd_list[(int)unix_client->debug_level - '1'] );
					debug_clients.clients_num[(int)unix_client->debug_level - '1']--;

					debugFree( debug_pos, 1204 );

					break;

				}

			}

		}

		list_del( (struct list_head *)&unix_if.client_list, list_pos, &unix_if.client_list );
		debugFree( list_pos, 1205 );

	}

	return NULL;

}

