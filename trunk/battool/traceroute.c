/* Copyright (C) 2007 B.A.T.M.A.N. contributors:
 * Andreas Langer <a.langer@q-dsl.de>
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

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include "battool.h"
#include "functions.h"

#define VERSION "0.1 alpha"



void traceroute_usage() {
	printf("Battool module traceroute\n");
	printf("Usage: battool traceroute|t [options] destination\n");
	printf("\t-h help\n");
	printf("destination:\n\t00:0a:00:93:d0:cf can write :a::93:d0:cf\n\tor use bat-hosts file\n");
	return;
}

int traceroute_main( int argc, char **argv, struct hosts *hosts ) {

	char *send_buff,							/* buffer to send */
			*rec_buff,								/* receive buffer */
			*mac_string = NULL,				/* string of mac address */
			*host_name = NULL,				/* name of host */
			return_mac[18],
			begin[] = "p:";						/* send buffer need two chars at begin for batman-advance socket*/

	int sbsize,										/* size of send buffer */
		rbsize,										/* size of receive buffer */
		optchar,										/* ascii code of programm option */
		i,
		count=0;

	uint8_t res,
			stop = 0,
			found_args = 1,
			mac[6];

	int32_t recv_buff_len;

	double time_delta = 0.0;
	
	struct icmp_packet icmp_packet;
	struct unix_if unix_if;
	struct timeval start,
					end;

	struct timeval timeout;
	struct hosts *tmp_hosts;

	fd_set read_socket;

	while ( ( optchar = getopt ( argc, argv, "h" ) ) != -1 ) {
		switch( optchar ) {
			case 'h':
				traceroute_usage();
				exit(EXIT_SUCCESS);
				break;
			default:
				traceroute_usage();
				exit(EXIT_FAILURE);
		}
	}

	if ( argc <= found_args ) {
		traceroute_usage();
		exit(EXIT_FAILURE);
	}

	find_mac_address( hosts , tmp_hosts, argv[found_args], mac_string, name, mac );

	if( mac_string  == NULL )
		mac_string = argv[found_args];

	if( convert_mac( mac_string, mac ) < 1 ) {
		printf("The mac address was not correct.\n");
		exit(EXIT_FAILURE);
	}

	unix_if.unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );

	unix_if.addr.sun_family = AF_LOCAL;
	strcpy( unix_if.addr.sun_path, UNIX_PATH );

	
	if ( connect ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof(struct sockaddr_un) ) < 0 ) {

		printf( "Error - can't connect to unix socket '%s': %s ! Is batmand running on this host ?\n", UNIX_PATH, strerror(errno) );
		close( unix_if.unix_sock );
		exit(EXIT_FAILURE);

	}

	sbsize = sizeof( struct icmp_packet ) + 2;
	rbsize = sizeof( struct icmp_packet );
	send_buff = malloc( sbsize );
	memset(send_buff, '\0', sbsize );
	rec_buff = malloc( rbsize );
	memset(rec_buff, '\0', rbsize );
	
	return_mac[0] = '\0';

	memcpy( &icmp_packet.dst,mac,6 );
	icmp_packet.packet_type = 1;
	icmp_packet.msg_type = ECHO_REQUEST;
	icmp_packet.ttl = 0;
	icmp_packet.seqno = 0;
	memcpy( send_buff, begin, 2 );

	for( ; !stop && count < 50; count++ ) {
		icmp_packet.ttl++;
		icmp_packet.seqno++;
		memcpy( send_buff+2, &icmp_packet, rbsize );


		for( i=0; i<3 && !stop; i++ )
		{

			if ( write( unix_if.unix_sock, send_buff, sbsize ) < 0 ) {
				printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
				close( unix_if.unix_sock );
				free( send_buff);
				exit(EXIT_FAILURE);
			}

			gettimeofday(&start,(struct timezone*)0);

			timeout.tv_sec = 2;
			timeout.tv_usec = 0;

			FD_ZERO(&read_socket);
			FD_SET( unix_if.unix_sock, &read_socket );
	 
			res = select( unix_if.unix_sock + 1, &read_socket, NULL, NULL, &timeout );

			if( res > 0 )
			{
				if ( ( recv_buff_len = read( unix_if.unix_sock, rec_buff, rbsize ) ) > 0 )
				{
					gettimeofday(&end,(struct timezone*)0);

					if( recv_buff_len == rbsize && ( ((struct icmp_packet *)rec_buff)->msg_type == ECHO_REPLY || ((struct icmp_packet *)rec_buff)->msg_type == TTL_EXCEEDED ) ) {

						time_delta = time_diff( &start, &end );

						if( i == 0) {
							convert_mac_i( ((struct icmp_packet *)rec_buff)->orig, return_mac );
							find_mac_address( hosts, tmp_hosts, return_mac, host_name, mac, name );

							if(host_name == NULL )
								printf("%d: %s %.3f ms", ((struct icmp_packet *)rec_buff)->seqno, return_mac, time_delta );
							else
								printf("%d: %s (%s) %.3f ms", ((struct icmp_packet *)rec_buff)->seqno, return_mac,host_name, time_delta );
						} else {
							printf("  %.3f ms", time_delta );
						}

					} else if( ((struct icmp_packet *)rec_buff)->msg_type == DESTINATION_UNREACHABLE ) {
						printf("Host unreachable\n");
						stop=1;
					} else {
						printf("undefined message type\n");
						stop=1;
					}
				}
			} else {
				printf(" * ");
				fflush(stdout);
				i--;
				continue;
			}
		}
		printf("\n");
		if( ((struct icmp_packet *)rec_buff)->msg_type == ECHO_REPLY )
			stop = 1;

	}
	exit(EXIT_SUCCESS);
}
