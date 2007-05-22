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

#include "battool.h"
#include "functions.h"

#define VERSION "0.1 alpha"

void ping_usage() {
	printf("Battool module ping\n");
	printf("Usage: battool ping [options] destination\n");
	printf("\t-c count\n");
	printf("\t-h help\n");
	printf("\t-i interval in seconds\n");
	printf("\t-v version\n");
	printf("destination: 00:0a:00:93:d0:cf can write :a::93:d0:cf\n");
	return;
}

int ping_main( int argc, char **argv ) {

	char *send_buff, *rec_buff;
	char begin[] = "p:";
	int sbsize,rbsize;
	uint8_t res, mac[6];
	int32_t recv_buff_len;
	struct icmp_packet icmp_packet;
	struct unix_if unix_if;
	struct timeval timeout,start,end;
	double time_delta;

	fd_set read_socket;
 	unsigned long sec,usec;
	
	int trans=0, recv=0, avg_count=0;
	float min= -1.0, avg=0.0, max=0.0;

	int optchar;
	uint8_t found_args = 1;
	int loop_count = -1;
	int loop_interval = 0;
	char *mac_string;

	while ( ( optchar = getopt ( argc, argv, "hvc:i:" ) ) != -1 ) {
		switch( optchar ) {
			case 'h':
				ping_usage();
				exit(EXIT_SUCCESS);
				break;
			case 'v':
				printf("Battool module ping %s\n", VERSION);
				exit(EXIT_SUCCESS);
				break;
			case 'c':
				loop_count = strtol(optarg, NULL , 10);
				if( loop_count < 1 ) loop_count = -1;
				found_args+=2;
				break;
			case 'i':
				loop_interval = strtol(optarg, NULL , 10);
				found_args+=2;
				break;
			default:
				ping_usage();
				exit(EXIT_FAILURE);
		}
	}

	if ( argc <= found_args ) {
		ping_usage();
		exit(EXIT_FAILURE);
	}
	
	mac_string = argv[found_args];

	
	if( convert_mac( mac_string, mac ) < 1 ) {
		printf("The mac address was not correct.\n");
		exit(EXIT_FAILURE);
	}

	sbsize = sizeof( struct icmp_packet ) + 2;
	rbsize = sizeof( struct icmp_packet );

	unix_if.unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );

	unix_if.addr.sun_family = AF_LOCAL;
	strcpy( unix_if.addr.sun_path, UNIX_PATH );

	
	if ( connect ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof(struct sockaddr_un) ) < 0 ) {

		printf( "Error - can't connect to unix socket '%s': %s ! Is batmand running on this host ?\n", UNIX_PATH, strerror(errno) );
		close( unix_if.unix_sock );
		exit(EXIT_FAILURE);

	}

	send_buff = malloc( sbsize );
	memset(send_buff, '\0', sbsize );
	rec_buff = malloc( rbsize );
	memset(rec_buff, '\0', rbsize );


	memcpy( &icmp_packet.dst,mac,6 );
	icmp_packet.packet_type = 1;
	icmp_packet.msg_type = ECHO_REQUEST;
	icmp_packet.ttl = 50;
	icmp_packet.seqno = 0;

	memcpy( send_buff, begin, 2 );
	printf("PING %s\n", mac_string );
	while( !Stop && loop_count != 0 ) {
		if( loop_count > 0 )
			loop_count--;

		icmp_packet.seqno++;
		memcpy( send_buff+2, &icmp_packet, rbsize );
		
		if ( write( unix_if.unix_sock, send_buff, sbsize ) < 0 ) {
			printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
			close( unix_if.unix_sock );
			free( send_buff);
			exit(EXIT_FAILURE);
		}

		gettimeofday(&start,(struct timezone*)0);
	 	trans++;

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
				if( recv_buff_len == rbsize && ((struct icmp_packet *)rec_buff)->msg_type == ECHO_REPLY )
				{
					
					sec = (unsigned long)end.tv_sec - start.tv_sec;
					if(sec>end.tv_sec) {
						sec += 1000000000UL;
						--sec;
					}
				
					usec = (unsigned long)end.tv_usec - start.tv_usec;
					if(usec>end.tv_usec) {
						usec += 1000000000UL;
						--usec;
					}

					if ( sec > 0 )
						usec = 1000000 * sec + usec;
			
					time_delta = (double)usec/1000;
					printf("%d bytes from %s icmp_seq=%d ttl=%d time=%.2f ms\n",recv_buff_len, mac_string, ((struct icmp_packet *)rec_buff)->seqno,((struct icmp_packet *)rec_buff)->ttl, time_delta );

					if( time_delta < min || min == -1.0 ) min = time_delta;
					if( time_delta > max ) max = time_delta;
					avg += time_delta;
					avg_count++;
					recv++;
				} else {
		
					if( ( (struct icmp_packet *)rec_buff)->msg_type == DESTINATION_UNREACHABLE )
						printf("Host %s is unreachable\n", mac_string );
					else
						printf("%d\n", ( (struct icmp_packet *)rec_buff)->msg_type );
				}
			}

		} else if ( res == 0 ) {
			printf("Host %s timeout\n",mac_string );
		}
		sleep( loop_interval?loop_interval:1 );
	}
	printf("--- %s ping statistic ---\n",mac_string );
	printf("%d packets transmitted, %d received, %d%c packet loss\n", trans, recv, ( (trans - recv) * 100 / trans ),'%');
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min < 0.0 ? 0.000 : min, avg_count?(avg / avg_count):0.000 ,max, max - ( min < 0.0 ? 0.0:min) );
	return 1;
}
