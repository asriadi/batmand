/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Marek Lindner
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
#include <sys/times.h>

#include "os.h"
#include "batman-adv.h"
#include "allocate.h"




#define BAT_LOGO_PRINT(x,y,z) printf( "\x1B[%i;%iH%c", y + 1, x, z )                      /* write char 'z' into column 'x', row 'y' */
#define BAT_LOGO_END(x,y) printf("\x1B[8;0H");fflush(NULL);bat_wait( x, y );              /* end of current picture */


extern struct vis_if vis_if;

static clock_t start_time;
static float system_tick;



uint32_t get_time( void ) {

	return (uint32_t)( ( (float)( times(NULL) - start_time ) * 1000 ) / system_tick );

}



/* batman animation */
void sym_print( char x, char y, char *z ) {

	char i = 0, Z;

	do{

		BAT_LOGO_PRINT( 25 + (int)x + (int)i, (int)y, z[(int)i] );

		switch ( z[(int)i] ) {

			case 92:
				Z = 47;   // "\" --> "/"
				break;

			case 47:
				Z = 92;   // "/" --> "\"
				break;

			case 41:
				Z = 40;   // ")" --> "("
				break;

			default:
				Z = z[(int)i];
				break;

		}

		BAT_LOGO_PRINT( 24 - (int)x - (int)i, (int)y, Z );
		i++;

	} while( z[(int)i - 1] );

	return;

}

int8_t send_udp_packet( unsigned char *packet_buff, int32_t packet_buff_len, struct sockaddr_in *broad, int32_t send_sock )
{

	if ( sendto( send_sock, packet_buff, packet_buff_len, 0, (struct sockaddr *)broad, sizeof(struct sockaddr_in) ) < 0 ) {
		if ( errno == 1 ) {
			debug_output( 0, "Error - can't send udp packet: %s.\nDoes your firewall allow outgoing packets on port %i ?\n", strerror(errno), ntohs( broad->sin_port ) );
		} else {
			debug_output( 0, "Error - can't send udp packet: %s.\n", strerror(errno) );
		}
		return -1;
	}
	return 0;
}




void bat_wait( int32_t T, int32_t t ) {

	struct timeval time;

	time.tv_sec = T;
	time.tv_usec = ( t * 10000 );

	select( 0, NULL, NULL, NULL, &time );

	return;

}



void print_animation( void ) {

	system( "clear" );
	BAT_LOGO_END( 0, 50 );

	sym_print( 0, 3, "." );
	BAT_LOGO_END( 1, 0 );

	sym_print( 0, 4, "v" );
	BAT_LOGO_END( 0, 20 );

	sym_print( 1, 3, "^" );
	BAT_LOGO_END( 0, 20 );

	sym_print( 1, 4, "/" );
	sym_print( 0, 5, "/" );
	BAT_LOGO_END( 0, 10 );

	sym_print( 2, 3, "\\" );
	sym_print( 2, 5, "/" );
	sym_print( 0, 6, ")/" );
	BAT_LOGO_END( 0, 10 );

	sym_print( 2, 3, "_\\" );
	sym_print( 4, 4, ")" );
	sym_print( 2, 5, " /" );
	sym_print( 0, 6, " )/" );
	BAT_LOGO_END( 0, 10 );

	sym_print( 4, 2, "'\\" );
	sym_print( 2, 3, "__/ \\" );
	sym_print( 4, 4, "   )" );
	sym_print( 1, 5, "   " );
	sym_print( 2, 6, "   /" );
	sym_print( 3, 7, "\\" );
	BAT_LOGO_END( 0, 15 );

	sym_print( 6, 3, " \\" );
	sym_print( 3, 4, "_ \\   \\" );
	sym_print( 10, 5, "\\" );
	sym_print( 1, 6, "          \\" );
	sym_print( 3, 7, " " );
	BAT_LOGO_END( 0, 20 );

	sym_print( 7, 1, "____________" );
	sym_print( 7, 3, " _   \\" );
	sym_print( 3, 4, "_      " );
	sym_print( 10, 5, " " );
	sym_print( 11, 6, " " );
	BAT_LOGO_END( 0, 25 );

	sym_print( 3, 1, "____________    " );
	sym_print( 1, 2, "'|\\   \\" );
	sym_print( 2, 3, " /         " );
	sym_print( 3, 4, " " );
	BAT_LOGO_END( 0, 25 );

	sym_print( 3, 1, "    ____________" );
	sym_print( 1, 2, "    '\\   " );
	sym_print( 2, 3, "__/  _   \\" );
	sym_print( 3, 4, "_" );
	BAT_LOGO_END( 0, 35 );

	sym_print( 7, 1, "            " );
	sym_print( 7, 3, " \\   " );
	sym_print( 5, 4, "\\    \\" );
	sym_print( 11, 5, "\\" );
	sym_print( 12, 6, "\\" );
	BAT_LOGO_END( 0 ,35 );

}

int addr_to_string(char *buff, uint8_t *hw_addr)
{
	return sprintf(buff, "%02x:%02x:%02x:%02x:%02x:%02x", hw_addr[0], hw_addr[1], hw_addr[2], hw_addr[3], hw_addr[4], hw_addr[5]);
}

static char static_addr_buf[30];
char *addr_to_string_static(uint8_t *hw_addr)
{
	sprintf(static_addr_buf, "%02x:%02x:%02x:%02x:%02x:%02x", hw_addr[0], hw_addr[1], hw_addr[2], hw_addr[3], hw_addr[4], hw_addr[5]);
	return(static_addr_buf);
}



int32_t rand_num( int32_t limit ) {

	return ( limit == 0 ? 0 : rand() % limit );

}



int main( int argc, char *argv[] ) {

	int8_t res;
	uint8_t i;


	/* check if user is root */
	if ( ( getuid() ) || ( getgid() ) ) {

		fprintf( stderr, "Error - you must be root to run batmand-adv !\n" );
		exit(EXIT_FAILURE);

	}


	INIT_LIST_HEAD_FIRST( forw_list );
	INIT_LIST_HEAD_FIRST( gw_list );
	INIT_LIST_HEAD_FIRST( if_list );


	for ( i = 0; i < 255; i++ ) {
		unix_packet[i] = NULL;
	}

	start_time = times(NULL);
	system_tick = (float)sysconf(_SC_CLK_TCK);


	apply_init_args( argc, argv );


	res = batman();

	restore_defaults();
	cleanup();
	checkLeak();

	return res;

}
