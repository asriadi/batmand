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

#include "os.h"
#include "batman-adv.h"
#include "list.h"
#include "allocate.h"




#define BAT_LOGO_PRINT(x,y,z) printf( "\x1B[%i;%iH%c", y + 1, x, z )                      /* write char 'z' into column 'x', row 'y' */
#define BAT_LOGO_END(x,y) printf("\x1B[8;0H");fflush(NULL);bat_wait( x, y );              /* end of current picture */


extern struct vis_if vis_if;

static struct timeval start_time;
static int8_t stop;


static void get_time_internal( struct timeval *tv ) {

	int32_t sec, usec;

	gettimeofday( tv, NULL );

	sec = tv->tv_sec - start_time.tv_sec;
	usec = tv->tv_usec - start_time.tv_usec;

	if ( usec < 0 ) {
		sec--;
		usec += 1000000;
	}

	tv->tv_sec = sec;
	tv->tv_usec = usec;

}

uint32_t get_time( void ) {

	struct timeval tv;

	get_time_internal(&tv);

	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
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



int8_t is_aborted() {

	return stop != 0;

}

// #include <netinet/ether.h>              /* ether_ntoa() */

char *addr_to_string( uint8_t *hw_addr ) {

	struct ether_addr *ether_addr;

	memcpy( ether_addr->ether_addr_octet, hw_addr, 6 );

	return ether_ntoa( ether_addr );

}



int32_t rand_num( int32_t limit ) {

	return ( limit == 0 ? 0 : rand() % limit );

}



static void handler( int32_t sig ) {

	stop = 1;

}


int main( int argc, char *argv[] ) {

	int8_t res;
	stop = 0;


	/* check if user is root */
	if ( ( getuid() ) || ( getgid() ) ) {

		fprintf( stderr, "Error - you must be root to run batmand-adv !\n" );
		exit(EXIT_FAILURE);

	}

	apply_init_args( argc, argv );


	signal( SIGINT, handler );
	signal( SIGTERM, handler );

	gettimeofday( &start_time, NULL );
	srand( getpid() );


	res = batman();


	close_all_sockets();
	cleanup();
	checkLeak();
	return res;

}
