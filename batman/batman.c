/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann,
 * Felix Fietkau, Marek Lindner
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



#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>


#include "os.h"
#include "batman.h"
#include "originator.h"
#include "schedule.h"



uint8_t debug_level = 0;


#ifdef PROFILE_DATA

uint8_t debug_level_max = 5;

#elif DEBUG_MALLOC && MEMORY_USAGE

uint8_t debug_level_max = 5;

#else

uint8_t debug_level_max = 4;

#endif


char *prog_name;


/*
 * "-g" is the command line switch for the gateway class,
 */

uint8_t gateway_class = 0;

/* "-r" is the command line switch for the routing class,
 * 0 set no default route
 * 1 use fast internet connection
 * 2 use stable internet connection
 * 3 use use best statistic (olsr style)
 * this option is used to set the routing behaviour
 */

uint8_t routing_class = 0;


int16_t originator_interval = 1000;   /* originator message interval in miliseconds */

struct gw_node *curr_gateway = NULL;
pthread_t curr_gateway_thread_id = 0;

uint32_t pref_gateway = 0;

char *policy_routing_script = NULL;
int policy_routing_pipe = 0;
pid_t policy_routing_script_pid;

unsigned char *hna_buff = NULL;

uint8_t num_hna = 0;

uint8_t found_ifs = 0;
uint8_t active_ifs = 0;
int32_t receive_max_sock = 0;
fd_set receive_wait_set;

uint8_t unix_client = 0;
uint8_t log_facility_active = 0;

struct hashtable_t *orig_hash;

struct list_head_first forw_list;
struct list_head_first gw_list;
struct list_head_first if_list;
struct list_head_first hna_list;
struct list_head_first hna_del_list;
struct list_head_first hna_chg_list;

struct vis_if vis_if;
struct unix_if unix_if;
struct debug_clients debug_clients;

pthread_mutex_t hna_chg_list_mutex;

unsigned char *vis_packet = NULL;
uint16_t vis_packet_size = 0;

uint64_t batman_clock_ticks = 0;

uint8_t hop_penalty = TQ_HOP_PENALTY;
uint8_t asym_power = TQ_ASYM_POWER;
uint32_t purge_timeout = PURGE_TIMEOUT;
uint8_t minimum_send = TQ_LOCAL_BIDRECT_SEND_MINIMUM;
uint8_t minimum_recv = TQ_LOCAL_BIDRECT_RECV_MINIMUM;
uint8_t global_win_size = TQ_GLOBAL_WINDOW_SIZE;
uint8_t local_win_size = TQ_LOCAL_WINDOW_SIZE;
uint8_t num_words = (TQ_LOCAL_WINDOW_SIZE / WORD_BIT_SIZE);



void usage( void )
{

        fprintf( stderr, "Usage: batman [options] interface [interface interface]\n" );
        fprintf( stderr, "       -a add announced network(s)\n" );
        fprintf( stderr, "       -A delete announced network(s)\n" );
        fprintf( stderr, "       -b run connection in batch mode\n" );
        fprintf( stderr, "       -c connect via unix socket\n" );
        fprintf( stderr, "       -d debug level\n" );
        fprintf( stderr, "       -g gateway class\n" );
        fprintf( stderr, "       -h this help\n" );
        fprintf( stderr, "       -H verbose help\n" );
        fprintf( stderr, "       -i internal options output\n" );
        fprintf( stderr, "       -o originator interval in ms\n" );
        fprintf( stderr, "       -p preferred gateway\n" );
        fprintf( stderr, "       -r routing class\n" );
        fprintf( stderr, "       -s visualization server\n" );
        fprintf( stderr, "       -v print version\n" );
        fprintf( stderr, "       --policy-routing-script\n" );

}



void verbose_usage( void )
{

        fprintf( stderr, "Usage: batman [options] interface [interface interface]\n\n" );
        fprintf( stderr, "       -a add announced network(s)\n" );
        fprintf( stderr, "          network/netmask is expected\n" );
        fprintf( stderr, "       -A delete announced network(s)\n" );
        fprintf( stderr, "          network/netmask is expected\n" );
        fprintf( stderr, "       -b run connection in batch mode\n" );
        fprintf( stderr, "       -c connect to running batmand via unix socket\n" );
        fprintf( stderr, "       -d debug level\n" );
        fprintf( stderr, "          default:         0 -> debug disabled\n" );
        fprintf( stderr, "          allowed values:  1 -> list neighbours\n" );
        fprintf( stderr, "                           2 -> list gateways\n" );
        fprintf( stderr, "                           3 -> observe batman\n" );
        fprintf( stderr, "                           4 -> observe batman (very verbose)\n\n" );

        if ( debug_level_max == 5  )
                fprintf( stderr, "                           5 -> memory debug / cpu usage\n\n" );

        fprintf( stderr, "       -g gateway class\n" );
        fprintf( stderr, "          default:         0 -> gateway disabled\n" );
        fprintf( stderr, "          allowed values:  download/upload in kbit/s (default) or mbit/s\n" );
        fprintf( stderr, "          note:            batmand will choose the nearest gateway class representing your speeds\n" );
        fprintf( stderr, "                           and therefore accepts all given values\n" );
        fprintf( stderr, "                           e.g. 5000\n" );
        fprintf( stderr, "                                5000kbit\n" );
        fprintf( stderr, "                                5mbit\n" );
        fprintf( stderr, "                                5mbit/1024\n" );
        fprintf( stderr, "                                5mbit/1024kbit\n" );
        fprintf( stderr, "                                5mbit/1mbit\n" );
        fprintf( stderr, "       -h shorter help\n" );
        fprintf( stderr, "       -H this help\n" );
        fprintf( stderr, "       -i gives information about all internal options\n" );
        fprintf( stderr, "       -o originator interval in ms\n" );
        fprintf( stderr, "          default: 1000, allowed values: >0\n\n" );
        fprintf( stderr, "       -p preferred gateway\n" );
        fprintf( stderr, "          default: none, allowed values: IP\n\n" );
        fprintf( stderr, "       -r routing class (only needed if gateway class = 0)\n" );
        fprintf( stderr, "          default:         0  -> set no default route\n" );
        fprintf( stderr, "          allowed values:  1  -> use fast internet connection (gw_flags * TQ)\n" );
        fprintf( stderr, "                           2  -> use stable internet connection (TQ)\n" );
        fprintf( stderr, "                           3  -> use fast-switch internet connection (TQ but switch as soon as a better gateway appears)\n\n" );
        fprintf( stderr, "                           XX -> use late-switch internet connection (TQ but switch as soon as a gateway appears which is XX TQ better)\n\n" );
        fprintf( stderr, "       -s visualization server\n" );
        fprintf( stderr, "          default: none, allowed values: IP\n\n" );
        fprintf( stderr, "       -v print version\n" );
        fprintf( stderr, "       --policy-routing-script send all routing table changes to the script\n" );

}



int is_batman_if( char *dev, struct batman_if **batman_if )
{

        struct list_head *if_pos;


        list_for_each( if_pos, &if_list ) {

                (*batman_if) = list_entry( if_pos, struct batman_if, list );

                if ( strcmp( (*batman_if)->dev, dev ) == 0 )
                        return 1;

        }

        return 0;

}



void add_del_hna( struct orig_node *orig_node, int8_t del )
{

        uint16_t hna_buff_count = 0;
        uint32_t hna, netmask;

        while ( ( hna_buff_count + 1 ) * 5 <= orig_node->hna_buff_len ) {

                memcpy( &hna, ( uint32_t *)&orig_node->hna_buff[ hna_buff_count * 5 ], 4 );
                netmask = ( uint32_t )orig_node->hna_buff[ ( hna_buff_count * 5 ) + 4 ];

                if ( ( netmask > 0 ) && ( netmask < 33 ) )
                        add_del_route( hna, netmask, orig_node->router->addr, orig_node->router->if_incoming->addr.sin_addr.s_addr, orig_node->batman_if->if_index, orig_node->batman_if->dev, BATMAN_RT_TABLE_NETWORKS, 0, del );

                hna_buff_count++;

        }

        if ( del ) {

                debugFree( orig_node->hna_buff, 1101 );
                orig_node->hna_buff_len = 0;

        }

}



void choose_gw()
{


        struct list_head *pos;
        struct gw_node *gw_node, *tmp_curr_gw = NULL;
        uint8_t max_gw_class = 0, max_tq = 0;
        uint32_t current_time, max_gw_factor = 0, tmp_gw_factor = 0;
        int download_speed, upload_speed;
        static char orig_str[ADDR_STR_LEN];
        prof_start( PROF_choose_gw );


        current_time = get_time_msec();
        if ((routing_class == 0) || ((int64_t)(get_time_msec64() - (originator_interval * local_win_size)) < 0)) {

                prof_stop( PROF_choose_gw );
                return;

        }

        if ( list_empty( &gw_list ) ) {

                if ( curr_gateway != NULL ) {

                        debug_output( 3, "Removing default route - no gateway in range\n" );

                        del_default_route();

                }

                prof_stop( PROF_choose_gw );
                return;

        }

        list_for_each( pos, &gw_list ) {

                gw_node = list_entry( pos, struct gw_node, list );

                /* ignore this gateway if recent connection attempts were unsuccessful */
                /* if it is our only gateway retry immediately */
                if ((gw_node != (struct gw_node *)gw_list.next) || (gw_node->list.next != (struct list_head *)&gw_list)) {

                        if ((int)(current_time - (gw_node->last_failure + 30000)) < 0)
                                continue;

                }

                if ( gw_node->orig_node->router == NULL )
                        continue;

                if ( gw_node->deleted )
                        continue;

                switch ( routing_class ) {

                case 1: /* fast connection */
                        get_gw_speeds( gw_node->orig_node->gwflags, &download_speed, &upload_speed );

                        if (((tmp_gw_factor = (((gw_node->orig_node->router->tq_avg * 100 ) / local_win_size) *
                                               ((gw_node->orig_node->router->tq_avg * 100) / local_win_size) *
                                               (download_speed / 64))) > max_gw_factor) ||
                                        ((tmp_gw_factor == max_gw_factor) && (gw_node->orig_node->router->tq_avg > max_tq)))
                                tmp_curr_gw = gw_node;
                        break;

                default: /* stable connection (use best statistic) */
                        /* fast-switch (use best statistic but change as soon as a better gateway appears) */
                        /* late-switch (use best statistic but change as soon as a better gateway appears which has $routing_class more tq points) */
                        if (gw_node->orig_node->router->tq_avg > max_tq)
                                tmp_curr_gw = gw_node;
                        break;

                }

                if ( gw_node->orig_node->gwflags > max_gw_class )
                        max_gw_class = gw_node->orig_node->gwflags;

                if (gw_node->orig_node->router->tq_avg > max_tq)
                        max_tq = gw_node->orig_node->router->tq_avg;

                if ( tmp_gw_factor > max_gw_factor )
                        max_gw_factor = tmp_gw_factor;

                if ( ( pref_gateway != 0 ) && ( pref_gateway == gw_node->orig_node->orig ) ) {

                        tmp_curr_gw = gw_node;

                        addr_to_string( tmp_curr_gw->orig_node->orig, orig_str, ADDR_STR_LEN );
                        debug_output( 3, "Preferred gateway found: %s (gw_flags: %i, tq: %i, gw_product: %i)\n", orig_str, gw_node->orig_node->gwflags, gw_node->orig_node->router->tq_avg, tmp_gw_factor );

                        break;

                }

        }


        if ( curr_gateway != tmp_curr_gw ) {

                if ( curr_gateway != NULL ) {

                        if ( tmp_curr_gw != NULL )
                                debug_output( 3, "Removing default route - better gateway found\n" );
                        else
                                debug_output( 3, "Removing default route - no gateway in range\n" );

                        del_default_route();

                }

                curr_gateway = tmp_curr_gw;

                /* may be the last gateway is now gone */
                if ( ( curr_gateway != NULL ) && ( !is_aborted() ) ) {

                        addr_to_string( curr_gateway->orig_node->orig, orig_str, ADDR_STR_LEN );
                        debug_output( 3, "Adding default route to %s (gw_flags: %i, tq: %i, gw_product: %i)\n", orig_str, max_gw_class, max_tq, max_gw_factor );

                        add_default_route();

                }

        }

        prof_stop( PROF_choose_gw );

}



void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node, unsigned char *hna_recv_buff, int16_t hna_buff_len )
{

        static char orig_str[ADDR_STR_LEN], next_str[ADDR_STR_LEN];
        prof_start( PROF_update_routes );


        debug_output( 4, "update_routes() \n" );


        if ( ( orig_node != NULL ) && ( orig_node->router != neigh_node ) ) {

                if ( ( orig_node != NULL ) && ( neigh_node != NULL ) ) {
                        addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
                        addr_to_string( neigh_node->addr, next_str, ADDR_STR_LEN );
                        debug_output( 4, "Route to %s via %s\n", orig_str, next_str );
                }

                /* route altered or deleted */
                if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( neigh_node == NULL ) ) {

                        if ( neigh_node == NULL ) {
                                debug_output( 4, "Deleting previous route\n" );
                        } else {
                                debug_output( 4, "Route changed\n" );
                        }

                        /* remove old announced network(s) */
                        if ( orig_node->hna_buff_len > 0 )
                                add_del_hna( orig_node, 1 );

                        add_del_route( orig_node->orig, 32, orig_node->router->addr, 0, orig_node->batman_if->if_index, orig_node->batman_if->dev, BATMAN_RT_TABLE_HOSTS, 0, 1 );

                }

                /* route altered or new route added */
                if ( ( ( orig_node->router != NULL ) && ( neigh_node != NULL ) ) || ( orig_node->router == NULL ) ) {

                        if ( orig_node->router == NULL ) {
                                debug_output( 4, "Adding new route\n" );
                        } else {
                                debug_output( 4, "Route changed\n" );
                        }

                        add_del_route( orig_node->orig, 32, neigh_node->addr, neigh_node->if_incoming->addr.sin_addr.s_addr, neigh_node->if_incoming->if_index, neigh_node->if_incoming->dev, BATMAN_RT_TABLE_HOSTS, 0, 0 );

                        orig_node->batman_if = neigh_node->if_incoming;
                        orig_node->router = neigh_node;

                        /* add new announced network(s) */
                        if ( ( hna_buff_len > 0 ) && ( hna_recv_buff != NULL ) ) {

                                orig_node->hna_buff = debugMalloc( hna_buff_len, 101 );
                                orig_node->hna_buff_len = hna_buff_len;

                                memmove( orig_node->hna_buff, hna_recv_buff, hna_buff_len );

                                add_del_hna( orig_node, 0 );

                        }

                }

                orig_node->router = neigh_node;

        } else if ( orig_node != NULL ) {

                /* may be just HNA changed */
                if ( ( hna_buff_len != orig_node->hna_buff_len ) || ( ( hna_buff_len > 0 ) && ( orig_node->hna_buff_len > 0 ) && ( memcmp( orig_node->hna_buff, hna_recv_buff, hna_buff_len ) != 0 ) ) ) {

                        if ( orig_node->hna_buff_len > 0 )
                                add_del_hna( orig_node, 1 );

                        if ( ( hna_buff_len > 0 ) && ( hna_recv_buff != NULL ) ) {

                                orig_node->hna_buff = debugMalloc( hna_buff_len, 102 );
                                orig_node->hna_buff_len = hna_buff_len;

                                memcpy( orig_node->hna_buff, hna_recv_buff, hna_buff_len );

                                add_del_hna( orig_node, 0 );

                        }

                }

        }

        prof_stop( PROF_update_routes );

}



void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags, uint16_t gw_port )
{

        struct list_head *gw_pos, *gw_pos_tmp;
        struct gw_node *gw_node;
        static char orig_str[ADDR_STR_LEN];
        int download_speed, upload_speed;
        prof_start( PROF_update_gw_list );

        list_for_each_safe( gw_pos, gw_pos_tmp, &gw_list ) {

                gw_node = list_entry(gw_pos, struct gw_node, list);

                if ( gw_node->orig_node == orig_node ) {

                        addr_to_string( gw_node->orig_node->orig, orig_str, ADDR_STR_LEN );
                        debug_output( 3, "Gateway class of originator %s changed from %i to %i\n", orig_str, gw_node->orig_node->gwflags, new_gwflags );

                        if ( new_gwflags == 0 ) {

                                gw_node->deleted = get_time_msec();
                                gw_node->orig_node->gwflags = new_gwflags;
                                debug_output( 3, "Gateway %s removed from gateway list\n", orig_str );

                                if (gw_node == curr_gateway)
                                        choose_gw();

                        } else {

                                gw_node->deleted = 0;
                                gw_node->orig_node->gwflags = new_gwflags;

                        }

                        prof_stop( PROF_update_gw_list );
                        return;

                }

        }

        addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
        get_gw_speeds( new_gwflags, &download_speed, &upload_speed );

        debug_output( 3, "Found new gateway %s -> class: %i - %i%s/%i%s\n", orig_str, new_gwflags, ( download_speed > 2048 ? download_speed / 1024 : download_speed ), ( download_speed > 2048 ? "MBit" : "KBit" ), ( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ), ( upload_speed > 2048 ? "MBit" : "KBit" ) );

        gw_node = debugMalloc(sizeof(struct gw_node), 103);
        memset(gw_node, 0, sizeof(struct gw_node));
        INIT_LIST_HEAD( &gw_node->list );

        gw_node->orig_node = orig_node;
        gw_node->gw_port = gw_port;
        gw_node->last_failure = get_time_msec();

        list_add_tail( &gw_node->list, &gw_list );

        prof_stop( PROF_update_gw_list );

}



/* returns the up and downspeeds in kbit, calculated from the class */
void get_gw_speeds( unsigned char gw_class, int *down, int *up )
{

        char sbit    = (gw_class&0x80)>>7;
        char dpart   = (gw_class&0x7C)>>3;
        char upart   = (gw_class&0x07);

        *down= 32*(sbit+2)*(1<<dpart);
        *up=   ((upart+1)*(*down))/8;

}



/* calculates the gateway class from kbit */
unsigned char get_gw_class( int down, int up )
{

        int mdown = 0, tdown, tup, difference = 0x0FFFFFFF;
        unsigned char gw_class = 0, sbit, part;


        /* test all downspeeds */
        for ( sbit = 0; sbit < 2; sbit++ ) {

                for ( part = 0; part < 16; part++ ) {

                        tdown = 32 * ( sbit + 2 ) * ( 1<<part );

                        if ( abs( tdown - down ) < difference ) {

                                gw_class = ( sbit<<7 ) + ( part<<3 );
                                difference = abs( tdown - down );
                                mdown = tdown;

                        }

                }

        }

        /* test all upspeeds */
        difference = 0x0FFFFFFF;

        for ( part = 0; part < 8; part++ ) {

                tup = ( ( part+1 ) * ( mdown ) ) / 8;

                if ( abs( tup - up ) < difference ) {

                        gw_class = ( gw_class&0xF8 ) | part;
                        difference = abs( tup - up );

                }

        }

        return gw_class;

}

int isDuplicate( struct orig_node *orig_node, uint16_t seqno )
{

        struct list_head *neigh_pos;
        struct neigh_node *neigh_node;

        prof_start( PROF_is_duplicate );

        list_for_each( neigh_pos, &orig_node->neigh_list ) {

                neigh_node = list_entry( neigh_pos, struct neigh_node, list );

                if ( get_bit_status( neigh_node->real_bits, orig_node->last_real_seqno, seqno ) ) {

                        prof_stop( PROF_is_duplicate );
                        return 1;

                }

        }

        prof_stop( PROF_is_duplicate );

        return 0;

}



int isBntog( uint32_t neigh, struct orig_node *orig_tog_node )
{

        if ( ( orig_tog_node->router != NULL ) && ( orig_tog_node->router->addr == neigh ) )
                return 1;

        return 0;

}

/* don't use math lib */
float my_powf(float x, int y)
{
        int i;
        float ret;
        for (ret=1, i = 0; i< y; i++)
                ret *= x;
        return(ret);
}



int isBidirectionalNeigh(struct orig_node *orig_node, struct orig_node *orig_neigh_node, struct bat_packet *in, uint32_t recv_time, struct batman_if *if_incoming, uint8_t is_duplicate)
{

        struct list_head *list_pos;
        struct neigh_node *neigh_node = NULL, *tmp_neigh_node = NULL;
        uint8_t total_count;
        static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];
        float packet_loss;


        if ( orig_node == orig_neigh_node ) {

                list_for_each( list_pos, &orig_node->neigh_list ) {

                        tmp_neigh_node = list_entry( list_pos, struct neigh_node, list );

                        if ( ( tmp_neigh_node->addr == orig_neigh_node->orig ) && ( tmp_neigh_node->if_incoming == if_incoming ) )
                                neigh_node = tmp_neigh_node;

                }

                if ( neigh_node == NULL )
                        neigh_node = create_neighbor(orig_node, orig_neigh_node, orig_neigh_node->orig, if_incoming);

                neigh_node->last_valid = recv_time;

        } else {

                /* find packet count of corresponding one hop neighbor */
                list_for_each( list_pos, &orig_neigh_node->neigh_list ) {

                        tmp_neigh_node = list_entry( list_pos, struct neigh_node, list );

                        if ( ( tmp_neigh_node->addr == orig_neigh_node->orig ) && ( tmp_neigh_node->if_incoming == if_incoming ) )
                                neigh_node = tmp_neigh_node;

                }

                if ( neigh_node == NULL )
                        neigh_node = create_neighbor(orig_neigh_node, orig_neigh_node, orig_neigh_node->orig, if_incoming);

        }

        orig_node->last_valid = recv_time;

        /* pay attention to not get a value bigger than 100 % */
        total_count = ( orig_neigh_node->bcast_own_sum[if_incoming->if_num] > neigh_node->real_packet_count ? neigh_node->real_packet_count : orig_neigh_node->bcast_own_sum[if_incoming->if_num] );

        /* if we have too few packets (too less data) we set tq_own to zero */
        /* if we receive too few packets it is not considered bidirectional */
        if ( ( total_count < minimum_send ) || ( neigh_node->real_packet_count < minimum_recv ) ) {

                orig_neigh_node->tq_own = 0;

        } else {

                /* neigh_node->real_packet_count is never zero as we only purge old information when getting new information */
                orig_neigh_node->tq_own = ((float) total_count) / ((float)neigh_node->real_packet_count);

        }

        /* 1 - ((1-x)** asym_power) */
        /* this does affect the nearly-symmetric links only a little,
         * but punishes asymetric links more. */
        /* this will give a value between 0 and TQ_MAX_VALUE */
        packet_loss = ((float) (local_win_size - neigh_node->real_packet_count)) / ((float) local_win_size );
        orig_neigh_node->tq_asym_penalty = 1.0 - my_powf(packet_loss, asym_power);

        in->tq = ((float)in->tq * orig_neigh_node->tq_own * orig_neigh_node->tq_asym_penalty);

        addr_to_string( orig_node->orig, orig_str, ADDR_STR_LEN );
        addr_to_string( orig_neigh_node->orig, neigh_str, ADDR_STR_LEN );

        /*debug_output( 3, "bidirectional: orig = %-15s neigh = %-15s => own_bcast = %2i, real recv = %2i, local tq: %3i, asym_penalty: %3i, total tq: %3i \n",
        orig_str, neigh_str, total_count, neigh_node->real_packet_count, orig_neigh_node->tq_own, orig_neigh_node->tq_asym_penalty, in->tq );*/
        debug_output( 4, "bidirectional: orig = %-15s neigh = %-15s => own_bcast = %2i, real recv = %2i, local tq: %3i, asym_penalty: %3i, total tq: %3i \n",
                      orig_str, neigh_str, total_count, neigh_node->real_packet_count, (int)(orig_neigh_node->tq_own * TQ_MAX_VALUE), (int)(orig_neigh_node->tq_asym_penalty * TQ_MAX_VALUE), in->tq );

        /* if link has the minimum required transmission quality consider it bidirectional */
        if (in->tq >= TQ_TOTAL_BIDRECT_LIMIT)
                return 1;

        return 0;

}



void generate_vis_packet()
{

        struct hash_it_t *hashit = NULL;
        struct orig_node *orig_node;
        struct vis_data *vis_data;
        struct list_head *list_pos;
        struct batman_if *batman_if;
        struct hna_node *hna_node;


        if ( vis_packet != NULL ) {

                debugFree( vis_packet, 1102 );
                vis_packet = NULL;
                vis_packet_size = 0;

        }

        vis_packet_size = sizeof(struct vis_packet);
        vis_packet = debugMalloc( vis_packet_size, 104 );

        memcpy( &((struct vis_packet *)vis_packet)->sender_ip, (unsigned char *)&(((struct batman_if *)if_list.next)->addr.sin_addr.s_addr), 4 );

        ((struct vis_packet *)vis_packet)->version = VIS_COMPAT_VERSION;
        ((struct vis_packet *)vis_packet)->gw_class = gateway_class;
        ((struct vis_packet *)vis_packet)->tq_max = TQ_MAX_VALUE;

        /* neighbor list */
        while ( NULL != ( hashit = hash_iterate( orig_hash, hashit ) ) ) {

                orig_node = hashit->bucket->data;

                /* we interested in 1 hop neighbours only */
                if ( ( orig_node->router != NULL ) && ( orig_node->orig == orig_node->router->addr ) && ( orig_node->router->tq_avg > 0 ) ) {

                        vis_packet_size += sizeof(struct vis_data);

                        vis_packet = debugRealloc( vis_packet, vis_packet_size, 105 );

                        vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

                        memcpy( &vis_data->ip, (unsigned char *)&orig_node->orig, 4 );

                        vis_data->data = htons(orig_node->router->tq_avg);
                        vis_data->type = DATA_TYPE_NEIGH;

                }

        }

        /* secondary interfaces */
        if ( found_ifs > 1 ) {

                list_for_each( list_pos, &if_list ) {

                        batman_if = list_entry( list_pos, struct batman_if, list );

                        if ( ((struct vis_packet *)vis_packet)->sender_ip == batman_if->addr.sin_addr.s_addr )
                                continue;

                        vis_packet_size += sizeof(struct vis_data);

                        vis_packet = debugRealloc( vis_packet, vis_packet_size, 106 );

                        vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

                        memcpy( &vis_data->ip, (unsigned char *)&batman_if->addr.sin_addr.s_addr, 4 );

                        vis_data->data = 0;
                        vis_data->type = DATA_TYPE_SEC_IF;

                }

        }

        /* hna announcements */
        if ( num_hna > 0 ) {

                list_for_each( list_pos, &hna_list ) {

                        hna_node = list_entry( list_pos, struct hna_node, list );

                        vis_packet_size += sizeof(struct vis_data);

                        vis_packet = debugRealloc( vis_packet, vis_packet_size, 107 );

                        vis_data = (struct vis_data *)(vis_packet + vis_packet_size - sizeof(struct vis_data));

                        memcpy( &vis_data->ip, (unsigned char *)&hna_node->addr, 4 );

                        vis_data->data = hna_node->netmask;
                        vis_data->type = DATA_TYPE_HNA;

                }

        }


        if ( vis_packet_size == sizeof(struct vis_packet) ) {

                debugFree( vis_packet, 1107 );
                vis_packet = NULL;
                vis_packet_size = 0;

        }

}



void send_vis_packet()
{

        generate_vis_packet();

        if ( vis_packet != NULL )
                send_udp_packet(vis_packet, vis_packet_size, &vis_if.addr, vis_if.sock, NULL);

}



uint8_t count_real_packets(struct bat_packet *in, uint32_t neigh, struct batman_if *if_incoming)
{

        struct list_head *list_pos;
        struct orig_node *orig_node;
        struct neigh_node *tmp_neigh_node;
        uint8_t is_duplicate = 0;


        orig_node = get_orig_node( in->orig );

        /*static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN];

        addr_to_string( in->orig, orig_str, ADDR_STR_LEN );
        addr_to_string( neigh, neigh_str, ADDR_STR_LEN );

        debug_output( 3, "count_real_packets: orig = %s, neigh = %s, seq = %i, last seq = %i\n", orig_str, neigh_str, in->seqno, orig_node->last_real_seqno );*/

        list_for_each( list_pos, &orig_node->neigh_list ) {

                tmp_neigh_node = list_entry( list_pos, struct neigh_node, list );

                if ( !is_duplicate )
                        is_duplicate = get_bit_status( tmp_neigh_node->real_bits, orig_node->last_real_seqno, in->seqno );

                if ( ( tmp_neigh_node->addr == neigh ) && ( tmp_neigh_node->if_incoming == if_incoming ) ) {

                        bit_get_packet( tmp_neigh_node->real_bits, in->seqno - orig_node->last_real_seqno, 1 );
                        /*debug_output( 3, "count_real_packets (yes): neigh = %s, is_new = %s, seq = %i, last seq = %i\n", neigh_str, ( is_new_seqno ? "YES" : "NO" ), in->seqno, orig_node->last_real_seqno );*/

                } else {

                        bit_get_packet( tmp_neigh_node->real_bits, in->seqno - orig_node->last_real_seqno, 0 );
                        /*debug_output( 3, "count_real_packets (no): neigh = %s, is_new = %s, seq = %i, last seq = %i\n", neigh_str, ( is_new_seqno ? "YES" : "NO" ), in->seqno, orig_node->last_real_seqno );*/

                }

                tmp_neigh_node->real_packet_count = bit_packet_count( tmp_neigh_node->real_bits );

        }

        if ( !is_duplicate ) {

                debug_output( 4, "updating last_seqno: old %d, new %d \n", orig_node->last_real_seqno, in->seqno );
                orig_node->last_real_seqno = in->seqno;

        }

        return is_duplicate;

}



int8_t batman()
{

        struct list_head *list_pos, *list_pos_tmp, *hna_pos, *hna_pos_tmp, *forw_pos_tmp, *prev_list_head;
        struct orig_node *orig_neigh_node, *orig_node;
        struct batman_if *batman_if, *if_incoming;
        struct hna_node *hna_node, *hna_node_exist;
        struct forw_node *forw_node;
        uint32_t neigh, hna, netmask, debug_timeout, vis_timeout, select_timeout, curr_time;
        unsigned char in[2001], *hna_recv_buff;
        static char orig_str[ADDR_STR_LEN], neigh_str[ADDR_STR_LEN], ifaddr_str[ADDR_STR_LEN], oldorig_str[ADDR_STR_LEN];
        int16_t hna_buff_count, hna_buff_len;
        uint8_t forward_old, if_rp_filter_all_old, if_rp_filter_default_old, if_send_redirects_all_old, if_send_redirects_default_old;
        uint8_t is_my_addr, is_my_orig, is_my_oldorig, is_broadcast, is_duplicate, is_bidirectional, is_bntog, has_unidirectional_flag, has_directlink_flag, has_version;
        int8_t res;


        debug_timeout = vis_timeout = get_time_msec();

        if ( NULL == ( orig_hash = hash_new( 128, compare_orig, choose_orig ) ) )
                return(-1);

        /* for profiling the functions */
        prof_init( PROF_choose_gw, "choose_gw" );
        prof_init( PROF_update_routes, "update_routes" );
        prof_init( PROF_update_gw_list, "update_gw_list" );
        prof_init( PROF_is_duplicate, "isDuplicate" );
        prof_init( PROF_get_orig_node, "get_orig_node" );
        prof_init( PROF_update_originator, "update_orig" );
        prof_init( PROF_purge_originator, "purge_orig" );
        prof_init( PROF_schedule_forward_packet, "schedule_forward_packet" );
        prof_init( PROF_send_outstanding_packets, "send_outstanding_packets" );

        if ( !( list_empty( &hna_list ) ) ) {

                list_for_each( list_pos, &hna_list ) {

                        hna_node = list_entry( list_pos, struct hna_node, list );

                        hna_buff = debugRealloc( hna_buff, ( num_hna + 1 ) * 5 * sizeof( unsigned char ), 15 );

                        memmove( &hna_buff[ num_hna * 5 ], ( unsigned char *)&hna_node->addr, 4 );
                        hna_buff[ ( num_hna * 5 ) + 4 ] = ( unsigned char )hna_node->netmask;

                        num_hna++;

                        /* add throw routing entries for own hna */
                        add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_NETWORKS, 1, 0 );
                        add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_HOSTS, 1, 0 );
                        add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH, 1, 0 );
                        add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL, 1, 0 );

                }

        }

        list_for_each( list_pos, &if_list ) {
                batman_if = list_entry( list_pos, struct batman_if, list );

                batman_if->out.version = COMPAT_VERSION;
                batman_if->out.flags = 0x00;
                batman_if->out.ttl = ( batman_if->if_num > 0 ? 2 : TTL );
                batman_if->out.gwflags = ( batman_if->if_num > 0 ? 0 : gateway_class );
                batman_if->out.seqno = 1;
                batman_if->out.gwport = htons(GW_PORT);
                batman_if->out.tq = TQ_MAX_VALUE;

                schedule_own_packet(batman_if);
        }

        if_rp_filter_all_old = get_rp_filter( "all" );
        if_rp_filter_default_old = get_rp_filter( "default" );

        if_send_redirects_all_old = get_send_redirects( "all" );
        if_send_redirects_default_old = get_send_redirects( "default" );

        set_rp_filter( 0, "all" );
        set_rp_filter( 0, "default" );

        set_send_redirects( 0, "all" );
        set_send_redirects( 0, "default" );

        forward_old = get_forwarding();
        set_forwarding(1);

        while ( !is_aborted() ) {

                debug_output( 4, " \n \n" );

                /* harden select_timeout against sudden time change (e.g. ntpdate) */
                curr_time = get_time_msec();
                select_timeout = ((int)(((struct forw_node *)forw_list.next)->send_time - curr_time) > 0 ?
                                  ((struct forw_node *)forw_list.next)->send_time - curr_time : 10);

                res = receive_packet( in, sizeof(in), &hna_buff_len, &neigh, select_timeout, &if_incoming );

                if ( res < 0 )
                        return -1;

                if ( res > 0 ) {

                        curr_time = get_time_msec();

                        addr_to_string( ((struct bat_packet *)&in)->orig, orig_str, sizeof(orig_str) );
                        addr_to_string( neigh, neigh_str, sizeof(neigh_str) );
                        addr_to_string( if_incoming->addr.sin_addr.s_addr, ifaddr_str, sizeof(ifaddr_str) );
                        addr_to_string( ((struct bat_packet *)&in)->old_orig, oldorig_str, sizeof(oldorig_str) );

                        is_my_addr = is_my_orig = is_my_oldorig = is_broadcast = is_duplicate = is_bidirectional = is_bntog = 0;

                        has_unidirectional_flag = ((struct bat_packet *)&in)->flags & UNIDIRECTIONAL ? 1 : 0;
                        has_directlink_flag = ((struct bat_packet *)&in)->flags & DIRECTLINK ? 1 : 0;
                        has_version = ((struct bat_packet *)&in)->version;

                        debug_output( 4, "Received BATMAN packet via NB: %s, IF: %s %s (from OG: %s, via old OG: %s, seqno %d, tq %d, TTL %d, V %d, UDF %d, IDF %d) \n", neigh_str, if_incoming->dev, ifaddr_str, orig_str, oldorig_str, ((struct bat_packet *)&in)->seqno, ((struct bat_packet *)&in)->tq, ((struct bat_packet *)&in)->ttl, has_version, has_unidirectional_flag, has_directlink_flag );

                        hna_buff_len -= sizeof(struct bat_packet);
                        hna_recv_buff = ( hna_buff_len > 4 ? in + sizeof(struct bat_packet) : NULL );

                        list_for_each( list_pos, &if_list ) {

                                batman_if = list_entry( list_pos, struct batman_if, list );

                                if ( neigh == batman_if->addr.sin_addr.s_addr )
                                        is_my_addr = 1;

                                if ( ((struct bat_packet *)&in)->orig == batman_if->addr.sin_addr.s_addr )
                                        is_my_orig = 1;

                                if ( neigh == batman_if->broad.sin_addr.s_addr )
                                        is_broadcast = 1;

                                if (((struct bat_packet *)&in)->old_orig == batman_if->addr.sin_addr.s_addr)
                                        is_my_oldorig = 1;

                        }


                        if ( ((struct bat_packet *)&in)->gwflags != 0 )
                                debug_output( 4, "Is an internet gateway (class %i) \n", ((struct bat_packet *)&in)->gwflags );

                        if ( hna_buff_len > 4 ) {

                                debug_output( 4, "HNA information received (%i HNA network%s): \n", hna_buff_len / 5, ( hna_buff_len / 5 > 1 ? "s": "" ) );
                                hna_buff_count = 0;

                                while ( ( hna_buff_count + 1 ) * 5 <= hna_buff_len ) {

                                        memmove( &hna, ( uint32_t *)&hna_recv_buff[ hna_buff_count * 5 ], 4 );
                                        netmask = ( uint32_t )hna_recv_buff[ ( hna_buff_count * 5 ) + 4 ];

                                        addr_to_string( hna, orig_str, sizeof(orig_str) );

                                        if ( ( netmask > 0 ) && ( netmask < 33 ) )
                                                debug_output( 4, "hna: %s/%i\n", orig_str, netmask );
                                        else
                                                debug_output( 4, "hna: %s/%i -> ignoring (invalid netmask) \n", orig_str, netmask );

                                        hna_buff_count++;

                                }

                        }


                        if (((struct bat_packet *)&in)->version != COMPAT_VERSION) {

                                debug_output( 4, "Drop packet: incompatible batman version (%i) \n", ((struct bat_packet *)&in)->version );

                        } else if (is_my_addr) {

                                debug_output( 4, "Drop packet: received my own broadcast (sender: %s) \n", neigh_str );

                        } else if (is_broadcast) {

                                debug_output( 4, "Drop packet: ignoring all packets with broadcast source IP (sender: %s) \n", neigh_str );

                        } else if (is_my_orig) {

                                orig_neigh_node = get_orig_node( neigh );

                                /*debug_output( 4, "received my own OGM via NB lastTxIfSeqno: %d, currRxSeqno: %d, prevRxSeqno: %d, currRxSeqno-prevRxSeqno %d \n", ( if_incoming->out.seqno - 2 ), ((struct bat_packet *)&in)->seqno, orig_neigh_node->bidirect_link[if_incoming->if_num], ((struct bat_packet *)&in)->seqno - orig_neigh_node->bidirect_link[if_incoming->if_num] );*/

                                /* neighbour has to indicate direct link and it has to come via the corresponding interface */
                                /* if received seqno equals last send seqno save new seqno for bidirectional check */
// 				if ( ( ((struct bat_packet *)&in)->flags & DIRECTLINK ) && ( if_incoming->addr.sin_addr.s_addr == ((struct bat_packet *)&in)->orig ) && ( ((struct bat_packet *)&in)->seqno - if_incoming->out.seqno + 2 == 0 ) ) {
//
// 					orig_neigh_node->bidirect_link[if_incoming->if_num] = ((struct bat_packet *)&in)->seqno;
//
// 					debug_output( 4, "indicating bidirectional link - updating bidirect_link seqno \n" );
//
// 				} else {
//
// 					debug_output( 4, "NOT indicating bidirectional link - NOT updating bidirect_link seqno \n" );
//
// 				}

                                if ( ( ((struct bat_packet *)&in)->flags & DIRECTLINK ) && ( if_incoming->addr.sin_addr.s_addr == ((struct bat_packet *)&in)->orig ) && ( ((struct bat_packet *)&in)->seqno - if_incoming->out.seqno + 2 == 0 ) ) {

                                        debug_output( 4, "count own bcast (is_my_orig): old = %i, ", orig_neigh_node->bcast_own_sum[if_incoming->if_num] );
                                        bit_mark( (TYPE_OF_WORD *)&(orig_neigh_node->bcast_own[if_incoming->if_num * num_words]), 0 );
                                        orig_neigh_node->bcast_own_sum[if_incoming->if_num] = bit_packet_count( (TYPE_OF_WORD *)&(orig_neigh_node->bcast_own[if_incoming->if_num * num_words]) );
                                        debug_output( 4, "new = %i \n", orig_neigh_node->bcast_own_sum[if_incoming->if_num] );

                                }

                                debug_output( 4, "Drop packet: originator packet from myself (via neighbour) \n" );

                        } else if (((struct bat_packet *)&in)->flags & UNIDIRECTIONAL) {

                                count_real_packets( (struct bat_packet *)in, neigh, if_incoming );

                                debug_output( 4, "Drop packet: originator packet with unidirectional flag \n" );

                        } else if (((struct bat_packet *)&in)->tq == 0) {

                                count_real_packets( (struct bat_packet *)in, neigh, if_incoming );

                                debug_output( 4, "Drop packet: originator packet with tq is 0 \n" );

                        } else if (is_my_oldorig) {

                                debug_output( 4, "Drop packet: ignoring all rebroadcast echos (sender: %s) \n", neigh_str );

                        } else {

                                is_duplicate = count_real_packets( (struct bat_packet *)in, neigh, if_incoming );

                                orig_node = get_orig_node( ((struct bat_packet *)&in)->orig );

                                /* if sender is a direct neighbor the sender ip equals originator ip */
                                orig_neigh_node = ( ((struct bat_packet *)&in)->orig == neigh ? orig_node : get_orig_node( neigh ) );

                                /* drop packet if sender is not a direct neighbor and if we no route towards it */
                                if ( ( ((struct bat_packet *)&in)->orig != neigh ) && ( orig_neigh_node->router == NULL ) ) {

                                        debug_output( 4, "Drop packet: OGM via unkown neighbor! \n" );

                                } else {

                                        is_bidirectional = isBidirectionalNeigh( orig_node, orig_neigh_node, (struct bat_packet *)in, curr_time, if_incoming, is_duplicate );

                                        /* update ranking if it is not a duplicate or has the same seqno and similar ttl as the non-duplicate */
                                        if ( ( is_bidirectional ) && ( ( !is_duplicate ) || ( ( orig_node->last_real_seqno == ((struct bat_packet *)&in)->seqno ) && ( orig_node->last_ttl - 3 <= ((struct bat_packet *)&in)->ttl ) ) ) )
                                                update_orig( orig_node, (struct bat_packet *)in, neigh, if_incoming, hna_recv_buff, hna_buff_len, is_duplicate, curr_time );

                                        /*is_bntog = isBntog( neigh, orig_node );*/

                                        /* is single hop (direct) neighbour */
                                        if ( ((struct bat_packet *)&in)->orig == neigh ) {

                                                /* it is our best route towards him */
                                                /*if ( is_bidirectional && is_bntog ) {*/

                                                /* mark direct link on incoming interface */
                                                schedule_forward_packet( orig_node, (struct bat_packet *)in, neigh, 0, 1, hna_recv_buff, hna_buff_len, if_incoming );

                                                debug_output( 4, "Forward packet: rebroadcast neighbour packet with direct link flag \n" );

                                                /* if an unidirectional neighbour sends us a packet - retransmit it with unidirectional flag to tell him that we get its packets */
                                                /* if a bidirectional neighbour sends us a packet - retransmit it with unidirectional flag if it is not our best link to it in order to prevent routing problems */
                                                /*} else if ( ( is_bidirectional && !is_bntog ) || ( !is_bidirectional ) ) {

                                                schedule_forward_packet( orig_node, (struct bat_packet *)in, 1, 1, hna_recv_buff, hna_buff_len, if_incoming );

                                                debug_output( 4, "Forward packet: rebroadcast neighbour packet with direct link and unidirectional flag \n" );

                                                }*/

                                                /* multihop originator */
                                        } else {

                                                if ( is_bidirectional ) {

                                                        if ( !is_duplicate ) {

                                                                schedule_forward_packet( orig_node, (struct bat_packet *)in, neigh, 0, 0, hna_recv_buff, hna_buff_len, if_incoming );

                                                                debug_output( 4, "Forward packet: rebroadcast originator packet \n" );

                                                        } else {

                                                                debug_output( 4, "Drop packet: duplicate packet received\n" );

                                                        }

                                                } else {

                                                        debug_output( 4, "Drop packet: not received via bidirectional link\n" );

                                                }

                                        }

                                }

                        }

                }


                send_outstanding_packets();


                if ((int)(curr_time - (debug_timeout + 1000)) > 0) {

                        debug_timeout = curr_time;

                        purge_orig( curr_time );

                        debug_orig();

                        check_inactive_interfaces();

                        if ( debug_clients.clients_num[4] > 0 ) {

                                checkIntegrity();
                                prof_print();

                        }

                        if ( ( routing_class != 0 ) && ( curr_gateway == NULL ) )
                                choose_gw();

                        if ((vis_if.sock) && ((int)(curr_time - (vis_timeout + 10000)) > 0)) {

                                vis_timeout = curr_time;
                                send_vis_packet();

                        }

                        if (pthread_mutex_trylock(&hna_chg_list_mutex) == 0) {

                                if (!(list_empty(&hna_chg_list))) {

                                        list_for_each_safe(list_pos, list_pos_tmp, &hna_chg_list) {

                                                hna_node = list_entry(list_pos, struct hna_node, list);
                                                addr_to_string( hna_node->addr, oldorig_str, sizeof(oldorig_str) );

                                                hna_node_exist = NULL;
                                                prev_list_head = (struct list_head *)&hna_list;

                                                list_for_each_safe(hna_pos, hna_pos_tmp, &hna_list) {

                                                        hna_node_exist = list_entry(hna_pos, struct hna_node, list);

                                                        if ((hna_node->addr == hna_node_exist->addr) && (hna_node->netmask == hna_node_exist->netmask)) {

                                                                if (hna_node->del) {
                                                                        debug_output(3, "Deleting HNA from announce network list: %s/%i\n", oldorig_str, hna_node->netmask );

                                                                        add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_NETWORKS, 1, 1 );
                                                                        add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_HOSTS, 1, 1 );
                                                                        add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH, 1, 1 );
                                                                        add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL, 1, 1 );

                                                                        list_del(prev_list_head, hna_pos, &hna_list);

                                                                        debugFree(hna_node_exist, 1109);
                                                                } else {
                                                                        debug_output(3, "Can't add HNA - already announcing network: %s/%i\n", oldorig_str, hna_node->netmask );
                                                                }

                                                                break;

                                                        }

                                                        prev_list_head = &hna_node_exist->list;
                                                        hna_node_exist = NULL;

                                                }

                                                if (hna_node_exist == NULL) {

                                                        if (hna_node->del) {
                                                                debug_output(3, "Can't delete HNA - network is not announced: %s/%i\n", oldorig_str, hna_node->netmask );
                                                        } else {
                                                                debug_output(3, "Adding HNA to announce network list: %s/%i\n", oldorig_str, hna_node->netmask );

                                                                /* add throw routing entries for own hna */
                                                                add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_NETWORKS, 1, 0 );
                                                                add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_HOSTS, 1, 0 );
                                                                add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH, 1, 0 );
                                                                add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL, 1, 0 );

                                                                /* add node */
                                                                hna_node_exist = debugMalloc( sizeof(struct hna_node), 105 );
                                                                memset(hna_node_exist, 0, sizeof(struct hna_node));
                                                                INIT_LIST_HEAD(&hna_node_exist->list);

                                                                hna_node_exist->addr = hna_node->addr;
                                                                hna_node_exist->netmask = hna_node->netmask;

                                                                list_add_tail(&hna_node_exist->list, &hna_list);
                                                        }

                                                }

                                                list_del((struct list_head *)&hna_chg_list, list_pos, &hna_chg_list);
                                                debugFree(hna_node, 1110);

                                        }

                                        if (hna_buff != NULL)
                                                debugFree(hna_buff, 1111);

                                        num_hna = 0;
                                        hna_buff = NULL;

                                        if (!(list_empty(&hna_list))) {

                                                list_for_each(list_pos, &hna_list) {

                                                        hna_node = list_entry(list_pos, struct hna_node, list);

                                                        hna_buff = debugRealloc(hna_buff, ( num_hna + 1 ) * 5 * sizeof( unsigned char ), 16);

                                                        memmove(&hna_buff[ num_hna * 5 ], ( unsigned char *)&hna_node->addr, 4);
                                                        hna_buff[ ( num_hna * 5 ) + 4 ] = ( unsigned char )hna_node->netmask;

                                                        num_hna++;

                                                }

                                        }

                                }

                                if (pthread_mutex_unlock(&hna_chg_list_mutex) != 0)
                                        debug_output(0, "Error - could not unlock mutex (hna_chg_list_mutex => 3): %s \n", strerror(errno));

                        }

                }

        }


        if ( debug_level > 0 )
                printf( "Deleting all BATMAN routes\n" );

        purge_orig(get_time_msec() + (5 * purge_timeout) + originator_interval);

        hash_destroy( orig_hash );


        list_for_each_safe( list_pos, hna_pos_tmp, &hna_list ) {

                hna_node = list_entry( list_pos, struct hna_node, list );

                /* add throw routing entries for own hna */
                add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_NETWORKS, 1, 1 );
                add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_HOSTS, 1, 1 );
                add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH, 1, 1 );
                add_del_route( hna_node->addr, hna_node->netmask, 0, 0, 0, "unknown", BATMAN_RT_TABLE_TUNNEL, 1, 1 );

                debugFree( hna_node, 1103 );

        }

        if ( hna_buff != NULL )
                debugFree( hna_buff, 1104 );


        list_for_each_safe( list_pos, forw_pos_tmp, &forw_list ) {

                forw_node = list_entry( list_pos, struct forw_node, list );

                list_del( (struct list_head *)&forw_list, list_pos, &forw_list );

                debugFree( forw_node->pack_buff, 1105 );
                debugFree( forw_node, 1106 );

        }

        if ( vis_packet != NULL )
                debugFree( vis_packet, 1108 );

        set_forwarding( forward_old );

        set_rp_filter( if_rp_filter_all_old, "all" );
        set_rp_filter( if_rp_filter_default_old, "default" );

        set_send_redirects( if_send_redirects_all_old, "all" );
        set_send_redirects( if_send_redirects_default_old, "default" );

        return 0;

}
