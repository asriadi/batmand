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

#ifndef _BATMAN_OS_H
#define _BATMAN_OS_H

#include "batman.h"

uint32_t get_time( void );
uint32_t get_time_sec( void );
int32_t rand_num( int32_t limit );
void addr_to_string( uint32_t addr, char *str, int32_t len );




void add_del_hna( struct orig_node *orig_node, int8_t del );
int8_t is_aborted();
void handler( int32_t sig );
void segmentation_fault( int32_t sig );
void restore_and_exit( uint8_t is_sigsegv );

/* route.c */
void add_del_route( uint32_t dest, uint8_t netmask, uint32_t router, int32_t ifi, char *dev, uint8_t rt_table, int8_t route_type, int8_t del );
void add_del_rule( uint32_t network, uint8_t netmask, int8_t rt_table, uint32_t prio, char *iif, int8_t dst_rule, int8_t del );
int add_del_interface_rules( int8_t del );
int flush_routes_rules( int8_t rt_table );

/* tun.c */
int8_t probe_tun();
int8_t del_dev_tun( int32_t fd );
int8_t add_dev_tun( struct batman_if *batman_if, uint32_t dest_addr, char *tun_dev, size_t tun_dev_size, int32_t *fd, int32_t *ifi );
int8_t set_tun_addr( int32_t fd, uint32_t tun_addr, char *tun_dev );

/* init.c */
void apply_init_args( int argc, char *argv[] );
void init_interface ( struct batman_if *batman_if );
void init_interface_gw ( struct batman_if *batman_if );

/* kernel.c */
void set_rp_filter( int32_t state, char* dev );
int32_t get_rp_filter( char *dev );
void set_send_redirects( int32_t state, char* dev );
int32_t get_send_redirects( char *dev );
void set_forwarding( int32_t state );
int32_t get_forwarding( void );
int8_t bind_to_iface( int32_t sock, char *dev );
int8_t use_kernel_module( char *dev );
int8_t use_gateway_module();

/* posix.c */
void print_animation( void );
void   del_default_route();
int8_t add_default_route();
int8_t receive_packet( unsigned char *packet_buff, int32_t packet_buff_len, int16_t *hna_buff_len, uint32_t *neigh, uint32_t timeout, struct batman_if **if_incoming );
int8_t send_udp_packet( unsigned char *packet_buff, int packet_buff_len, struct sockaddr_in *broad, int send_sock );
void restore_defaults();
void cleanup();

/* tunnel.c */
void *gw_listen( void *arg );
void *client_to_gw_tun( void *arg );

/* unix_sokcet.c */
void *unix_listen( void *arg );
void debug_output( int8_t debug_prio, char *format, ... );


#endif
