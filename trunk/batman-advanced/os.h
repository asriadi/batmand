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

#include "batman-adv.h"

int8_t is_aborted();
int32_t rand_num( int32_t limit );
char *addr_to_string( uint8_t *hw_addr );
uint32_t get_time( void );

int8_t rawsock_create(char *devicename);
int32_t rawsock_read( int32_t rawsock, struct ether_header *recv_header, unsigned char *buf, int16_t size );
int32_t rawsock_write( int32_t rawsock, struct ether_header *send_header, unsigned char *buf, int16_t size );

int8_t tap_probe();
int32_t tap_create( int16_t mtu, uint8_t *hw_addr );
void tap_destroy( int32_t tap_fd );
void tap_write( int32_t tap_fd, unsigned char *buff, int16_t buff_len );

int8_t receive_packet( unsigned char *packet_buff, int16_t packet_buff_len, int16_t *pay_buff_len, uint8_t *neigh, uint32_t timeout, struct batman_if **if_incoming );
int8_t send_packet( unsigned char *packet_buff, int16_t packet_buff_len, uint8_t *recv_addr, int32_t send_sock );

void apply_init_args( int argc, char *argv[] );
int16_t init_interface ( struct batman_if *batman_if );
void init_interface_gw ( struct batman_if *batman_if );

void print_animation( void );
void close_all_sockets();
void *gw_listen( void *arg );

void *client_to_gw_tun( void *arg );

void debug();
void debug_output( int8_t debug_prio, char *format, ... );
void cleanup();



#endif
