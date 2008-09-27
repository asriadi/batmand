/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Marek Lindner, Axel Neumann
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


/* get_time functions MUST be called at least every 2*MAX_SELECT_TIMEOUT_MS to allow for properly working time-drift checks */

/* overlaps after approximately 138 years */
#define get_time_sec()  get_time( NO, NULL  ) 

/* overlaps after 49 days, 17 hours, 2 minutes, and 48 seconds */
#define get_time_msec() get_time( YES, NULL ) 

# define timercpy(d, a) (d)->tv_sec = (a)->tv_sec; (d)->tv_usec = (a)->tv_usec; 


/* posix.c */

enum {
	CLEANUP_SUCCESS,
	CLEANUP_FAILURE,
	CLEANUP_CONTINUE 
};

void print_animation( void );
void   del_default_route();
int8_t add_default_route( struct gw_node *new_curr_gw );

int8_t send_udp_packet( unsigned char *packet_buff, int32_t packet_buff_len, struct sockaddr_in *dst, int32_t send_sock );

void cleanup_all( int status );

uint32_t get_time( uint8_t msec, struct timeval *precise_tv );
	
void fake_start_time( int32_t fake );

int32_t rand_num( uint32_t limit );

void addr_to_string( uint32_t addr, char *str, int32_t len );

//void add_del_hna( struct orig_node *orig_node, struct ext_packet *hna_array, int16_t hna_array_len /*int8_t del*/ );
int8_t is_aborted();
void handler( int32_t sig );
void segmentation_fault( int32_t sig );
void restore_and_exit( uint8_t is_sigsegv );

void init_set_bits_table256( void );
uint8_t get_set_bits( uint32_t v );


/* init.c */

#define MAX_UNIX_MSG_SIZE 500


void prepare_add_del_own_hna ( char *optarg_str, uint32_t addr, uint16_t netmask, int8_t del, uint8_t atype, int creq );
void prepare_add_del_own_srv ( char *optarg_str, uint32_t addr, uint16_t port, uint8_t seqno, int8_t del );
void set_init_val( char* switch_name, int32_t switch_val, int min, int max, int32_t *target_value, int creq );
void set_init_arg( char* switch_name, char* switch_arg, int min, int max, int32_t *target_value, int creq );
void apply_init_args ( int argc, char *argv[] );
void init_interface ( struct batman_if *batman_if );
void deactivate_interface ( struct batman_if *batman_if );
void check_interfaces ();
void set_readfds();


void stop_gw_service ( void );
void start_gw_service ( void );

void debug_params( int fd );
void debug_config( int fd );




/* route.c */

struct rules_node {
	struct list_head list;
	uint32_t network;
	uint8_t netmask;
	uint8_t rt_table;
	uint32_t prio;
	char *iif;
	int8_t rule_type;
};

 
struct routes_node {
	struct list_head list;
	uint32_t dest;
	uint8_t netmask;
	uint32_t router;
	uint32_t source;
	uint8_t rt_table;
	int8_t route_type;
};

void init_route( void );
void cleanup_route( void );

void recv_ifevent_netlink_sk( void );

void add_del_route( uint32_t dest, uint8_t netmask, uint32_t router, uint32_t source, int32_t ifi, char *dev, uint8_t rt_table, int8_t route_type, int8_t del, int8_t track );

void add_del_rule( uint32_t network, uint8_t netmask, uint8_t rt_table, uint32_t prio, char *iif, int8_t rule_type, int8_t del, int8_t track );
void flush_tracked_rules_and_routes( void );
int add_del_interface_rules( int8_t del, uint8_t setup_tunnel, uint8_t setup_networks );
int flush_routes_rules( int8_t rt_table );

void check_kernel_config( struct batman_if *batman_if, int8_t init );
void restore_kernel_config( struct batman_if *batman_if );

int8_t bind_to_iface( int32_t sock, char *dev );


/* tun.c */
int8_t probe_tun(uint8_t print_to_stderr);
int8_t del_dev_tun( int32_t fd );
int8_t add_dev_tun(  uint32_t dest_addr, char *tun_dev, size_t tun_dev_size, int32_t *fd, int32_t *ifi );
int8_t set_tun_addr( int32_t fd, uint32_t tun_addr, char *tun_dev );






/* tunnel.c */
void *gw_listen( void *arg );
void *client_to_gw_tun( void *arg );

#define MAX_MTU 1500


#define TUNNEL_DATA 0x01
#define TUNNEL_IP_REQUEST 0x02
#define TUNNEL_IP_INVALID 0x03
#define TUNNEL_KEEPALIVE_REQUEST 0x04 /* unused */
#define TUNNEL_KEEPALIVE_REPLY 0x05   /* unused */
#define TUNNEL_IP_REPLY 0x06

#define GW_STATE_UNKNOWN  0x01
#define GW_STATE_VERIFIED 0x02

#define ONE_MINUTE                60000

#define GW_STATE_UNKNOWN_TIMEOUT  (1  * ONE_MINUTE)
#define GW_STATE_VERIFIED_TIMEOUT (5  * ONE_MINUTE)

#define IP_LEASE_TIMEOUT          (1 * ONE_MINUTE)

#define MAX_TUNNEL_IP_REQUESTS 60 /*12*/
#define TUNNEL_IP_REQUEST_TIMEOUT 1000 /* msec */

	
struct tun_request_type {
	uint32_t lease_ip;
	uint16_t lease_lt;
} __attribute__((packed));

struct tun_data_type {
	unsigned char ip_packet[MAX_MTU];
} __attribute__((packed));

struct tun_packet_start {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int type:4;
	unsigned int version:4;  /* should be the first field in the packet in network byte order */
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int type:4;
#else
# error "Please fix <bits/endian.h>"
#endif
} __attribute__((packed));

struct tun_packet
{
	uint8_t  reserved1;
	uint8_t  reserved2;
	uint8_t  reserved3;

	struct tun_packet_start start;
#define TP_TYPE  start.type
#define TP_VERS  start.version	

	union
	{
		struct tun_request_type trt;
		struct tun_data_type tdt;
	}tt;
#define LEASE_IP  tt.trt.lease_ip
#define LEASE_LT  tt.trt.lease_lt
#define IP_PACKET tt.tdt.ip_packet
} __attribute__((packed));


#define TX_RP_SIZE (sizeof(struct tun_packet_start) + sizeof(struct tun_request_type))
#define TX_DP_SIZE (sizeof(struct tun_packet_start) + sizeof(struct tun_data_type))



#endif
