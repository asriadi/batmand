/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Marek Lindner, Simon Wunderlich
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



#ifndef _BATMAN_BATMAN_H
#define _BATMAN_BATMAN_H

#include <pthread.h>
#include <stdint.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ether.h>      /* ether_ntoa() */
#include "list.h"
#include "bitarray.h"
#include "hash.h"
#include "allocate.h"


#define SOURCE_VERSION "0.1 pre-alpha"
#define COMPAT_VERSION 1
#define UNIDIRECTIONAL 0x80
#define DIRECTLINK 0x40
#define ADDR_STR_LEN 16

#define UNIX_PATH "/var/run/batmand-adv.socket"

#define ETH_P_BATMAN  0x0842
#define ETH_BATMAN    0x10
#define ETH_BROADCAST 0x20
#define ETH_UNICAST   0x30


/*
 * No configuration files or fancy command line switches yet
 * To experiment with B.A.T.M.A.N. settings change them here
 * and recompile the code
 * Here is the stuff you may want to play with:
 */

#define JITTER 100
#define TTL 50             /* Time To Live of broadcast messages */
#define BIDIRECT_TIMEOUT 2
#define TIMEOUT 60000      /* sliding window size of received orginator messages in ms */
#define SEQ_RANGE 64       /* sliding packet range of received orginator messages in squence numbers (should be a multiple of our word size) */



#define NUM_WORDS ( SEQ_RANGE / WORD_BIT_SIZE )



extern unsigned char broadcastAddr[];

extern uint8_t debug_level;
extern uint8_t gateway_class;
extern uint8_t routing_class;
extern int16_t orginator_interval;
extern uint32_t pref_gateway;

extern struct gw_node *curr_gateway;
pthread_t curr_gateway_thread_id;

extern uint8_t found_ifs;
extern int32_t receive_max_sock;
extern fd_set receive_wait_set;
extern int32_t tap_sock;

extern uint8_t unix_client;

extern struct hashtable_t *orig_hash;

extern struct list_head if_list;
extern struct list_head gw_list;
extern struct list_head forw_list;
extern struct vis_if vis_if;
extern struct unix_if unix_if;
extern struct debug_clients debug_clients;

extern char *gw2string[];

struct packet
{
	uint8_t  flags;    /* 0x80: UNIDIRECTIONAL link, 0x40: DIRECTLINK flag, ... */
	uint8_t  ttl;
	uint8_t  orig[6];
	uint16_t seqno;
	uint8_t  gwflags;  /* flags related to gateway functions: gateway class */
	uint8_t  version;  /* batman version field */
} __attribute__((packed));

struct orig_node                 /* structure for orig_list maintaining nodes of mesh */
{
	uint8_t  orig[6];			/* important, must be first entry! (for faster hash comparison) */
	struct neigh_node *router;
	struct batman_if *batman_if;
	uint16_t *bidirect_link;    /* if node is a bidrectional neighbour, when my originator packet was broadcasted (replied) by this node and received by me */
	uint32_t last_aware;        /* when last packet from this node was received */
	uint16_t last_seqno;        /* last and best known sequence number */
	uint16_t last_bcast_seqno;  /* last broadcast sequence number received by this host */
	TYPE_OF_WORD seq_bits[ NUM_WORDS ];
	struct list_head neigh_list;
	uint8_t  gwflags;      /* flags related to gateway functions: gateway class */
} __attribute((packed));

struct neigh_node
{
	struct list_head list;
	uint8_t  addr[6];
	uint8_t packet_count;
	uint8_t  last_ttl;         /* ttl of last received packet */
	uint32_t last_aware;            /* when last packet via this neighbour was received */
	TYPE_OF_WORD seq_bits[ NUM_WORDS ];
	struct batman_if *if_incoming;
};

struct forw_node                 /* structure for forw_list maintaining packets to be send/forwarded */
{
	struct list_head list;
	uint32_t send_time;
	uint8_t  own;
	unsigned char *pack_buff;
	int16_t  pack_buff_len;
	struct batman_if *if_outgoing;
};

struct gw_node
{
	struct list_head list;
	struct orig_node *orig_node;
	uint16_t unavail_factor;
	uint32_t last_failure;
	uint32_t deleted;
};

struct batman_if
{
	struct list_head list;
	char *dev;
	int32_t raw_sock;
	int16_t if_num;
	uint8_t  hw_addr[6];
	uint16_t bcast_seqno;
	pthread_t listen_thread_id;
	struct packet out;
	struct list_head client_list;
};

// struct gw_client
// {
// 	struct list_head list;
// 	struct batman_if *batman_if;
// 	int32_t sock;
// 	uint32_t last_keep_alive;
// 	struct sockaddr_in addr;
// };

// struct vis_if {
// 	int32_t sock;
// 	struct sockaddr_in addr;
// };

struct unix_if {
	int32_t unix_sock;
	pthread_t listen_thread_id;
	struct sockaddr_un addr;
	struct list_head client_list;
};

struct unix_client {
	struct list_head list;
	int32_t sock;
	uint8_t debug_level;
};

struct debug_clients {
	void *fd_list[4];
	int16_t clients_num[4];
	pthread_mutex_t *mutex[4];
};

struct debug_level_info {
	struct list_head list;
	int32_t fd;
};

struct curr_gw_data {
	unsigned int orig;
	struct gw_node *gw_node;
	struct batman_if *batman_if;
};


int8_t batman( void );
void   usage( void );
void   verbose_usage( void );
void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node );
void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags );
int isMyMac( uint8_t *addr );

#endif
