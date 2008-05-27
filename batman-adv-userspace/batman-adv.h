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
#include "list-batman.h"
#include "dlist.h"
#include "bitarray.h"
#include "hash.h"
#include "allocate.h"
#include "packet.h"
#include "dlist.h"
#include "vis-types.h"


#define SOURCE_VERSION "0.1-beta" 
#define DIRECTLINK 0x40
#define ADDR_STR_LEN 16
#define VIS_COMPAT_VERSION (128 | 20)
#define VIS_PORT 4307

#define UNIX_PATH "/var/run/batmand-adv.socket"

/* this might only work in gcc, for other compiler remove this.
 * We should ask the makefile to check this for us. */
#define UNUSEDPARAM_ATTRIBUTE	1
#ifndef BATUNUSED
	#if defined(UNUSEDPARAM_ATTRIBUTE)
		#define BATUNUSED(x) (x)__attribute__((unused))
	#elif defined(UNUSEDPARAM_OMIT)
		#define BATUNUSED(x) /* x */
	#else
		#define BATUNUSED(x) x
	#endif
#endif


/***
 *
 * Things you should enable via your make file:
 *
 * DEBUG_MALLOC   enables malloc() / free() wrapper functions to detect memory leaks / buffer overflows / etc
 * MEMORY_USAGE   allows you to monitor the internal memory usage (needs DEBUG_MALLOC to work)
 * PROFILE_DATA   allows you to monitor the cpu usage for each function
 *
 ***/


#ifndef REVISION_VERSION
#define REVISION_VERSION "0"
#endif



/*
 * No configuration files or fancy command line switches yet
 * To experiment with B.A.T.M.A.N. settings change them here
 * and recompile the code
 * Here is the stuff you may want to play with:
 */

#define JITTER 100
#define TTL 50                /* Time To Live of broadcast messages */
#define PURGE_TIMEOUT 200000  /* purge originators after time in ms if no valid packet comes in -> TODO: check influence on TQ_LOCAL_WINDOW_SIZE */
#define TQ_MAX_VALUE 255
#define TQ_LOCAL_WINDOW_SIZE 64     /* sliding packet range of received originator messages in squence numbers (should be a multiple of our word size) */
#define TQ_GLOBAL_WINDOW_SIZE 10
#define TQ_LOCAL_BIDRECT_SEND_MINIMUM 1
#define TQ_LOCAL_BIDRECT_RECV_MINIMUM 1
#define TQ_TOTAL_BIDRECT_LIMIT 1

#define TQ_HOP_PENALTY 10

#define PACKETS_PER_CYCLE 10  /* this seems to be a reasonable value (i've tested for different setups) */
							  /* how many packets to read from the virtual interfaces, maximum.
							   * low value = high throughput, high CPU-load
							   * big value = low throughput, low CPU-load
							   * infinity = as it was before. */
#define BROADCAST_UNKNOWN_DEST	1
							  /* if a packet with unknown destination should be sent, that means the port
							   * can not be looked up in the translation table, a switch usually
							   * broadcasts the packet. This should happen very rarely, as the switch
							   * will learn source-MACs with every sent frame, but it is intended as
							   * fallback solution.
							   * Because it is a broadcast, and therefore expensive, it might be better
							   * to turn it off. A client must do ARP-Requests then or wait for the
							   * destination to send/broadcast something. */
#define BATMAN_MAXPACKETSIZE	(sizeof(struct unicast_packet)>sizeof(struct bcast_packet)?sizeof(struct unicast_packet):sizeof(struct bcast_packet))
								/* maximum size of a packet which carries payload. This should be calculated by the compiler.*/
#define BATMAN_MAXFRAMESIZE		(sizeof(struct ether_header) + BATMAN_MAXPACKETSIZE)	/* size of an ethernet frame. */

#define NUM_WORDS (TQ_LOCAL_WINDOW_SIZE / WORD_BIT_SIZE)

#define AGE_THRESHOLD		3600000
			/* purge from local hna list after 60 minutes. */

#define ETH_STR_LEN 20


extern unsigned char broadcastAddr[];

extern uint8_t debug_level;
extern uint8_t debug_level_max;
extern uint8_t gateway_class;
extern uint8_t routing_class;
extern int16_t originator_interval;
extern uint32_t num_hna;
extern uint32_t pref_gateway;

extern unsigned char *hna_buff;

extern struct gw_node *curr_gateway;
pthread_t curr_gateway_thread_id;

extern uint8_t found_ifs;
extern int32_t receive_max_sock;
extern fd_set receive_wait_set;
extern int32_t tap_sock;
extern int32_t tap_mtu;

extern uint8_t unix_client;
extern struct unix_client *unix_packet[256];

extern uint32_t curr_time;

extern struct hashtable_t *orig_hash;

extern struct list_head_first if_list;
extern struct list_head_first gw_list;
extern struct list_head_first forw_list;
extern struct vis_if vis_if;
extern struct unix_if unix_if;
extern struct debug_clients debug_clients;

extern char *gw2string[];


struct orig_node                    /* structure for orig_list maintaining nodes of mesh */
{
	uint8_t  orig[6];           /* important, must be first entry! (for faster hash comparison) */
	struct neigh_node *router;
	struct batman_if *batman_if;
	uint32_t last_valid;        /* when last packet from this node was received */
	uint16_t last_seqno;        /* last and best known sequence number */
	uint16_t last_bcast_seqno;  /* last broadcast sequence number received by this host */
	int		 num_hna;
	uint8_t *hna_buff;
	struct  dlist_head hna_list;
	int16_t  hna_buff_len;
	struct list_head_first neigh_list;
	uint8_t  gwflags;           /* flags related to gateway functions: gateway class */
	TYPE_OF_WORD *bcast_own;
	uint8_t *bcast_own_sum;
	uint8_t tq_own;
	int tq_asym_penalty;
	uint16_t last_real_seqno;
	uint8_t last_ttl;
	TYPE_OF_WORD seq_bits[NUM_WORDS];
};

struct neigh_node
{
	struct list_head list;
	uint8_t addr[6];
	uint8_t real_packet_count;
	uint8_t tq_recv[TQ_GLOBAL_WINDOW_SIZE];
	uint8_t tq_index;
	uint8_t tq_avg;
	uint8_t last_ttl;         /* ttl of last received packet */
	uint32_t last_valid;       /* when last packet via this neighbour was received */
	TYPE_OF_WORD real_bits[NUM_WORDS];
	struct orig_node *orig_node;
	struct batman_if *if_incoming;
};

struct forw_node                  /* structure for forw_list maintaining packets to be send/forwarded */
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
	struct batman_packet out;
	struct list_head_first client_list;
};

// struct gw_client
// {
// 	struct list_head list;
// 	struct batman_if *batman_if;
// 	int32_t sock;
// 	uint32_t last_keep_alive;
// 	struct sockaddr_in addr;
// };

struct vis_if {
	int32_t sock;
 	struct sockaddr_in addr;
};

struct unix_if {
	int32_t unix_sock;
	pthread_t listen_thread_id;
	struct sockaddr_un addr;
	struct list_head_first client_list;
};

struct unix_client {
	struct list_head list;
	int32_t sock;
	uint8_t debug_level;
	uint8_t uid;
};

struct debug_clients {
	void **fd_list;
	int16_t *clients_num;
	pthread_mutex_t **mutex;
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
void update_routes( struct orig_node *orig_node, struct neigh_node *neigh_node, unsigned char *hna_recv_buff, int16_t hna_buff_len );
void update_gw_list( struct orig_node *orig_node, uint8_t new_gwflags );
int is_my_mac( uint8_t *addr );

#endif
