/*
 * vis.h
 *
 * Copyright (C) 2006 Andreas Langer <a.langer@q-dsl.de>, Marek Lindner:
 *
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



#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>


#include "vis-types.h"
#include "hash.h"
#include "allocate.h"
#include "list-batman.h"



#define SOURCE_VERSION "0.1-alpha"  //put exactly one distinct word inside the string like "0.3-pre-alpha" or "0.3-rc1" or "0.3"
#define VERSION "0.1 alpha"
#define VIS_COMPAT_VERSION (128|20)

#define MAXCHAR 4096

#define VIS_PORT 4307
#define DOT_DRAW_PORT 2004

#define ADDR_STR_LEN 20




extern struct list_head_first vis_if_list;

extern pthread_t udp_server_thread;
extern pthread_t master_thread;
extern pthread_mutex_t hash_mutex;

extern struct hashtable_t *node_hash;
extern struct hashtable_t *secif_hash;

extern uint8_t debug_level;



struct thread_data {
	int socket;
	char ip[ADDR_STR_LEN];
};

struct neighbour {
	struct list_head list;
	uint8_t addr[6];
	unsigned char packet_count;
	unsigned char last_seen;
};

struct hna {
	struct list_head list;
	uint8_t addr[6];
	unsigned char netmask;
	unsigned char last_seen;
};

struct node {
	uint8_t addr[6];
	unsigned char last_seen;
	unsigned char gw_class;
	unsigned char seq_range;
	struct list_head_first neigh_list;
	struct list_head_first secif_list;
	struct list_head_first hna_list;
};

struct secif {
	uint8_t addr[6];
	struct node *orig;
};

struct secif_lst {
	struct list_head list;
	uint8_t addr[6];
	unsigned char last_seen;
};

typedef struct _buffer {
	char *buffer;
	int counter;
	struct _buffer *next;
	pthread_mutex_t mutex;
} buffer_t;

struct vis_if {
	struct list_head list;
	char *dev;
	int32_t udp_sock;
	int32_t tcp_sock;
	struct sockaddr_in udp_addr;
	struct sockaddr_in tcp_addr;
};

void clean_secif_hash();
void clean_node_hash();
void clean_buffer();
void exit_error(char *format, ...);
int8_t is_aborted();
void debug_output(char *format, ...);

void *udp_server();

void addr_to_string(unsigned char *addr, char *str, int len);
