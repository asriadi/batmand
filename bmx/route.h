/*
 * Copyright (C) 2006 BATMAN/BMX contributors:
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

#define DEV_LO "lo"
#define DEV_UNKNOWN "unknown"
#define MAX_MTU 1500


extern int32_t base_port;
#define ARG_BASE_PORT "base_port"
#define DEF_BASE_PORT 4305
#define MIN_BASE_PORT 1025
#define MAX_BASE_PORT 60000




/***
 *
 * Things you should leave as is unless your know what you are doing !
 *
 * RT_TABLE_INTERFACES	routing table for announced (non-primary) interfaces IPs and other unique IP addresses
 * RT_TABLE_HOSTS	routing table for routes towards originators
 * RT_TABLE_NETWORKS	routing table for announced networks
 * RT_TABLE_TUNNEL	routing table for the tunnel towards the internet gateway
 * RT_PRIO_DEFAULT	standard priority for routing rules
 * RT_PRIO_UNREACH	standard priority for unreachable rules
 * RT_PRIO_TUNNEL	standard priority for tunnel routing rules
 *
 ***/

#define RT_TABLE_INTERFACES -1
#define RT_TABLE_HOSTS      -2
#define RT_TABLE_NETWORKS   -3
#define RT_TABLE_TUNNEL     -4



extern uint8_t if_conf_soft_changed; // temporary enabled to trigger changed interface configuration
extern uint8_t if_conf_hard_changed; // temporary enabled to trigger changed interface configuration

extern int Mtu_min;


struct routes_node {
	struct list_node list;
	uint32_t dest;
	uint16_t netmask;
	uint16_t rt_table;
	uint32_t metric;
	int16_t rta_type;
	int8_t track_t;
};


struct rules_node {
	struct list_node list;
	uint32_t prio;
	char *iif;
	uint32_t network;
	int16_t netmask;
	int16_t rt_table;
	int16_t rta_type;
	int8_t track_t;
};



//track types:
enum {
	TRACK_NO,
	TRACK_STANDARD,    //basic rules to interfaces, host, and networks routing tables
	TRACK_MY_HNA,
	TRACK_MY_NET,
	TRACK_OTHER_HOST,
	TRACK_OTHER_HNA,
	TRACK_TUNNEL
};

void configure_route( uint32_t dest, int16_t mask, uint32_t metric, uint32_t gw, uint32_t src, int32_t ifi, char *dev,
                    int16_t rt_table_macro, int16_t rta_type, int8_t del, int8_t track_t );

/***
 *
 * rule types: 0 = RTA_SRC, 1 = RTA_DST, 2 = RTA_IIF
#define RTA_SRC 0
#define RTA_DST 1
#define RTA_IIF 2
 *
 ***/

// void add_del_rule( uint32_t network, uint8_t netmask, int16_t rt_macro, uint32_t prio, char *iif, int8_t rule_type, int8_t del, int8_t track_t );

enum {
 IF_RULE_SET_TUNNEL,
 IF_RULE_CLR_TUNNEL,
 IF_RULE_SET_NETWORKS,
 IF_RULE_CLR_NETWORKS,
 IF_RULE_UPD_ALL,
 IF_RULE_CHK_IPS
};

int update_interface_rules( uint8_t cmd );


void check_kernel_config( struct dev_node *dev_node );

//int8_t bind_to_iface( int32_t sock, char *dev );

//int is_interface_up(char *dev);
void dev_deactivate ( struct dev_node *dev_node );
void dev_check ();

void init_route( void );
void cleanup_route( void );

