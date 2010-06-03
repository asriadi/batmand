/*
 * Copyright (C) 2010 BMX contributors:
 * Axel Neumann
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
 */


#define ARG_UHNA "unicast_hna"
#define ARG_HNAS "uhnas"

struct uhna4_key {
	uint8_t reserved;
	uint8_t prefix_len;
	IP4_T glip4;
	uint32_t metric_be;
};

struct uhna4_node {
	struct uhna4_key key;
	struct orig_node *on;
};

extern struct avl_tree global_uhna_tree;
extern struct avl_tree local_uhna_tree;

struct plugin_v2 *hna_get_plugin_v2( void );

void set_uhna4_key(struct uhna4_key *key, uint8_t prefix_len, IP4_T glip4, uint32_t metric);

int create_description_tlv_ip4(uint8_t *data, uint16_t max_size);
int create_description_tlv_hna4(uint8_t *data, uint16_t max_size);

int process_description_tlv_hna4(struct orig_node *on, struct frame_header *tlv, IDM_T op, struct ctrl_node *cn );


//struct uhna4_node *get_global_uhna_node( struct uhna4_key* key );

