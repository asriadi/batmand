/*
 * Copyright (C) 2008 B.A.T.M.A.N. contributors:
 * Simon Wunderlich
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

#define VIS_TIMEOUT		200000

struct vis_info {
	unsigned long       first_seen;
	struct timer_list   vis_timer;
	struct list_head   *receive_from_list;	
			/* list of server-neighbors we received a vis-packet from. 
			 * we should not reply to them. */
	struct vis_packet packet;
	/* vis_info may follow here*/
} __attribute__((packed));

struct vis_info_entry {
	uint8_t  dest[ETH_ALEN];
	uint8_t  quality;	/* quality = 0 means HNA */
} __attribute__((packed));

extern struct hashtable_t *vis_hash;
extern spinlock_t vis_hash_lock;

void receive_vis_packet(struct ethhdr *ethhdr, struct vis_packet *vis_packet, int vis_info_len);
int vis_init(void);
int vis_quit(void);
