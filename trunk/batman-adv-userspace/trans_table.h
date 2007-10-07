/*
 * Copyright (C) 2007 B.A.T.M.A.N. contributors:
 * Simon Wunderlich
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
 * trans_table.h 
 */

#include "dlist.h"
#include "list-batman.h"

struct trans_element_t {
	unsigned char mac[6], batman_mac[6];
	int age;
	struct dlist_head list_link;

};

int 			 transtable_init();
int 			 transtable_quit();
int 			 transtable_add( unsigned char *mac, unsigned char *batman_mac);
unsigned char 	*transtable_search( unsigned char *mac);
void 			 hna_add(unsigned char *mac, unsigned char *mymac);
void 			 hna_del(struct trans_element_t *elem);
void 			 hna_update();
void 			 hna_remove_list(struct dlist_head *list);
void 			 hna_add_buff( struct orig_node *orig_node);
void 			 hna_del_buff( struct orig_node *orig_node);
