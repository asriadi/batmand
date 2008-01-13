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
 * trans_table.c - implements a MAC translation table
 *
 */

#include <string.h>			/* memcpy() */
#include <stdlib.h>			/* malloc(), free() */
#include <stdio.h>			/* printf() */
#include "hash.h"			/* hash_* functions */
#include "originator.h"		/* compare_orig(), choose_orig() */
#include "os.h"				/* debug_output(), addr_to_string() */
#include "trans_table.h"	/* our prototype */


int					 hna_changed = 0;
uint32_t 			 num_hna;
uint8_t 			*hna_buff;
struct dlist_head 	 hna_list;
struct hashtable_t 	*trans_hash;
unsigned char 		 bcast_addr[6]= { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			  		 zero_addr[6]= {     0,    0,    0,    0,    0,    0};
/* initialize the translation table hash */
int transtable_init() {
	INIT_DLIST_HEAD(&hna_list);
	trans_hash= hash_new( 4096, compare_orig, choose_orig);
	/* add ourselves */
	if (trans_hash != NULL)
		hna_add(((struct batman_if *)if_list.next)->hw_addr, ((struct batman_if *)if_list.next)->hw_addr);
	return ( (trans_hash == NULL)?-1:0 );
}

int transtable_quit() {
	hash_delete(trans_hash, free);
	return (0);
}
/* check if a payload MAC-address is already in the hash-table and add it if it's new */
int transtable_add(unsigned char *mac, unsigned char *batman_mac) {
	struct trans_element_t *elem;
	/* ignore broadcast, multicast and zero */
	if (memcmp( mac, bcast_addr, 6) == 0) return(-1);
	if (memcmp( mac, zero_addr, 6) == 0) return(-1);
	if ((mac[0] == 0x01) && (mac[1] == 0x00) && (mac[2] == 0x5e) && (!(mac[3] & 0x80))) return(-1);

	elem = hash_find(trans_hash, mac);	/* first check, then add saves us a malloc() in
										 * most of the times where no mac is to add,
										 * so this should be faster */
	if (elem != NULL)
		if (memcmp(batman_mac, elem->batman_mac, 6) != 0) {
			/* host changed to a new batman_mac. delete it and reassign. */
			dlist_del(&elem->list_link);
			hash_remove(trans_hash, elem);
			if (is_my_mac(elem->batman_mac))	/* node switched to some of our neighbours. */
				hna_changed = 1;
			free(elem);
			elem= NULL;
		}
	/* (re)assign a new element */
	if (elem == NULL) {
		elem = malloc(sizeof(struct trans_element_t));
		INIT_DLIST_HEAD(&(elem->list_link));
		memcpy(elem->mac, mac, 6);
		memcpy(elem->batman_mac, batman_mac, 6);
		elem->age= curr_time;
		hash_add(trans_hash, elem);
		debug_output( 3, "MAC: Add %s\n",	addr_to_string_static(mac));
		debug_output( 3, "MAC: to originator %s\n",	addr_to_string_static(batman_mac));
		return(0);
	}
	return(-1);
}

/* Returns the batman interface address which matches to the payload MAC-address, or NULL if it could not be found. */
unsigned char *transtable_search(unsigned char *mac) {
	struct trans_element_t *elem;

	elem= hash_find(trans_hash, mac);
	if ( elem != NULL)	{
/*		debug_output( 4, "HNA: transtable_search Found MAC %s at ",	addr_to_string(elem->mac));
		debug_output( 4, "HNA: at %s\n",							addr_to_string(elem->batman_mac)); */

		return(elem->batman_mac);
	}
	else {
/*		debug_output( 4, "HNA: transtable_search COULD NOT FIND MAC %s at ",	addr_to_string(mac)); */
		return(NULL);
	}
}
/* delete an host from the table */
void hna_del(struct trans_element_t *elem)
{

/*	debug_output(4, "HNA: hna_del(%s) \n", addr_to_string(elem->mac) ); */
	dlist_del(&elem->list_link);
	hash_remove(trans_hash, elem);
	free(elem);

}
/* check if already in hna buff and add if needed */
void hna_add(unsigned char *mac, unsigned char *mymac)
{
	struct trans_element_t *elem;
	elem = hash_find(trans_hash, mac);

	debug_output(3, "HNA: hna_add(%s) \n", addr_to_string_static(mac) );
	if (elem != NULL) {
		if (is_my_mac(elem->batman_mac)) {
			elem->age = curr_time;
			return;
		} else {		/* this host moved to my place. */
			hna_del(elem);
			elem = NULL;
		}
	}
	if (elem == NULL) { /* not found or deleted */
		transtable_add( mac, mymac);
		elem = hash_find(trans_hash, mac);
		if (elem != NULL) {
			elem->age = curr_time;
			dlist_add(&elem->list_link, &hna_list);
			hna_changed = 1;

		} else {
			/* something went wrong. Maybe it got into the broadcast
			 * checker or something. */
			return;
		}
	}
}

/* removes all entries from a hna_list from the hash*/
void hna_remove_list(struct dlist_head *list) {
	struct trans_element_t *elem, *tmp;
	dlist_for_each_entry_safe(elem, tmp, list, list_link) {
		hna_del(elem);
	}

}

/* iterate through the list and remove old entries */
void hna_update()
{
	struct trans_element_t *elem, *tmp;
	int cnt_hna = 0;

/*	debug_output(4, "HNA: hna_update() (curr_time = %d)", curr_time);*/
	dlist_for_each_entry_safe(elem, tmp, &hna_list, list_link) {
		/* purge old entries, but never ourselves */
		if (((curr_time - elem->age) > AGE_THRESHOLD) && (memcmp(elem->mac, ((struct batman_if *)if_list.next)->hw_addr, 6)!= 0)) {
			debug_output(3, "HNA: hna_update: purge old mac %s.\n", addr_to_string_static(elem->mac) );
			hna_del(elem);
			hna_changed = 1;
		} else
			cnt_hna++;
	}
	if (hna_changed == 1) {
		/* rewrite the HNA-buffer */
		num_hna = cnt_hna;
		hna_buff = debugRealloc(hna_buff, num_hna*6, 601);
		debug_output(3, "HNA: Local HNA changed: (%d hnas counted)\n", cnt_hna );
		cnt_hna = 0;
		dlist_for_each_entry(elem, &hna_list, list_link) {
			debug_output(3, "HNA: %d: %s  \n", cnt_hna, addr_to_string_static(elem->mac));
			memcpy(&hna_buff[6*cnt_hna], elem->mac, 6);
			cnt_hna++;
		}
		hna_changed = 0;

		/* only announce as many hosts as possible in the batman-packet and space in batman_packet->num_hna
		   That also should give a limit to MAC-flooding. */
		if ((num_hna > (tap_mtu - BATMAN_MAXFRAMESIZE)/6) || (num_hna > 255))
			num_hna = ((tap_mtu - BATMAN_MAXFRAMESIZE)/6 > 255 ? 255 : (tap_mtu - BATMAN_MAXFRAMESIZE)/6);

		((struct batman_if *)if_list.next)->out.num_hna = num_hna;
	}
}

/* add the hosts from the hna_buff into the hashtable and linked list */
void hna_add_buff(struct orig_node *orig_node)
{
	int 				 	 i;
	unsigned char 			*host;
	struct trans_element_t  *elem;

	for (i = 0 ; i < orig_node->hna_buff_len/6 ; i++) {
		host = &orig_node->hna_buff[i * 6];
		if (transtable_add(host, orig_node->orig) == 0) {
			elem = hash_find(trans_hash, host);
			dlist_add(&elem->list_link, &orig_node->hna_list);
		}
	}
}

/* removes and clears the hna_list from an orig_node */
void hna_del_buff( struct orig_node *orig_node)
{
	hna_remove_list(&orig_node->hna_list);
	debugFree(orig_node->hna_buff, 1101);
	orig_node->hna_buff_len = 0;
}

