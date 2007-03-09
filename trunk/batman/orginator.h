/* Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Simon Wunderlich, Marek Lindner
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



int orig_comp(void *data1, void *data2);
int orig_choose(void *data, int32_t size);
struct orig_node *get_orig_node( uint32_t addr );
void update_originator( struct orig_node *orig_node, struct packet *in, uint32_t neigh, struct batman_if *if_incoming, unsigned char *hna_recv_buff, int16_t hna_buff_len );
void purge_orginator( uint32_t curr_time );
void debug_orginator();

