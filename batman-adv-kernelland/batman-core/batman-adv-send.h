/*
 * Copyright (C) 2007 B.A.T.M.A.N. contributors:
 * Marek Lindner
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





#include "types.h"



void start_bcast_timer(struct batman_if *batman_if);
void send_own_packet(unsigned long data);
void send_forward_packet(struct orig_node *orig_node, struct ethhdr *ethhdr, struct batman_packet *batman_packet, uint8_t udf, uint8_t idf, unsigned char *hna_buff, int hna_buff_len, struct batman_if *if_outgoing);
