/*
 * Copyright (C) 2007-2008 B.A.T.M.A.N. contributors:
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



#define BAT_HEADER_LEN sizeof(struct ethhdr) + (sizeof(struct unicast_packet) > sizeof(struct bcast_packet) ? sizeof(struct unicast_packet) : sizeof(struct bcast_packet))
#define BAT_IF_MTU 1500 - BAT_HEADER_LEN



void interface_setup(struct net_device *dev);
int interface_open(struct net_device *dev);
int interface_release(struct net_device *dev);
struct net_device_stats *interface_stats(struct net_device *dev);
int interface_change_mtu(struct net_device *dev, int new_mtu);
int interface_tx(struct sk_buff *skb, struct net_device *dev);
void interface_rx(struct net_device *dev, void *packet, int packet_len);
