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





#include "batman-adv-main.h"
#include "packet.h"		/* batman packet definitions */



struct batman_if
{
	struct list_head list;
	int16_t if_num;
	struct net_device *net_dev;
	struct socket *raw_sock;
	struct timer_list bcast_timer;
	uint16_t bcast_seqno;	/* give own bcast messages seq numbers to avoid broadcast storms */
	struct batman_packet out;
};

