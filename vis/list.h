/*
 * list.h
 *
 * Copyright (C) 2006 Andreas Langer <andreas_lbg@gmx.de>:
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


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>


struct neighbour {
	struct node *node;
	unsigned char packet_count;
	struct neighbour *next;	
};

struct node {
	unsigned int addr;
	unsigned char packet_count_average;
	unsigned char last_seen;
	char deleted:1;
	struct neighbour *neighbour;
	struct node *next;
	pthread_mutex_t mutex;
};

typedef struct _buffer {
	char *buffer;
	int counter;
	struct _buffer *next;
	pthread_mutex_t mutex;
} buffer_t;

extern buffer_t *fillme;

void handle_node(unsigned int addr,unsigned int sender, unsigned char packet_count, struct node **root );
void write_data_in_buffer( struct node *node );
void addr_to_string(unsigned int addr, char *str, int len);
