/*
 * list.c
 *
 * Copyright (C) 2006 Andreas Langer <a.langer@q-dsl.de>:
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

#include <pthread.h>
#include "list.h"

static int calc_packet_count_average(struct node *node)
{
	struct neighbour *neigh;
	int pc = 0, cnt = 0;
	
	if(node->neighbour == NULL)
		return(0);
	
	for(neigh = node->neighbour; neigh != NULL; neigh = neigh->next)
	{
		pc += neigh->packet_count;
		cnt++;	
	}
	return(pc/cnt);
}

static void add_neighbour_node(struct node *orig, unsigned char packet_count, struct neighbour **neigh)
{		
	struct neighbour *prev = NULL;
		
	while( (*neigh) != NULL)
	{
		if( (*neigh)->node == orig)
		{
			(*neigh)->packet_count = packet_count;
			return;	
		}
		prev = (*neigh);
		neigh = &(*neigh)->next;
	}
		
	(*neigh) = (struct neighbour*)malloc(sizeof(struct neighbour));
	memset( (*neigh), 0, sizeof( struct neighbour ) ); 
	(*neigh)->node = orig;
	(*neigh)->packet_count = packet_count;
	(*neigh)->next = NULL;
	if(prev != NULL)
		prev->next = (*neigh);
	return;
}

struct node *get_node( unsigned int addr, struct node **node )
{
	struct node *prev = NULL;

	while( *node != NULL)
	{
		prev = *node;

		if( (*node)->addr == addr)
		{
			pthread_mutex_lock(&(*node)->mutex);
			(*node)->last_seen = 50;
			(*node)->deleted = 0;
			pthread_mutex_unlock(&(*node)->mutex);
			return( (*node) );
		}
		
		node = &(*node)->next;
	}

	if( (*node) == NULL)
	{
		
		(*node) = (struct node *)malloc(sizeof(struct node));
		(*node)->addr = addr;
		(*node)->neighbour = NULL;
		(*node)->packet_count_average = 0;
		(*node)->last_seen = 50;
		(*node)->deleted = 0;
		if(pthread_mutex_init(&(*node)->mutex, NULL) != 0)
		{
			printf("cannot create mutex.\n");
			exit (EXIT_FAILURE);
		}

		if( prev != NULL )
			prev->next = *node;
		(*node)->next = NULL;
		
	}
		
	return( (*node) );
}


void handle_node(unsigned int addr,unsigned int sender, unsigned char packet_count, struct node **root)
{
	struct node *src_node, *orig_node;
	
	orig_node = get_node( addr, &(*root) );
	src_node  = get_node( sender, &(*root) );

	add_neighbour_node( orig_node, packet_count, &src_node->neighbour );
	src_node->packet_count_average = calc_packet_count_average( src_node );
	return;
}

void addr_to_string(unsigned int addr, char *str, int len)
{
	inet_ntop(AF_INET, &addr, str, len);
	return;
}

void write_data_in_buffer( struct node *node )
{
	struct neighbour *neigh;
	
	char from_str[16];
	char to_str[16];
	char tmp[100];

	memset( tmp, '\0', sizeof( tmp ) );
	for( ; node != NULL; node = node->next )
	{
		
		for( neigh = node->neighbour; neigh != NULL; neigh = neigh->next )
		{
			addr_to_string( node->addr, from_str, sizeof( from_str ) );
			addr_to_string( neigh->node->addr, to_str, sizeof( to_str ) );
/*			snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"%s\"[label=\"10.00\"]\n", from_str, to_str );*/
			snprintf( tmp, sizeof( tmp ), "\"%s\" -> \"%s\"[label=\"%d\"]\n", from_str, to_str, ( int )neigh->packet_count );
			fillme->buffer = (char *)realloc( fillme->buffer, strlen( tmp ) + strlen( fillme->buffer ) + 1 );

			strncat( fillme->buffer, tmp, strlen( tmp ) );
		}

	}
	return;
}

