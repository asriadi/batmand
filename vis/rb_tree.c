/*
 * rb_tree.c
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
#include <pthread.h>
#include "rb_tree.h"

struct node *brother( struct node **node )
{
	if( (*node) != NULL && (*node)->father != NULL )
	{
		if( (*node) == (*node)->father->left )
			return (*node)->father->right;
		else
			return (*node)->father->left;
	} else
		return NULL;
}

struct node *uncle( struct node **node )
{
	if( (*node) != NULL && (*node)->father != NULL && (*node)->father->father != NULL )
	{
		if( (*node)->father == (*node)->father->father->left )
			return (*node)->father->father->right;
		else
			return (*node)->father->father->left;
	} else
		return NULL;
}

struct node *grandpa( struct node **node )
{
	if( (*node) != NULL && (*node)->father != NULL && (*node)->father->father != NULL )
	{
		return (*node)->father->father;
	} else
		return NULL;
}

static void left_rotation( struct node **node, struct node **root )
{
	struct node *x = (*node);
	struct node *y = x->right;
	struct node *alpha = x->left;
	struct node *beta = y->left;
	struct node *gamma = y->right;
	struct node *fx = x->father;

	/* printf("left rotation %d\n", x->addr); */

	if( fx != NULL )
	{
		if( (*node) == fx->left )
			fx->left = y;
		else
			fx->right = y;
	} else
		*root = y;

	y->father = fx;
	y->right = gamma;
	y->left = x;

	x->father = y;
	x->left = alpha;
	x->right = beta;

	if( alpha != NULL ) alpha->father = x;
	if( beta != NULL ) beta->father = x;
	if( gamma != NULL ) gamma->father = y;
	return;
}

static void right_rotation( struct node **node, struct node **root )
{
	struct node *y = (*node);
	struct node *x = y->left;
	struct node *alpha = x->left;
	struct node *beta = x->right;
	struct node *gamma = y->right;
	struct node *fy = y->father;

	/*printf("right rotation %d\n", y->addr );*/

	if( fy != NULL )
	{
		if( (*node) == fy->left )
			fy->left = x;
		else
			fy->right = x;
	} else
		*root = x;

	x->father = fy;
	x->left = alpha;
	x->right = y;

	y->father = x;
	y->left = beta;
	y->right = gamma;

	if( alpha != NULL ) alpha->father = x;
	if( beta != NULL ) beta->father = y;
	if( gamma != NULL ) gamma->father = y;
	return;
}

static void clearance( struct node **node, struct node **root )
{
	struct node *u = uncle( &(*node) ); 
	struct node *g = grandpa( &(*node) );
	struct node *f = (*node)->father;

	/*printf("clearance %d\n", (*node)->addr);*/

	if( f == NULL )
	{
		/*printf(" clear 1. %d\n", (*node)->addr );*/
		(*node)->color = black;
		return;
	} else {
		if( f->color == black )
		{
			/*printf(" clear 2. %d\n", f->addr );*/
			return;
		} else {
			if( u != NULL && u->color == red )
			{
				/*printf(" clear 3. %d\n", u->addr );*/
				f->color = black;
				u->color = black;
				g->color = red;
				clearance( &g, root );
			} else {
				if( (*node) == f->right && f == g->left )
				{
					/*printf(" clear 4a. %d\n", f->addr );*/
					left_rotation( &f, root );
					(*node) = (*node)->left;
					u = uncle( &(*node) );
					g = (*node)->father->father;
					f = (*node)->father;
				} else if ( (*node) == f->left && f == g->right ) {
					/*printf(" clear 4b. %d\n", f->addr );*/
					right_rotation( &f, root );
					(*node) = (*node)->right;
					u = uncle( &(*node) );
					g = (*node)->father->father;
					f = (*node)->father;
				}

				/*printf(" clear 5. %d\n", f->addr);*/
				f->color = black;
				g->color = red;
				if( (*node) == f->left && f == g->left )
					right_rotation( &g, root );
				else
					left_rotation( &g, root );
			}
		}
	}
	return;
}

/*void print_data(struct node *node)*/
/*{*/
	/*struct neighbour *neigh;*/
	
	/*char str[16];*/
	/*if(node != NULL)*/
	/*{*/
		/*print_data(node->left);*/
		/*addr_to_string(node->addr,str,sizeof(str));*/
		/*printf("node %-15s => %2u last seen => %2u\n",str,node->packet_count_average,node->last_seen);*/
		/*for(neigh = node->neighbour;neigh != NULL; neigh = neigh->next)*/
		/*{*/
			/*addr_to_string(neigh->node->addr,str,sizeof(str));*/
			/*printf("\tneighbour => %15s => %u\n", str, neigh->packet_count);	*/
		/*}*/
		/*print_data(node->right);	*/
	/*}*/
	/*return;*/
/*}*/



static int __calc_packet_count_average(struct node *node)
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

static void __add_neighbour_node(struct node *orig, unsigned char packet_count, struct neighbour **neigh)
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
	(*neigh)->node = orig;
	(*neigh)->packet_count = packet_count;
	(*neigh)->next = NULL;
	if(prev != NULL)
		prev->next = (*neigh);
	return;
}

struct node *__get_node(unsigned int addr,struct node **node)
{
	struct node **root = node;
	struct node *prev = (*node);

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
		else if( (*node)->addr > addr)
			node = &(*node)->left;
		else
			node = &(*node)->right;
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

		(*node)->left = (*node)->right = NULL;
		
		if( prev != NULL )
		{
			(*node)->father = prev;
			(*node)->color = red;
			clearance( &(*node), root );
		} else {
			(*node)->father = NULL;
			(*node)->color = black;
		}
		
		/*printf("create %d (%s)\n", (*node)->addr, (*node)->color == 0 ? "red" : "black");*/
	}
	return( (*node) );
}

/*void printtree( struct node *node )*/
/*{*/
	/*printf("%d (%s)\n", node->addr, node->color == 0 ? "red" : "black" );*/
	/*printf("go left\n");*/
	/*if( node->left != NULL )*/
		/*printtree( node->left );*/
	/*printf("back from left\n");*/
	/*printf("go right\n");*/
	/*if( node->right != NULL )*/
		/*printtree( node->right );*/
	/*printf("back from right\n");*/
	/*return;*/
/*}*/



void handle_node(unsigned int addr,unsigned int sender, unsigned char packet_count, struct node **root)
{
	struct node *src_node, *orig_node;
	
	orig_node = __get_node( addr, &(*root) );
	src_node  = __get_node( sender, &(*root) );
	__add_neighbour_node( orig_node, packet_count, &src_node->neighbour );
	src_node->packet_count_average = __calc_packet_count_average( src_node );
	return;
}

