#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "data.h"


static struct node *root_node = NULL;

static void *__get_batman_node(unsigned int addr,struct node **node)
{
	while(*node != NULL)
	{
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
	}
	return( (*node) );
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

static void __print_data(struct node *node)
{
	struct neighbour *neigh;
	
	char str[16];
	if(node != NULL)
	{
		__print_data(node->left);
		addr_to_string(node->addr,str,sizeof(str));
		printf("node %s => %u last seen => %u\n",str,node->packet_count_average,node->last_seen);
		for(neigh = node->neighbour;neigh != NULL; neigh = neigh->next)
		{
			addr_to_string(neigh->node->addr,str,sizeof(str));
			printf("\tneighbour => %s => %u\n", str, neigh->packet_count);	
		}
		__print_data(node->right);	
	}
	return;
}

static void __scan_nodes(struct node **node)
{
	if( (*node) != NULL)
	{
		__scan_nodes( &(*node)->left);
		if( (*node)->last_seen == 0 && (*node)->deleted == 0 )
		{
			/*printf("delete node %u %u\n", (*node)->addr,(*node)->last_seen);*/
			pthread_mutex_lock(&(*node)->mutex);
			(*node)->deleted = 1;
			pthread_mutex_unlock(&(*node)->mutex);
		} else {
			pthread_mutex_lock(&(*node)->mutex);
			(*node)->last_seen--;
			pthread_mutex_unlock(&(*node)->mutex);
			/*printf("last seen %u -1 for %u\n",(*node)->last_seen,(*node)->addr);*/
		}
		__scan_nodes( &(*node)->right);	
	}
	return;
}

void addr_to_string(unsigned int addr, char *str, int len)
{
	inet_ntop(AF_INET, &addr, str, len);
	return;
}

void handle_node(unsigned int addr,unsigned int sender, unsigned char packet_count)
{
	struct node *src_node, *orig_node;
	
	orig_node = __get_batman_node(addr,&root_node);
	src_node = __get_batman_node(sender,&root_node);
	__add_neighbour_node(orig_node,packet_count,&src_node->neighbour);
	src_node->packet_count_average = __calc_packet_count_average(src_node);
	return;
}

void print_data()
{
	printf("----------data-----------------\n");
	__print_data(root_node);
	return;
}

void *node_cleaner(void *notused)
{	
	while(1)
	{
		__scan_nodes(&root_node);
		sleep(3);
	}
	return NULL;
}
