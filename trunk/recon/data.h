#ifndef DATA_H_
#define DATA_H_

#include <pthread.h>

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
	struct node *right;
	struct node *left;
	pthread_mutex_t mutex;
};

void handle_node(unsigned int addr,unsigned int sender, unsigned char packet_count);
void addr_to_string(unsigned int addr, char *str, int len);
void print_data();
void *node_cleaner(void *notused);

#endif /*DATA_H_*/
