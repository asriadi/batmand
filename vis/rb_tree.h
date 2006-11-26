#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>

enum farb_typ { red = 0, black };

struct neighbour {
	struct node *node;
	unsigned char packet_count;
	struct neighbour *next;	
};

struct node {
	unsigned int addr;
	int color;
	unsigned char packet_count_average;
	unsigned char last_seen;
	char deleted:1;
	struct neighbour *neighbour;
	struct node *left;
	struct node *right;
	struct node *father;
	pthread_mutex_t mutex;
};
extern char *buffer;

void handle_node(unsigned int addr,unsigned int sender, unsigned char packet_count, struct node **root );
void addr_to_string(unsigned int addr, char *str, int len);
void print_data(struct node *node);
void write_data_in_buffer( struct node *node );
void buffer_init();
void add_end();
