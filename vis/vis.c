#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include "rb_tree.h"

#define MAXCHAR 4096
#define PORT 1967
#define S3D_PORT 1968
#define ADDR_STR_LEN 16
#define PACKET_FIELDS 5

static int on = 1;
struct node *root = NULL;

void *udp_server (void *srv_addr)
{
	char recive_dgram[MAXCHAR];
	char addr_str[ADDR_STR_LEN];
	
	struct sockaddr_in server, client;
	int sock, n, packet_count,i;
	socklen_t len;
	
	sock = socket(PF_INET, SOCK_DGRAM,0 );

	memset( &server, 0, sizeof (server));
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	inet_pton(AF_INET, (char *)srv_addr,&server.sin_addr);

	if(server.sin_addr.s_addr == INADDR_NONE)
	{
		printf("invalid adress %s", (char *) srv_addr);
		exit(EXIT_FAILURE);
	}

	if(sock < 0)
	{
		printf("Cannot create socket => %s\n",strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0)
	{
		printf("Cannot enable ip: %s\n", strerror(errno));
		close(sock);
		exit(EXIT_FAILURE);			
	}
	
	if(bind( sock, (struct sockaddr*)&server, sizeof(server)) < 0)
	{
		printf("Error by bind => %s\n",strerror(errno));
		close(sock);
		exit(EXIT_FAILURE);
	}

	while(1)
	{
		int orig;
		len = sizeof(client);

		n = recvfrom(sock, recive_dgram, sizeof(recive_dgram), 0, (struct sockaddr*) &client, &len);
		addr_to_string(client.sin_addr.s_addr, addr_str, sizeof(addr_str));
		packet_count = n / PACKET_FIELDS;
		for( i=0;i < packet_count; i++)
		{
			memmove(&orig,(unsigned int*)&recive_dgram[i*PACKET_FIELDS],4);
			handle_node(orig,client.sin_addr.s_addr,(unsigned char)recive_dgram[i*PACKET_FIELDS+4], &root);

		}
	}
	close(sock);
	return( NULL );
}

int main(int argc, char **argv)
{
	int sd, client;
	struct sockaddr_in sa;

	pthread_t udp_server_thread;
	pthread_create( &udp_server_thread, NULL, &udp_server, argv[1] );
	
	char client_ip[16];

	if(argc < 2)
	{
		fprintf(stderr,"Usage: recon <ip>\n");
		return(EXIT_FAILURE);
	}

	if( ( sd = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
	{
		printf( "socket() failed: %s\n", strerror( errno ) );
		exit( EXIT_FAILURE );
	}

	memset( &sa, 0, sizeof( sa ) );
	sa.sin_family = AF_INET;
	sa.sin_port = htons( S3D_PORT );
	sa.sin_addr.s_addr = htonl( INADDR_ANY );
	
	if( setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int) ) < 0)
	{
		printf("Cannot enable ip: %s\n", strerror(errno));
		close( sd );
		exit(EXIT_FAILURE);			
	}
	
	if( bind( sd, ( struct sockaddr *)&sa, sizeof( sa ) ) < 0 )
	{
		printf( "bind() failed: %s\n", strerror( errno ) );
		exit( EXIT_FAILURE );
	}

	if( listen( sd, 32 ) < 0 )
	{
		printf( "listen() failed: %s\n", strerror( errno ) );
		close( sd );
		exit( EXIT_FAILURE );
	}

	for( ; ; )
	{
		if( ( client = accept( sd, NULL, NULL ) ) < 0 )
		{
			printf( "accept() failed: %s\n", strerror( errno ) );
			close( sd );
			exit( EXIT_FAILURE );
		}
		buffer_init();
		write_data_in_buffer( root );
		add_end();
		write( client, buffer, sizeof( buffer ) );

		sleep(2000);	
	}
	return EXIT_SUCCESS;
}

