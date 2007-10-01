/*
 * Copyright (C) 2006 BATMAN contributors:
 * Thomas Lopatic, Marek Lindner
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



#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <paths.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>


#include "../os.h"
#include "../batman.h"

#define IOCSETDEV 1

int8_t stop;



int my_daemon() {

	int fd;

	switch( fork() ) {

		case -1:
			return -1;

		case 0:
			break;

		default:
			exit(EXIT_SUCCESS);

	}

	if ( setsid() == -1 )
		return(-1);

	/* Make certain we are not a session leader, or else we might reacquire a controlling terminal */
	if ( fork() )
		exit(EXIT_SUCCESS);

	chdir( "/" );

	if ( ( fd = open(_PATH_DEVNULL, O_RDWR, 0) ) != -1 ) {

		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if ( fd > 2 )
			close(fd);

	}

	return 0;

}



void apply_init_args( int argc, char *argv[] ) {

	struct in_addr tmp_ip_holder;
	struct batman_if *batman_if;
	struct hna_node *hna_node;
	struct debug_level_info *debug_level_info;
	struct list_head *list_pos;
	uint8_t found_args = 1, batch_mode = 0;
	uint16_t netmask;
	int8_t res;

	int32_t optchar, option_index, recv_buff_len, bytes_written, download_speed = 0, upload_speed = 0;
	char str1[16], str2[16], *slash_ptr, *unix_buff, *buff_ptr, *cr_ptr;
	char routing_class_opt = 0, gateway_class_opt = 0, pref_gw_opt = 0;
	uint32_t vis_server = 0;
	static struct option long_options[] =
	{
		{"no-policy-routing",     no_argument,       0, 'n'},
		{0, 0, 0, 0}
	};

	memset( &tmp_ip_holder, 0, sizeof (struct in_addr) );
	stop = 0;
	prog_name = argv[0];


	printf( "WARNING: You are using the unstable batman branch. If you are interested in *using* batman get the latest stable release !\n" );

	while ( ( optchar = getopt_long( argc, argv, "a:bcd:hHo:g:p:r:s:vV", long_options, &option_index ) ) != -1 ) {

		switch ( optchar ) {

			case 'a':

				if ( ( slash_ptr = strchr( optarg, '/' ) ) == NULL ) {

					printf( "Invalid announced network (netmask is missing): %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				*slash_ptr = '\0';

				if ( inet_pton( AF_INET, optarg, &tmp_ip_holder ) < 1 ) {

					*slash_ptr = '/';
					printf( "Invalid announced network (IP is invalid): %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				errno = 0;

				netmask = strtol( slash_ptr + 1, NULL, 10 );

				if ( ( errno == ERANGE ) || ( errno != 0 && netmask == 0 ) ) {

					perror("strtol");
					exit(EXIT_FAILURE);

				}

				if ( netmask < 1 || netmask > 32 ) {

					*slash_ptr = '/';
					printf( "Invalid announced network (netmask is invalid): %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				hna_node = debugMalloc( sizeof(struct hna_node), 203 );
				memset( hna_node, 0, sizeof(struct hna_node) );
				INIT_LIST_HEAD( &hna_node->list );

				hna_node->addr = tmp_ip_holder.s_addr;
				hna_node->netmask = netmask;

				list_add_tail( &hna_node->list, &hna_list );

				*slash_ptr = '/';


				/* increment found_args only by one if optarg and optchar are directly following each other
				   increment found_args by two if there is some space between the arguments */
				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'b':
				batch_mode++;
				break;

			case 'c':
				unix_client++;
				break;

			case 'd':

				errno = 0;

				debug_level = strtol( optarg, NULL, 10 );

				if ( ( errno == ERANGE ) || ( errno != 0 && debug_level == 0 ) ) {

					perror("strtol");
					exit(EXIT_FAILURE);

				}

				if ( debug_level > debug_level_max ) {

					printf( "Invalid debug level: %i\nDebug level has to be between 0 and %i.\n", debug_level, debug_level_max );
					exit(EXIT_FAILURE);

				}

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'g':

				if ( ( slash_ptr = strchr( optarg, '/' ) ) != NULL )
					*slash_ptr = '\0';

				errno = 0;

				download_speed = strtol( optarg, NULL, 10 );

				if ( ( errno == ERANGE ) || ( errno != 0 && download_speed == 0 ) ) {

					perror("strtol");
					exit(EXIT_FAILURE);

				}

				if ( ( strlen( optarg ) > 4 ) && ( ( strncmp( optarg + strlen( optarg ) - 4, "MBit", 4 ) == 0 ) || ( strncmp( optarg + strlen( optarg ) - 4, "mbit", 4 ) == 0 ) || ( strncmp( optarg + strlen( optarg ) - 4, "Mbit", 4 ) == 0 ) ) )
					download_speed *= 1024;

				if ( slash_ptr != NULL ) {

					errno = 0;

					upload_speed = strtol( slash_ptr + 1, NULL, 10 );

					if ( ( errno == ERANGE ) || ( errno != 0 && upload_speed == 0 ) ) {
						perror("strtol");
						exit(EXIT_FAILURE);
					}

					if ( ( strlen( slash_ptr + 1 ) > 4 ) && ( ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "MBit", 4 ) == 0 ) || ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "mbit", 4 ) == 0 ) || ( strncmp( slash_ptr + 1 + strlen( slash_ptr + 1 ) - 4, "Mbit", 4 ) == 0 ) ) )
						upload_speed *= 1024;

					*slash_ptr = '/';

				}

				gateway_class_opt = 1;

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'H':
				verbose_usage();
				exit(EXIT_SUCCESS);

			case 'n':
				no_policy_routing = 1;
				found_args++;
				break;

			case 'o':

				errno = 0;

				originator_interval = strtol( optarg, NULL, 10 );

				if ( originator_interval < 1 ) {

					printf( "Invalid originator interval specified: %i.\nThe Interval has to be greater than 0.\n", originator_interval );
					exit(EXIT_FAILURE);

				}

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'p':

				errno = 0;

				if ( inet_pton( AF_INET, optarg, &tmp_ip_holder ) < 1 ) {

					printf( "Invalid preferred gateway IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				pref_gateway = tmp_ip_holder.s_addr;

				pref_gw_opt = 1;

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'r':

				errno = 0;

				routing_class = strtol( optarg, NULL, 10 );

				if ( routing_class > 3 ) {

					printf( "Invalid routing class specified: %i.\nThe class is a value between 0 and 3.\n", routing_class );
					exit(EXIT_FAILURE);

				}

				routing_class_opt = 1;

				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 's':

				errno = 0;
				if ( inet_pton( AF_INET, optarg, &tmp_ip_holder ) < 1 ) {

					printf( "Invalid preferred visualation server IP specified: %s\n", optarg );
					exit(EXIT_FAILURE);

				}

				vis_server = tmp_ip_holder.s_addr;


				found_args += ( ( *((char*)( optarg - 1)) == optchar ) ? 1 : 2 );
				break;

			case 'v':

				printf( "B.A.T.M.A.N. %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
				exit(EXIT_SUCCESS);

			case 'V':

				print_animation();

				printf( "\x1B[0;0HB.A.T.M.A.N. %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );
				printf( "\x1B[9;0H \t May the bat guide your path ...\n\n\n" );

				exit(EXIT_SUCCESS);

			case 'h':
			default:
				usage();
				exit(EXIT_SUCCESS);

		}

	}

	if ( ( download_speed > 0 ) && ( upload_speed == 0 ) )
		upload_speed = download_speed / 5;

	if ( download_speed > 0 ) {

		gateway_class = get_gw_class( download_speed, upload_speed );
		get_gw_speeds( gateway_class, &download_speed, &upload_speed );

	}


	if ( ( gateway_class != 0 ) && ( routing_class != 0 ) ) {
		fprintf( stderr, "Error - routing class can't be set while gateway class is in use !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	if ( ( gateway_class != 0 ) && ( pref_gateway != 0 ) ) {
		fprintf( stderr, "Error - preferred gateway can't be set while gateway class is in use !\n" );
		usage();
		exit(EXIT_FAILURE);
	}

	/* use routing class 1 if none specified */
	if ( ( routing_class == 0 ) && ( pref_gateway != 0 ) )
		routing_class = 1;

	if ( ( ( routing_class != 0 ) || ( gateway_class != 0 ) ) && ( !probe_tun() ) )
		exit(EXIT_FAILURE);

	if ( ! unix_client ) {

		if ( argc <= found_args ) {

			fprintf( stderr, "Error - no interface specified\n" );
			usage();
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		signal( SIGINT, handler );
		signal( SIGTERM, handler );
		signal( SIGPIPE, SIG_IGN );
		signal( SIGSEGV, segmentation_fault );

		debug_clients.fd_list = debugMalloc( sizeof(struct list_head_first *) * debug_level_max, 203 );
		debug_clients.mutex = debugMalloc( sizeof(pthread_mutex_t *) * debug_level_max, 209 );
		debug_clients.clients_num = debugMalloc( sizeof(int16_t) * debug_level_max, 209 );

		for ( res = 0; res < debug_level_max; res++ ) {

			debug_clients.fd_list[res] = debugMalloc( sizeof(struct list_head_first), 204 );
			((struct list_head_first *)debug_clients.fd_list[res])->next = debug_clients.fd_list[res];
			((struct list_head_first *)debug_clients.fd_list[res])->prev = debug_clients.fd_list[res];

			debug_clients.mutex[res] = debugMalloc( sizeof(pthread_mutex_t), 209 );
			pthread_mutex_init( (pthread_mutex_t *)debug_clients.mutex[res], NULL );

			debug_clients.clients_num[res] = 0;

		}

		if ( flush_routes_rules(0) < 0 ) {

			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( flush_routes_rules(1) < 0 ) {

			restore_defaults();
			exit(EXIT_FAILURE);

		}


		FD_ZERO( &receive_wait_set );

		while ( argc > found_args ) {

			batman_if = debugMalloc( sizeof(struct batman_if), 206 );
			memset( batman_if, 0, sizeof(struct batman_if) );
			INIT_LIST_HEAD( &batman_if->list );

			batman_if->dev = argv[found_args];
			batman_if->if_num = found_ifs;
			batman_if->udp_tunnel_sock = 0;

			list_add_tail( &batman_if->list, &if_list );

			init_interface ( batman_if );

			if ( batman_if->if_num > 0 ) {

				hna_node = debugMalloc( sizeof(struct hna_node), 207 );
				memset( hna_node, 0, sizeof(struct hna_node) );
				INIT_LIST_HEAD( &hna_node->list );

				hna_node->addr = batman_if->addr.sin_addr.s_addr;
				hna_node->netmask = 32;

				list_add_tail( &hna_node->list, &hna_list );

			}

			if ( batman_if->udp_recv_sock > receive_max_sock )
				receive_max_sock = batman_if->udp_recv_sock;

			FD_SET( batman_if->udp_recv_sock, &receive_wait_set );

			addr_to_string( batman_if->addr.sin_addr.s_addr, str1, sizeof (str1) );
			addr_to_string( batman_if->broad.sin_addr.s_addr, str2, sizeof (str2) );

			printf( "Using interface %s with address %s and broadcast address %s\n", batman_if->dev, str1, str2 );

			found_ifs++;
			found_args++;

		}


		unlink( UNIX_PATH );
		unix_if.unix_sock = socket( AF_LOCAL, SOCK_STREAM, 0 );

		memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );
		unix_if.addr.sun_family = AF_LOCAL;
		strcpy( unix_if.addr.sun_path, UNIX_PATH );

		if ( bind ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof (struct sockaddr_un) ) < 0 ) {

			printf( "Error - can't bind unix socket '%s': %s\n", UNIX_PATH, strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( listen( unix_if.unix_sock, 10 ) < 0 ) {

			printf( "Error - can't listen unix socket '%s': %s\n", UNIX_PATH, strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		/* daemonize */
		if ( debug_level == 0 ) {

			if ( my_daemon() < 0 ) {

				printf( "Error - can't fork to background: %s\n", strerror(errno) );
				restore_defaults();
				exit(EXIT_FAILURE);

			}

			openlog( "batmand", LOG_PID, LOG_DAEMON );

		} else {

			printf( "B.A.T.M.A.N. %s%s (compatibility version %i)\n", SOURCE_VERSION, ( strncmp( REVISION_VERSION, "0", 1 ) != 0 ? REVISION_VERSION : "" ), COMPAT_VERSION );

			debug_clients.clients_num[ debug_level - 1 ]++;
			debug_level_info = debugMalloc( sizeof(struct debug_level_info), 205 );
			INIT_LIST_HEAD( &debug_level_info->list );
			debug_level_info->fd = 1;
			list_add( &debug_level_info->list, (struct list_head_first *)debug_clients.fd_list[debug_level - 1] );

		}

		pthread_create( &unix_if.listen_thread_id, NULL, &unix_listen, NULL );

		/* add rule for hna networks */
		add_del_rule( 0, 0, BATMAN_RT_TABLE_NETWORKS, BATMAN_RT_PRIO_UNREACH - 1, 0, 1, 0 );

		/* add unreachable routing table entry */
		add_del_route( 0, 0, 0, 0, 0, "unknown", BATMAN_RT_TABLE_UNREACH, 2, 0 );

		if ( routing_class > 0 ) {

			if ( add_del_interface_rules( 0 ) < 0 ) {

				restore_defaults();
				exit(EXIT_FAILURE);

			}

		}

		memset( &vis_if, 0, sizeof(vis_if) );

		if ( vis_server ) {

			vis_if.addr.sin_family = AF_INET;
			vis_if.addr.sin_port = htons(PORT + 2);
			vis_if.addr.sin_addr.s_addr = vis_server;
			vis_if.sock = socket( PF_INET, SOCK_DGRAM, 0 );

		}

		if ( gateway_class != 0 ) {

			list_for_each( list_pos, &if_list ) {

				batman_if = list_entry( list_pos, struct batman_if, list );

				init_interface_gw( batman_if );

			}

		}


		if ( debug_level > 0 ) {

			printf( "debug level: %i\n", debug_level );

			if ( originator_interval != 1000 )
				printf( "originator interval: %i\n", originator_interval );

			if ( gateway_class > 0 )
				printf( "gateway class: %i -> propagating: %i%s/%i%s\n", gateway_class, ( download_speed > 2048 ? download_speed / 1024 : download_speed ), ( download_speed > 2048 ? "MBit" : "KBit" ), ( upload_speed > 2048 ? upload_speed / 1024 : upload_speed ), ( upload_speed > 2048 ? "MBit" : "KBit" ) );

			if ( routing_class > 0 )
				printf( "routing class: %i\n", routing_class );

			if ( pref_gateway > 0 ) {
				addr_to_string( pref_gateway, str1, sizeof(str1) );
				printf( "preferred gateway: %s\n", str1 );
			}

			if ( vis_server > 0 ) {
				addr_to_string( vis_server, str1, sizeof(str1) );
				printf( "visualisation server: %s\n", str1 );
			}

		}

	/* connect to running batmand via unix socket */
	} else {

		unix_if.unix_sock = socket( AF_LOCAL, SOCK_STREAM, 0 );

		memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );
		unix_if.addr.sun_family = AF_LOCAL;
		strcpy( unix_if.addr.sun_path, UNIX_PATH );

		if ( connect ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof(struct sockaddr_un) ) < 0 ) {

			printf( "Error - can't connect to unix socket '%s': %s ! Is batmand running on this host ?\n", UNIX_PATH, strerror(errno) );
			close( unix_if.unix_sock );
			exit(EXIT_FAILURE);

		}

		unix_buff = debugMalloc( 1501, 5001 );

		if ( debug_level > 0 ) {

			if ( debug_level <= debug_level_max ) {

				snprintf( unix_buff, 10, "d:%c", debug_level );

				if ( ( debug_level > 2 ) && ( batch_mode ) )
					printf( "WARNING: Your chosen debug level (%i) does not support batch mode !\n", debug_level );

			}

		} else if ( routing_class_opt ) {

			batch_mode = 1;
			snprintf( unix_buff, 10, "r:%c", routing_class );

		} else if ( pref_gw_opt ) {

			batch_mode = 1;
			addr_to_string( pref_gateway, str1, sizeof(str1) );
			snprintf( unix_buff, 20, "p:%s", str1 );

		} else if ( gateway_class_opt ) {

			batch_mode = 1;
			snprintf( unix_buff, 10, "g:%c", gateway_class );

		} else {

			batch_mode = 1;
			snprintf( unix_buff, 10, "i" );

		}

		if ( write( unix_if.unix_sock, unix_buff, 20 ) < 0 ) {

			printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
			close( unix_if.unix_sock );
			debugFree( unix_buff, 5101 );
			exit(EXIT_FAILURE);

		}

		while ( ( recv_buff_len = read( unix_if.unix_sock, unix_buff, 1500 ) ) > 0 ) {

			unix_buff[recv_buff_len] = '\0';

			buff_ptr = unix_buff;
			bytes_written = 0;

			while ( ( cr_ptr = strchr( buff_ptr, '\n' ) ) != NULL ) {

				*cr_ptr = '\0';

				if ( strncmp( buff_ptr, "EOD", 3 ) == 0 ) {

					if ( batch_mode ) {

						close( unix_if.unix_sock );
						debugFree( unix_buff, 5102 );
						exit(EXIT_SUCCESS);

					}

				} else if ( strncmp( buff_ptr, "BOD", 3 ) == 0 ) {

					if ( !batch_mode )
						system( "clear" );

				} else {

					printf( "%s\n", buff_ptr );

				}

				bytes_written += strlen( buff_ptr ) + 1;
				buff_ptr = cr_ptr + 1;

			}

			if ( bytes_written != recv_buff_len )
				printf( "%s", buff_ptr );

		}

		close( unix_if.unix_sock );
		debugFree( unix_buff, 5103 );

		if ( recv_buff_len < 0 ) {

			printf( "Error - can't read from unix socket: %s\n", strerror(errno) );
			exit(EXIT_FAILURE);

		} else {

			printf( "Connection terminated by remote host\n" );

		}

		exit(EXIT_SUCCESS);

	}

}



void init_interface ( struct batman_if *batman_if ) {

	struct ifreq int_req;
	int16_t on = 1;


	if ( strlen( batman_if->dev ) > IFNAMSIZ - 1 ) {
		printf( "Error - interface name too long: %s\n", batman_if->dev );
		restore_defaults();
		exit(EXIT_FAILURE);
	}

	if ( ( batman_if->udp_recv_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

		printf( "Error - can't create receive socket: %s", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	memset( &int_req, 0, sizeof (struct ifreq) );
	strncpy( int_req.ifr_name, batman_if->dev, IFNAMSIZ - 1 );

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFADDR, &int_req ) < 0 ) {

		printf( "Error - can't get IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	batman_if->addr.sin_family = AF_INET;
	batman_if->addr.sin_port = htons(PORT);
	batman_if->addr.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr;

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFBRDADDR, &int_req ) < 0 ) {

		printf( "Error - can't get broadcast IP address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	batman_if->broad.sin_family = AF_INET;
	batman_if->broad.sin_port = htons(PORT);
	batman_if->broad.sin_addr.s_addr = ((struct sockaddr_in *)&int_req.ifr_broadaddr)->sin_addr.s_addr;

	if ( batman_if->broad.sin_addr.s_addr == 0 ) {

		printf( "Error - invalid broadcast address detected (0.0.0.0): %s\n", batman_if->dev );
		restore_defaults();
		exit(EXIT_FAILURE);

	}


#ifdef __linux__
	/* The SIOCGIFINDEX ioctl is Linux specific, but I am not yet sure if the
	 * equivalent exists on *BSD. There is a function called if_nametoindex()
	 * on both Linux and BSD.
	 * Maybe it does the same as this code and we can simply call it instead?
	 * --stsp
	 */
	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFINDEX, &int_req ) < 0 ) {

		printf( "Error - can't get index of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	batman_if->if_index = int_req.ifr_ifindex;
#else
	batman_if->if_index = 0;
#endif

	if ( ioctl( batman_if->udp_recv_sock, SIOCGIFNETMASK, &int_req ) < 0 ) {

		printf( "Error - can't get netmask address of interface %s: %s\n", batman_if->dev, strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

	batman_if->netaddr = ( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr & batman_if->addr.sin_addr.s_addr );
	batman_if->netmask = bit_count( ((struct sockaddr_in *)&int_req.ifr_addr)->sin_addr.s_addr );

	add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_HOSTS, BATMAN_RT_PRIO_DEFAULT + batman_if->if_num, 0, 1, 0 );
	add_del_rule( batman_if->netaddr, batman_if->netmask, BATMAN_RT_TABLE_UNREACH, BATMAN_RT_PRIO_UNREACH + batman_if->if_num, 0, 1, 0 );

	if ( ( batman_if->udp_send_sock = use_kernel_module( batman_if->dev ) ) < 0 ) {

		if ( ( batman_if->udp_send_sock = socket( PF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {

			printf( "Error - can't create send socket: %s", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( setsockopt( batman_if->udp_send_sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(int) ) < 0 ) {

			printf( "Error - can't enable broadcasts: %s\n", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( bind_to_iface( batman_if->udp_send_sock, batman_if->dev ) < 0 ) {

			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( bind( batman_if->udp_send_sock, (struct sockaddr *)&batman_if->addr, sizeof(struct sockaddr_in) ) < 0 ) {

			printf( "Error - can't bind send socket: %s\n", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

	}

	if ( bind_to_iface( batman_if->udp_recv_sock, batman_if->dev ) < 0 ) {

		restore_defaults();
		exit(EXIT_FAILURE);

	}

	if ( bind( batman_if->udp_recv_sock, (struct sockaddr *)&batman_if->broad, sizeof(struct sockaddr_in) ) < 0 ) {

		printf( "Error - can't bind receive socket: %s\n", strerror(errno) );
		restore_defaults();
		exit(EXIT_FAILURE);

	}

}




void init_interface_gw ( struct batman_if *batman_if ) {

	int32_t sock_opts, err, skfd;
	struct ifreq ifr;
	struct sockaddr_in sin;
	struct batgat_ioc_args ioc;

	if ( ( batman_if->udp_tunnel_sock = use_gateway_module( batman_if->dev ) ) < 0 ) {

		batman_if->addr.sin_port = htons(PORT + 1);

		batman_if->udp_tunnel_sock = socket( PF_INET, SOCK_DGRAM, 0 );

		if ( batman_if->udp_tunnel_sock < 0 ) {

			debug_output( 0, "Error - can't create tunnel socket: %s", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		if ( bind( batman_if->udp_tunnel_sock, (struct sockaddr *)&batman_if->addr, sizeof(struct sockaddr_in) ) < 0 ) {

			debug_output( 0, "Error - can't bind tunnel socket: %s\n", strerror(errno) );
			restore_defaults();
			exit(EXIT_FAILURE);

		}

		/* make udp socket non blocking */
		sock_opts = fcntl( batman_if->udp_tunnel_sock, F_GETFL, 0 );
		fcntl( batman_if->udp_tunnel_sock, F_SETFL, sock_opts | O_NONBLOCK );

		batman_if->addr.sin_port = htons(PORT);

		pthread_create( &batman_if->listen_thread_id, NULL, &gw_listen, batman_if );

	} else {

		ioc.universal = strlen( batman_if->dev );
		strncpy( ioc.dev_name, batman_if->dev, IFNAMSIZ - 1 );

		if( ioctl( batman_if->udp_tunnel_sock, IOCSETDEV, &ioc ) < 0 ) {
			debug_output( 0, "Error - can't add device %s: %s\n", batman_if->dev,strerror(errno) );
			batman_if->dev = NULL;
			restore_defaults();
			exit(EXIT_FAILURE);
		}

		/* set ip address of gate device */

		if( ( skfd = socket( AF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
			debug_output( 0, "Error - can't create socket to gate\n" );
			restore_defaults();
			exit( EXIT_FAILURE );
		}


		memset( &ifr, 0, sizeof( ifr ) );
		memset(&sin, 0, sizeof(struct sockaddr));

		strncpy( ifr.ifr_name, ioc.dev_name, IFNAMSIZ - 1 );

		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = ioc.universal;
		memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

		if( ( err =  ioctl( skfd, SIOCSIFADDR, &ifr ) ) < 0 ) {
			debug_output( 0, "Error - can't set IFADDR %s: %s", ioc.dev_name, strerror(err) );
			close( skfd );
			restore_defaults();
			exit( EXIT_FAILURE );
		}


		memset( &ifr, 0, sizeof( ifr ) );
		strncpy( ifr.ifr_name, ioc.dev_name, IFNAMSIZ - 1 );
		if( ioctl( skfd, SIOCGIFFLAGS, &ifr ) < 0) {
			debug_output( 0, "Error - can't get IFFLAGS for %s: %s\n", ioc.dev_name, strerror(errno) );
			close( skfd );
			restore_defaults();
			exit( EXIT_FAILURE );
		}

		strncpy( ifr.ifr_name, ioc.dev_name, IFNAMSIZ - 1 );
		ifr.ifr_flags |= ( IFF_UP | IFF_RUNNING );

		if( ioctl( skfd, SIOCSIFFLAGS, &ifr ) < 0) {
			debug_output( 0, "Error - can't set IFFLAGS for %s: %s\n", ioc.dev_name, strerror(errno) );
			close( skfd );
			restore_defaults();
			exit( EXIT_FAILURE );
		}

		close( skfd );

		add_del_route( ioc.universal, 24, 0, 0, ioc.ifindex, ioc.dev_name, 254, 0, 0 );


	}

}


