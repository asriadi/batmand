/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Marek Lindner, Simon Wunderlich
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



#include <stdio.h>              /* perror() */
#include <string.h>             /* strncpy() */
#include <unistd.h>             /* close() */
#include <sys/ioctl.h>          /* ioctl(), SIO* */
#include <arpa/inet.h>          /* htons() */
#include <sys/uio.h>            /* writev(), readv() */
#include <sys/types.h>          /* socket(), bind() */
#include <sys/socket.h>         /* socket(), bind() */
#include <net/if.h>             /* struct ifreq */
#include <net/ethernet.h>       /* ETH_P_ALL, struct ether_header */
#include <netpacket/packet.h>   /* sockaddr_ll */
#include <errno.h>              /* errno */
#include <fcntl.h>              /* O_RDWR */
#include <netinet/ip.h>         /* tunnel stuff */
#include <asm/types.h>          /* __u16 */
#include <linux/if_tun.h>       /* tap interface */
#include <linux/if_tunnel.h>

#include "os.h"
#include "batman-adv.h"




/* creates a raw socket for the [devicename], returns the socket or -1 on error */
int8_t rawsock_create(char *devicename) {
	int32_t rawsock;
	struct ifreq req;
	struct sockaddr_ll addr;


	if ( ( rawsock = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_BATMAN) ) ) < 0 ) {

		debug_output( 0, "Error - can't create raw socket on interface %s: %s \n", devicename, strerror(errno) );
		return(-1);

	}

	strncpy(req.ifr_name, devicename, IFNAMSIZ);

	if ( ioctl(rawsock, SIOCGIFINDEX, &req) < 0 ) {

		debug_output( 0, "Error - can't create raw socket (SIOCGIFINDEX) on interface %s: %s \n", devicename, strerror(errno) );
		return(-1);

	}


	addr.sll_family   = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_BATMAN);
	addr.sll_ifindex  = req.ifr_ifindex;


	if ( bind(rawsock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ) {

		debug_output( 0, "Error - can't bind raw socket on interface %s: %s \n", devicename, strerror(errno) );
		close(rawsock);
		return(-1);

	}

	return (rawsock);

}



/* reads size bytes of input, and the header. returns num of bytes received on success, < 0 on error. */
int32_t rawsock_read(int32_t rawsock, struct ether_header *recv_header, unsigned char *buf, int16_t size) {
	struct iovec vector[2];
	int32_t packet_size;

	vector[0].iov_base = recv_header;
	vector[0].iov_len  = sizeof(struct ether_header);
	vector[1].iov_base = buf;
	vector[1].iov_len  = size;

	if ( ( packet_size = readv(rawsock, vector, 2) ) < 0 ) {

		/* non blocking socket returns */
		if ( errno != EAGAIN )
			debug_output( 0, "Error - can't read from raw socket: %s \n", strerror(errno) );

		return -1;

	}

/*	printf("source = %s\n", addr_to_string_static((struct ether_addr *)recv_header->ether_shost));
	printf("dest   = %s\n", addr_to_string_static((struct ether_addr *)recv_header->ether_dhost));
	printf("type: %08x\n",ntohs(recv_header->ether_type));*/

	return packet_size - sizeof(struct ether_header);

}



/* write size bytes of input, and the header. returns 0 on success, < 0 on error.*/
int32_t rawsock_write(int32_t rawsock, struct ether_header *send_header, unsigned char *buf, int16_t size) {
	struct iovec vector[2];
	int32_t ret;
	int i;

	vector[0].iov_base = send_header;
	vector[0].iov_len  = sizeof(struct ether_header);
	vector[1].iov_base = buf;
	vector[1].iov_len  = size;

	send_header->ether_type = htons(ETH_P_BATMAN);
/*	if (buf[0] != BAT_PACKET) {

	debug_output(4, "[B]batman source = %s, ", addr_to_string_static((struct ether_addr *)send_header->ether_shost) );
	debug_output(4, "dest   = %s, ", addr_to_string_static((struct ether_addr *)send_header->ether_dhost));
	debug_output(4, "type: %08x, len %i, battype %d\n",ntohs(send_header->ether_type), size, buf[0]);
	if ( buf[0] == BAT_UNICAST) {
		debug_output(4, "[E]ther source = %s ", 	addr_to_string_static((struct ether_addr *)((struct ether_header *)(buf + sizeof(struct unicast_packet)))->ether_shost));
		debug_output(4, "dest   = %s ", 			addr_to_string_static((struct ether_addr *)((struct ether_header *)(buf + sizeof(struct unicast_packet)))->ether_dhost));
		debug_output(4, "type   = %04x", 			((struct ether_header *)(buf + sizeof(struct unicast_packet)))->ether_type);
	}
	if ( buf[0] == BAT_BCAST) {
		debug_output(4, "[E]ther source = %s ", addr_to_string_static((struct ether_addr *)((struct ether_header *)(buf + sizeof(struct bcast_packet)))->ether_shost));
		debug_output(4, "dest   = %s ", addr_to_string_static((struct ether_addr *)((struct ether_header *)(buf + sizeof(struct bcast_packet)))->ether_dhost));
		debug_output(4, "type   = %04x ", ((struct ether_header *)(buf + sizeof(struct bcast_packet)))->ether_type);
		debug_output(4, "seqno =  %d\n", ntohs(((struct bcast_packet *)buf)->seqno) );
	}
	}
	printf("\n");*/
/*
	if ( memcmp( send_header->ether_dhost, broadcastAddr, 6 ) == 0 ) {

		if ( size == sizeof(struct batman_packet) ) {

			printf( "batman: orig = %s, \n", addr_to_string( ((struct batman_packet *)buf)->orig ) );

		} else {

			unsigned char *pay_buff = buf + sizeof(struct bcast_packet);
			printf( "broadcast: to = %s, ", addr_to_string( ((struct ether_header *)pay_buff)->ether_dhost ) );
			printf( "from = %s, \n", addr_to_string( ((struct ether_header *)pay_buff)->ether_shost ) );

		}

	} else {

		unsigned char *pay_buff = buf + sizeof(struct unicast_packet);
		printf( "unicast: to = %s, ", addr_to_string( ((struct ether_header *)pay_buff)->ether_dhost ) );
		printf( "from = %s, \n", addr_to_string( ((struct ether_header *)pay_buff)->ether_shost ) );

	}*/

	/* Try sending PACKETS_PER_CYCLE times to send the packet, and drop it otherwise. */
	for (i=0; i< PACKETS_PER_CYCLE; i++) {
		if ( ( ret = writev(rawsock, vector, 2) ) < 0 ) {
			if (errno == EAGAIN || errno == ESPIPE){
				debug_output( 4, "Error - can't write to raw socket: %s , but we retry\n", strerror(errno) );
				continue;
			} else {
				debug_output( 0, "Error - can't write to raw socket: %s \n", strerror(errno) );
				return -1;
			}
		} else break;
	}
	return 0;


	return(ret);

}



/* Probe for tap interface availability */
int8_t tap_probe() {

	int32_t fd;

	if ( ( fd = open( "/dev/net/tun", O_RDWR ) ) < 0 ) {

		debug_output( 0, "Error - could not open '/dev/net/tun' ! Is the tun kernel module loaded ? \n" );
		return 0;

	}

	close( fd );

	return 1;

}



int32_t tap_create( int16_t mtu ) {

	int32_t fd, tmp_fd, tap_opts;
	struct ifreq ifr_tap, ifr_if;

	/* set up tunnel device */
	memset( &ifr_tap, 0, sizeof(ifr_tap) );
	memset( &ifr_if, 0, sizeof(ifr_if) );
	ifr_tap.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy( ifr_tap.ifr_name, "bat0", IFNAMSIZ );

	if ( ( fd = open( "/dev/net/tun", O_RDWR ) ) < 0 ) {

		debug_output( 0, "Error - can't create tap device (/dev/net/tun): %s \n", strerror(errno) );
		return -1;

	}

	if ( ( ioctl( fd, TUNSETIFF, (void *) &ifr_tap ) ) < 0 ) {

		debug_output( 0, "Error - can't create tap device (TUNSETIFF): %s \n", strerror(errno) );
		close( fd );
		return -1;

	}

/*	if ( ioctl( fd, TUNSETPERSIST, 1 ) < 0 ) {

	debug_output( 0, "Error - can't create tap device (TUNSETPERSIST): %s\n", strerror(errno) );
		close( fd );
		return -1;

 	}*/


	tmp_fd = socket( AF_INET, SOCK_DGRAM, 0 );

	if ( tmp_fd < 0 ) {
		debug_output( 0, "Error - can't create tap device (udp socket): %s \n", strerror(errno) );
		tap_destroy( fd );
		return -1;
	}

	if ( ioctl( tmp_fd, SIOCGIFHWADDR, &ifr_tap ) < 0 ) {

		debug_output( 0, "Error - can't create tap device (SIOCGIFHWADDR): %s \n", strerror(errno) );
		tap_destroy( fd );
		close( tmp_fd );
		return -1;

	}

	memcpy( &ifr_tap.ifr_hwaddr.sa_data, ((struct batman_if *)if_list.next)->hw_addr, 6 );

	if ( ioctl( tmp_fd, SIOCSIFHWADDR, &ifr_tap ) < 0 ) {

		debug_output( 0, "Error - can't create tap device (SIOCSIFHWADDR): %s \n", strerror(errno) );
		tap_destroy( fd );
		close( tmp_fd );
		return -1;

	}

	if ( ioctl( tmp_fd, SIOCGIFFLAGS, &ifr_tap ) < 0 ) {

		debug_output( 0, "Error - can't create tap device (SIOCGIFFLAGS): %s \n", strerror(errno) );
		tap_destroy( fd );
		close( tmp_fd );
		return -1;

	}


	ifr_tap.ifr_flags |= IFF_UP;
	ifr_tap.ifr_flags |= IFF_RUNNING;

	if ( ioctl( tmp_fd, SIOCSIFFLAGS, &ifr_tap ) < 0 ) {

		debug_output( 0, "Error - can't create tap device (SIOCSIFFLAGS): %s \n", strerror(errno) );
		tap_destroy( fd );
		close( tmp_fd );
		return -1;

	}

	/* make tap interface non blocking */
	tap_opts = fcntl( fd, F_GETFL, 0 );
	fcntl( fd, F_SETFL, tap_opts | O_NONBLOCK );

	/* set MTU of tap interface: real MTU - BATMAN_MAXFRAMESIZE */
	if ( mtu < 100 ) {

		debug_output( 0, "Warning - MTU smaller than 100 -> can't reduce MTU anymore \n" );

	} else {

		ifr_tap.ifr_mtu = mtu - BATMAN_MAXFRAMESIZE;

		if ( ioctl( tmp_fd, SIOCSIFMTU, &ifr_tap ) < 0 ) {

			debug_output( 0, "Error - can't create tap device (SIOCSIFMTU): %s \n", strerror(errno) );
			tap_destroy( fd );
			close( tmp_fd );
			return -1;

		}

	}

	close( tmp_fd );

	return fd;

}



void tap_destroy( int32_t tap_fd ) {

	if ( ioctl( tap_fd, TUNSETPERSIST, 0 ) < 0 ) {

		debug_output( 0, "Error - can't delete tap device: %s \n", strerror(errno) );

	}

	close( tap_fd );

}


