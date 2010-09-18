/*
 * Copyright (C) 2007-2010 B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <lindner_marek@yahoo.de>
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



#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "main.h"
#include "traceroute.h"
#include "functions.h"
#include "packet.h"
#include "bat-hosts.h"
#include "debugfs.h"


#define TTL_MAX 50
#define NUM_PACKETS 3


void traceroute_usage(void)
{
	printf("Usage: batctl traceroute [options] mac|bat-host \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't convert addresses to bat-host names\n");
}

int traceroute(char *mesh_iface, int argc, char **argv)
{
	struct icmp_packet icmp_packet_out, icmp_packet_in;
	struct bat_host *bat_host;
	struct ether_addr *dst_mac = NULL;
	struct timeval tv;
	fd_set read_socket;
	ssize_t read_len;
	char *dst_string, *mac_string, *return_mac, dst_reached = 0;
	int ret = EXIT_FAILURE, res, trace_fd = 0, i;
	int found_args = 1, optchar, seq_counter = 0, read_opt = USE_BAT_HOSTS;
	double time_delta[NUM_PACKETS];
	char *debugfs_mnt;
	char icmp_socket[MAX_PATH+1];

	while ((optchar = getopt(argc, argv, "hn")) != -1) {
		switch (optchar) {
		case 'h':
			traceroute_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			found_args += 1;
			break;
		default:
			traceroute_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc <= found_args) {
		printf("Error - target mac address or bat-host name not specified\n");
		traceroute_usage();
		return EXIT_FAILURE;
	}

	dst_string = argv[found_args];
	bat_hosts_init();
	bat_host = bat_hosts_find_by_name(dst_string);

	if (bat_host)
		dst_mac = &bat_host->mac_addr;

	if (!dst_mac) {
		dst_mac = ether_aton(dst_string);

		if (!dst_mac) {
			printf("Error - the traceroute destination is not a mac address or bat-host name: %s\n", dst_string);
			goto out;
		}
	}

	mac_string = ether_ntoa_long(dst_mac);

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt) {
		printf("Error - can't mount or find debugfs\n");
		goto out;
	}

	debugfs_make_path(SOCKET_PATH_FMT, mesh_iface, icmp_socket, sizeof(icmp_socket));

	trace_fd = open(icmp_socket, O_RDWR);

	if (trace_fd < 0) {
		printf("Error - can't open a connection to the batman adv kernel module via the socket '%s': %s\n",
				icmp_socket, strerror(errno));
		printf("Check whether the module is loaded and active.\n");
		goto out;
	}

	memcpy(&icmp_packet_out.dst, dst_mac, ETH_ALEN);
	icmp_packet_out.version = COMPAT_VERSION;
	icmp_packet_out.packet_type = BAT_ICMP;
	icmp_packet_out.msg_type = ECHO_REQUEST;
	icmp_packet_out.seqno = 0;

	printf("traceroute to %s (%s), %d hops max, %zu byte packets\n",
		dst_string, mac_string, TTL_MAX, sizeof(icmp_packet_out));

	for (icmp_packet_out.ttl = 1; !dst_reached && icmp_packet_out.ttl < TTL_MAX; icmp_packet_out.ttl++) {
		return_mac = NULL;
		bat_host = NULL;

		for (i = 0; i < NUM_PACKETS; i++) {
			icmp_packet_out.seqno = htons(++seq_counter);

			if (write(trace_fd, (char *)&icmp_packet_out, sizeof(icmp_packet_out)) < 0) {
				printf("Error - can't write to batman adv kernel file '%s': %s\n", icmp_socket, strerror(errno));
				continue;
			}

			start_timer();

			tv.tv_sec = 2;
			tv.tv_usec = 0;

			FD_ZERO(&read_socket);
			FD_SET(trace_fd, &read_socket);

			res = select(trace_fd + 1, &read_socket, NULL, NULL, &tv);

			if (res <= 0) {
				time_delta[i] = 0.0;
				continue;
			}

			read_len = read(trace_fd, (char *)&icmp_packet_in, sizeof(icmp_packet_in));

			if (read_len < 0) {
				printf("Error - can't read from batman adv kernel file '%s': %s\n", icmp_socket, strerror(errno));
				continue;
			}

			if ((size_t)read_len < sizeof(icmp_packet_in)) {
				printf("Warning - dropping received packet as it is smaller than expected (%zu): %zd\n",
					sizeof(icmp_packet_in), read_len);
				continue;
			}

			switch (icmp_packet_in.msg_type) {
			case ECHO_REPLY:
				dst_reached = 1;
				/* fall through */
			case TTL_EXCEEDED:
				time_delta[i] = end_timer();

				if (!return_mac) {
					return_mac = ether_ntoa_long((struct ether_addr *)&icmp_packet_in.orig);

					if (read_opt & USE_BAT_HOSTS)
						bat_host = bat_hosts_find_by_mac((char *)&icmp_packet_in.orig);
				}

				break;
			case DESTINATION_UNREACHABLE:
				printf("%s: Destination Host Unreachable\n", dst_string);
				goto out;
			case PARAMETER_PROBLEM:
				printf("Error - the batman adv kernel module version (%d) differs from ours (%d)\n",
						icmp_packet_in.ttl, COMPAT_VERSION);
				printf("Please make sure to compatible versions!\n");
				goto out;
			default:
				printf("Unknown message type %d len %zd received\n", icmp_packet_in.msg_type, read_len);
				break;
			}
		}

		if (!bat_host)
			printf("%2hu: %s", icmp_packet_out.ttl, (return_mac ? return_mac : "*"));
		else
			printf("%2hu: %s (%s)",	icmp_packet_out.ttl, bat_host->name, return_mac);

		for (i = 0; i < NUM_PACKETS; i++) {
			if (time_delta[i])
				printf("  %.3f ms", time_delta[i]);
			else
				printf("   *");
		}

		printf("\n");
	}

	ret = EXIT_SUCCESS;

out:
	bat_hosts_free();
	if (trace_fd)
		close(trace_fd);
	return ret;
}
