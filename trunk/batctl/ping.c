/* Copyright (C) 2007-2009 B.A.T.M.A.N. contributors:
 * Andreas Langer <a.langer@q-dsl.de>
 * Marek Lindner <lindner_marek@yahoo.de>
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
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>

#include "main.h"
#include "ping.h"
#include "functions.h"
#include "packet.h"
#include "bat-hosts.h"


char is_aborted = 0;


void ping_usage(void)
{
	printf("Usage: batctl ping [options] mac|bat-host \n");
	printf("options:\n");
	printf(" \t -c ping packet count \n");
	printf(" \t -h print this help\n");
	printf(" \t -i interval in seconds\n");
	printf(" \t -t timeout in seconds\n");
}

void sig_handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		is_aborted = 1;
		break;
	default:
		break;
	}
}

int ping(int argc, char **argv)
{
	struct icmp_packet icmp_packet_out, icmp_packet_in;
	struct timeval start, end, tv;
	struct ether_addr *dst_mac = NULL;
	struct bat_host *bat_host;
	ssize_t read_len;
	fd_set read_socket;
	int ret = EXIT_FAILURE, ping_fd = 0, res, optchar, found_args = 1;
	int loop_count = -1, loop_interval = 1, timeout = 1;
	unsigned int seq_counter = 0, packets_out = 0, packets_in = 0;
	char *dst_string, *mac_string;
	double time_delta;
	float min = 0.0, max = 0.0, avg = 0.0;

	while ((optchar = getopt(argc, argv, "hc:i:t:")) != -1) {
		switch (optchar) {
		case 'c':
			loop_count = strtol(optarg, NULL , 10);
			if (loop_count < 1)
				loop_count = -1;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		case 'h':
			ping_usage();
			return EXIT_SUCCESS;
		case 'i':
			loop_interval = strtol(optarg, NULL , 10);
			if (loop_interval < 1)
				loop_interval = 1;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		case 't':
			timeout = strtol(optarg, NULL , 10);
			if (timeout < 1)
				timeout = 1;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		default:
			ping_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc <= found_args) {
		printf("Error - target mac address or bat-host name not specified\n");
		ping_usage();
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
			printf("Error - the ping destination is not a mac address or bat-host name: %s\n", dst_string);
			goto out;
		}
	}

	mac_string = ether_ntoa(dst_mac);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	ping_fd = open(BAT_DEVICE, O_RDWR);

	if (ping_fd < 0) {
		printf("Error - can't open a connection to the batman adv kernel module via the device '%s': %s\n",
				BAT_DEVICE, strerror(errno));
		printf("Check whether the module is loaded and active.\n");
		goto out;
	}

	memcpy(&icmp_packet_out.dst, dst_mac, ETH_ALEN);
	icmp_packet_out.packet_type = BAT_ICMP;
	icmp_packet_out.version = COMPAT_VERSION;
	icmp_packet_out.msg_type = ECHO_REQUEST;
	icmp_packet_out.ttl = 50;
	icmp_packet_out.seqno = 0;

	printf("PING %s (%s) %zi(%zi) bytes of data\n", dst_string, mac_string,
		sizeof(icmp_packet_out), sizeof(icmp_packet_out) + 28);

	while (!is_aborted) {
		if (loop_count == 0)
			break;

		if (loop_count > 0)
			loop_count--;

		icmp_packet_out.seqno = htons(++seq_counter);

		if (write(ping_fd, (char *)&icmp_packet_out, sizeof(icmp_packet_out)) < 0) {
			printf("Error - can't write to batman adv kernel file '%s': %s\n", BAT_DEVICE, strerror(errno));
			goto sleep;
		}

		gettimeofday(&start, (struct timezone*)0);

		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		FD_ZERO(&read_socket);
		FD_SET(ping_fd, &read_socket);

		res = select(ping_fd + 1, &read_socket, NULL, NULL, &tv);

		if (is_aborted)
			break;

		packets_out++;

		if (res == 0) {
			printf("Host %s timeout\n", mac_string);
			goto sleep;
		}

		if (res < 0)
			goto sleep;

		read_len = read(ping_fd, (char *)&icmp_packet_in, sizeof(icmp_packet_in));

		if (read_len < 0) {
			printf("Error - can't read from batman adv kernel file '%s': %s\n", BAT_DEVICE, strerror(errno));
			goto sleep;
		}

		if ((size_t)read_len < sizeof(icmp_packet_in)) {
			printf("Warning - dropping received packet as it is smaller than expected (%zd): %zd\n",
				sizeof(icmp_packet_in), read_len);
			goto sleep;
		}

		switch (icmp_packet_in.msg_type) {
		case ECHO_REPLY:
			gettimeofday(&end, (struct timezone*)0);
			time_delta = time_diff(&start, &end);
			printf("%zd bytes from %s icmp_seq=%u ttl=%d time=%.2f ms\n",
					read_len, dst_string, ntohs(icmp_packet_in.seqno),
					icmp_packet_in.ttl, time_delta);

			if ((time_delta < min) || (min == 0.0))
				min = time_delta;
			if (time_delta > max)
				max = time_delta;
			avg += time_delta;
			packets_in++;
			break;
		case DESTINATION_UNREACHABLE:
			printf("From %s icmp_seq=%u Destination Host Unreachable\n", dst_string, ntohs(icmp_packet_in.seqno));
			break;
		case TTL_EXCEEDED:
			printf("From %s icmp_seq=%u Time to live exceeded\n", dst_string, ntohs(icmp_packet_in.seqno));
			break;
		case PARAMETER_PROBLEM:
			printf("Error - the batman adv kernel module version (%d) differs from ours (%d)\n",
					icmp_packet_in.ttl, COMPAT_VERSION);
			printf("Please make sure to compatible versions!\n");
			goto out;
		default:
			printf("Unknown message type %d len %zd received\n", icmp_packet_in.msg_type, read_len);
			break;
		}

sleep:
		if ((tv.tv_sec != 0) || (tv.tv_usec != 0)) {
			printf("sleeping: sec: %d, usec: %d\n", (int)tv.tv_sec, (int)tv.tv_usec);
			select(0, NULL, NULL, NULL, &tv);
		}

	}

	printf("--- %s ping statistics ---\n", dst_string);
	printf("%d packets transmitted, %d received, %d%c packet loss\n",
		packets_out, packets_in, (((packets_out - packets_in) * 100) / packets_out), '%');
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
		min, (packets_in ? (avg / packets_in) : 0.000), max, (max - min));

	ret = EXIT_SUCCESS;

out:
	bat_hosts_free();
	if (ping_fd)
		close(ping_fd);
	return ret;
}
