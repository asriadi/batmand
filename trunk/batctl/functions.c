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


#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>

#include "main.h"
#include "functions.h"
#include "bat-hosts.h"


static struct timeval start_time;

void start_timer(void)
{
	gettimeofday(&start_time, NULL);
}

double end_timer(void)
{
	struct timeval end_time, diff;

	gettimeofday(&end_time, NULL);
	diff.tv_sec = end_time.tv_sec - start_time.tv_sec;
	diff.tv_usec = end_time.tv_usec - start_time.tv_usec;

	if (diff.tv_usec < 0) {
		diff.tv_sec--;
		diff.tv_usec += 1000000;
	}

	return (((double)diff.tv_sec * 1000) + ((double)diff.tv_usec / 1000));
}

char *ether_ntoa_long(const struct ether_addr *addr)
{
	static char asc[18];

	sprintf(asc, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr->ether_addr_octet[0], addr->ether_addr_octet[1],
		addr->ether_addr_octet[2], addr->ether_addr_octet[3],
		addr->ether_addr_octet[4], addr->ether_addr_octet[5]);

	return asc;
}

static int check_proc_dir(void)
{
	struct stat st;

	if (stat("/proc", &st) != 0) {
		printf("Error - the folder '/proc' was not found on the system\n");
		printf("Please make sure that the proc filesystem is properly mounted\n");
		return EXIT_FAILURE;
	}

	if (stat(PROC_ROOT_PATH, &st) == 0)
        	return EXIT_SUCCESS;

	printf("Error - the folder '%s' was not found within the proc filesystem\n", PROC_ROOT_PATH);
	printf("Please make sure that the batman-adv kernel module is loaded\n");
	return EXIT_FAILURE;
}

int read_proc_file(char *path, int read_opt)
{
	struct ether_addr *mac_addr;
	struct bat_host *bat_host;
	int fd = 0, res = EXIT_FAILURE, fd_opts;
	unsigned int bytes_written;
	char full_path[500], buff[1500], *buff_ptr, *cr_ptr, *space_ptr, extra_char;
	ssize_t read_len;

	if (read_opt & USE_BAT_HOSTS)
		bat_hosts_init();

	if (check_proc_dir() != EXIT_SUCCESS)
		goto out;

	strncpy(full_path, PROC_ROOT_PATH, strlen(PROC_ROOT_PATH));
	full_path[strlen(PROC_ROOT_PATH)] = '\0';
	strncat(full_path, path, sizeof(full_path) - strlen(full_path));

open:
	fd = open(full_path, O_RDONLY);

	if (fd < 0) {
		printf("Error - can't open file '%s': %s\n", full_path, strerror(errno));
		goto out;
	}

	/* make fd socket non blocking to exit immediately if the file to read is empty */
	fd_opts = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, fd_opts | O_NONBLOCK);

	if (read_opt & CLR_CONT_READ)
		system("clear");

read:
	while (1) {
		read_len = read(fd, buff, sizeof(buff));

		if (read_len < 0) {
			/* file was empty */
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
				break;

			printf("Error - can't read from file '%s': %s\n", full_path, strerror(errno));
			goto out;
		}

		if (read_len == 0)
			break;

		buff[read_len] = '\0';

		if (!(read_opt & USE_BAT_HOSTS)) {
			printf("%s", buff);
			goto check_eof;
		}

		/* replace mac addresses with bat host names */
		buff_ptr = buff;
		bytes_written = 0;

		while ((cr_ptr = strchr(buff_ptr, '\n')) != NULL) {

			*cr_ptr = '\0';

			while ((space_ptr = strchr(buff_ptr, ' ')) != NULL) {

				*space_ptr = '\0';
				extra_char = '\0';

				if ((strlen(buff_ptr) == ETH_STR_LEN + 1) && (buff_ptr[ETH_STR_LEN] == ',')) {
					extra_char = ',';
					buff_ptr[ETH_STR_LEN] = '\0';
				}

				if (strlen(buff_ptr) != ETH_STR_LEN)
					goto print_plain_buff;

				mac_addr = ether_aton(buff_ptr);

				if (!mac_addr)
					goto print_plain_buff;

				bat_host = bat_hosts_find_by_mac((char *)mac_addr);

				if (!bat_host)
					goto print_plain_buff;

				if (read_opt & LOG_MODE)
					printf("%s", bat_host->name);
				else
					/* keep table format */
					printf("%17s", bat_host->name);

				if (extra_char != '\0')
					printf("%c", extra_char);

				printf(" ");
				goto written;

print_plain_buff:
				printf("%s ", buff_ptr);

written:
				bytes_written += strlen(buff_ptr) + 1;
				buff_ptr = space_ptr + 1;

			}

			printf("%s\n", buff_ptr);
			buff_ptr = cr_ptr + 1;

		}

		if (bytes_written != (size_t)read_len)
			printf("%s", buff_ptr);

check_eof:
		if (sizeof(buff) != (size_t)read_len)
			break;
	}

	if (read_opt & CONT_READ) {
		sleep(1);
		goto read;
	}

	if (read_opt & CLR_CONT_READ) {
		if (fd)
			close(fd);
		sleep(1);
		goto open;
	}

	res = EXIT_SUCCESS;

out:
	if (fd)
		close(fd);

	if (read_opt & USE_BAT_HOSTS)
		bat_hosts_free();

	return res;
}

int write_proc_file(char *path, char *value)
{
	int fd = 0, res = EXIT_FAILURE;
	char full_path[500];
	ssize_t write_len;

	if (check_proc_dir() != EXIT_SUCCESS)
		goto out;

	strncpy(full_path, PROC_ROOT_PATH, strlen(PROC_ROOT_PATH));
	full_path[strlen(PROC_ROOT_PATH)] = '\0';
	strncat(full_path, path, sizeof(full_path) - strlen(full_path));

	fd = open(full_path, O_WRONLY);

	if (fd < 0) {
		printf("Error - can't open file '%s': %s\n", full_path, strerror(errno));
		goto out;
	}

	write_len = write(fd, value, strlen(value) + 1);

	if (write_len < 0) {
		printf("Error - can't write to file '%s': %s\n", full_path, strerror(errno));
		goto out;
	}

	res = EXIT_SUCCESS;

out:
	if (fd)
		close(fd);
	return res;
}
