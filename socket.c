/*
 * These are socket routines for the main module of CNTLM
 *
 * CNTLM is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * CNTLM is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Copyright (c) 2007 David Kubicek
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include "utils.h"

/*
 * gethostbyname() wrapper. Return 1 if OK, otherwise 0.
 */
int so_resolv(struct in_addr *host, const char *name) {
	struct hostent *resolv;

	resolv = gethostbyname(name);
	if (!resolv)
		return 0;

	memcpy(host, resolv->h_addr, resolv->h_length);
	return 1;
}

/*
 * Connect to a host. Host is required to be resolved
 * in the struct in_addr already.
 * Returns: socket descriptor
 */
int so_connect(struct in_addr host, int port) {
	int fd;
	struct sockaddr_in saddr;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("cannot create socket()");
		exit(1);
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr = host;

	if (connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
		return -1;

	return fd;
}

/*
 * Bind the specified port and listen on it.
 * Return socket descriptor if OK, otherwise 0.
 */
int so_listen(int port, int gateway) {
	struct sockaddr_in saddr;
	int fd;
	socklen_t clen;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Cannot create socket");
		exit(1);
	}

	clen = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen));
	memset((void *)&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr.s_addr = htonl((gateway ? INADDR_ANY : INADDR_LOOPBACK));

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr))) {
		fprintf(stderr, "Cannot bind port %d: %s!\n", port, strerror(errno));
		return -1;
	}

	if (listen(fd, 5))
		return -1;

	return fd;
}

/*
 * Return 1 if data is available on the socket,
 * 0 if connection was closed
 * -1 if error (errno is set)
 */
int so_recvtest(int fd) {
	char buf;
	int i;
#ifndef MSG_DONTWAIT
	unsigned int flags;

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	i = recv(fd, &buf, 1, MSG_PEEK);
	fcntl(fd, F_SETFL, flags);
#else
	i = recv(fd, &buf, 1, MSG_DONTWAIT | MSG_PEEK);
#endif

	return i;
}

/*
 * Return true if there are some data on the socket
 */
int so_dataready(int fd) {
	return so_recvtest(fd) > 0;
}

/*
 * Reliable way of finding out whether a connection was closed
 * on the remote end, without actually reading from it.
 */
int so_closed(int fd) {
	int i;

	if (fd == -1)
		return 1;

	i = so_recvtest(fd);
	return (i == 0 || (i == -1 && errno != EAGAIN));
}

/*
 * Receive a single line from the socket. This is no super-efficient
 * implementation, but more than we need to read in a few headers.
 * What's more, the data is actually recv'd from a socket buffer.
 *
 * I had to time this in comparison to recv with block read :) and
 * the performance was very similar. Given the fact that it keeps us
 * from creating a whole buffering scheme around the socket (HTTP 
 * connection is both line and block oriented, switching back and forth),
 * it is actually quite cool. ;)
 *
 * Streams using fdopen() didn't yield such comfort (memory allocation,
 * split r/w FILE *args in functions, etc) and simplicity.
 */
int so_recvln(int fd, char **buf, int *size) {
	int len = 0;
	int r = 1;
	char c = 0;
	char *tmp;

	while (len < *size-1 && c != '\n') {
		r = read(fd, &c, 1);
		if (r <= 0)
			break;

		(*buf)[len++] = c;

		/*
		 * end of buffer, still no EOL?
		 */
		if (len == *size-1 && c != '\n') {
			*size *= 2;
			tmp = realloc(*buf, *size);
			if (tmp == NULL)
				return -1;
			else
				*buf = tmp;
		}
	}
	VAL(*buf, char, len) = 0;

	return r;
}

