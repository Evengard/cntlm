/*
 * HTTP handling routines and related socket stuff for CNTLM
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

#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>

#include "utils.h"
#include "socket.h"

#define BLOCK		2048

extern int debug;

/*
 * Receive HTTP request/response from the given socket. Fill in pre-allocated
 * rr_data_t structure.
 * Returns: 1 if OK, 0 in case of socket EOF or other error
 */
int headers_recv(int fd, rr_data_t data) {
	char *tok, *s3 = 0;
	int len;
	char *buf;
	char *ccode = NULL;
	char *host = NULL;
	int i, bsize;

	bsize = BUFSIZE;
	buf = new(bsize);

	i = so_recvln(fd, &buf, &bsize);

	if (i <= 0)
		goto bailout;

	if (debug)
		printf("HEAD: %s", buf);

	/*
	 * Are we reading HTTP request (from client) or response (from server)?
	 */
	trimr(buf);
	len = strlen(buf);
	tok = strtok_r(buf, " ", &s3);
	if (!strncasecmp(buf, "HTTP/", 5) && tok) {
		data->req = 0;
		data->http = NULL;
		data->msg = NULL;

		data->http = substr(tok, 7, 1);

		tok = strtok_r(NULL, " ", &s3);
		if (tok) {
			ccode = strdup(tok);

			tok += strlen(ccode);
			while (tok < buf+len && *tok++ == ' ');

			if (strlen(tok))
				data->msg = strdup(tok);
		}

		if (!data->msg)
			data->msg = strdup("");

		if (!ccode || strlen(ccode) != 3 || (data->code = atoi(ccode)) == 0 || !data->http) {
			i = -1;
			goto bailout;
		}
	} else if (tok) {
		data->req = 1;
		data->method = NULL;
		data->url = NULL;
		data->http = NULL;

		data->method = strdup(tok);

		tok = strtok_r(NULL, " ", &s3);
		if (tok)
			data->url = strdup(tok);

		tok = strtok_r(NULL, " ", &s3);
		if (tok)
			data->http = substr(tok, 7, 1);

		if (!data->url || !data->http) {
			i = -1;
			goto bailout;
		}

		tok = strstr(data->url, "://");
		if (tok) {
			s3 = strchr(tok+3, '/');
			host = substr(tok+3, 0, s3 ? s3-tok-3 : 0);
		}
	} else {
		if (debug)
			printf("headers_recv: Unknown header (%s).\n", buf);
		i = -1;
		goto bailout;
	}

	/*
	 * Read in all headers, do not touch any possible HTTP body
	 */
	do {
		i = so_recvln(fd, &buf, &bsize);
		trimr(buf);
		if (i > 0 && is_http_header(buf)) {
			data->headers = hlist_add(data->headers, get_http_header_name(buf), get_http_header_value(buf), 0, 0);
		}
	} while (strlen(buf) != 0 && i > 0);

	if (host && !hlist_in(data->headers, "Host"))
		data->headers = hlist_add(data->headers, "Host", host, 1, 1);

bailout:
	if (ccode) free(ccode);
	if (host) free(host);
	free(buf);

	if (i <= 0) {
		if (debug)
			printf("headers_recv: fd %d warning %d (connection closed)\n", fd, i);
		return 0;
	}

	return 1;
}

/*
 * Send HTTP request/response to the given socket based on what's in "data".
 * Returns: 1 if OK, 0 in case of socket error
 */
int headers_send(int fd, rr_data_t data) {
	hlist_t t;
	char *buf;
	int i, len;

	/*
	 * First compute required buffer size (avoid realloc, etc)
	 */
	if (data->req)
		len = 20 + strlen(data->method) + strlen(data->url) + strlen(data->http);
	else
		len = 20 + strlen(data->http) + strlen(data->msg);

	t = data->headers;
	while (t) {
		len += 20 + strlen(t->key) + strlen(t->value);
		t = t->next;
	}

	/*
	 * We know how much memory we need now...
	 */
	buf = new(len);

	/*
	 * Prepare the first request/response line
	 */
	len = 0;
	if (data->req)
		len = sprintf(buf, "%s %s HTTP/1.%s\r\n", data->method, data->url, data->http);
	else if (!data->skip_http)
		len = sprintf(buf, "HTTP/1.%s %03d %s\r\n", data->http, data->code, data->msg);

	/*
	 * Now add all headers.
	 */
	t = data->headers;
	while (t) {
		len += sprintf(buf+len, "%s: %s\r\n", t->key, t->value);
		t = t->next;
	}

	/*
	 * Terminate headers
	 */
	strcat(buf, "\r\n");

	/*
	 * Flush it all down the toilet
	 */
	if (!so_closed(fd))
		i = write(fd, buf, len+2);
	else
		i = -999;

	free(buf);

	if (i <= 0 || i != len+2) {
		if (debug)
			printf("headers_send: fd %d warning %d (connection closed)\n", fd, i);
		return 0;
	}

	return 1;
}

/*
 * Connection cleanup - discard "size" of incomming data.
 */
int data_drop(int src, int size) {
	char *buf;
	int i, block, c = 0;

	if (!size)
		return 1;

	buf = new(BLOCK);
	do {
		block = (size-c > BLOCK ? BLOCK : size-c);
		i = read(src, buf, block);
		c += i;
	} while (i > 0 && c < size);

	free(buf);
	if (i <= 0) {
		if (debug)
			printf("data_drop: fd %d warning %d (connection closed)\n", src, i);
		return 0;
	}

	return 1;
}

/*
 * Forward "size" of data from "src" to "dst". If size == -1 then keep
 * forwarding until src reaches EOF.
 */
int data_send(int dst, int src, int size) {
	char *buf;
	int i, block;
	int c = 0;
	int j = 1;

	if (!size)
		return 1;

	buf = new(BLOCK);

	do {
		block = (size == -1 || size-c > BLOCK ? BLOCK : size-c);
		i = read(src, buf, block);
		
		if (i > 0)
			c += i;

		if (debug)
			printf("data_send: read %d of %d / %d of %d (errno = %s)\n", i, block, c, size, i < 0 ? strerror(errno) : "ok");

		if (so_closed(dst)) {
			i = -999;
			break;
		}

		if (i > 0) {
			j = write(dst, buf, i);

			if (debug)
				printf("data_send: wrote %d of %d\n", j, i);
		}

	} while (i > 0 && j > 0 && (size == -1 || c <  size));

	free(buf);

	if (i <= 0 || j <= 0) {
		if (i == 0 && j > 0 && (size == -1 || c == size))
			return 1;

		if (debug)
			printf("data_send: fds %d:%d warning %d (connection closed)\n", dst, src, i);
		return 0;
	}

	return 1;
}

/*
 * Forward chunked HTTP body from "src" descriptor to "dst".
 */
int chunked_data_send(int dst, int src) {
	char *buf;
	int bsize;
	int i, w, csize;

	char *err = NULL;

	bsize = BUFSIZE;
	buf = new(bsize);

	/* Take care of all chunks */
	do {
		i = so_recvln(src, &buf, &bsize);
		if (i <= 0) {
			if (debug)
				printf("chunked_data_send: aborting, read error\n");
			free(buf);
			return 0;
		}

		if (debug)
			printf("Line: %s", buf);

		/*
		printf("*buf = ");
		for (i = 0; i < 100; i++) {
			printf("%02x ", buf[i]);
			if (i % 8 == 7)
				printf("\n       ");
		}
		printf("\n");
		*/

		csize = strtol(buf, &err, 16);

		if (debug)
			printf("strtol: %d (%x) - err: %s\n", csize, csize, err);

		if (*err != '\r' && *err != '\n' && *err != ';' && *err != ' ' && *err != '\t') {
			if (debug)
				printf("chunked_data_send: aborting, chunk size format error\n");
			free(buf);
			return 0;
		}

		if (debug && !csize)
			printf("last chunk: %d\n", csize);

		i = write(dst, buf, strlen(buf));
		if (csize)
			if (!data_send(dst, src, csize+2)) {
				if (debug)
					printf("chunked_data_send: aborting, data_send failed\n");

				free(buf);
				return 0;
			}

	} while (csize != 0);

	/* Take care of possible trailer */
	do {
		i = so_recvln(src, &buf, &bsize);
		if (debug)
			printf("Trailer header(i=%d): %s\n", i, buf);
		if (i > 0)
			w = write(dst, buf, strlen(buf));
	} while (i > 0 && buf[0] != '\r' && buf[0] != '\n');

	free(buf);
	return 1;
}

/*
 * Full-duplex forwarding between proxy and client descriptors.
 * Used for bidirectional HTTP CONNECT connection.
 */
int tunnel(int cd, int sd) {
	fd_set set;
	int from, to, ret, sel;
	char *buf;

	buf = new(BUFSIZE);

	if (debug)
		printf("tunnel: select cli: %d, srv: %d\n", cd, sd);

	do {
		FD_ZERO(&set);
		FD_SET(cd, &set);
		FD_SET(sd, &set);

		sel = select(FD_SETSIZE, &set, NULL, NULL, NULL);
		if (sel > 0) {
			if (FD_ISSET(cd, &set)) {
				from = cd;
				to = sd;
			} else {
				from = sd;
				to = cd;
			}

			ret = read(from, buf, BUFSIZE);
			if (ret > 0) {
				ret = write(to, buf, ret);
			} if (ret <= 0) {
				free(buf);
				return (ret == 0);
			}
		} else if (sel < 0) {
			free(buf);
			return 0;
		}
	} while (1);

	free(buf);
	return 1;
}

