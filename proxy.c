/*
 * This is the main module of the CNTLM
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

#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <regex.h>
#include <ctype.h>
#include <pwd.h>
#include <fcntl.h>
#include <syslog.h>
#include <termios.h>
#include <fnmatch.h>

/*
 * Some helping routines like linked list manipulation substr(), memory
 * allocation, NTLM authentication routines, etc.
 */
#include "config/config.h"
#include "socket.h"
#include "utils.h"
#include "ntlm.h"
#include "swap.h"
#include "config.h"
#include "acl.h"
#include "pages.c"

#define DEFAULT_PORT	"3128"

#define BLOCK		2048
#define MINIBUF_SIZE	100
#define SAMPLE		4096
#define STACK_SIZE	sizeof(void *)*8*1024

#define PLUG_NONE	0x0000
#define PLUG_SENDHEAD	0x0001
#define PLUG_SENDDATA	0x0002
#define PLUG_ERROR	0x8000
#define PLUG_ALL	0x7FFF

/*
 * A couple of shortcuts for if statements
 */
#define CONNECT(data)	(data && data->req && !strcasecmp("CONNECT", data->method))
#define HEAD(data)	(data && data->req && !strcasecmp("HEAD", data->method))
#define GET(data)	(data && data->req && !strcasecmp("GET", data->method))

/*
 * Global read-only data initialized in main(). Comments list funcs. which use
 * them. Having these global avoids the need to pass them to each thread and
 * from there again a few times to inner calls.
 */
int debug = 0;						/* all debug printf's and possibly external modules */

static char *user;					/* authenticate() */
static char *domain;
static char *workstation;
static char *passlm = NULL;
static char *passnt = NULL;
static char *passntlm2 = NULL;
static int hashntlm2 = 1;
static int hashnt = 0;
static int hashlm = 0;
static uint32_t flags = 0;

static int quit = 0;					/* sighandler() */
static int asdaemon = 1;				/* myexit() */
static int ntlmbasic = 0;				/* process() */
static int serialize = 0;
static int scanner_plugin = 0;
static long scanner_plugin_maxsize = 0;

static int precache = 0;
static int active_conns = 0;
static pthread_mutex_t active_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * List of finished threads. Each thread process() adds itself to it when
 * finished. Main regularly joins and removes all tid's in there.
 */
static plist_t threads_list = NULL;
static pthread_mutex_t threads_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * List of cached connections. Accessed by each thread process().
 */
static plist_t connection_list = NULL;
static pthread_mutex_t connection_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * List of available proxies and current proxy id for proxy_connect().
 */
static int parent_count = 0;
static int parent_curr = 0;
static pthread_mutex_t parent_mtx = PTHREAD_MUTEX_INITIALIZER;

static plist_t parent_list = NULL;
typedef struct {
	struct in_addr host;
	int port;
} proxy_t;

/*
 * List of custom header substitutions.
 */
static hlist_t header_list = NULL;			/* process() */
static plist_t scanner_agent_list = NULL;		/* scanner_hook() */
static hlist_t users_list = NULL;			/* socks5() */

/*
 * General signal handler. Fast exit, no waiting for threads and shit.
 */
void sighandler(int p) {
	if (!quit)
		syslog(LOG_INFO, "Signal %d received, issuing clean shutdown\n", p);
	else
		syslog(LOG_INFO, "Signal %d received, forcing shutdown\n", p);

	if (quit++ || debug)
		exit(0);
}

void myexit(int rc) {
	if (rc)
		fprintf(stderr, "Exitting with error. Check daemon logs or run with -v.\n");
	
	exit(rc);
}

/*
 * Keep count of active connections (trasferring data)
 */
void update_active(int i) {
	pthread_mutex_lock(&active_mtx);
	active_conns += i;
	pthread_mutex_unlock(&active_mtx);
}

/*
 * Retur/ count of active connections (trasferring data)
 */
int check_active(void) {
	int r;

	pthread_mutex_lock(&active_mtx);
	r = active_conns;
	pthread_mutex_unlock(&active_mtx);

	return r;
}

/*
 * Connect to the selected proxy. If the request fails, pick next proxy
 * in the line. Each request scans the whole list until all items are tried
 * or a working proxy is found, in which case it is selected and used by
 * all threads until it stops working. Then the search starts again.
 */
int proxy_connect(void) {
	proxy_t *aux;
	int i, prev;
	plist_t list, tmp;
	int loop = 0;

	prev = parent_curr;
	pthread_mutex_lock(&parent_mtx);
	if (parent_curr == 0) {
		aux = (proxy_t *)plist_get(parent_list, ++parent_curr);
		syslog(LOG_INFO, "Using proxy %s:%d\n", inet_ntoa(aux->host), aux->port);
	}
	pthread_mutex_unlock(&parent_mtx);

	do {
		aux = (proxy_t *)plist_get(parent_list, parent_curr);
		i = so_connect(aux->host, aux->port);
		if (i <= 0) {
			pthread_mutex_lock(&parent_mtx);
			if (parent_curr >= parent_count)
				parent_curr = 0;
			aux = (proxy_t *)plist_get(parent_list, ++parent_curr);
			pthread_mutex_unlock(&parent_mtx);
			syslog(LOG_ERR, "Proxy connect failed, will try %s:%d\n", inet_ntoa(aux->host), aux->port);
		}
	} while (i <= 0 && ++loop < parent_count);

	if (i <= 0 && loop >= parent_count)
		syslog(LOG_ERR, "No proxy on the list works. You lose.\n");

	/*
	 * We have to invalidate the cached connections if we moved to a different proxy
	 */
	if (prev != parent_curr) {
		pthread_mutex_lock(&connection_mtx);
		list = connection_list;
		while (list) {
			tmp = list->next;
			close(list->key);
			list = tmp;
		}
		plist_free(connection_list);
		pthread_mutex_unlock(&connection_mtx);
	}
		

	return i;
}

/*
 * Parse proxy parameter and add it to the global list.
 */
int parent_add(char *parent, int port) {
	int len, i;
	char *proxy;
	proxy_t *aux;
	struct in_addr host;

	/*
	 * Check format and parse it.
	 */
	proxy = strdup(parent);
	len = strlen(proxy);
	i = strcspn(proxy, ": ");
	if (i != len) {
		proxy[i++] = 0;
		while (i < len && (proxy[i] == ' ' || proxy[i] == '\t'))
			i++;

		if (i >= len) {
			free(proxy);
			return 0;
		}

		port = atoi(proxy+i);
	}

	/*
	 * No port argument and not parsed from proxy?
	 */
	if (!port) {
		syslog(LOG_ERR, "Invalid proxy specification %s.\n", parent);
		free(proxy);
		myexit(1);
	}

	/*
	 * Try to resolve proxy address
	 */
	if (debug)
		syslog(LOG_INFO, "Resolving proxy %s...\n", proxy);
	if (!so_resolv(&host, proxy)) {
		syslog(LOG_ERR, "Cannot resolve proxy %s, discarding.\n", parent);
		free(proxy);
		return 0;
	}

	aux = (proxy_t *)new(sizeof(proxy_t));
	aux->host = host;
	aux->port = port;
	parent_list = plist_add(parent_list, ++parent_count, (char *)aux);

	free(proxy);
	return 1;
}

/*
 * Register and bind new proxy service port.
 */
void listen_add(const char *service, plist_t *list, char *spec, int gateway) {
	struct in_addr source;
	int i, p, len, port;
	char *tmp;

	len = strlen(spec);
	p = strcspn(spec, ":");
	if (p < len-1) {
		tmp = substr(spec, 0, p);
		if (!so_resolv(&source, tmp)) {
			syslog(LOG_ERR, "Cannot resolve listen address %s\n", tmp);
			myexit(1);
		}
		free(tmp);
		port = atoi(tmp = spec+p+1);
	} else {
		source.s_addr = htonl(gateway ? INADDR_ANY : INADDR_LOOPBACK);
		port = atoi(tmp = spec);
	}

	if (!port) {
		syslog(LOG_ERR, "Invalid listen port %s.\n", tmp);
		myexit(1);
	}

	i = so_listen(port, source);
	if (i > 0) {
		*list = plist_add(*list, i, NULL);
		syslog(LOG_INFO, "%s listening on %s:%d\n", service, inet_ntoa(source), port);
	}
}

/*
 * Register a new tunnel definition, bind service port.
 */
void tunnel_add(plist_t *list, char *spec, int gateway) {
	struct in_addr source;
	int i, len, count, pos, port;
	char *field[4];
	char *tmp;

	spec = strdup(spec);
	len = strlen(spec);
	field[0] = spec;
	for (count = 1, i = 0; i < len; ++i)
		if (spec[i] == ':') {
			spec[i] = 0;
			field[count++] = spec+i+1;
		}

	pos = 0;
	if (count == 4) {
		if (!so_resolv(&source, field[pos])) {
                        syslog(LOG_ERR, "Cannot resolve tunel listen address: %s\n", field[pos]);
                        myexit(1);
                }
		pos++;
	} else
		source.s_addr = htonl(gateway ? INADDR_ANY : INADDR_LOOPBACK);

	if (count-pos == 3) {
		port = atoi(field[pos]);
		if (port == 0) {
			syslog(LOG_ERR, "Invalid tunnel local port: %s\n", field[pos]);
			myexit(1);
		}

		if (!strlen(field[pos+1]) || !strlen(field[pos+2])) {
			syslog(LOG_ERR, "Invalid tunnel target: %s:%s\n", field[pos+1], field[pos+2]);
			myexit(1);
		}

		tmp = new(strlen(field[pos+1]) + strlen(field[pos+2]) + 2 + 1);
		strcpy(tmp, field[pos+1]);
		strcat(tmp, ":");
		strcat(tmp, field[pos+2]);

		i = so_listen(port, source);
		if (i > 0) {
			*list = plist_add(*list, i, tmp);
			syslog(LOG_INFO, "New tunnel from %s:%d to %s\n", inet_ntoa(source), port, tmp);
		} else
			free(tmp);
	} else {
		printf("Tunnel specification incorrect ([laddress:]lport:rserver:rport).\n");
		myexit(1);
	}

	free(spec);
}

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
		if (i > 0 && head_ok(buf)) {
			data->headers = hlist_add(data->headers, head_name(buf), head_value(buf), 0, 0);
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
	int i, csize;

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

		write(dst, buf, strlen(buf));
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
			write(dst, buf, strlen(buf));
	} while (i > 0 && buf[0] != '\r' && buf[0] != '\n');

	free(buf);
	return 1;
}

/*
 * Full-duplex forwarding between proxy and client descriptors.
 * Used for bidirectional HTTP CONNECT connection.
 */
int tunnel(int cd, int sd) {
	struct timeval timeout;
	fd_set set;
	int i, to, ret, sel;
	char *buf;

	buf = new(BUFSIZE);

	if (debug)
		printf("tunnel: select cli: %d, srv: %d\n", cd, sd);

	do {
		FD_ZERO(&set);
		FD_SET(cd, &set);
		FD_SET(sd, &set);

		ret = 1;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		sel = select(FD_SETSIZE, &set, NULL, NULL, &timeout);
		if (sel > 0) {
			if (FD_ISSET(cd, &set)) {
				i = cd;
				to = sd;
			} else {
				i = sd;
				to = cd;
			}

			ret = read(i, buf, BUFSIZE);
			if (so_closed(to)) {
				free(buf);
				return 0;
			}

			if (ret > 0);
				write(to, buf, ret);

		} else if (sel < 0) {
			free(buf);
			return 0;
		}
	} while (ret > 0);

	free(buf);
	return 1;
}

/*
 * Duplicate client request headers, change requested method to HEAD
 * (so we avoid any body transfers during NTLM negotiation), and add
 * proxy authentication request headers.
 *
 * Read the reply, if it contains NTLM challenge, generate final
 * NTLM auth message and insert it into the original client header,
 * which is then processed by caller himself.
 *
 * If the immediate reply is an error message, it get stored into
 * error if not NULL, so it can be forwarded to the client. Caller
 * must then free it!
 */
int authenticate(int sd, rr_data_t data, char *user, char *passntlm2, char *passnt, char *passlm, char *domain, int silent) {
	char *tmp, *buf, *challenge;
	rr_data_t auth;
	int len, rc;

	buf = new(BUFSIZE);

	strcpy(buf, "NTLM ");
	len = ntlm_request(&tmp, workstation, domain, hashntlm2, hashnt, hashlm, flags);
	to_base64(MEM(buf, unsigned char, 5), MEM(tmp, unsigned char, 0), len, BUFSIZE-5);
	free(tmp);
	
	auth = dup_rr_data(data);

	/*
	 * If the request is CONNECT, we keep it unmodified as there are no possible data
	 * transfers until auth is fully negotiated. All other requests are changed to HEAD.
	 */
	if (!CONNECT(data)) {
		free(auth->method);
		auth->method = strdup("GET");
	}
	auth->headers = hlist_mod(auth->headers, "Proxy-Authorization", buf, 1);
	auth->headers = hlist_del(auth->headers, "Content-Length");

	if (debug && !silent) {
		printf("\nSending auth request...\n");
		hlist_dump(auth->headers);
	}

	if (!headers_send(sd, auth)) {
		rc = 0;
		goto bailout;
	}

	free_rr_data(auth);
	auth = new_rr_data();

	if (debug && !silent)
		printf("Reading auth response...\n");

	if (!headers_recv(sd, auth)) {
		rc = 0;
		goto bailout;
	}

	tmp = hlist_get(auth->headers, "Content-Length");
	if (tmp && (len = atoi(tmp))) {
		if (debug)
			printf("Got %d too many bytes.\n", len);
		data_drop(sd, len);
	}

	if (auth->code == 407) {
		tmp = hlist_get(auth->headers, "Proxy-Authenticate");
		if (tmp) {
			challenge = new(strlen(tmp));
			len = from_base64(challenge, tmp+5);
			if (len > NTLM_CHALLENGE_MIN) {
				len = ntlm_response(&tmp, challenge, len, user, passntlm2, passnt, passlm, workstation, domain, hashntlm2, hashnt, hashlm);
				if (len > 0) {
					strcpy(buf, "NTLM ");
					to_base64(MEM(buf, unsigned char, 5), MEM(tmp, unsigned char, 0), len, BUFSIZE-5);
					data->headers = hlist_mod(data->headers, "Proxy-Authorization", buf, 1);
					free(tmp);
				} else {
					syslog(LOG_ERR, "No target info block. Cannot do NTLMv2!\n");
					rc = 0;
					free(challenge);
					goto bailout;
				}
			} else {
				syslog(LOG_ERR, "Proxy returning invalid challenge!\n");
				rc = 0;
				free(challenge);
				goto bailout;
			}

			free(challenge);
		} else {
			if (debug)
				hlist_dump(auth->headers);
			syslog(LOG_WARNING, "No Proxy-Authenticate received! NTLM not supported?\n");
		}
	} else if (auth->code >= 500 && auth->code <= 599) {
		syslog(LOG_WARNING, "The request was denied!\n");

		close(sd);
		rc = 500;

		goto bailout;
	}

	rc = 1;

bailout:
	free_rr_data(auth);
	free(buf);

	return rc;
}

/*
 * Auth connection "sd" and try to return negotiated CONNECT
 * connection to a remote host:port (thost).
 *
 * Return 0 for success, -1 for proxy negotiation error and
 * -HTTP_CODE in case the request failed.
 */
int make_connect(int sd, const char *thost) {
	rr_data_t data1, data2;
	int ret;

	if (!sd || !thost || !strlen(thost))
		return -1;

	data1 = new_rr_data();
	data2 = new_rr_data();

	data1->req = 1;
	data1->method = strdup("CONNECT");
	data1->url = strdup(thost);
	data1->http = strdup("0");
	data1->headers = hlist_mod(data1->headers, "Proxy-Connection", "Keep-Alive", 1);

	if (debug)
		printf("Starting authentication...\n");

	ret = authenticate(sd, data1, user, passntlm2, passnt, passlm, domain, 0);
	if (ret && ret != 500) {
		if (so_closed(sd)) {
			close(sd);
			sd = proxy_connect();
			if (sd <= 0) {
				ret = -1;
				goto bailout;
			}
		}

		if (debug) {
			printf("Sending real request:\n");
			hlist_dump(data1->headers);
		}

		if (headers_send(sd, data1)) {
			if (debug)
				printf("Reading real response:\n");

			if (headers_recv(sd, data2)) {
				if (debug)
					hlist_dump(data2->headers);
				if (data2->code == 200) {
					if (debug)
						printf("Ok CONNECT response. Tunneling...\n");
					ret = 0;
					goto bailout;
				} else if (data2->code == 407) {
					syslog(LOG_ERR, "Authentication for tunnel %s failed!\n", thost);
				} else {
					syslog(LOG_ERR, "Request for CONNECT denied!\n");
				}
				ret = -data2->code;
			} else { 
				if (debug)
					printf("Reading response failed!\n");
				ret = -1;
			}
		} else {
			if (debug)
				printf("Sending request failed!\n");
			ret = -1;
		}
	} else {
		if (ret == 500)
			syslog(LOG_ERR, "Tunneling to %s not allowed!\n", thost);
		else
			syslog(LOG_ERR, "Authentication requests failed!\n");
		ret = -500;
	}

bailout:
	free_rr_data(data1);
	free_rr_data(data2);

	return ret;
}

/*
 * Return 0 if no body, -1 if until EOF, number if size known
 */
int has_body(rr_data_t request, rr_data_t response) {
	rr_data_t current;
	int length, nobody;
	char *tmp;

	/*
	 * Checking complete req+res conversation or just the
	 * first part when there's no response yet?
	 */
	current = (response->http != NULL ? response : request);

	/*
	 * HTTP body length decisions. There MUST NOT be any body from 
	 * server if the request was HEAD or reply is 1xx, 204 or 304.
	 * No body can be in GET request if direction is from client.
	 */
	if (current == response) {
		nobody = (HEAD(request) ||
			(response->code >= 100 && response->code < 200) ||
			response->code == 204 ||
			response->code == 304);
	} else {
		nobody = GET(request) || HEAD(request);
	}

	/*
	 * Otherwise consult Content-Length. If present, we forward exaclty
	 * that many bytes.
	 *
	 * If not present, but there is Transfer-Encoding or Content-Type
	 * (or a request to close connection, that is, end of data is signaled
	 * by remote close), we will forward until EOF.
	 *
	 * No C-L, no T-E, no C-T == no body.
	 */
	tmp = hlist_get(current->headers, "Content-Length");
	if (!nobody && tmp == NULL && (hlist_in(current->headers, "Content-Type")
			|| hlist_in(current->headers, "Transfer-Encoding")
			|| (response->code == 200))) {
		length = -1;
	} else
		length = (tmp == NULL || nobody ? 0 : atol(tmp));

	return length;
}

int scanner_hook(rr_data_t *request, rr_data_t *response, int *cd, int *sd, long maxKBs) {
	char *buf, *line, *pos, *tmp, *pat, *post, *isaid, *uurl;
	int bsize, lsize, size, len, i, nc;
	rr_data_t newreq, newres;
	plist_t list;
	int ok = 1;
	int done = 0;
	int headers_initiated = 0;
	long c, progress = 0, filesize = 0;

	if (!(*request)->method || !(*response)->http
		|| has_body(*request, *response) != -1
		|| hlist_subcmp((*response)->headers, "Transfer-Encoding", "chunked")
		|| !hlist_subcmp((*response)->headers, "Proxy-Connection", "close"))
		return PLUG_SENDHEAD | PLUG_SENDDATA;

	tmp = hlist_get((*request)->headers, "User-Agent");
	if (tmp) {
		tmp = lowercase(strdup(tmp));
		list = scanner_agent_list;
		while (list) {
			pat = lowercase(strdup(list->aux));
			if (debug)
				printf("scanner_hook: matching U-A header (%s) to %s\n", tmp, pat);
			if (!fnmatch(pat, tmp, 0)) {
				if (debug)
					printf("scanner_hook: positive match!\n");
				maxKBs = 0;
				free(pat);
				break;
			}
			free(pat);
			list = list->next;
		}
		free(tmp);
	}

	bsize = SAMPLE;
	buf = new(bsize);

	len = 0;
	do {
		size = read(*sd, buf + len, SAMPLE - len - 1);
		if (debug)
			printf("scanner_hook: read %d of %d\n", size, SAMPLE - len);
		if (size > 0)
			len += size;
	} while (size > 0 && len < SAMPLE - 1);

	if (strstr(buf, "<title>Downloading status</title>") && (pos=strstr(buf, "ISAServerUniqueID=")) && (pos = strchr(pos, '"'))) {
		pos++;
		c = strlen(pos);
		for (i = 0; i < c && pos[i] != '"'; ++i);

		if (pos[i] == '"') {
			isaid = substr(pos, 0, i);
			if (debug)
				printf("scanner_hook: ISA id = %s\n", isaid);

			lsize = BUFSIZE;
			line = new(lsize);
			do {
				i = so_recvln(*sd, &line, &lsize);

				c = strlen(line);
				if (len + c >= bsize) {
					bsize *= 2;
					tmp = realloc(buf, bsize);
					if (tmp == NULL)
						break;
					else
						buf = tmp;
				}

				strcat(buf, line);
				len += c;

				if (i > 0 && (!strncmp(line, " UpdatePage(", 12) || (done=!strncmp(line, "DownloadFinished(", 17)))) {
					if (debug)
						printf("scanner_hook: %s", line);

					if ((pos=strstr(line, "To be downloaded"))) {
						filesize = atol(pos+16);
						if (debug)
							printf("scanner_hook: file size detected: %ld KiBs (max: %ld)\n", filesize/1024, maxKBs);

						if (maxKBs && (maxKBs == 1 || filesize/1024 > maxKBs))
							break;

						/*
						 * We have to send HTTP protocol ID so we can send the notification
						 * headers during downloading. Once we've done that, it cannot appear
						 * again, which it would if we returned PLUG_SENDHEAD, so we must
						 * remember to not include it.
						 */
						headers_initiated = 1;
						tmp = new(MINIBUF_SIZE);
						snprintf(tmp, MINIBUF_SIZE, "HTTP/1.%s 200 OK\r\n", (*request)->http);
						write(*cd, tmp, strlen(tmp));
						free(tmp);
					}

					if (!headers_initiated) {
						if (debug)
							printf("scanner_hook: Giving up, \"To be downloaded\" line not found!\n");
						break;
					}

					/*
					 * Send a notification header to the client, just so it doesn't timeout
					 */
					if (!done) {
						tmp = new(MINIBUF_SIZE);
						progress = atol(line+12);
						snprintf(tmp, MINIBUF_SIZE, "ISA-Scanner: %ld of %ld\r\n", progress, filesize);
						write(*cd, tmp, strlen(tmp));
						free(tmp);
					}

					/*
					 * If download size is unknown beforehand, stop when downloaded amount is over ISAScannerSize
					 */
					if (!filesize && maxKBs && maxKBs != 1 && progress/1024 > maxKBs)
						break;
				}
			} while (i > 0 && !done);

			if (i > 0 && done && (pos = strstr(line, "\",\"")+3) && (c = strchr(pos, '"')-pos) > 0) {
				tmp = substr(pos, 0, c);
				pos = urlencode(tmp);
				free(tmp);

				uurl = urlencode((*request)->url);

				post = new(BUFSIZE);
				snprintf(post, bsize, "%surl=%s&%sSaveToDisk=YES&%sOrig=%s", isaid, pos, isaid, isaid, uurl);

				if (debug)
					printf("scanner_hook: Getting file with URL data = %s\n", (*request)->url);

				tmp = new(MINIBUF_SIZE);
				snprintf(tmp, MINIBUF_SIZE, "%d", (int)strlen(post));

				newres = new_rr_data();
				newreq = dup_rr_data(*request);

				free(newreq->method);
				newreq->method = strdup("POST");
				hlist_mod(newreq->headers, "Referer", (*request)->url, 1);
				hlist_mod(newreq->headers, "Content-Type", "application/x-www-form-urlencoded", 1);
				hlist_mod(newreq->headers, "Content-Length", tmp, 1);
				free(tmp);

				/*
				 * Try to use a cached connection or authenticate new.
				 */
				pthread_mutex_lock(&connection_mtx);
				i = plist_pop(&connection_list);
				pthread_mutex_unlock(&connection_mtx);
				if (i) {
					if (debug)
						printf("scanner_hook: Found autenticated connection %d!\n", i);
					nc = i;
				} else {
					nc = proxy_connect();
					c = authenticate(nc, newreq, user, passntlm2, passnt, passlm, domain, 0);
					if (c > 0 && c != 500) {
						if (debug)
							printf("scanner_hook: Authentication OK, getting the file...\n");
					} else {
						if (debug)
							printf("scanner_hook: Authentication failed\n");
						nc = 0;
					}
				}

				/*
				 * The POST request for the real file
				 */
				if (nc && headers_send(nc, newreq) && write(nc, post, strlen(post)) && headers_recv(nc, newres)) {
					if (debug)
						hlist_dump(newres->headers);

					free_rr_data(*response);

					/*
					 * We always know the filesize here. Send it to the client, because ISA doesn't!!!
					 * The clients progress bar doesn't work without it and it stinks!
					 */
					if (filesize || progress) {
						tmp = new(20);
						snprintf(tmp, 20, "%ld", filesize ? filesize : progress);
						newres->headers = hlist_mod(newres->headers, "Content-Length", tmp, 1);
					}

					/*
					 * Here we remember if previous code already sent some headers
					 * to the client. In such case, do not include the HTTP/1.x ID.
					 */
					newres->skip_http = headers_initiated;
					*response = dup_rr_data(newres);
					*sd = nc;

					len = 0;
					ok = PLUG_SENDHEAD | PLUG_SENDDATA;
				} else if (debug)
					printf("scanner_hook: New request failed\n");

				free(newreq);
				free(newres);
				free(post);
				free(uurl);
			}

			free(line);
			free(isaid);
		} else if (debug)
			printf("scanner_hook: ISA id not found\n");
	}

	if (len) {
		if (debug) {
			printf("scanner_hook: flushing %d original bytes\n", len);
			hlist_dump((*response)->headers);
		}

		if (!headers_send(*cd, *response)) {
			if (debug)
				printf("scanner_hook: failed to send headers\n");
			free(buf);
			return PLUG_ERROR;
		}

		size = write(*cd, buf, len);
		if (size > 0)
			ok = PLUG_SENDDATA;
		else
			ok = PLUG_ERROR;
	}

	if (debug)
		printf("scanner_hook: ending with %d\n", ok);

	free(buf);
	return ok;
}

/*
 * Thread starts here. Connect to the proxy, clear "already authenticated" flag.
 *
 * Then process the client request, authentication and proxy reply
 * back to client. We loop here to allow proxy keep-alive connections)
 * until the proxy closes.
 */
void *process(void *client) {
	int *rsocket[2], *wsocket[2];
	int i, loop, bodylen, keep, chunked, plugin;
	rr_data_t data[2], errdata;
	hlist_t tl;
	char *tmp, *buf, *pos, *dom;
	char *puser, *ppassntlm2, *ppassnt, *ppasslm, *pdomain;		/* Per-thread credentials; for NTLM-to-basic */

	int cd = (int)client;
	int authok = 0;
	int sd = 0;

	if (debug)
		printf("Thread processing...\n");

	pthread_mutex_lock(&connection_mtx);
	if (debug)
		plist_dump(connection_list);
	i = plist_pop(&connection_list);
	pthread_mutex_unlock(&connection_mtx);
	if (i) {
		if (debug)
			printf("Found autenticated connection %d!\n", i);
		sd = i;
		authok = 1;
	}

	if (!sd)
		sd = proxy_connect();

	puser = new(MINIBUF_SIZE);
	ppassntlm2 = new(MINIBUF_SIZE);
	ppassnt = new(MINIBUF_SIZE);
	ppasslm = new(MINIBUF_SIZE);
	pdomain = new(MINIBUF_SIZE);

	strlcpy(pdomain, domain, MINIBUF_SIZE);
	if (!ntlmbasic) {
		strlcpy(puser, user, MINIBUF_SIZE);
		if (passntlm2)
			memcpy(ppassntlm2, passntlm2, 16);
		if (passnt)
			memcpy(ppassnt, passnt, 21);
		if (passlm)
			memcpy(ppasslm, passlm, 21);
	}

	if (sd <= 0)
		goto bailout;

	do {
		/*
		 * data[0] is for the first loop pass
		 *   - we read the request headers from the client
		 *   - if not already done, we try to authenticate the connection
		 *   - we send the request headers to the proxy with HTTP body, if present
		 *
		 * data[1] is for the second pass
		 *   - read proxy response
		 *   - forward it to the client with HTTP body, if present
		 */
		data[0] = new_rr_data();
		data[1] = new_rr_data();

		rsocket[0] = wsocket[1] = &cd;
		rsocket[1] = wsocket[0] = &sd;

		keep = 0;

		for (loop = 0; loop < 2; loop++) {
			if (debug) {
				printf("\n******* Round %d C: %d, S: %d *******!\n", loop+1, cd, sd);
				printf("Reading headers...\n");
			}

			if (precache) update_active(1);

			if (!headers_recv(*rsocket[loop], data[loop])) {
				close(sd);
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				goto bailout;
			}

			chunked = 0;

			if (debug)
				hlist_dump(data[loop]->headers);

			/*
			 * NTLM-to-Basic implementation
			 * Switch to this mode automatically if the config-file
			 * supplied credentials don't work.
			 */
			if (!loop && ntlmbasic) {
				tmp = hlist_get(data[loop]->headers, "Proxy-Authorization");
				pos = NULL;
				buf = NULL;

				if (tmp) {
					buf = new(strlen(tmp));
					i = 5;
					while (tmp[++i] == ' ');
					from_base64(buf, tmp+i);
					if (debug)
						printf("NTLM-to-basic: Received client credentials.\n");
					pos = strchr(buf, ':');
				}

				if (pos == NULL) {
					if (debug && tmp != NULL)
						printf("NTLM-to-basic: Could not parse given credentials.\n");
					if (debug)
						printf("NTLM-to-basic: Sending the client auth request.\n");

					tmp = gen_auth_page(data[loop]->http);
					write(cd, tmp, strlen(tmp));
					free(tmp);

					if (buf) {
						memset(buf, 0, strlen(buf));
						free(buf);
					}

					close(sd);
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					if (precache) update_active(-1);
					goto bailout;
				} else {
					dom = strchr(buf, '\\');
					if (dom == NULL) {
						strlcpy(puser, buf, MIN(MINIBUF_SIZE, pos-buf+1));
					} else {
						strlcpy(pdomain, buf, MIN(MINIBUF_SIZE, dom-buf+1));
						strlcpy(puser, dom+1, MIN(MINIBUF_SIZE, pos-dom));
					}

					if (hashntlm2) {
						tmp = ntlm2_hash_password(puser, pdomain, pos+1);
						memcpy(ppassntlm2, tmp, 16);
						free(tmp);
					}

					if (hashnt) {
						tmp = ntlm_hash_nt_password(pos+1);
						memcpy(ppassnt, tmp, 21);
						free(tmp);
					}

					if (hashlm) {
						tmp = ntlm_hash_lm_password(pos+1);
						memcpy(ppasslm, tmp, 21);
						free(tmp);
					}

					if (debug) {
						printf("NTLM-to-basic: Credentials parsed: %s\\%s at %s\n", pdomain, puser, workstation);
					}

					memset(buf, 0, strlen(buf));
					free(buf);
				}
			}

			/*
			} else if (loop && data[loop]->code == 407) {
				if (debug)
					printf("NTLM-to-basic: Given credentials failed for proxy access.\n");

				if (!ntlmbasic)
					forced_basic = 1;

				tmp = gen_auth_page(data[loop]->http);
				write(cd, tmp, strlen(tmp));
				free(tmp);

				close(sd);
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				goto bailout;
			}
			*/

			/*
			 * Try to request keep-alive for every connection, but first remember if client
			 * really asked for it. If not, disconnect from him after the request and keep
			 * the authenticated connection in a pool.
			 *
			 * This way, proxy doesn't (or rather shouldn't) close our connection after
			 * completing the request. We store this connection and when the client is done
			 * and disconnects, we have an authenticated connection ready for future clients.
			 *
			 * The connection pool is shared among all threads, allowing maximum reuse.
			 */
			if (!loop && data[loop]->req) {
				if (hlist_subcmp(data[loop]->headers, "Proxy-Connection", "keep-alive"))
					keep = 1;

				/*
				 * Header replacement implementation
				 */
				tl = header_list;
				while (tl) {
					data[loop]->headers = hlist_mod(data[loop]->headers, tl->key, tl->value, 0);
					tl = tl->next;
				}

				/*
				 * Also remove runaway P-A from the client (e.g. Basic from N-t-B), which might 
				 * cause some ISAs to deny us, even if the connection is already auth'd.
				 */
				data[loop]->headers = hlist_mod(data[loop]->headers, "Proxy-Connection", "Keep-Alive", 1);
				if (!CONNECT(data[loop]))
					data[loop]->headers = hlist_mod(data[loop]->headers, "Connection", "Keep-Alive", 1);
				data[loop]->headers = hlist_del(data[loop]->headers, "Proxy-Authorization");
			}

			/*
			 * Got request from client and connection is not yet authenticated?
			 */
			if (!loop && data[0]->req && !authok) {
				errdata = NULL;
				if (!(i = authenticate(*wsocket[0], data[0], puser, ppassntlm2, ppassnt, ppasslm, pdomain, 0)))
					syslog(LOG_ERR, "Authentication requests failed. Will try without.\n");

				if (!i || so_closed(sd)) {
					if (debug)
						printf("Proxy closed connection. Reconnecting...\n");
					close(sd);
					sd = proxy_connect();
					if (sd <= 0) {
						free_rr_data(data[0]);
						free_rr_data(data[1]);
						if (precache) update_active(-1);
						goto bailout;
					}
				}
			}

			/*
			 * Was the request first and did we authenticated with proxy?
			 * Remember not to authenticate this connection any more, should
			 * it be reused for future client requests.
			 */
			if (loop && !authok && data[1]->code != 407)
				authok = 1;

			/*
			 * This is to make the ISA AV scanner bullshit transparent.
			 * If the page returned is scan-progress-html-fuck instead
			 * of requested file/data, parse it, wait for completion,
			 * make a new request to ISA for the real data and substitute
			 * the result for the original response html-fuck response.
			 */
			plugin = PLUG_ALL;
			if (scanner_plugin && loop) {
				plugin = scanner_hook(&data[0], &data[1], wsocket[loop], rsocket[loop], scanner_plugin_maxsize);
			}

			bodylen = has_body(data[0], data[1]);
			if (debug && bodylen == -1) {
				printf("*************************\n");
				printf("CL: %s, C: %s, CT: %s, TE: %s\n", 
					hlist_get(data[loop]->headers, "Content-Length"),
					hlist_get(data[loop]->headers, "Connection"),
					hlist_get(data[loop]->headers, "Content-Type"),
					hlist_get(data[loop]->headers, "Transfer-Encoding"));
			}

			if (plugin & PLUG_SENDHEAD) {
				if (debug) {
					printf("Sending headers...\n");
					if (!loop)
						hlist_dump(data[loop]->headers);
				}

				/*
				if (loop && serialize) {
					hlist_mod(data[loop]->headers, "Proxy-Connection", "close", 1);
					hlist_mod(data[loop]->headers, "Connection", "close", 1);
				}
				*/

				/*
				 * Forward client's headers to the proxy and vice versa; authenticate()
				 * might have by now prepared 1st and 2nd auth steps and filled our
				 * headers with the 3rd, final, NTLM message.
				 */
				if (!headers_send(*wsocket[loop], data[loop])) {
					close(sd);
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					if (precache) update_active(-1);
					goto bailout;
				}
			}

			/*
			 * Was the request CONNECT and proxy agreed?
			 */
			if (loop && CONNECT(data[0]) && data[1]->code == 200) {
				if (debug)
					printf("Ok CONNECT response. Tunneling...\n");

				tunnel(cd, sd);
				close(sd);
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				if (precache) update_active(-1);
				goto bailout;
			}
			
			if (plugin & PLUG_SENDDATA) {
				/*
				 * Ok, so do we expect any body?
				 */
				if (bodylen) {
					/*
					 * Check for supported T-E.
					 */
					if (hlist_subcmp(data[loop]->headers, "Transfer-Encoding", "chunked"))
						chunked = 1;

					if (chunked) {
						if (debug)
							printf("Chunked body included.\n");

						if (!chunked_data_send(*wsocket[loop], *rsocket[loop])) {
							if (debug)
								printf("Could not chunk send whole body\n");
							close(sd);
							free_rr_data(data[0]);
							free_rr_data(data[1]);
							if (precache) update_active(-1);
							goto bailout;
						} else if (debug) {
							printf("Chunked body sent.\n");
						}
					} else {
						if (debug)
							printf("Body included. Lenght: %d\n", bodylen);

						if (!bodylen || !data_send(*wsocket[loop], *rsocket[loop], bodylen)) {
							if (debug)
								printf("Could not send whole body\n");
							close(sd);
							free_rr_data(data[0]);
							free_rr_data(data[1]);
							if (precache) update_active(-1);
							goto bailout;
						} else if (debug) {
							printf("Body sent.\n");
						}
					}
				} else if (debug)
					printf("No body.\n");

				if (precache) update_active(-1);

				/*
				 * Windows cannot detect remotely closed connection
				 * as accurately as UNIX. We look if the proxy explicitly
				 * tells us that it's closing the connection and if so, use
				 * it as fact that the connection is closed.
				 */
				if (hlist_subcmp(data[loop]->headers, "Proxy-Connection", "close")) {
					if (debug)
						printf("PROXY CLOSED CONNECTION\n");
					close(sd);
				}

			}
		}

		free_rr_data(data[0]);
		free_rr_data(data[1]);
	} while (!so_closed(sd) && !so_closed(cd) && !serialize && (keep || so_dataready(cd)));

bailout:
	free(puser);
	free(ppassntlm2);
	free(ppassnt);
	free(ppasslm);
	free(pdomain);

	if (debug)
		printf("\nThread finished.\n");

	close(cd);
	if (!so_closed(sd) && authok) {
		if (debug)
			printf("Storing the connection for reuse (%d:%d).\n", cd, sd);
		pthread_mutex_lock(&connection_mtx);
		connection_list = plist_add(connection_list, sd, NULL);
		pthread_mutex_unlock(&connection_mtx);
	} else
		close(sd);

	/*
	 * Add ourself to the "threads to join" list.
	 */
	if (!serialize) {
		pthread_mutex_lock(&threads_mtx);
		threads_list = plist_add(threads_list, (unsigned long)pthread_self(), NULL);
		pthread_mutex_unlock(&threads_mtx);
	}

	return NULL;
}

void *precache_thread(void *data) {
	int i, sd;
	rr_data_t data1, data2;
	char *tmp;
	int new = 0;

	while (!quit) {
		if (plist_count(connection_list) < precache && check_active() < 1) {
			printf("precache_thread: creating new connection (active: %d)\n", active_conns);
			sd = proxy_connect();

			data1 = new_rr_data();
			data2 = new_rr_data();

			data1->req = 1;
			data1->method = strdup("GET");
			data1->url = strdup("http://www.google.com/");
			data1->http = strdup("1");

			i = authenticate(sd, data1, user, passntlm2, passnt, passlm, domain, 1);
			if (i && i == 1 && !so_closed(sd) && headers_send(sd, data1) && headers_recv(sd, data2) && data2->code == 302) {
				tmp = hlist_get(data2->headers, "Content-Length");
				if (tmp)
					data_drop(sd, atoi(tmp));

				new++;
				pthread_mutex_lock(&connection_mtx);
				connection_list = plist_add(connection_list, sd, NULL);
				pthread_mutex_unlock(&connection_mtx);
			} else {
				if (debug)
					printf("precache_thread: cooling down (i = %d, closed = %d, code = %d)...\n", i, so_closed(sd), data2->code);
				sleep(60);
			}
		} else {
			printf("                                                                                                SLEEPING\n");
			sleep(4);
			//if (new > 0) {
			if (active_conns > 0) {
				new = 0;
				printf("*************************************************************************\n");
				printf("precache_thread: connection cache full (%d), resting (active: %d)\n", plist_count(connection_list), active_conns);
			}
			sched_yield();
		}
	}

	return NULL;
}

/*
 * Another thread-create function. This one does the tunneling/forwarding
 * for the -L parameter. We receive malloced structure (pthreads pass only
 * one pointer arg) containing accepted client socket and a string with
 * remote server:port address.
 *
 * The -L is obviously better tunneling solution than using extra tools like
 * "corkscrew" which after all require us for authentication and tunneling
 *  their HTTP CONNECT in the end.
 */
void *autotunnel(void *client) {
	int cd = ((struct thread_arg_s *)client)->fd;
	char *thost = ((struct thread_arg_s *)client)->target;
	int sd;

	sd = proxy_connect();
	free(client);

	if (sd <= 0) {
		close(cd);
		return NULL;
	}

	if (debug)
		printf("Tunneling to %s for client %d...\n", thost, cd);

	if (!make_connect(sd, thost)) {
		tunnel(cd, sd);
	}

	close(sd);
	close(cd);

	/*
	 * Add ourself to the "threads to join" list.
	 */
	pthread_mutex_lock(&threads_mtx);
	threads_list = plist_add(threads_list, (unsigned long)pthread_self(), NULL);
	pthread_mutex_unlock(&threads_mtx);

	return NULL;
}

void *socks5(void *client) {
	int cd = (int)client;
	char *tmp, *thost, *tport, *uname, *upass;
	unsigned char *bs, *auths, *addr;
	unsigned short port;
	int ver, r, c, i;

	int found = -1;
	int sd = 0;
	int open = !hlist_count(users_list);

	// Check version, possibly fuck'em
	bs = (unsigned char *)new(10);
	thost = new(MINIBUF_SIZE);
	tport = new(MINIBUF_SIZE);
	r = read(cd, bs, 2);
	if (r != 2 || bs[0] != 5)
		goto bail1;

	// Read offered auth schemes
	c = bs[1];
	auths = (unsigned char *)new(c+1);
	r = read(cd, auths, c);
	if (r != c)
		goto bail2;

	// Are we wide open and client is OK with no auth?
	if (open) {
		for (i = 0; i < c && (auths[i] || (found = 0)); ++i);
	}

	// If not, accept plain auth if offered
	if (found < 0) {
		for (i = 0; i < c && (auths[i] != 2 || !(found = 2)); ++i);
	}

	// If not found fuck'em; if so, complete handshake
	if (found < 0) {
		bs[0] = 5;
		bs[1] = 0xFF;
		write(cd, bs, 2);
		goto bail2;
	} else {
		bs[0] = 5;
		bs[1] = found;
		write(cd, bs, 2);
	}

	// Auth negotiated?
	if (found != 0) {
		// Check ver and read username len
		r = read(cd, bs, 2);
		if (r != 2) {
			bs[0] = 1;
			bs[1] = 0xFF;		// Unsuccessful (not supported)
			write(cd, bs, 2);
			goto bail2;
		}
		c = bs[1];

		// Read username and pass len
		uname = new(c+1);
		r = read(cd, uname, c+1);
		if (r != c+1) {
			free(uname);
			goto bail2;
		}
		i = uname[c];
		uname[c] = 0;
		c = i;

		// Read pass
		upass = new(c+1);
		r = read(cd, upass, c);
		if (r != c) {
			free(upass);
			free(uname);
			goto bail2;
		}
		upass[c] = 0;
		
		// Check it
		tmp = hlist_get(users_list, uname);
		if (!hlist_count(users_list) || (tmp && !strcmp(tmp, upass))) {
			bs[0] = 1;
			bs[1] = 0;		// Success
		} else {
			bs[0] = 1;
			bs[1] = 0xFF;		// Failed
		}

		// Send response
		write(cd, bs, 2);
		free(upass);
		free(uname);

		// Fuck'em if auth failed
		if (!bs[0])
			goto bail2;
	}

	// Read request type
	r = read(cd, bs, 4);
	if (r != 4)
		goto bail2;

	// Do we support it? If not, fuck'em
	if (bs[1] != 1 || (bs[3] != 1 && bs[3] != 3)) {
		bs[0] = 5;
		bs[1] = 2;			// Not allowed
		bs[2] = 0;
		bs[3] = 1;			// Dummy IPv4
		memset(bs+4, 0, 6);
		write(cd, bs, 10);
		goto bail2;
	}

	// Ok, it's connect req for domain or IPv4
	// Let's read dest address
	if (bs[3] == 1) {
		ver = 1;			// IPv4
		c = 4;
	} else if (bs[3] == 3) {
		ver = 2;			// FQDN
		r = read(cd, &c, 1);
		if (r != 1)
			goto bail2;
	} else
		goto bail2;

	addr = (unsigned char *)new(c+10 + 1);
	r = read(cd, addr, c);
	if (r != c)
		goto bail3;
	addr[c] = 0;

	// Convert the address to character string
	if (ver == 1) {
		sprintf(thost, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	} else {
		strlcpy(thost, (char *)addr, MINIBUF_SIZE);
	}

	// Read port number and convert to host byte order
	r = read(cd, &port, 2);
	if (r != 2)
		goto bail3;
	sprintf(tport, "%d", ntohs(port));
	strlcat(thost, ":", MINIBUF_SIZE);
	strlcat(thost, tport, MINIBUF_SIZE);

	// Try to get the connection from proxy
	sd = proxy_connect();
	if (sd <= 0 || (i=make_connect(sd, thost))) {
		bs[0] = 5;
		bs[1] = 1;			// General failure
		bs[2] = 0;
		bs[3] = 1;			// Dummy IPv4
		memset(bs+4, 0, 6);
		write(cd, bs, 10);
		goto bail3;
	} else {
		bs[0] = 5;
		bs[1] = 0;			// Success
		bs[2] = 0;
		bs[3] = 1;			// Dummy IPv4
		memset(bs+4, 0, 6);
		write(cd, bs, 10);
	}

	tunnel(cd, sd);

bail3:
	free(addr);
bail2:
	free(auths);
bail1:
	free(thost);
	free(tport);
	free(bs);
	close(cd);
	if (sd)
		close(sd);

	return NULL;
}

#define MAGIC_TESTS	11

void magic_auth_detect(const char *url) {
	int i, nc, c, found = -1;
	rr_data_t req, res;
	char *tmp, *pos, *host = NULL;

	char *authstr[5] = { "NTLMv2", "NTLM2SR", "NT", "NTLM", "LM" };
	int prefs[MAGIC_TESTS][5] = {
		/* NT, LM, NTLMv2, Flags, Auth param equiv. */
		{ 0, 0, 1, 0, 0 },
		{ 0, 0, 1, 0xa208b207, 0 },
		{ 0, 0, 1, 0xa2088207, 0 },
		{ 2, 0, 0, 0, 1 },
		{ 2, 0, 0, 0x88207, 1 },
		{ 1, 0, 0, 0, 2 },
		{ 1, 0, 0, 0x8205, 2 },
		{ 1, 1, 0, 0, 3 },
		{ 1, 1, 0, 0x8207, 3 },
		{ 0, 1, 0, 0, 4 },
		{ 0, 1, 0, 0x8206, 4 }
	};

	debug = 0;

	if (!passnt || !passlm || !passntlm2) {
		printf("Cannot detect NTLM dialect - password or its hashes must be defined, try -I\n");
		exit(1);
	}

	pos = strstr(url, "://");
	if (pos) {
		tmp = strchr(pos+3, '/');
		host = substr(pos+3, 0, tmp ? tmp-pos-3 : 0);
	} else {
		fprintf(stderr, "Invalid URL (%s)\n", url);
		return;
	}

	for (i = 0; i < MAGIC_TESTS; ++i) {
		res = new_rr_data();
		req = new_rr_data();

		req->req = 1;
		req->method = strdup("GET");
		req->url = strdup(url);
		req->http = strdup("1");
		req->headers = hlist_add(req->headers, "Proxy-Connection", "Keep-Alive", 1, 1);
		if (host)
			req->headers = hlist_add(req->headers, "Host", host, 1, 1);

		hashnt = prefs[i][0];
		hashlm = prefs[i][1];
		hashntlm2 = prefs[i][2];
		flags = prefs[i][3];

		printf("Config profile %2d/%d... ", i+1, MAGIC_TESTS);

		nc = proxy_connect();
		if (nc <= 0) {
			printf("\nConnection to proxy failed, bailing out\n");
			free_rr_data(res);
			free_rr_data(req);
			close(nc);
			if (host)
				free(host);
			return;
		}

		c = authenticate(nc, req, user, passntlm2, passnt, passlm, domain, 0);
		if (c <= 0 || c == 500) {
			printf("Auth request ignored (HTTP code: %d)\n", c);
			free_rr_data(res);
			free_rr_data(req);
			close(nc);
			continue;
		}

		if (!headers_send(nc, req) || !headers_recv(nc, res)) {
			printf("Connection closed\n");
		} else {
			if (res->code == 407) {
				printf("Credentials rejected\n");
			} else {
				printf("OK (HTTP code: %d)\n", res->code);
				if (found < 0) {
					found = i;
					/*
					 * Following only for prod. version
					 */
					free_rr_data(res);
					free_rr_data(req);
					close(nc);
					break;
				}
			}
		}

		free_rr_data(res);
		free_rr_data(req);
		close(nc);
	}

	if (found > -1) {
		printf("----------------------------[ Profile %2d ]------\n", found);
		printf("Auth            %s\n", authstr[prefs[found][4]]);
		if (prefs[found][3])
			printf("Flags           0x%x\n", prefs[found][3]);
		if (prefs[found][0]) {
			printf("PassNT          %s\n", tmp=printmem(passnt, 16, 8));
			free(tmp);
		}
		if (prefs[found][1]) {
			printf("PassLM          %s\n", tmp=printmem(passlm, 16, 8));
			free(tmp);
		}
		if (prefs[found][2]) {
			printf("PassNTLMv2      %s\n", tmp=printmem(passntlm2, 16, 8));
			free(tmp);
		}
		printf("------------------------------------------------\n");
	} else
		printf("You have used wrong credentials, bad URL or your proxy is quite insane,\nin which case try submitting a Support Request.\n");

	if (host)
		free(host);
}

void carp(const char *msg, int console) {
	if (console)
		printf(msg);
	else
		syslog(LOG_ERR, msg);
	
	myexit(1);
}

int main(int argc, char **argv) {
	char *tmp, *head, *uid, *pidfile, *auth;
	char *password, *cpassntlm2, *cpassnt, *cpasslm;
	struct passwd *pw;
	struct termios termold, termnew;
	pthread_attr_t pattr;
	pthread_t pthr;
	hlist_t list;
	int i;

	int cd = 0;
	int help = 0;
	int nuid = 0;
	int ngid = 0;
	int gateway = 0;
	int tc = 0;
	int tj = 0;
	int interactivepwd = 0;
	int interactivehash = 0;
	int tracefile = 0;
	plist_t tunneld_list = NULL;
	plist_t proxyd_list = NULL;
	plist_t socksd_list = NULL;
	plist_t rules = NULL;
	config_t cf = NULL;
	char *magic_detect = NULL;

	user = new(MINIBUF_SIZE);
	domain = new(MINIBUF_SIZE);
	password = new(MINIBUF_SIZE);
	cpassntlm2 = new(MINIBUF_SIZE);
	cpassnt = new(MINIBUF_SIZE);
	cpasslm = new(MINIBUF_SIZE);
	workstation = new(MINIBUF_SIZE);
	pidfile = new(MINIBUF_SIZE);
	uid = new(MINIBUF_SIZE);
	auth = new(MINIBUF_SIZE);

	openlog("cntlm", LOG_CONS, LOG_DAEMON);

#if config_endian == 0
	syslog(LOG_INFO, "Starting cntlm version " VERSION " for BIG endian\n");
#else
	syslog(LOG_INFO, "Starting cntlm version " VERSION " for LITTLE endian\n");
#endif

	while ((i = getopt(argc, argv, ":-:a:c:d:fghIl:p:r:su:vw:A:BD:F:G:HL:M:P:S:T:U:")) != -1) {
		switch (i) {
			case 'A':
			case 'D':
				if (!acl_add(&rules, optarg, (i == 'A' ? ACL_ALLOW : ACL_DENY)))
					myexit(1);
				break;
			case 'a':
				strlcpy(auth, optarg, MINIBUF_SIZE);
				break;
			case 'B':
				ntlmbasic = 1;
				break;
			case 'c':
				if (!(cf = config_open(optarg))) {
					syslog(LOG_ERR, "Cannot access specified config file: %s\n", optarg);
					myexit(1);
				}
				break;
			case 'd':
				strlcpy(domain, optarg, MINIBUF_SIZE);
				break;
			case 'F':
				flags = swap32(strtoul(optarg, &tmp, 0));
				break;
			case 'f':
				asdaemon = 0;
				break;
			case 'G':
				if (strlen(optarg)) {
					scanner_plugin = 1;
					if (!scanner_plugin_maxsize)
						scanner_plugin_maxsize = 1;
					i = strlen(optarg) + 3;
					tmp = new(i);
					snprintf(tmp, i, "*%s*", optarg);
					scanner_agent_list = plist_add(scanner_agent_list, 0, tmp);
				}
				break;
			case 'g':
				gateway = 1;
				break;
			case 'H':
				interactivehash = 1;
				break;
			case 'I':
				interactivepwd = 1;
				break;
			case 'L':
				/*
				 * Parse and validate the argument.
				 * Create a listening socket for tunneling.
				 */
				tunnel_add(&tunneld_list, optarg, gateway);
				break;
			case 'l':
				/*
				 * Create a listening socket for proxy function.
				 */
				listen_add("Proxy", &proxyd_list, optarg, gateway);
				break;
			case 'M':
				magic_detect = strdup(optarg);
				break;
			case 'P':
				strlcpy(pidfile, optarg, MINIBUF_SIZE);
				break;
			case 'p':
				/*
				 * Overwrite the password parameter with '*'s to make it
				 * invisible in "ps", /proc, etc.
				 */
				strlcpy(password, optarg, MINIBUF_SIZE);
				for (i = strlen(optarg)-1; i >= 0; --i)
					optarg[i] = '*';
				break;
			case 'r':
				if (head_ok(optarg))
					header_list = hlist_add(header_list, head_name(optarg), head_value(optarg), 0, 0);
				break;
			case 'S':
				scanner_plugin = 1;
				scanner_plugin_maxsize = atol(optarg);
				break;
			case 's':
				/*
				 * Do not use threads - for debugging purposes only
				 */
				serialize = 1;
				break;
			case 'T':
				tracefile = open(optarg, O_CREAT | O_EXCL | O_WRONLY, 0600);
				if (tracefile < 0) {
					fprintf(stderr, "Cannot create the trace file, make sure it doesn't already exist.\n");
					myexit(1);
				} else {
					printf("Redirecting all output to %s\n", optarg);
					dup2(tracefile, 1);
					dup2(tracefile, 2);
					printf("Cntlm debug trace, version " VERSION);
#ifdef __CYGWIN__
					printf(" win32/cygwin port");
#endif
					printf(".\nCommand line: ");
					for (i = 0; i < argc; ++i)
						printf("%s ", argv[i]);
					printf("\n");
				}
				break;
			case 'U':
				strlcpy(uid, optarg, MINIBUF_SIZE);
				break;
			case 'u':
				i = strcspn(optarg, "@");
				if (i != strlen(optarg)) {
					strlcpy(user, optarg, MIN(MINIBUF_SIZE, i+1));
					strlcpy(domain, optarg+i+1, MINIBUF_SIZE);
				} else {
					strlcpy(user, optarg, MINIBUF_SIZE);
				}
				break;
			case 'v':
				debug = 1;
				asdaemon = 0;
				openlog("cntlm", LOG_CONS | LOG_PERROR, LOG_DAEMON);
				break;
			case 'w':
				strlcpy(workstation, optarg, MINIBUF_SIZE);
				break;
			case 'h':
			default:
				help = 1;
		}
	}

	/*
	 * Help requested?
	 */
	if (help) {
		printf("CNTLM - Accelerating NTLM Authentication Proxy version " VERSION "\nCopyright (c) 2oo7 David Kubicek\n\n"
			"This program comes with NO WARRANTY, to the extent permitted by law. You\n"
			"may redistribute copies of it under the terms of the GNU GPL Version 2 or\n"
			"newer. For more information about these matters, see the file LICENSE.\n"
			"For copyright holders of included encryption routines see headers.\n\n");

		fprintf(stderr, "Usage: %s [-AaBcDdFfgHhILlMPSsTUvw] -u <user>[@<domain>] -p <pass> <proxy_host>[:]<proxy_port> ...\n", argv[0]);
		fprintf(stderr, "\t-A  <address>[/<net>]\n"
				"\t    New ACL allow rule. Address can be an IP or a hostname, net must be a number (CIDR notation)\n");
		fprintf(stderr, "\t-a  ntlm | nt | lm\n"
				"\t    Authentication parameter - combined NTLM, just LM, or just NT. Default is to,\n"
				"\t    send both, NTLM. It is the most versatile setting and likely to work for you.\n");
		fprintf(stderr, "\t-B  Enable NTLM-to-basic authentication.\n");
		fprintf(stderr, "\t-c  <config_file>\n"
				"\t    Configuration file. Other arguments can be used as well, overriding\n"
				"\t    config file settings.\n");
		fprintf(stderr, "\t-D  <address>[/<net>]\n"
				"\t    New ACL deny rule. Syntax same as -A.\n");
		fprintf(stderr, "\t-d  <domain>\n"
				"\t    Domain/workgroup can be set separately.\n");
		fprintf(stderr, "\t-f  Run in foreground, do not fork into daemon mode.\n");
		fprintf(stderr, "\t-F  <flags>\n"
				"\t    NTLM authentication flags.\n");
		fprintf(stderr, "\t-G  <pattern>\n"
				"\t    User-Agent matching for the trans-isa-scan plugin.\n");
		fprintf(stderr, "\t-g  Gateway mode - listen on all interfaces, not only loopback.\n");
		fprintf(stderr, "\t-H  Prompt for the password interactively, print its hashes and exit (NTLMv2 needs -u and -d).\n");
		fprintf(stderr, "\t-h  Print this help info along with version number.\n");
		fprintf(stderr, "\t-I  Prompt for the password interactively.\n");
		fprintf(stderr, "\t-L  [<saddr>:]<lport>:<rhost>:<rport>\n"
				"\t    Forwarding/tunneling a la OpenSSH. Same syntax - listen on lport\n"
				"\t    and forward all connections through the proxy to rhost:rport.\n"
				"\t    Can be used for direct tunneling without corkscrew, etc.\n");
		fprintf(stderr, "\t-l  [<saddr>:]<lport>\n"
				"\t    Main listening port for the NTLM proxy.\n");
		fprintf(stderr, "\t-M  <testurl>\n"
				"\t    Magic autodetection of proxy's NTLM dialect.\n");
		fprintf(stderr, "\t-P  <pidfile>\n"
				"\t    Create a PID file upon successful start.\n");
		fprintf(stderr, "\t-p  <password>\n"
				"\t    Account password. Will not be visible in \"ps\", /proc, etc.\n");
		fprintf(stderr, "\t-r  \"HeaderName: value\"\n"
				"\t    Add a header substitution. All such headers will be added/replaced\n"
				"\t    in the client's requests.\n");
		fprintf(stderr, "\t-S  <size_in_kb>\n"
				"\t    Enable transparent handler of ISA AV scanner plugin for files up to size_in_kb KiB.\n");
		fprintf(stderr, "\t-s  Do not use threads, serialize all requests - for debugging only.\n");
		fprintf(stderr, "\t-U  <uid>\n"
				"\t    Run as uid. It is an important security measure not to run as root.\n");
		fprintf(stderr, "\t-u  <user>[@<domain]\n"
				"\t    Domain/workgroup can be set separately.\n");
		fprintf(stderr, "\t-v  Print debugging information.\n");
		fprintf(stderr, "\t-w  <workstation>\n"
				"\t    Some proxies require correct NetBIOS hostname.\n\n");
		exit(1);
	}

	/*
	 * More arguments on the command-line? Must be proxies.
	 */
	i = optind;
	while (i < argc) {
		tmp = strchr(argv[i], ':');
		parent_add(argv[i], !tmp && i+1 < argc ? atoi(argv[i+1]) : 0);
		i += (!tmp ? 2 : 1);
	}

	/*
	 * No configuration file yet? Load the default.
	 */
#ifdef SYSCONFDIR
	if (!cf) {
#ifdef __CYGWIN__
		tmp = getenv("PROGRAMFILES");
		if (tmp == NULL) {
			tmp = "C:\\Program Files";
		}

		head = new(MINIBUF_SIZE);
		strlcpy(head, tmp, MINIBUF_SIZE);
		strlcat(head, "\\cntlm\\cntlm.ini", MINIBUF_SIZE);
		cf = config_open(head);
#else
		cf = config_open(SYSCONFDIR "/cntlm.conf");
#endif
		if (debug) {
			if (cf)
				printf("Default config file opened successfully\n");
			else
				syslog(LOG_ERR, "Could not open default config file\n");
		}
	}
#endif

	/*
	 * If any configuration file was successfully opened, parse it.
	 */
	if (cf) {
		/*
		 * Check if gateway mode is requested before actually binding any ports.
		 */
		tmp = new(MINIBUF_SIZE);
		CFG_DEFAULT(cf, "Gateway", tmp, MINIBUF_SIZE);
		if (!strcasecmp("yes", tmp))
			gateway = 1;
		free(tmp);

		/*
		 * Check for NTLM-to-basic settings
		 */
		tmp = new(MINIBUF_SIZE);
		CFG_DEFAULT(cf, "NTLMToBasic", tmp, MINIBUF_SIZE);
		if (!strcasecmp("yes", tmp))
			ntlmbasic = 1;
		free(tmp);

		/*
		 * Setup the rest of tunnels.
		 */
		while ((tmp = config_pop(cf, "Tunnel"))) {
			tunnel_add(&tunneld_list, tmp, gateway);
			free(tmp);
		}

		/*
		 * Bind the rest of proxy service ports.
		 */
		while ((tmp = config_pop(cf, "Listen"))) {
			listen_add("Proxy", &proxyd_list, tmp, gateway);
			free(tmp);
		}

		/*
		 * Bind the rest of SOCKS5 service ports.
		 */
		while ((tmp = config_pop(cf, "SOCKS5"))) {
			listen_add("SOCKS5 proxy", &socksd_list, tmp, gateway);
			free(tmp);
		}

		/*
		 * Accept only headers not specified on the command line.
		 * Command line has higher priority.
		 */
		while ((tmp = config_pop(cf, "Header"))) {
			if (head_ok(tmp)) {
				head = head_name(tmp);
				if (!hlist_in(header_list, head))
					header_list = hlist_add(header_list, head_name(tmp), head_value(tmp), 0, 0);
				free(head);
			} else
				syslog(LOG_ERR, "Invalid header format: %s\n", tmp);

			free(tmp);
		}

		/*
		 * Add the rest of parent proxies.
		 */
		while ((tmp = config_pop(cf, "Proxy"))) {
			parent_add(tmp, 0);
			free(tmp);
		}

		/*
		 * No ACLs on the command line? Use config file.
		 */
		if (rules == NULL) {
			list = cf->options;
			while (list) {
				if (!(i=strcasecmp("Allow", list->key)) || !strcasecmp("Deny", list->key))
					if (!acl_add(&rules, list->value, i ? ACL_DENY : ACL_ALLOW))
						myexit(1);
				list = list->next;
			}

			while ((tmp = config_pop(cf, "Allow")))
				free(tmp);
			while ((tmp = config_pop(cf, "Deny")))
				free(tmp);
		}

		/*
		 * Single options.
		 */
		CFG_DEFAULT(cf, "Auth", auth, MINIBUF_SIZE);
		CFG_DEFAULT(cf, "Domain", domain, MINIBUF_SIZE);
		CFG_DEFAULT(cf, "Password", password, MINIBUF_SIZE);
		CFG_DEFAULT(cf, "PassNTLMv2", cpassntlm2, MINIBUF_SIZE);
		CFG_DEFAULT(cf, "PassNT", cpassnt, MINIBUF_SIZE);
		CFG_DEFAULT(cf, "PassLM", cpasslm, MINIBUF_SIZE);
		CFG_DEFAULT(cf, "Username", user, MINIBUF_SIZE);
		CFG_DEFAULT(cf, "Workstation", workstation, MINIBUF_SIZE);

		tmp = new(MINIBUF_SIZE);
		CFG_DEFAULT(cf, "Flags", tmp, MINIBUF_SIZE);
		if (!flags)
			flags = swap32(strtoul(tmp, NULL, 0));
		free(tmp);

		tmp = new(MINIBUF_SIZE);
		CFG_DEFAULT(cf, "ISAScannerSize", tmp, MINIBUF_SIZE);
		if (!scanner_plugin_maxsize && strlen(tmp)) {
			scanner_plugin = 1;
			scanner_plugin_maxsize = atoi(tmp);
		}
		free(tmp);

		while ((tmp = config_pop(cf, "SOCKS5Access"))) {
			head = strchr(tmp, ':');
			if (!head) {
				syslog(LOG_ERR, "Invalid username:password format for SOCKS5Access: %s\n", tmp);
			} else {
				head[0] = 0;
				users_list = hlist_add(users_list, tmp, head+1, 1, 1);
				printf("Adding SOCKS5 user %s, pass %s\n", tmp, head+1);
			}
		}
					

		/*
		 * Add User-Agent matching patterns.
		 */
		while ((tmp = config_pop(cf, "ISAScannerAgent"))) {
			scanner_plugin = 1;
			if (!scanner_plugin_maxsize)
				scanner_plugin_maxsize = 1;

			if ((i = strlen(tmp))) {
				head = new(i + 3);
				snprintf(head, i+3, "*%s*", tmp);
				scanner_agent_list = plist_add(scanner_agent_list, 0, head);
			}
			free(tmp);
		}

		/*
		 * Print out unused/unknown options.
		 */
		list = cf->options;
		while (list) {
			syslog(LOG_INFO, "Ignoring config file option: %s\n", list->key);
			list = list->next;
		}

		/*
		CFG_DEFAULT(cf, "PidFile", pidfile, MINIBUF_SIZE);
		CFG_DEFAULT(cf, "Uid", uid, MINIBUF_SIZE);
		*/
	}

	config_close(cf);

	if (!ntlmbasic && !strlen(user))
		carp("Parent proxy account username missing.\n", interactivehash || interactivepwd || magic_detect);

	if (!ntlmbasic && !strlen(domain))
		carp("Parent proxy account domain missing.\n", interactivehash || interactivepwd || magic_detect);

	if (!interactivehash && !parent_list)
		carp("Parent proxy address missing.\n", interactivepwd || magic_detect);

	if (!interactivehash && !magic_detect && !proxyd_list)
		carp("No proxy service ports were successfully opened.\n", interactivepwd);

	/*
	 * Set default value for the workstation. Hostname if possible.
	 */
	if (!strlen(workstation)) {
#if config_gethostname == 1
		gethostname(workstation, MINIBUF_SIZE);
#endif
		if (!strlen(workstation))
			strlcpy(workstation, "cntlm", MINIBUF_SIZE);

		syslog(LOG_INFO, "Workstation name used: %s\n", workstation);
	}

	/*
	 * Parse selected NTLM hash combination.
	 */
	if (strlen(auth)) {
		if (!strcasecmp("ntlm", auth)) {
			hashnt = 1;
			hashlm = 1;
			hashntlm2 = 0;
		} else if (!strcasecmp("nt", auth)) {
			hashnt = 1;
			hashlm = 0;
			hashntlm2 = 0;
		} else if (!strcasecmp("lm", auth)) {
			hashnt = 0;
			hashlm = 1;
			hashntlm2 = 0;
		} else if (!strcasecmp("ntlmv2", auth)) {
			hashnt = 0;
			hashlm = 0;
			hashntlm2 = 1;
		} else if (!strcasecmp("ntlm2sr", auth)) {
			hashnt = 2;
			hashlm = 0;
			hashntlm2 = 0;
		} else {
			syslog(LOG_ERR, "Unknown NTLM auth combination.\n");
			myexit(1);
		}
	}

	if (!magic_detect)
		syslog(LOG_INFO, "Using following NTLM hashes: NTLMv2(%d) NT(%d) LM(%d)\n", hashntlm2, hashnt, hashlm);

	if (flags)
		syslog(LOG_INFO, "Using manual NTLM flags: 0x%X\n", swap32(flags));

	/*
	 * Last chance to get password from the user
	 */
	if (interactivehash || (interactivepwd && !ntlmbasic)) {
		printf("Password: ");
		tcgetattr(0, &termold);
		termnew = termold;
		termnew.c_lflag &= ~(ISIG | ECHO);
		tcsetattr(0, TCSADRAIN, &termnew);
		fgets(password, MINIBUF_SIZE, stdin);
		tcsetattr(0, TCSADRAIN, &termold);
		i = strlen(password)-1;
		trimr(password);
		printf("\n");
	}

	/*
	 * Convert optional PassNT, PassLM and PassNTLMv2 strings to hashes
	 * unless plaintext pass was used, which has higher priority.
	 *
	 * If plain password is present, calculate its NT and LM hashes 
	 * and remove it from the memory.
	 */
	if (!strlen(password)) {
		if (strlen(cpassntlm2)) {
			passntlm2 = scanmem(cpassntlm2, 8);
			if (!passntlm2) {
				syslog(LOG_ERR, "Invalid PassNTLMv2 hash, terminating\n");
				exit(1);
			}
			passntlm2 = realloc(passntlm2, 21 + 1);
			memset(passntlm2+16, 0, 5);
		}
		if (strlen(cpassnt)) {
			passnt = scanmem(cpassnt, 8);
			if (!passnt) {
				syslog(LOG_ERR, "Invalid PassNT hash, terminating\n");
				exit(1);
			}
			passnt = realloc(passnt, 21 + 1);
			memset(passnt+16, 0, 5);
		}
		if (strlen(cpasslm)) {
			passlm = scanmem(cpasslm, 8);
			if (!passlm) {
				syslog(LOG_ERR, "Invalid PassLM hash, terminating\n");
				exit(1);
			}
			passlm = realloc(passlm, 21 + 1);
			memset(passlm+16, 0, 5);
		}
	} else {
		if (hashnt || magic_detect || interactivehash)
			passnt = ntlm_hash_nt_password(password);
		if (hashlm || magic_detect || interactivehash)
			passlm = ntlm_hash_lm_password(password);
		if (hashntlm2 || magic_detect || interactivehash) {
			passntlm2 = ntlm2_hash_password(user, domain, password);
		}
		memset(password, 0, strlen(password));
	}

	/*
	 * Try known NTLM auth combinations and print which ones work.
	 * User can pick the best (most secure) one as his config.
	 */
	if (magic_detect) {
		magic_auth_detect(magic_detect);
		exit(0);
	}

	if (interactivehash) {
		tmp = printmem(passlm, 16, 8);
		printf("PassLM          %s\n", tmp);
		free(tmp);
		tmp = printmem(passnt, 16, 8);
		printf("PassNT          %s\n", tmp);
		free(tmp);
		if (passntlm2 && strlen(passntlm2)) {
			tmp = printmem(passntlm2, 16, 8);
			printf("PassNTLMv2      %s    # Only for user '%s', domain '%s'\n", tmp, user, domain);
			free(tmp);
		}
		exit(0);
	}

	/*
	 * If we're going to need a password, check we really have it.
	 */
	if (!ntlmbasic && ((hashnt && !passnt) || (hashlm && !passlm) || (hashntlm2 && !passntlm2))) {
		syslog(LOG_ERR, "Parent proxy account password (or required hashes) missing.\n");
		myexit(1);
	}

	/*
	 * Ok, we are ready to rock. If daemon mode was requested,
	 * fork and die. The child will not be group leader anymore
	 * and can thus create a new session for itself and detach
	 * from the controlling terminal.
	 */
	if (asdaemon) {
		if (debug)
			printf("Forking into background as requested.\n");

		i = fork();
		if (i == -1) {
			perror("Fork into background failed");		/* fork failed */
			myexit(1);
		} else if (i)
			myexit(0);					/* parent */

		setsid();
		umask(0);
		chdir("/");
		i = open("/dev/null", O_RDWR);
		if (i >= 0) {
			dup2(i, 0);
			dup2(i, 1);
			dup2(i, 2);
			if (i > 2)
				close(i);
		}
	}

	/*
	 * Reinit syslog logging to include our PID, after forking
	 * it is going to be OK
	 */
	if (asdaemon) {
		openlog("cntlm", LOG_CONS | LOG_PID, LOG_DAEMON);
		syslog(LOG_INFO, "Daemon ready");
	} else {
		openlog("cntlm", LOG_CONS | LOG_PID | LOG_PERROR, LOG_DAEMON);
		syslog(LOG_INFO, "Cntlm ready, staying in the foreground");
	}

	/*
	 * Check and change UID.
	 */
	if (strlen(uid)) {
		if (getuid() && geteuid()) {
			syslog(LOG_WARNING, "No root privileges; keeping identity %d:%d\n", getuid(), getgid());
		} else {
			if (isdigit(uid[0])) {
				nuid = atoi(uid);
				ngid = nuid;
				if (nuid <= 0) {
					syslog(LOG_ERR, "Numerical uid parameter invalid\n");
					myexit(1);
				}
			} else {
				pw = getpwnam(uid);
				if (!pw || !pw->pw_uid) {
					syslog(LOG_ERR, "Username %s in -U is invalid\n", uid);
					myexit(1);
				}
				nuid = pw->pw_uid;
				ngid = pw->pw_gid;
			}
			setgid(ngid);
			i = setuid(nuid);
			syslog(LOG_INFO, "Changing uid:gid to %d:%d - %s\n", nuid, ngid, strerror(errno));
			if (i) {
				syslog(LOG_ERR, "Terminating\n");
				myexit(1);
			}
		}
	}

	/*
	 * PID file requested? Try to create one (it must not exist).
	 * If we fail, exit with error.
	 */
	if (strlen(pidfile)) {
		umask(0);
		cd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (cd < 0) {
			syslog(LOG_ERR, "Error creating a new PID file\n");
			myexit(1);
		}

		tmp = new(50);
		snprintf(tmp, 50, "%d\n", getpid());
		write(cd, tmp, strlen(tmp));
		free(tmp);
		close(cd);
	}

	/*
	 * Free already processed options.
	 */
	free(auth);
	free(uid);
	free(password);
	free(cpassntlm2);
	free(cpassnt);
	free(cpasslm);

	/*
	 * Change the handler for signals recognized as clean shutdown.
	 * When the handler is called (termination request), it signals
	 * this news by adding 1 to the global quit variable.
	 */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, &sighandler);
	signal(SIGTERM, &sighandler);
	signal(SIGHUP, &sighandler);

	if (precache) {
		pthread_attr_init(&pattr);
		pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
		pthread_attr_setstacksize(&pattr, STACK_SIZE);
#ifndef __CYGWIN__
		pthread_attr_setguardsize(&pattr, 0);
#endif
		pthread_create(&pthr, &pattr, precache_thread, NULL);
		pthread_attr_destroy(&pattr);
	}

	/*
	 * This loop iterates over every connection request on any of
	 * the listening ports. We keep the number of created threads.
	 *
	 * We also check the "finished threads" list, threads_list, here and
	 * free the memory of all inactive threads. Then, we update the
	 * number of finished threads.
	 *
	 * The loop ends, when we were "killed" and all threads created
	 * are finished, OR if we were killed more than once. This way,
	 * we have a "clean" shutdown (wait for all connections to finish
	 * after the first kill) and a "forced" one (user insists and
	 * killed us twice).
	 */
	while (quit < 1 || tc != tj) {
		struct thread_arg_s *data;
		struct sockaddr_in caddr;
		struct timeval tv;
		socklen_t clen;
		fd_set set;
		plist_t t;
		int tid = 0;

		FD_ZERO(&set);

		/*
		 * Watch for proxy ports.
		 */
		t = proxyd_list;
		while (t) {
			FD_SET(t->key, &set);
			t = t->next;
		}

		/*
		 * Watch for SOCKS5 ports.
		 */
		t = socksd_list;
		while (t) {
			FD_SET(t->key, &set);
			t = t->next;
		}

		/*
		 * Watch for tunneled ports.
		 */
		t = tunneld_list;
		while (t) {
			FD_SET(t->key, &set);
			t = t->next;
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		/*
		 * Wait here for data (connection request) on any of the listening 
		 * sockets. When ready, establish the connection. For the main
		 * port, a new process() thread is spawned to service the HTTP
		 * request. For tunneled ports, autotunnel() thread is created.
		 * 
		 */
		cd = select(FD_SETSIZE, &set, NULL, NULL, &tv);
		if (cd > 0) {
			for (i = 0; i < FD_SETSIZE; ++i) {
				if (FD_ISSET(i, &set)) {
					clen = sizeof(caddr);
					cd = accept(i, (struct sockaddr *)&caddr, (socklen_t *)&clen);

					if (cd < 0) {
						syslog(LOG_ERR, "Serious error during accept: %s\n", strerror(errno));
						continue;
					}

					/*
					 * Check main access control list.
					 */
					if (acl_check(rules, caddr.sin_addr) != ACL_ALLOW) {
						syslog(LOG_WARNING, "Connection denied for %s:%d\n", inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
						tmp = gen_denied_page(inet_ntoa(caddr.sin_addr));
						write(cd, tmp, strlen(tmp));
						free(tmp);
						close(cd);
						continue;
					}

					/*
					 * Log peer IP if it's not localhost
					 */
					if (debug || (gateway && caddr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)))
						syslog(LOG_INFO, "Connection accepted from %s:%d\n", inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));

					pthread_attr_init(&pattr);
					pthread_attr_setstacksize(&pattr, STACK_SIZE);
#ifndef __CYGWIN__
					pthread_attr_setguardsize(&pattr, 0);
#endif

					if (plist_in(proxyd_list, i)) {
						if (!serialize)
							tid = pthread_create(&pthr, &pattr, process, (void *)cd);
						else
							process((void *)cd);
					} else if (plist_in(socksd_list, i)) {
						tid = pthread_create(&pthr, &pattr, socks5, (void *)cd);
					} else {
						data = (struct thread_arg_s *)new(sizeof(struct thread_arg_s));
						data->fd = cd;
						data->target = plist_get(tunneld_list, i);
						tid = pthread_create(&pthr, &pattr, autotunnel, (void *)data);
					}

					pthread_attr_destroy(&pattr);

					if (tid)
						syslog(LOG_ERR, "Serious error during pthread_create: %d\n", tid);
					else
						tc++;
				}
			}
		} else if (cd < 0 && !quit)
			syslog(LOG_ERR, "Serious error during select: %s\n", strerror(errno));

		if (threads_list) {
			pthread_mutex_lock(&threads_mtx);
			t = threads_list;
			while (t) {
				plist_t tmp = t->next;
				tid = pthread_join((pthread_t)t->key, (void *)&i);

				if (!tid) {
					tj++;
					if (debug)
						printf("Joining thread %lu; rc: %d\n", t->key, i);
				} else
					syslog(LOG_ERR, "Serious error during pthread_join: %d\n", tid);

				free(t);
				t = tmp;
			}
			threads_list = NULL;
			pthread_mutex_unlock(&threads_mtx);
		}
	}

	syslog(LOG_INFO, "Terminating with %d active threads\n", tc - tj);
	pthread_mutex_lock(&connection_mtx);
	plist_free(connection_list);
	pthread_mutex_unlock(&connection_mtx);

	hlist_free(header_list);
	plist_free(scanner_agent_list);
	plist_free(tunneld_list);
	plist_free(proxyd_list);
	plist_free(socksd_list);
	plist_free(rules);

	if (strlen(pidfile))
		unlink(pidfile);
	if (passntlm2)
		free(passntlm2);
	if (passnt)
		free(passnt);
	if (passlm)
		free(passlm);

	free(pidfile);
	free(user);
	free(domain);
	free(workstation);

	parent_list = plist_free(parent_list);

	exit(0);
}

