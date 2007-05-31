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

/*
 * Some helping routines like linked list manipulation substr(), memory
 * allocation, NTLM authentication routines, etc.
 */
#include "socket.h"
#include "utils.h"
#include "ntlm.h"
#include "config.h"

#define DEFAULT_PORT	"3128"

#define BLOCK		2048
#define AUTHSIZE	100
#define STACK_SIZE	sizeof(int)*8*1024

/*
 * A couple of shortcuts for if statements
 */
#define CONNECT(data)	(data && data->req && !strcasecmp("CONNECT", data->method))
#define HEAD(data)	(data && data->req && !strcasecmp("HEAD", data->method))

/*
 * Global read-only data initialized in main(). Comments list funcs. which use
 * them. Having these global avoids the need to pass them to each thread and
 * from there again a few times to inner calls.
 */
static char *user;			/* authenticate() */
static char *domain;
static char *workstation;
static char *password;
static int hashnt = 1;
static int hashlm = 1;

static int quit = 0;			/* sighandler() */
static int debug = 0;			/* all info printf's */

/*
 * List of finished threads. Each thread process() adds itself to it when
 * finished. Main regularly joins and removes all tid's in there.
 */
static plist_t tlist = NULL;
static pthread_mutex_t tlist_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * List of cached connections. Accessed by each thread process().
 */
static plist_t clist = NULL;
static pthread_mutex_t clist_mtx = PTHREAD_MUTEX_INITIALIZER;

/*
 * List of available proxies and current proxy id for proxy_connect().
 */
static int pcount = 0;
static int pcurr = 0;
static pthread_mutex_t pcurr_mtx = PTHREAD_MUTEX_INITIALIZER;

static plist_t lparents = NULL;
typedef struct {
	struct in_addr host;
	int port;
} proxy_t;

/*
 * List of custom header substitutions.
 */
static hlist_t lheaders = NULL;		/* process() */

/*
 * General signal handler. Fast exit, no waiting for threads and shit.
 */
void sighandler(int p) {
	if (!quit)
		syslog(LOG_INFO, "Signal %d received, issuing clean shutdown\n", p);
	else
		syslog(LOG_INFO, "Signal %d received, forcing shutdown\n", p);

	quit++;
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

	prev = pcurr;
	pthread_mutex_lock(&pcurr_mtx);
	if (pcurr == 0) {
		aux = (proxy_t *)plist_get(lparents, ++pcurr);
		syslog(LOG_INFO, "Using proxy %s:%d\n", inet_ntoa(aux->host), aux->port);
	}
	pthread_mutex_unlock(&pcurr_mtx);

	do {
		aux = (proxy_t *)plist_get(lparents, pcurr);
		i = so_connect(aux->host, aux->port);
		if (i <= 0) {
			pthread_mutex_lock(&pcurr_mtx);
			if (pcurr >= pcount)
				pcurr = 0;
			aux = (proxy_t *)plist_get(lparents, ++pcurr);
			pthread_mutex_unlock(&pcurr_mtx);
			syslog(LOG_ERR, "Proxy connect failed, will try %s:%d\n", inet_ntoa(aux->host), aux->port);
		}
	} while (i <= 0 && ++loop < pcount);

	if (i <= 0 && loop >= pcount)
		syslog(LOG_ERR, "No proxy on the list works. You lose.\n");

	/*
	 * We have to invalidate the cached connections if we moved to a different proxy
	 */
	if (prev != pcurr) {
		pthread_mutex_lock(&clist_mtx);
		list = clist;
		while (list) {
			tmp = list->next;
			close(list->key);
			list = tmp;
		}
		plist_free(clist);
		pthread_mutex_unlock(&clist_mtx);
	}
		

	return i;
}

/*
 * Parse proxy parameter and add it to the global list.
 */
int parent_proxy(char *proxy, int port) {
	int len, i;
	proxy_t *aux;
	struct in_addr host;

	/*
	 * Check format and parse it.
	 */
	proxy = strdupl(proxy);
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
		free(proxy);
		return 0;
	}

	/*
	 * Try to resolve proxy address
	 */
	if (debug)
		syslog(LOG_INFO, "Resolving proxy %s...\n", proxy);
	if (!so_resolv(&host, proxy)) {
		syslog(LOG_ERR, "Cannot resolve proxy %s, discarding.\n", proxy);
		free(proxy);
		return 0;
	}

	aux = (proxy_t *)new(sizeof(proxy_t));
	aux->host = host;
	aux->port = port;
	lparents = plist_add(lparents, ++pcount, (char *)aux);

	free(proxy);
	return 1;
}

/*
 * Receive HTTP request/response from the given socket. Fill in pre-allocated
 * "data" structure.
 * Returns: 1 if OK, 0 in case of socket EOF or other error
 */
int headers_recv(int fd, rr_data_t data) {
	char *tok, *s3;
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
		if (tok)
			ccode = strdupl(tok);

		while (s3 < buf+len && *s3 == ' ')
			s3++;
		if (strlen(s3))
			data->msg = strdupl(s3);

		if (!ccode || strlen(ccode) != 3 || (data->code = atoi(ccode)) == 0 || !data->http || !data->msg) {
			i = -1;
			goto bailout;
		}
	} else if (tok) {
		data->req = 1;
		data->method = NULL;
		data->url = NULL;
		data->http = NULL;

		data->method = strdupl(tok);

		tok = strtok_r(NULL, " ", &s3);
		if (tok)
			data->url = strdupl(tok);

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
		syslog(LOG_ERR, "headers_recv: Unknown header (%s).\n", buf);
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
			syslog(LOG_WARNING, "headers_recv: fd %d warning %d (connection closed)\n", fd, i);
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
	if (data->req)
		len = sprintf(buf, "%s %s HTTP/1.%s\r\n", data->method, data->url, data->http);
	else
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
			syslog(LOG_WARNING, "headers_send: fd %d warning %d (connection closed)\n", fd, i);
		return 0;
	}

	return 1;
}

/*
 * Read "size" of data from the socket and discard it.
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
			syslog(LOG_WARNING, "data_drop: fd %d warning %d (connection closed)\n", src, i);
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
	int j = 0;

	if (!size)
		return 1;

	buf = new(BLOCK);

	do {
		block = (size == -1 || size-c > BLOCK ? BLOCK : size-c);
		i = read(src, buf, block);
		c += i;

		if (debug)
			printf("data_send: read %d of %d / %d of %d\n", i, block, c, size);

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
			syslog(LOG_WARNING, "data_send: fds %d:%d warning %d (connection closed)\n", dst, src, i);
		return 0;
	}

	return 1;
}

/*
 * Full-duplex forwarding between proxy and client descriptors.
 * Used for the HTTP CONNECT method.
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
 * Read in the reply, if it contains NTLM challenge, generate final
 * NTLM auth message and insert it into the original client header,
 * which is then normally proessed back in process().
 */
int authenticate(int sd, rr_data_t data) {
	char *tmp, *buf, *challenge;
	rr_data_t auth;
	int len;

	buf = new(BUFSIZE);

	strcpy(buf, "NTLM ");
	len = ntlm_request(&tmp, workstation, domain, hashnt, hashlm);
	to_base64(MEM(buf, unsigned char, 5), MEM(tmp, unsigned char, 0), len, BUFSIZE-5);
	free(tmp);
	
	auth = dup_rr_data(data);

	/*
	 * If the request is CONNECT, we keep it unmodified as there are no possible data
	 * transfers until auth is fully negotiated. All other requests are changed to HEAD.
	 */
	if (!CONNECT(data)) {
		free(auth->method);
		auth->method = strdupl("HEAD");
	}
	auth->headers = hlist_mod(auth->headers, "Proxy-Authorization", buf, 1);
	auth->headers = hlist_del(auth->headers, "Content-Length");

	if (debug) {
		printf("\nSending auth request...\n");
		hlist_dump(auth->headers);
	}

	if (!headers_send(sd, auth)) {
		free_rr_data(auth);
		free(buf);
		return 0;
	}

	free_rr_data(auth);
	auth = new_rr_data();

	if (debug)
		printf("Reading auth response...\n");

	if (!headers_recv(sd, auth)) {
		free_rr_data(auth);
		free(buf);
		return 0;
	}

	if (debug)
		hlist_dump(auth->headers);

	/*
	tmp = hlist_get(auth->headers, "Content-Length");
	if (tmp && (len = atoi(tmp))) {
		printf("Got %d too many bytes.\n", len);
		data_drop(sd, len);
	}
	*/

	if (auth->code == 407) {
		tmp = hlist_get(auth->headers, "Proxy-Authenticate");
		if (tmp) {
			challenge = new(strlen(tmp));
			from_base64(challenge, tmp+5);

			len = ntlm_response(&tmp, challenge, user, password, workstation, domain, hashnt, hashlm);
			strcpy(buf, "NTLM ");
			to_base64(MEM(buf, unsigned char, 5), MEM(tmp, unsigned char, 0), len, BUFSIZE-5);
			data->headers = hlist_mod(data->headers, "Proxy-Authorization", buf, 1);

			free(tmp);
			free(challenge);
		} else {
			syslog(LOG_WARNING, "No Proxy-Authenticate received! NTLM not supported?\n");
		}
	} else if (auth->code >= 500 && auth->code <= 599) {
		if (debug)
			printf("REQUEST DENIED\n\n");

		free_rr_data(auth);
		free(buf);

		return 500;
	}

	free_rr_data(auth);
	free(buf);

	return 1;
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
	int i, loop, nobody, keep;
	rr_data_t data[2];
	hlist_t tl;
	char *tmp;

	int cd = (int)client;
	int authok = 0;
	int sd = 0;

	if (debug)
		printf("Thread processing...\n");

	pthread_mutex_lock(&clist_mtx);
	if (debug)
		plist_dump(clist);
	i = plist_pop(&clist);
	pthread_mutex_unlock(&clist_mtx);
	if (i) {
		if (debug)
			printf("Found autenticated connection %d!\n", i);
		sd = i;
		authok = 1;
	}

	if (!sd)
		sd = proxy_connect();

	if (sd <= 0)
		goto bailout;

	do {
		/* data[0] is for the first loop pass
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
				printf("\n******* Round %d C: %d, S: %d*******!\n", loop+1, cd, sd);
				printf("Reading headers...\n");
			}
			if (!headers_recv(*rsocket[loop], data[loop])) {
				close(sd);
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				goto bailout;
			}

			if (debug)
				hlist_dump(data[loop]->headers);

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
				tmp = hlist_get(data[loop]->headers, "Proxy-Connection");
				if (tmp) {
					tmp = strdupl(tmp);
					lowercase(tmp);
					if (strstr(tmp, "keep-alive"))
						keep = 1;
					free(tmp);
				}

				tl = lheaders;
				while (tl) {
					data[loop]->headers = hlist_mod(data[loop]->headers, tl->key, tl->value, 1);
					tl = tl->next;
				}
				data[loop]->headers = hlist_mod(data[loop]->headers, "Proxy-Connection", "Keep-Alive", 1);

			}

			/*
			 * Got request from client and connection is not yet authenticated?
			 */
			if (!loop && data[0]->req && !authok) {
				if (!(i = authenticate(*wsocket[0], data[0])))
					syslog(LOG_ERR, "Authentication requests failed. Will try without.\n");

				if (!i || so_closed(sd)) {
					if (debug)
						printf("Proxy closed connection. Reconnecting...\n");
					close(sd);
					sd = proxy_connect();
					if (sd <= 0) {
						free_rr_data(data[0]);
						free_rr_data(data[1]);
						goto bailout;
					}
				}
			}

			/*
			 * Forward client's headers to the proxy; authenticate() might have
			 * by now prepared 1st and 2nd auth steps and filled our headers with
			 * the 3rd, final, NTLM message.
			 */
			if (debug) {
				printf("Sending headers...\n");
				if (!loop)
					hlist_dump(data[loop]->headers);
			}

			/*
			 * Client might have closed connection, discarding requested data.
			 * Close proxy connection, which might have some data left unread.
			 */
			if (!headers_send(*wsocket[loop], data[loop])) {
				close(sd);
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				goto bailout;
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
				goto bailout;
			} else {
				/*
				 * Was the request first and did we authenticated with proxy?
				 * Remember not to authenticate this connection any more, should
				 * it be keep-alive reused for more client requests.
				 */
				if (!authok && data[1]->code != 407)
					authok = 1;

				/*
				 * HTTP body lenght decisions. There MUST NOT be any body if the
				 * request was HEAD or reply is 1xx, 204 or 304.
				 */
				nobody = (!data[loop]->req && (HEAD(data[0]) ||
					(data[1]->code >= 100 && data[1]->code < 200) ||
					data[1]->code == 204 ||
					data[1]->code == 304));

				/*
				 * Otherwise consult Content-Length. If present, we forward exaclty
				 * that many bytes.
				 *
				 * If not present, but there was Transfer-Encoding or Content-Type
				 * (or a request to close connection, that is, end of data is signaled
				 * by remote close), we will forward until EOF. I need to add support
				 * for chunked encoding, but it can wait (used rarely).
				 *
				 * No C-L, no T-E, no C-T == no body.
				 */

				tmp = hlist_get(data[loop]->headers, "Content-Length");
				if (!nobody && tmp == NULL && (hlist_in(data[loop]->headers, "Content-Type")
						|| hlist_in(data[loop]->headers, "Transfer-Encoding"))) {
					i = -1;
					if (debug) {
						printf("*************************\n");
						printf("CL: %s, C: %s, CT: %s, TE: %s\n", 
							hlist_get(data[loop]->headers, "Content-Length"),
							hlist_get(data[loop]->headers, "Connection"),
							hlist_get(data[loop]->headers, "Content-Type"),
							hlist_get(data[loop]->headers, "Transfer-Encoding"));
					}
				} else
					i = (tmp == NULL || nobody ? 0 : atol(tmp));

				if (i) {
					if (debug)
						printf("Body included. Lenght: %d\n", i);

					/*
					 * Not all data transfered to the client. Close proxy connection as it
					 * might contain unspecified amount of unread data.
					 */
					if (!data_send(*wsocket[loop], *rsocket[loop], i)) {
						if (debug)
							printf("Could not send whole body\n");
						close(sd);
						free_rr_data(data[0]);
						free_rr_data(data[1]);
						goto bailout;
					} else if (debug) {
						printf("Body sent.\n");
					}
				} else if (debug)
					printf("No body.\n");
			}
		}

		free_rr_data(data[0]);
		free_rr_data(data[1]);
	} while (!so_closed(sd) && !so_closed(cd) && (keep || so_dataready(cd)));

bailout:
	if (debug)
		printf("\nThread finished.\n");

	close(cd);
	if (!so_closed(sd) && authok) {
		if (debug)
			printf("Storing the connection for reuse.\n");
		pthread_mutex_lock(&clist_mtx);
		clist = plist_add(clist, sd, NULL);
		pthread_mutex_unlock(&clist_mtx);
	} else
		close(sd);

	/*
	 * Add ourself to the "threads to join" list.
	 */
	pthread_mutex_lock(&tlist_mtx);
	tlist = plist_add(tlist, pthread_self(), NULL);
	pthread_mutex_unlock(&tlist_mtx);

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
	rr_data_t data1, data2;
	int i, sd;
	int cd = ((struct thread_arg_s *)client)->fd;
	char *thost = ((struct thread_arg_s *)client)->target;

	sd = proxy_connect();
	free(client);

	if (sd <= 0) {
		close(cd);
		return NULL;
	}

	if (debug)
		printf("Tunneling to %s for client %d...\n", thost, cd);

	data1 = new_rr_data();
	data2 = new_rr_data();

	data1->req = 1;
	data1->method = strdupl("CONNECT");
	data1->url = strdupl(thost);
	data1->http = strdupl("0");

	if (debug)
		printf("Starting authentication...\n");

	i = authenticate(sd, data1);
	if (i && i != 500) {
		if (so_closed(sd)) {
			close(sd);
			sd = proxy_connect();
			if (sd <= 0) 
				goto bailout;
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

					tunnel(cd, sd);
				} else if (data2->code == 407) {
					syslog(LOG_ERR, "Authentication for tunnel %s failed!\n", thost);
				} else if (debug)
					syslog(LOG_ERR, "Request for CONNECT denied!\n");
			} else if (debug)
				printf("Reading response failed!\n");
		} else if (debug)
			printf("Sending request failed!\n");
	} else if (i == 500)
		syslog(LOG_ERR, "Tunneling to %s not allowed!\n", thost);
	else
		syslog(LOG_ERR, "Authentication requests failed!\n");

bailout:
	close(sd);
	close(cd);

	free_rr_data(data1);
	free_rr_data(data2);

	/*
	 * Add ourself to the "threads to join" list.
	 */
	pthread_mutex_lock(&tlist_mtx);
	tlist = plist_add(tlist, pthread_self(), NULL);
	pthread_mutex_unlock(&tlist_mtx);

	return NULL;
}

void proxy_add(plist_t *list, char *spec, int gateway) {
	struct in_addr source;
	int i, p, len, port;
	char *tmp;

	len = strlen(spec);
	p = strcspn(spec, ":");
	if (p < len-1) {
		tmp = substr(spec, 0, p);
		if (!so_resolv(&source, tmp)) {
			syslog(LOG_ERR, "Cannot resolve listen address %s\n", tmp);
			exit(1);
		}
		free(tmp);
		port = atoi(tmp = spec+p+1);
	} else {
		source.s_addr = htonl(gateway ? INADDR_ANY : INADDR_LOOPBACK);
		port = atoi(tmp = spec);
	}

	if (port == 0) {
		syslog(LOG_ERR, "Invalid listen port %s.\n", tmp);
		exit(1);
	}

	i = so_listen(port, source);
	if (i > 0) {
		*list = plist_add(*list, i, NULL);
		syslog(LOG_INFO, "Proxy listening on %s:%d\n", inet_ntoa(source), port);
	} else
		exit(1);
}

void tunnel_add(plist_t *list, char *spec, int gateway) {
	struct in_addr source;
	int i, len, count, pos, port;
	char *field[4];
	char *tmp;

	spec = strdupl(spec);
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
                        exit(1);
                }
		pos++;
	} else
		source.s_addr = htonl(gateway ? INADDR_ANY : INADDR_LOOPBACK);

	if (count-pos == 3) {
		port = atoi(field[pos]);
		if (port == 0) {
			syslog(LOG_ERR, "Invalid tunnel local port: %s\n", field[pos]);
			exit(1);
		}

		if (!strlen(field[pos+1]) || !strlen(field[pos+2])) {
			syslog(LOG_ERR, "Invalid tunnel target: %s:%s\n", field[pos+1], field[pos+2]);
			exit(1);
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
		exit(1);
	}

	free(spec);
}

int main(int argc, char **argv) {
	char *tmp, *head, *uid, *pidfile, *auth;
	struct passwd *pw;
	hlist_t list;
	int i;

	int cd = 0;
	int help = 0;
	int nuid = 0;
	int ngid = 0;
	int daemon = 1;
	int gateway = 0;
	int tc = 0;
	int tj = 0;
	plist_t ltunnel = NULL;
	plist_t lproxy = NULL;
	config_t cf = NULL;

	user = new(AUTHSIZE);
	domain = new(AUTHSIZE);
	password = new(AUTHSIZE);
	workstation = new(AUTHSIZE);
	pidfile = new(AUTHSIZE);
	uid = new(AUTHSIZE);
	auth = new(AUTHSIZE);

	openlog("cntlm", LOG_CONS, LOG_DAEMON);
	syslog(LOG_INFO, "Starting cntlm version " VERSION);

	while ((i = getopt(argc, argv, ":a:c:d:fgl:p:u:vw:L:P:U:")) != -1) {
		switch (i) {
			case 'a':
				strlcpy(auth, optarg, AUTHSIZE);
				break;
			case 'c':
				if (!(cf = config_open(optarg))) {
					syslog(LOG_ERR, "Cannot access specified config file: %s\n", optarg);
					exit(1);
				}
				break;
			case 'd':
				strlcpy(domain, optarg, AUTHSIZE);
				break;
			case 'v':
				debug++;
			case 'f':
				daemon = 0;
				openlog("cntlm", LOG_CONS | LOG_PERROR, LOG_DAEMON);
				break;
			case 'g':
				gateway = 1;
				break;
			case 'h':
				if (head_ok(optarg))
					lheaders = hlist_add(lheaders, head_name(optarg), head_value(optarg), 0, 0);
				break;
			case 'l':
				proxy_add(&lproxy, optarg, gateway);
				break;
			case 'p':
				/*
				 * Overwrite the password parameter with '*'s to make it
				 * invisible in "ps", /proc, etc.
				 */
				strlcpy(password, optarg, AUTHSIZE);
				for (i = strlen(optarg)-1; i >= 0; --i)
					optarg[i] = '*';
				break;
			case 'u':
				i = strcspn(optarg, "@");
				if (i != strlen(optarg)) {
					strlcpy(user, optarg, MIN(AUTHSIZE, i+1));
					strlcpy(domain, optarg+i+1, AUTHSIZE);
				} else {
					strlcpy(user, optarg, AUTHSIZE);
				}
				break;
			case 'w':
				strlcpy(workstation, optarg, AUTHSIZE);
				break;
			case 'L':
				/*
				 * Parse and validate the argument using regex.
				 * Create a listening socket and store the target to a linked list
				 */
				tunnel_add(&ltunnel, optarg, gateway);
				break;
			case 'P':
				strlcpy(pidfile, optarg, AUTHSIZE);
				break;
			case 'U':
				strlcpy(uid, optarg, AUTHSIZE);
				break;
			default:
				help = 1;
		}
	}

	/*
	 * More arguments on the command-line? Must be proxies.
	 */
	i = optind;
	while (i < argc) {
		tmp = strchr(argv[i], ':');
		parent_proxy(argv[i], !tmp && i+1 < argc ? atoi(argv[i+1]) : 0);
		i += (!tmp ? 2 : 1);
	}

	/*
	 * No configuration file yet? Load the default.
	 */
#ifdef SYSCONFDIR
	if (!cf) {
		cf = config_open(SYSCONFDIR "/cntlm.conf");
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
		tmp = new(AUTHSIZE);
		CFG_DEFAULT(cf, "Gateway", tmp, AUTHSIZE);
		if (!strcasecmp("yes", tmp))
			gateway = 1;
		free(tmp);

		/*
		 * Setup the rest of tunnels.
		 */
		while ((tmp = config_pop(cf, "Tunnel"))) {
			tunnel_add(&ltunnel, tmp, gateway);
			free(tmp);
		}

		/*
		 * Bind the rest of proxy service ports.
		 */
		while ((tmp = config_pop(cf, "Listen"))) {
			proxy_add(&lproxy, tmp, gateway);
			free(tmp);
		}

		/*
		 * Accept only headers not specified on the command line.
		 * Command line has higher priority.
		 */
		while ((tmp = config_pop(cf, "Header"))) {
			if (head_ok(tmp)) {
				head = head_name(tmp);
				if (!hlist_in(lheaders, head))
					lheaders = hlist_add(lheaders, head_name(tmp), head_value(tmp), 0, 0);
				free(head);
			} else
				syslog(LOG_ERR, "Invalid header format: %s\n", tmp);

			free(tmp);
		}

		/*
		 * Add the rest of parent proxies.
		 */
		while ((tmp = config_pop(cf, "Proxy"))) {
			parent_proxy(tmp, 0);
			free(tmp);
		}

		/*
		 * Single options.
		 */
		CFG_DEFAULT(cf, "Auth", domain, AUTHSIZE);
		CFG_DEFAULT(cf, "Domain", domain, AUTHSIZE);
		CFG_DEFAULT(cf, "Password", password, AUTHSIZE);
		CFG_DEFAULT(cf, "Username", user, AUTHSIZE);
		CFG_DEFAULT(cf, "Workstation", workstation, AUTHSIZE);

		/*
		 * Print out unused/unknown options.
		 */
		list = cf->options;
		while (list) {
			syslog(LOG_INFO, "Ignoring option: %s\n", list->key);
			list = list->next;
		}

		/*
		CFG_DEFAULT(cf, "PidFile", pidfile, AUTHSIZE);
		CFG_DEFAULT(cf, "Uid", uid, AUTHSIZE);
		*/
	}

	config_close(cf);

	/*
	 * Any of the vital options missing?
	 */
	if (help || !strlen(user) || !strlen(password) || !lparents) {
		printf("CNTLM - Accelerating NTLM Authentication Proxy version " VERSION "\nCopyright (c) 2oo7 David Kubicek\n\n"
			"This program comes with NO WARRANTY, to the extent permitted by law. You\n"
			"may redistribute copies of it under the terms of the GNU GPL Version 2.1\n"
			"or newer. For more information about these matters, see the file LICENSE.\n"
			"For copyright holders of included encryption routines see headers.\n\n");

		fprintf(stderr, "Usage: %s [-acdfghlvwLPU] -u <user>[@<domain>] -p <pass> <proxy_host>[:]<proxy_port>\n", argv[0]);
		fprintf(stderr, "\t-a  ntlm | nt | lm\n"
				"\t    Authentication parameter - combined NTLM, just LM, or just NT. Default is to,\n"
				"\t    send both, NTLM. It is the most versatile setting and likely to work for you.\n");
		fprintf(stderr, "\t-c  <config_file>\n"
				"\t    Configuration file. Other arguments can be used as well, overriding\n"
				"\t    config file settings.\n");
		fprintf(stderr, "\t-d  <domain>\n"
				"\t    Domain/workgroup can be set separately.\n");
		fprintf(stderr, "\t-f  Run in foreground, do not fork into daemon mode.\n");
		fprintf(stderr, "\t-g  Gateway mode - listen on all interfaces, not only loopback.\n");
		fprintf(stderr, "\t-h  \"HeaderName: value\"\n"
				"\t    Add a header substitution. All such headers will be added/replaced\n"
				"\t    in the client's requests.\n");
		fprintf(stderr, "\t-L  [<saddr>:]<lport>:<rhost>:<rport>\n"
				"\t    Forwarding/tunneling a la OpenSSH. Same syntax - listen on lport\n"
				"\t    and forward all connections through the proxy to rhost:rport.\n"
				"\t    Can be used for direct tunneling without corkscrew, etc.\n");
		fprintf(stderr, "\t-l  [<saddr>:]<lport>\n"
				"\t    Main listening port for the NTLM proxy.\n");
		fprintf(stderr, "\t-P  <pidfile>\n"
				"\t    Create a PID file upon successful start.\n");
		fprintf(stderr, "\t-p  <password>\n"
				"\t    Account password. Will not be visible in \"ps\", /proc, etc.\n");
		fprintf(stderr, "\t-U  <uid>\n"
				"\t    Run as uid. It is an important security measure not to run as root.\n");
		fprintf(stderr, "\t-u  <user>[@<domain]\n"
				"\t    Domain/workgroup can be set separately.\n");
		fprintf(stderr, "\t-v  Print debugging information.\n");
		fprintf(stderr, "\t-w  <workstation>\n"
				"\t    Some proxies require correct NetBIOS hostname.\n\n");

		if (!strlen(user)) {
			syslog(LOG_ERR, "Parent proxy username missing.\n");
		}
		if (!strlen(password)) {
			syslog(LOG_ERR, "Parent proxy account password missing.\n");
		}
		if (!lparents) {
			syslog(LOG_ERR, "Parent proxy address missing.\n");
		}

		exit(1);
	}

	/*
	 * Setup selected NTLM hash combination.
	 */
	if (strlen(auth)) {
		if (!strcasecmp("ntlm", auth)) {
			hashnt = hashlm = 1;
		} else if (!strcasecmp("nt", auth)) {
			hashnt = 1;
			hashlm = 0;
		} else if (!strcasecmp("lm", auth)) {
			hashnt = 0;
			hashlm = 1;
		} else {
			syslog(LOG_ERR, "Unknown NTLM auth combination.\n");
			exit(1);
		}
	}

	/*
	 * Set default values.
	 */
	if (!strlen(workstation))
		strlcpy(workstation, user, AUTHSIZE);

	if (!lproxy)
		proxy_add(&lproxy, DEFAULT_PORT, gateway);

	/*
	 * Ok, we are ready to rock. If daemon mode was requested,
	 * fork and die. The child will not be group leader anymore
	 * and can thus create a new session for itself and detach
	 * from the controlling terminal.
	 */
	if (daemon) {
		if (debug)
			printf("Forking into background as requested.\n");

		i = fork();
		if (i == -1) {
			perror("Fork into background failed");		/* fork failed */
			exit(1);
		} else if (i)
			exit(0);					/* parent */

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
	if (daemon) {
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
			syslog(LOG_ERR, "Not running with root privileges; cannot change uid\n");
		} else {
			if (isdigit(uid[0])) {
				nuid = atoi(uid);
				ngid = nuid;
				if (nuid <= 0) {
					syslog(LOG_ERR, "Numerical uid parameter invalid\n");
					exit(1);
				}
			} else {
				pw = getpwnam(uid);
				if (!pw || !pw->pw_uid) {
					syslog(LOG_ERR, "Username uid parameter invalid\n");
					exit(1);
				}
				nuid = pw->pw_uid;
				ngid = pw->pw_gid;
			}
			setgid(ngid);
			i = setuid(nuid);
			syslog(LOG_INFO, "Changing uid:gid to %d:%d - %s\n", nuid, ngid, strerror(errno));
			if (i) {
				syslog(LOG_ERR, "Terminating\n");
				exit(1);
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
			exit(1);
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

	/*
	 * Change the handler for signals recognized as clean shutdown.
	 * When the handler is called (termination request), it signals
	 * this news by adding 1 to the global quit variable. This allows
	 * us to keep track of how many times we were "killed". See the
	 * main loop description below for details.
	 */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, &sighandler);
	signal(SIGTERM, &sighandler);
	signal(SIGHUP, &sighandler);

	/*
	 * This loop iterates over every connection request on any of
	 * the listening ports. We keep the number of created threads.
	 *
	 * We also check the "finished threads" list, tlist, here and
	 * free the memory of all inactive threads. Then, we update the
	 * number of finished threads.
	 *
	 * The loop ends, when we were "killed" and all threads created
	 * are finished, OR if we were killed more than once. This way,
	 * we have a "clean" shutdown (wait for all connections to finish
	 * after the first kill) and a "forced" one (user insists and
	 * killed us twice; ignore running threads).
	 */
	while ((quit != 1 || tc != tj) && (quit <= 1)) {
		struct thread_arg_s *data;
		struct sockaddr_in caddr;
		pthread_attr_t attr;
		struct timeval tv;
		socklen_t clen;
		pthread_t thr;
		fd_set set;
		plist_t t;
		int tid;

		FD_ZERO(&set);

		/*
		 * Watch for proxy ports.
		 */
		t = lproxy;
		while (t) {
			FD_SET(t->key, &set);
			t = t->next;
		}

		/*
		 * Watch for tunneled ports.
		 */
		t = ltunnel;
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
					 * Log peer IP if it's not localhost
					 */
					if (debug || (gateway && caddr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)))
						syslog(LOG_INFO, "Connection accepted from %s:%d\n", inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));

					pthread_attr_init(&attr);
					pthread_attr_setstacksize(&attr, STACK_SIZE);
					pthread_attr_setguardsize(&attr, 0);

					if (!plist_in(lproxy, i)) {
						data = (struct thread_arg_s *)new(sizeof(struct thread_arg_s));
						data->fd = cd;
						data->target = plist_get(ltunnel, i);
						tid = pthread_create(&thr, &attr, autotunnel, (void *)data);
					} else {
						tid = pthread_create(&thr, &attr, process, (void *)cd);
					}

					pthread_attr_destroy(&attr);

					if (tid)
						syslog(LOG_ERR, "Serious error during pthread_create: %d\n", tid);
					else
						tc++;
				}
			}
		} else if (cd < 0 && !quit)
			syslog(LOG_ERR, "Serious error during select: %s\n", strerror(errno));

		if (tlist) {
			pthread_mutex_lock(&tlist_mtx);
			t = tlist;
			while (t) {
				plist_t tmp = t->next;
				tid = pthread_join(t->key, (void *)&i);

				if (!tid) {
					tj++;
					if (debug)
						printf("Joining thread %lu; rc: %d\n", t->key, i);
				} else
					syslog(LOG_ERR, "Serious error during pthread_join: %d\n", tid);

				free(t);
				t = tmp;
			}
			tlist = NULL;
			pthread_mutex_unlock(&tlist_mtx);
		}
	}

	syslog(LOG_INFO, "Terminating with %d active threads\n", tc - tj);
	pthread_mutex_lock(&clist_mtx);
	plist_free(clist);
	pthread_mutex_unlock(&clist_mtx);

	hlist_free(lheaders);
	plist_free(ltunnel);
	plist_free(lproxy);

	if (strlen(pidfile))
		unlink(pidfile);

	free(pidfile);
	free(user);
	free(domain);
	free(password);
	free(workstation);

	/*
	 * Might need mutex in case of forced shutdown
	 */
	lparents = plist_free(lparents);

	exit(0);
}

