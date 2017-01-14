/*
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

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

extern int h_errno;

#include "auth.h"
#include "direct.h"
#include "globals.h"
#include "http.h"
#include "ntlm.h"
#include "pages.h"
#include "socket.h"
#include "utils.h"

int host_connect(const char *hostname, int port) {
	struct in_addr addr;

	errno = 0;
	if (!so_resolv(&addr, hostname)) {
		//if (debug)
		//	printf("so_resolv: %s failed (%d: %s)\n", hostname, h_errno, hstrerror(h_errno));
		return -1;
	}

	return so_connect(addr, port);
}

int www_authenticate(int sd, rr_data_t request, rr_data_t response, struct auth_s *creds) {
	char *tmp, *buf, *challenge;
	rr_data_t auth;
	int len;

	int rc = 0;

	buf = new (BUFSIZE);

	strcpy(buf, "NTLM ");
	len = ntlm_request(&tmp, creds);
	if (len) {
		to_base64(MEM(buf, uint8_t, 5), MEM(tmp, uint8_t, 0), len, BUFSIZE - 5);
		free(tmp);
	}

	auth = dup_rr_data(request);
	auth->headers = hlist_mod(auth->headers, "Connection", "keep-alive", 1);
	auth->headers = hlist_mod(auth->headers, "Authorization", buf, 1);
	auth->headers = hlist_mod(auth->headers, "Content-Length", "0", 1);
	auth->headers = hlist_del(auth->headers, "Transfer-Encoding");

	/*
	 * Drop whatever error page server returned
	 */
	if (!http_body_drop(sd, response))
		goto bailout;

	if (debug) {
		printf("\nSending WWW auth request...\n");
		hlist_dump(auth->headers);
	}

	if (!headers_send(sd, auth))
		goto bailout;

	if (debug)
		printf("\nReading WWW auth response...\n");

	/*
	 * Get NTLM challenge
	 */
	reset_rr_data(auth);
	if (!headers_recv(sd, auth)) {
		goto bailout;
	}

	if (debug)
		hlist_dump(auth->headers);

	/*
	 * Auth required?
	 */
	if (auth->code == 401) {
		if (!http_body_drop(sd, auth))
			goto bailout;

		tmp = hlist_get(auth->headers, "WWW-Authenticate");
		if (tmp && strlen(tmp) > 6 + 8) {
			challenge = new (strlen(tmp) + 5 + 1);
			len = from_base64(challenge, tmp + 5);
			if (len > NTLM_CHALLENGE_MIN) {
				len = ntlm_response(&tmp, challenge, len, creds);
				if (len > 0) {
					strcpy(buf, "NTLM ");
					to_base64(MEM(buf, uint8_t, 5), MEM(tmp, uint8_t, 0), len, BUFSIZE - 5);
					request->headers = hlist_mod(request->headers, "Authorization", buf, 1);
					free(tmp);
				} else {
					syslog(LOG_ERR, "No target info block. Cannot do NTLMv2!\n");
					response->errmsg = "Invalid NTLM challenge from web server";
					free(challenge);
					goto bailout;
				}
			} else {
				syslog(LOG_ERR, "Server returning invalid challenge!\n");
				response->errmsg = "Invalid NTLM challenge from web server";
				free(challenge);
				goto bailout;
			}

			free(challenge);
		} else {
			syslog(LOG_WARNING, "No challenge in WWW-Authenticate!\n");
			response->errmsg = "Web server reply missing NTLM challenge";
			goto bailout;
		}
	} else {
		goto bailout;
	}

	if (debug)
		printf("\nSending WWW auth...\n");

	if (!headers_send(sd, request)) {
		goto bailout;
	}

	if (debug)
		printf("\nReading final server response...\n");

	reset_rr_data(auth);
	if (!headers_recv(sd, auth)) {
		goto bailout;
	}

	rc = 1;

	if (debug)
		hlist_dump(auth->headers);

bailout:
	if (rc)
		response = copy_rr_data(response, auth);
	free_rr_data(auth);
	free(buf);

	return rc;
}

rr_data_t direct_request(void *cdata, rr_data_t request) {
	rr_data_t data[2], rc = NULL;
	struct auth_s *tcreds = NULL;
	int *rsocket[2], *wsocket[2];
	int w, loop, sd;
	char *tmp;

	char *hostname = NULL;
	int port = 0;
	int conn_alive = 0;

	int cd = ((struct thread_arg_s *)cdata)->fd;
	struct sockaddr_in caddr = ((struct thread_arg_s *)cdata)->addr;

	if (debug)
		printf("Direct thread processing...\n");

	sd = host_connect(request->hostname, request->port);
	if (sd < 0) {
		syslog(LOG_WARNING, "Connection failed for %s:%d (%s)", request->hostname, request->port, strerror(errno));
		tmp = gen_502_page(request->http, strerror(errno));
		w = write(cd, tmp, strlen(tmp));
		// We don't really care about the result - shut up GCC warning (unused-but-set-variable)
		if (!w)
			w = 1;
		free(tmp);

		rc = (void *)-1;
		goto bailout;
	}

	/*
	 * Now save NTLM credentials for purposes of this thread.
	 * If web auth fails, we'll rewrite them like with NTLM-to-Basic in proxy mode.
	 */
	tcreds = dup_auth(g_creds, /* fullcopy */ 1);

	if (request->hostname) {
		hostname = strdup(request->hostname);
		port = request->port;
	} else {
		tmp = gen_502_page(request->http, "Invalid request URL");
		w = write(cd, tmp, strlen(tmp));
		free(tmp);

		rc = (void *)-1;
		goto bailout;
	}

	do {
		if (request) {
			data[0] = dup_rr_data(request);
			request = NULL;
		} else {
			data[0] = new_rr_data();
		}
		data[1] = new_rr_data();

		rsocket[0] = wsocket[1] = &cd;
		rsocket[1] = wsocket[0] = &sd;

		conn_alive = 0;

		for (loop = 0; loop < 2; ++loop) {
			if (data[loop]->empty) { // Isn't this the first loop with request supplied by caller?
				if (debug) {
					printf("\n******* Round %d C: %d, S: %d *******\n", loop + 1, cd, sd);
					printf("Reading headers (%d)...\n", *rsocket[loop]);
				}
				if (!headers_recv(*rsocket[loop], data[loop])) {
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					rc = (void *)-1;
					goto bailout;
				}
			}

			/*
			 * Check whether this new request still talks to the same server as previous.
			 * If no, return request to caller, he must decide on forward or direct
			 * approach.
			 */
			if (loop == 0 && hostname && data[0]->hostname && (strcasecmp(hostname, data[0]->hostname) || port != data[0]->port)) {
				if (debug)
					printf("\n******* D RETURN: %s *******\n", data[0]->url);

				rc = dup_rr_data(data[0]);
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				goto bailout;
			}

			if (debug)
				hlist_dump(data[loop]->headers);

			if (loop == 0 && data[0]->req) {
				syslog(LOG_DEBUG, "%s %s %s", inet_ntoa(caddr.sin_addr), data[0]->method, data[0]->url);

				/*
				 * Convert full proxy request URL into a relative URL
				 * Host header is already inserted by headers_recv()
				 */
				if (data[0]->rel_url) {
					if (data[0]->url)
						free(data[0]->url);
					data[0]->url = strdup(data[0]->rel_url);
				}

				/*
				 * Force proxy keep-alive if the client can handle it (HTTP >= 1.1)
				 */
				if (data[0]->http_version >= 11)
					data[0]->headers = hlist_mod(data[0]->headers, "Connection", "keep-alive", 1);

				/*
				 * Also remove runaway P-A from the client (e.g. Basic from N-t-B), which might 
				 * cause some ISAs to deny us, even if the connection is already auth'd.
				 */
				while (hlist_get(data[loop]->headers, "Proxy-Authorization")) {
					data[loop]->headers = hlist_del(data[loop]->headers, "Proxy-Authorization");
				}

				/*
				 * Try to get auth from client if present
				 */
				if (http_parse_basic(data[0]->headers, "Authorization", tcreds) > 0 && debug)
					printf("NTLM-to-basic: Credentials parsed: %s\\%s at %s\n", tcreds->domain, tcreds->user, tcreds->workstation);
			}

			/*
			 * Is this a CONNECT request?
			 */
			if (loop == 0 && CONNECT(data[0])) {
				if (debug)
					printf("CONNECTing...\n");

				data[1]->empty = 0;
				data[1]->req = 0;
				data[1]->code = 200;
				data[1]->msg = strdup("Connection established");
				data[1]->http = strdup(data[0]->http);

				if (headers_send(cd, data[1]))
					tunnel(cd, sd);

				free_rr_data(data[0]);
				free_rr_data(data[1]);
				rc = (void *)-1;
				goto bailout;
			}

			if (loop == 1 && data[1]->code == 401 && hlist_subcmp_all(data[1]->headers, "WWW-Authenticate", "NTLM")) {
				/*
				 * Server closing the connection after 401?
				 * Should never happen.
				 */
				if (hlist_subcmp(data[1]->headers, "Connection", "close")) {
					if (debug)
						printf("Reconnect before WWW auth\n");
					close(sd);
					sd = host_connect(data[0]->hostname, data[0]->port);
					if (sd < 0) {
						tmp = gen_502_page(data[0]->http, "WWW authentication reconnect failed");
						w = write(cd, tmp, strlen(tmp));
						free(tmp);

						rc = (void *)-1;
						goto bailout;
					}
				}
				if (!www_authenticate(*wsocket[0], data[0], data[1], tcreds)) {
					if (debug)
						printf("WWW auth connection error.\n");

					tmp = gen_502_page(data[1]->http, data[1]->errmsg ? data[1]->errmsg : "Error during WWW-Authenticate");
					w = write(cd, tmp, strlen(tmp));
					free(tmp);

					free_rr_data(data[0]);
					free_rr_data(data[1]);

					rc = (void *)-1;
					goto bailout;
				} else if (data[1]->code == 401) {
					/*
					 * Server giving 401 after auth?
					 * Request basic auth
					 */
					tmp = gen_401_page(data[1]->http, data[0]->hostname, data[0]->port);
					w = write(cd, tmp, strlen(tmp));
					free(tmp);

					free_rr_data(data[0]);
					free_rr_data(data[1]);

					rc = (void *)-1;
					goto bailout;
				}
			}

			/*
			 * Check if we should loop for another request.  Required for keep-alive
			 * connections, client might really need a non-interrupted conversation.
			 *
			 * We default to keep-alive server connections, unless server explicitly
			 * flags closing the connection or we detect a body with unknown size
			 * (end marked by server closing).
			 */
			if (loop == 1) {
				conn_alive = !hlist_subcmp(data[1]->headers, "Connection", "close") && http_has_body(data[0], data[1]) != -1 && data[0]->http_version >= 11;
				if (conn_alive) {
					data[1]->headers = hlist_mod(data[1]->headers, "Proxy-Connection", "keep-alive", 1);
					data[1]->headers = hlist_mod(data[1]->headers, "Connection", "keep-alive", 1);
				} else {
					data[1]->headers = hlist_mod(data[1]->headers, "Proxy-Connection", "close", 1);
					data[1]->headers = hlist_mod(data[1]->headers, "Connection", "close", 1);
					rc = (void *)-1;
				}
			}

			if (debug) {
				printf("Sending headers (%d)...\n", *wsocket[loop]);
				if (loop == 0) {
					printf("HEAD: %s %s %s\n", data[loop]->method, data[loop]->url, data[loop]->http);
					hlist_dump(data[loop]->headers);
				}
			}

			/*
			 * Send headers
			 */
			if (!headers_send(*wsocket[loop], data[loop])) {
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				rc = (void *)-1;
				goto bailout;
			}

			if (!http_body_send(*wsocket[loop], *rsocket[loop], data[0], data[1])) {
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				rc = (void *)-1;
				goto bailout;
			}
		}

		free_rr_data(data[0]);
		free_rr_data(data[1]);

	} while (conn_alive && !so_closed(sd) && !so_closed(cd) && !serialize);

bailout:
	if (tcreds)
		free(tcreds);
	if (hostname)
		free(hostname);

	close(sd);

	return rc;
}

void direct_tunnel(void *thread_data) {
	int sd, port = 0;
	char *pos, *hostname;

	int cd = ((struct thread_arg_s *)thread_data)->fd;
	char *thost = ((struct thread_arg_s *)thread_data)->target;
	struct sockaddr_in caddr = ((struct thread_arg_s *)thread_data)->addr;

	hostname = strdup(thost);
	if ((pos = strchr(hostname, ':')) != NULL) {
		*pos = 0;
		port = atoi(++pos);
	}

	sd = host_connect(hostname, port);
	if (sd <= 0)
		goto bailout;

	syslog(LOG_DEBUG, "%s FORWARD %s", inet_ntoa(caddr.sin_addr), thost);
	if (debug)
		printf("Portforwarding to %s for client %d...\n", thost, cd);

	tunnel(cd, sd);

bailout:
	free(hostname);
	close(sd);
	close(cd);

	return;
}
