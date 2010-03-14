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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>

#include "utils.h"
#include "globals.h"
#include "auth.h"
#include "http.h"
#include "socket.h"
#include "ntlm.h"
#include "forward.h"
#include "scanner.h"
#include "pages.h"

#define MAGIC_TESTS	11

int parent_curr = 0;
pthread_mutex_t parent_mtx = PTHREAD_MUTEX_INITIALIZER;

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
	current = (response->http ? response : request);

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
 * Duplicate client request headers, change requested method to HEAD
 * (so we avoid any body transfers during NTLM negotiation), and add
 * proxy authentication request headers.
 *
 * Read the reply, if it contains NTLM challenge, generate final
 * NTLM auth message and insert it into the original client header,
 * which is then processed by caller himself.
 *
 * If the proxy closes the connection for some reason, we notify our
 * caller by setting closed to 1. Otherwise, it is set to 0.
 * If closed == NULL, we do not signal anything.
 *
 * Caller must init & free "response" (if interested)
 *
 */
int proxy_authenticate(int sd, rr_data_t request, rr_data_t response, struct auth_s *creds, int *closed) {
	char *tmp, *buf, *challenge;
	rr_data_t auth;
	int len, rc, pretend407 = 0;

	if (closed)
		*closed = 0;

	auth = dup_rr_data(request);

	buf = new(BUFSIZE);

	strcpy(buf, "NTLM ");
	len = ntlm_request(&tmp, creds);
	to_base64(MEM(buf, unsigned char, 5), MEM(tmp, unsigned char, 0), len, BUFSIZE-5);
	free(tmp);

	auth->headers = hlist_mod(auth->headers, "Proxy-Authorization", buf, 1);

	/*
	 * - If the request is CONNECT, we have to keep it unmodified -
	 *
	 * DISABLED because if request succeeds without auth, we just forward it
	 * so we can't really change the request.
	 *
	 * We still make the request twice in case the client is sending a body
	 * or is using chunked encoding. Otherwise we'd have to chache the whole 
	 * body in the memory. Making the request twice is better (first being
	 * just a probe without body).
	 */
	/*
	if (!CONNECT(request)) {
		free(auth->method);
		auth->method = strdup("GET");
	}
	*/

	tmp = hlist_get(auth->headers, "Content-Length");
	if ((tmp && atoi(tmp) > 0) || hlist_get(auth->headers, "Transfer-Encoding")) {
		/*
		 * There's a body - make this request just a probe. Do not send any body.
		 * If no auth is requested, we just forward reply to client to avoid
		 * another duplicate request in our caller (which traditionally finishes
		 * the 2nd part of NTLM handshake). Without auth, there's no need for the
		 * final request. However, if client has a body, we make this request without
		 * it and let caller do the request in full. If we did it here, we'd have to
		 * cache the body in memory (even chunked) and carry it around. Not practical.
		 */
		if (debug)
			printf("Will send just a probe request.\n");
		pretend407 = 1;
	}
	auth->headers = hlist_del(auth->headers, "Content-Length");
	auth->headers = hlist_del(auth->headers, "Transfer-Encoding");

	if (debug) {
		printf("\nSending auth request...\n");
		hlist_dump(auth->headers);
	}

	if (!headers_send(sd, auth)) {
		rc = 0;
		goto bailout;
	}

	if (debug)
		printf("\nReading auth response...\n");

	/*
	 * Return response if requested
	 */
	if (response) {
		free_rr_data(auth);
		auth = response;
	}

	reset_rr_data(auth);
	if (!headers_recv(sd, auth)) {
		rc = 0;
		goto bailout;
	}

	if (debug)
		hlist_dump(auth->headers);

	/*
	 * Should auth continue?
	 */
	if (auth->code == 407) {
		tmp = hlist_get(auth->headers, "Content-Length");
		if (tmp && (len = atoi(tmp))) {
			if (debug)
				printf("Got %d too many bytes.\n", len);
			data_drop(sd, len);
		}

		tmp = hlist_get(auth->headers, "Proxy-Authenticate");
		if (tmp) {
			challenge = new(strlen(tmp) + 5 + 1);
			len = from_base64(challenge, tmp + 5);
			if (len > NTLM_CHALLENGE_MIN) {
				len = ntlm_response(&tmp, challenge, len, creds);
				if (len > 0) {
					strcpy(buf, "NTLM ");
					to_base64(MEM(buf, unsigned char, 5), MEM(tmp, unsigned char, 0), len, BUFSIZE-5);
					request->headers = hlist_mod(request->headers, "Proxy-Authorization", buf, 1);
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
			syslog(LOG_WARNING, "No Proxy-Authenticate received! NTLM not supported?\n");
		}
	} else if (auth->code >= 500 && auth->code <= 599) {
		/*
		 * Proxy didn't like the request, close connection and don't try again.
		 */
		syslog(LOG_WARNING, "The request was denied!\n");
		//close(sd);
		rc = 500;
		goto bailout;
	} else {
		/*
		 * No auth was neccessary, let the caller make the request again.
		 * Unless he wants the response+data, then let him finish the processing.
		 */
		if (pretend407) {
			if (debug)
				printf("Forcing new request.\n");
			if (response)
				response->code = 407;				// See explanation above
			if (closed)
				*closed = 1;
		}

		if (closed && !response)
			*closed = 1;
	}

	/*
	 * Does proxy intend to close the connection? E.g. it didn't require auth
	 * at all or there was some problem. If so, let caller know that it should
	 * reconnect!
	 *
	 * Unless caller wants the response+data, then let him finish the processing.
	 */
	if (closed && !response && hlist_subcmp(auth->headers, "Proxy-Connection", "close")) {
		if (debug)
			printf("Proxy signals it's closing the connection.\n");
		*closed = 1;
	}

	rc = 1;

bailout:
	if (!response)
		free_rr_data(auth);
	free(buf);

	return rc;
}

/*
 * Thread starts here. Connect to the proxy, clear "already authenticated" flag.
 *
 * Then process the client request, authentication and proxy reply
 * back to client. We loop here to allow proxy keep-alive connections)
 * until the proxy closes.
 */
void forward_request(void *cdata) {
	int *rsocket[2], *wsocket[2];
	int i, w, loop, bodylen, keep, chunked, plugin, closed;
	rr_data_t data[2], errdata;
	hlist_t tl;
	char *tmp, *buf, *pos, *dom;
	struct auth_s *tcreds;						/* Per-thread credentials; for NTLM-to-basic */

	int authok = 0;
	int noauth = 0;
	int sd = 0;

	int cd = ((struct thread_arg_s *)cdata)->fd;
	struct sockaddr_in caddr = ((struct thread_arg_s *)cdata)->addr;
	free(cdata);

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

	if (!ntlmbasic) {
		tcreds = dup_auth(creds, 1);
	} else {
		tcreds = dup_auth(creds, 0);
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
				printf("\n******* Round %d C: %d, S: %d (authok=%d, noauth=%d) *******!\n", loop+1, cd, sd, authok, noauth);
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

			if (loop == 0 && data[0]->req)
				syslog(LOG_DEBUG, "%s %s %s", inet_ntoa(caddr.sin_addr), data[0]->method, data[0]->url);

shortcut:
			chunked = 0;

			/*
			 * NTLM-to-Basic implementation
			 * Switch to this mode automatically if the config-file
			 * supplied credentials don't work.
			 */
			if (loop == 0 && ntlmbasic) {
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

					tmp = gen_407_page(data[loop]->http);
					w = write(cd, tmp, strlen(tmp));
					free(tmp);

					if (buf) {
						memset(buf, 0, strlen(buf));
						free(buf);
					}

					close(sd);
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					goto bailout;
				} else {
					dom = strchr(buf, '\\');
					if (dom == NULL) {
						auth_strncpy(tcreds, user, buf, MIN(MINIBUF_SIZE, pos-buf+1));
					} else {
						auth_strncpy(tcreds, domain, buf, MIN(MINIBUF_SIZE, dom-buf+1));
						auth_strncpy(tcreds, user, dom+1, MIN(MINIBUF_SIZE, pos-dom));
					}

					if (tcreds->hashntlm2) {
						tmp = ntlm2_hash_password(tcreds->user, tcreds->domain, pos+1);
						auth_memcpy(tcreds, passntlm2, tmp, 16);
						free(tmp);
					}

					if (tcreds->hashnt) {
						tmp = ntlm_hash_nt_password(pos+1);
						auth_memcpy(tcreds, passnt, tmp, 21);
						free(tmp);
					}

					if (tcreds->hashlm) {
						tmp = ntlm_hash_lm_password(pos+1);
						auth_memcpy(tcreds, passlm, tmp, 21);
						free(tmp);
					}

					if (debug) {
						printf("NTLM-to-basic: Credentials parsed: %s\\%s at %s\n", tcreds->domain, tcreds->user, tcreds->workstation);
					}

					memset(buf, 0, strlen(buf));
					free(buf);
				}
			}

			/*
			} else if (loop == 1 && data[loop]->code == 407) {
				if (debug)
					printf("NTLM-to-basic: Given credentials failed for proxy access.\n");

				if (!ntlmbasic)
					forced_basic = 1;

				tmp = gen_407_page(data[loop]->http);
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
			if (loop == 0 && data[loop]->req) {
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
			if (loop == 0 && data[0]->req && !authok) {
				errdata = NULL;
				i = proxy_authenticate(*wsocket[0], data[0], data[1], tcreds, &closed);

				if (closed || so_closed(sd)) {
					if (debug)
						printf("Proxy closed connection (i=%d, closed=%d, so_closed=%d). Reconnecting.\n", i, closed, so_closed(sd));
					close(sd);
					sd = proxy_connect();
					if (sd <= 0) {
						free_rr_data(data[0]);
						free_rr_data(data[1]);
						goto bailout;
					}
				} else if (i) {
					if (data[1]->code != 407) {
						if (debug)
							printf("Proxy auth not requested - just forwarding.\n");
						noauth = 1;
						loop = 1;
						goto shortcut;
					}
				} else
					syslog(LOG_ERR, "Authentication requests failed. Will try without.\n");

				reset_rr_data(data[1]);
			}

			/*
			 * Was the request first and did we authenticate with proxy?
			 * Remember not to authenticate this connection any more, should
			 * it be reused for future client requests.
			 */
			if (loop == 1 && !authok && STATUS_OK(data[1]))
				authok = 1;

			/*
			 * This is to make the ISA AV scanner bullshit transparent.
			 * If the page returned is scan-progress-html-fuck instead
			 * of requested file/data, parse it, wait for completion,
			 * make a new request to ISA for the real data and substitute
			 * the result for the original response html-fuck response.
			 */
			plugin = PLUG_ALL;
			if (loop == 1 && scanner_plugin) {
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
					if (loop == 0)
						hlist_dump(data[loop]->headers);
				}

				/*
				if (loop == 1 && serialize) {
					hlist_mod(data[loop]->headers, "Proxy-Connection", "close", 1);
					hlist_mod(data[loop]->headers, "Connection", "close", 1);
				}
				*/

				/*
				 * Forward client's headers to the proxy and vice versa; proxy_authenticate()
				 * might have by now prepared 1st and 2nd auth steps and filled our
				 * headers with the 3rd, final, NTLM message.
				 */
				if (!headers_send(*wsocket[loop], data[loop])) {
					close(sd);
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					goto bailout;
				}
			}

			/*
			 * Was the request CONNECT and proxy agreed?
			 */
			if (loop == 1 && CONNECT(data[0]) && data[1]->code == 200) {
				if (debug)
					printf("Ok CONNECT response. Tunneling...\n");

				tunnel(cd, sd);
				close(sd);
				free_rr_data(data[0]);
				free_rr_data(data[1]);
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
							goto bailout;
						} else if (debug) {
							printf("Body sent.\n");
						}
					}
				} else if (debug)
					printf("No body.\n");

				/*
				 * Windows cannot detect remotely closed connection
				 * as accurately as UNIX. We look if the proxy explicitly
				 * tells us that it's closing the connection and if so,
				 * we accept it as a fact.
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
	} while (!so_closed(sd) && !so_closed(cd) && !serialize && !noauth && !ntlmbasic && (keep || so_dataready(cd)));

bailout:
	if (debug)
		printf("\nThread finished.\n");

	free_auth(tcreds);
	close(cd);

	if (!so_closed(sd) && authok && !noauth) {
		if (debug)
			printf("Storing the connection for reuse (%d:%d).\n", cd, sd);
		pthread_mutex_lock(&connection_mtx);
		connection_list = plist_add(connection_list, sd, NULL);
		pthread_mutex_unlock(&connection_mtx);
	} else
		close(sd);

	/*
	 * Add ourselves to the "threads to join" list.
	 */
	if (!serialize) {
		pthread_mutex_lock(&threads_mtx);
		threads_list = plist_add(threads_list, (unsigned long)pthread_self(), NULL);
		pthread_mutex_unlock(&threads_mtx);
	}
}

/*
 * Auth connection "sd" and try to return negotiated CONNECT
 * connection to a remote host:port (thost).
 *
 * Return 0 for success, -1 for proxy negotiation error and
 * -HTTP_CODE in case the request failed.
 */
int prepare_http_connect(int sd, const char *thost) {
	rr_data_t data1, data2;
	int ret, closed;
	hlist_t tl;

	if (!sd || !thost || !strlen(thost))
		return -1;

	data1 = new_rr_data();
	data2 = new_rr_data();

	data1->req = 1;
	data1->method = strdup("CONNECT");
	data1->url = strdup(thost);
	data1->http = strdup("1");
	data1->headers = hlist_mod(data1->headers, "Proxy-Connection", "Keep-Alive", 1);

	/*
	 * Header replacement
	 */
	tl = header_list;
	while (tl) {
		data1->headers = hlist_mod(data1->headers, tl->key, tl->value, 1);
		tl = tl->next;
	}

	if (debug)
		printf("Starting authentication...\n");

	ret = proxy_authenticate(sd, data1, NULL, creds, &closed);
	if (ret && ret != 500) {
		if (closed || so_closed(sd)) {
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
				printf("\nReading real response:\n");

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
 * Another thread-create function. This one does the tunneling/forwarding
 * for the -L parameter. We receive malloced structure (pthreads pass only
 * one pointer arg) containing accepted client socket and a string with
 * remote server:port address.
 *
 * The -L is obviously better tunneling solution than using extra tools like
 * "corkscrew" which after all require us for authentication and tunneling
 *  their HTTP CONNECT in the end.
 */
void *tunnel_thread(void *data) {
	int sd;

	int cd = ((struct thread_arg_s *)data)->fd;
	char *thost = ((struct thread_arg_s *)data)->target;
	struct sockaddr_in caddr = ((struct thread_arg_s *)data)->addr;
	free(data);

	sd = proxy_connect();

	if (sd <= 0) {
		close(cd);
		return NULL;
	}

	if (debug)
		printf("Tunneling to %s for client %d...\n", thost, cd);
	syslog(LOG_DEBUG, "%s TUNNEL %s", inet_ntoa(caddr.sin_addr), thost);

	if (!prepare_http_connect(sd, thost)) {
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

void *socks5_thread(void *data) {
	char *tmp, *thost, *tport, *uname, *upass;
	unsigned char *bs, *auths, *addr;
	unsigned short port;
	int ver, r, c, i, w;

	int found = -1;
	int sd = 0;
	int open = !hlist_count(users_list);

	int cd = ((struct thread_arg_s *)data)->fd;
	struct sockaddr_in caddr = ((struct thread_arg_s *)data)->addr;
	free(data);

	/*
	 * Check client's version, possibly fuck'em
	 */
	bs = (unsigned char *)new(10);
	thost = new(MINIBUF_SIZE);
	tport = new(MINIBUF_SIZE);
	r = read(cd, bs, 2);
	if (r != 2 || bs[0] != 5)
		goto bail1;

	/*
	 * Read offered auth schemes
	 */
	c = bs[1];
	auths = (unsigned char *)new(c+1);
	r = read(cd, auths, c);
	if (r != c)
		goto bail2;

	/*
	 * Are we wide open and client is OK with no auth?
	 */
	if (open) {
		for (i = 0; i < c && (auths[i] || (found = 0)); ++i);
	}

	/*
	 * If not, accept plain auth if offered
	 */
	if (found < 0) {
		for (i = 0; i < c && (auths[i] != 2 || !(found = 2)); ++i);
	}

	/*
	 * If not open and no auth offered or open and auth requested, fuck'em
	 * and complete the handshake
	 */
	if (found < 0) {
		bs[0] = 5;
		bs[1] = 0xFF;
		w = write(cd, bs, 2);
		goto bail2;
	} else {
		bs[0] = 5;
		bs[1] = found;
		w = write(cd, bs, 2);
	}

	/*
	 * Plain auth negotiated?
	 */
	if (found != 0) {
		/*
		 * Check ver and read username len
		 */
		r = read(cd, bs, 2);
		if (r != 2) {
			bs[0] = 1;
			bs[1] = 0xFF;		/* Unsuccessful (not supported) */
			w = write(cd, bs, 2);
			goto bail2;
		}
		c = bs[1];

		/*
		 * Read username and pass len
		 */
		uname = new(c+1);
		r = read(cd, uname, c+1);
		if (r != c+1) {
			free(uname);
			goto bail2;
		}
		i = uname[c];
		uname[c] = 0;
		c = i;

		/*
		 * Read pass
		 */
		upass = new(c+1);
		r = read(cd, upass, c);
		if (r != c) {
			free(upass);
			free(uname);
			goto bail2;
		}
		upass[c] = 0;

		/*
		 * Check credentials against the list
		 */
		tmp = hlist_get(users_list, uname);
		if (!hlist_count(users_list) || (tmp && !strcmp(tmp, upass))) {
			bs[0] = 1;
			bs[1] = 0;		/* Success */
		} else {
			bs[0] = 1;
			bs[1] = 0xFF;		/* Failed */
		}

		/*
		 * Send response
		 */
		w = write(cd, bs, 2);
		free(upass);
		free(uname);

		/*
		 * Fuck'em if auth failed
		 */
		if (bs[1])
			goto bail2;
	}

	/*
	 * Read request type
	 */
	r = read(cd, bs, 4);
	if (r != 4)
		goto bail2;

	/*
	 * Is it connect for supported address type (IPv4 or DNS)? If not, fuck'em
	 */
	if (bs[1] != 1 || (bs[3] != 1 && bs[3] != 3)) {
		bs[0] = 5;
		bs[1] = 2;			/* Not allowed */
		bs[2] = 0;
		bs[3] = 1;			/* Dummy IPv4 */
		memset(bs+4, 0, 6);
		w = write(cd, bs, 10);
		goto bail2;
	}

	/*
	 * Ok, it's connect to a domain or IP
	 * Let's read dest address
	 */
	if (bs[3] == 1) {
		ver = 1;			/* IPv4, we know the length */
		c = 4;
	} else if (bs[3] == 3) {
		ver = 2;			/* FQDN, get string length */
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

	/*
	 * Convert the address to character string
	 */
	if (ver == 1) {
		sprintf(thost, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);	/* It's in network byte order */
	} else {
		strlcpy(thost, (char *)addr, MINIBUF_SIZE);
	}

	/*
	 * Read port number and convert to host byte order int
	 */
	r = read(cd, &port, 2);
	if (r != 2)
		goto bail3;
	sprintf(tport, "%d", ntohs(port));
	strlcat(thost, ":", MINIBUF_SIZE);
	strlcat(thost, tport, MINIBUF_SIZE);

	/*
	 * Try connect to parent proxy
	 */
	sd = proxy_connect();
	if (sd <= 0 || (i=prepare_http_connect(sd, thost))) {
		/*
		 * No such luck, report failure
		 */
		bs[0] = 5;
		bs[1] = 1;			/* General failure */
		bs[2] = 0;
		bs[3] = 1;			/* Dummy IPv4 */
		memset(bs+4, 0, 6);
		w = write(cd, bs, 10);
		goto bail3;
	} else {
		/*
		 * Proxy ok, auth worked
		 */
		bs[0] = 5;
		bs[1] = 0;			/* Success */
		bs[2] = 0;
		bs[3] = 1;			/* Dummy IPv4 */
		memset(bs+4, 0, 6);
		w = write(cd, bs, 10);
	}

	syslog(LOG_DEBUG, "%s SOCKS %s", inet_ntoa(caddr.sin_addr), thost);

	/*
	 * Let's give them bi-directional connection they asked for
	 */
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

void magic_auth_detect(const char *url) {
	int i, nc, c, closed, found = -1;
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

	if (!creds->passnt || !creds->passlm || !creds->passntlm2) {
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
		req->headers = hlist_add(req->headers, "Proxy-Connection", "Keep-Alive", HLIST_ALLOC, HLIST_ALLOC);
		if (host)
			req->headers = hlist_add(req->headers, "Host", host, HLIST_ALLOC, HLIST_ALLOC);

		creds->hashnt = prefs[i][0];
		creds->hashlm = prefs[i][1];
		creds->hashntlm2 = prefs[i][2];
		creds->flags = prefs[i][3];

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

		c = proxy_authenticate(nc, req, NULL, creds, &closed);
		if (c <= 0 || c == 500 || closed) {
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
			printf("PassNT          %s\n", tmp=printmem(creds->passnt, 16, 8));
			free(tmp);
		}
		if (prefs[found][1]) {
			printf("PassLM          %s\n", tmp=printmem(creds->passlm, 16, 8));
			free(tmp);
		}
		if (prefs[found][2]) {
			printf("PassNTLMv2      %s\n", tmp=printmem(creds->passntlm2, 16, 8));
			free(tmp);
		}
		printf("------------------------------------------------\n");
	} else
		printf("You have used wrong credentials, bad URL or your proxy is quite insane,\nin which case try submitting a Support Request.\n");

	if (host)
		free(host);
}

