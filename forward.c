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

#include <sys/types.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
 * Connect to the selected proxy. If the request fails, pick next proxy
 * in the line. Each request scans the whole list until all items are tried
 * or a working proxy is found, in which case it is selected and used by
 * all threads until it stops working. Then the search starts again.
 *
 * Writes required credentials into passed auth_s structure
 */
int proxy_connect(struct auth_s *credentials) {
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

	if (i > 0 && credentials != NULL)
		copy_auth(credentials, g_creds, /* fullcopy */ !ntlmbasic);

	return i;
}

/*
 * Send request, read reply, if it contains NTLM challenge, generate final
 * NTLM auth message and insert it into the original client header,
 * which is then processed by caller himself.
 *
 * If response is present, we fill in proxy's reply. Caller can tell
 * if auth was required or not from response->code. If not, caller has
 * a full reply to forward to client.
 *
 * Return 0 in case of network error, 1 when proxy replies
 *
 * Caller must init & free "request" and "response" (if supplied)
 *
 */
int proxy_authenticate(int sd, rr_data_t request, rr_data_t response, struct auth_s *credentials) {
	char *tmp, *buf, *challenge;
	rr_data_t auth;
	int len;

	int pretend407 = 0;
	int rc = 0;

	buf = new(BUFSIZE);

	strcpy(buf, "NTLM ");
	len = ntlm_request(&tmp, credentials);
	to_base64(MEM(buf, unsigned char, 5), MEM(tmp, unsigned char, 0), len, BUFSIZE-5);
	free(tmp);

	auth = dup_rr_data(request);
	auth->headers = hlist_mod(auth->headers, "Proxy-Authorization", buf, 1);

	//tmp = hlist_get(auth->headers, "Content-Length");
	//if ((tmp && atoi(tmp) > 0) || hlist_get(auth->headers, "Transfer-Encoding")) {
	if (http_has_body(request, response) != 0) {
		/*
		 * There's a body - make this request just a probe. Do not send any body. If no auth
		 * is required, we let our caller send the reply directly to the client to avoid
		 * another duplicate request later (which traditionally finishes the 2nd part of
		 * NTLM handshake). Without auth, there's no need for the final request. 
		 *
		 * However, if client has a body, we make this request without it and let caller do
		 * the second request in full. If we did it here, we'd have to cache the request
		 * body in memory (even chunked) and carry it around. Not practical.
		 *
		 * When caller sees 407, he makes the second request. That's why we pretend a 407
		 * in this situation. Without it, caller wouldn't make it, sending the client a
		 * reply to our PROBE, not the real request.
		 *
		 */
		if (debug)
			printf("Will send just a probe request.\n");
		pretend407 = 1;
	}
	auth->headers = hlist_mod(auth->headers, "Content-Length", "0", 1);
	auth->headers = hlist_del(auth->headers, "Transfer-Encoding");

	if (debug) {
		printf("\nSending PROXY auth request...\n");
		hlist_dump(auth->headers);
	}

	if (!headers_send(sd, auth)) {
		goto bailout;
	}

	if (debug)
		printf("\nReading PROXY auth response...\n");

	/*
	 * Return response if requested. "auth" is used to get it,
	 * so make it point to the caller's structure.
	 */
	if (response) {
		free_rr_data(auth);
		auth = response;
	}

	reset_rr_data(auth);
	if (!headers_recv(sd, auth)) {
		goto bailout;
	}

	if (debug)
		hlist_dump(auth->headers);

	rc = 1;

	/*
	 * Auth required?
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
				len = ntlm_response(&tmp, challenge, len, credentials);
				if (len > 0) {
					strcpy(buf, "NTLM ");
					to_base64(MEM(buf, unsigned char, 5), MEM(tmp, unsigned char, 0), len, BUFSIZE-5);
					request->headers = hlist_mod(request->headers, "Proxy-Authorization", buf, 1);
					free(tmp);
				} else {
					syslog(LOG_ERR, "No target info block. Cannot do NTLMv2!\n");
					free(challenge);
					goto bailout;
				}
			} else {
				syslog(LOG_ERR, "Proxy returning invalid challenge!\n");
				free(challenge);
				goto bailout;
			}

			free(challenge);
		} else {
			syslog(LOG_WARNING, "No Proxy-Authenticate, NTLM not supported?\n");
		}
	} else if (pretend407) {
		if (debug)
			printf("Client has a body - forcing second request.\n");
		if (response)
			response->code = 407;				// See explanation above
	}

	// FIXME: co kdyz fakt zavre po 407? jen 0 a 1?? 
bailout:
	if (!response)
		free_rr_data(auth);

	free(buf);

	return rc;
}

/*
 * Forwarding thread. Connect to the proxy, process auth then request.
 *
 * First read request, then call proxy_authenticate() which will send
 * the request. If proxy returns 407, it will compute NTLM reply and
 * return authenticated request to us. If proxy returns full response
 * (no auth needed), it returns the full reply. Then we just forward 
 * the reply to client OR make the request again with properly auth'd
 * headers provided by proxy_authenticate().
 *
 * We loop while we see Connection: keep-alive, thus making sure clients
 * can have uninterrupted conversations with a web server. Proxy-Connection
 * is not our concern, it's handled in the caller, proxy_thread(). If it's
 * present, however, we cache the auth'd proxy connection for reuse.
 *
 * Some proxies return Connection: keep-alive even when not requested and
 * would make us loop indefinitely. Because of that, we remember which server
 * we're talking to and if that changes, we return the request to be processed
 * by our caller.
 *
 * Caller decides which URL's to forward and which to process directly, that's
 * also why we return the request if the server name changes.
 *
 * We return NULL when we're finished or a pointer to another request.
 * Returned request means server name has changed and needs to be checked
 * agains NoProxy exceptions.
 *
 * thread_data is NOT freed
 * request is NOT freed
 */
rr_data_t forward_request(void *thread_data, rr_data_t request) {
	int i, w, loop, plugin;
	int *rsocket[2], *wsocket[2];
	rr_data_t data[2], rc = NULL;
	hlist_t tl;
	char *tmp;

	struct auth_s *tcreds = NULL;						/* Per-thread credentials */
	char *hostname = NULL;
	int proxy_alive = 0;
	int conn_alive = 0;
	int authok = 0;
	int noauth = 0;
	int auth_tries = 0;
	int was_cached = 0;
	int sd = 0;

	int cd = ((struct thread_arg_s *)thread_data)->fd;
	struct sockaddr_in caddr = ((struct thread_arg_s *)thread_data)->addr;

	if (debug) {
		printf("Thread processing...\n");
		plist_dump(connection_list);
	}

	/*
	 * NTLM credentials for purposes of this thread (tcreds) are given to
	 * us by proxy_connect() or retrieved from connection cache.
	 *
	 * Ultimately, the source for creds is always proxy_connect(), but when
	 * we cache a connection, we store creds associated with it in the 
	 * cache as well, in case we'll need them.
	 */
	pthread_mutex_lock(&connection_mtx);
	i = plist_pop(&connection_list, (void **)&tcreds);
	pthread_mutex_unlock(&connection_mtx);
	if (i) {
		if (debug)
			printf("Found autenticated connection %d!\n", i);
		sd = i;
		authok = 1;
		was_cached = 1;
	} else {
		tcreds = new_auth();
		sd = proxy_connect(tcreds);
		if (sd <= 0) {
			tmp = gen_502_page(request->http, "Parent proxy unreacheable");
			w = write(cd, tmp, strlen(tmp));
			free(tmp);
			rc = (void *)-1;
			goto bailout;
		}
	}

	/*
	 * Each thread only serves req's for one hostname. If hostname changes,
	 * we return request to our caller for a new direct/forward decision.
	 */
	if (request->hostname) {
		hostname = strdup(request->hostname);
	}

	do {
		/*
		 * data[0] is for the first loop pass
		 *   - first do {} loop iteration uses request passed from caller,
		 *     in subsequent iterations we read the request headers from the client
		 *   - if not already done, we try to authenticate the connection
		 *   - we send the request headers to the proxy with HTTP body, if present
		 *
		 * data[1] is for the second pass
		 *   - read proxy response
		 *   - forward it to the client with HTTP body, if present
		 *
		 * There are two goto's:
		 *   - auth_retry: jump here from second iter. of inner loop, when we detect
		 *     that auth failed. "request" is set to the original request and by jumping
		 *     here, we effectively re-try the attempt. This is just in case we're using
		 *     a cached connection - it must have timed out, so we reconnect and try
		 *     again.
		 *   - shortcut: jump there from first iter. of inner loop, when we detect
		 *     that auth isn't required by proxy. We do loop++, make the jump and
		 *     the reply to our auth attempt (containing valid response) is sent to
		 *     client directly without us making the request a second time.
		 *
		 *  Both goto's can be done via "break", but this is more obvious hopefully.
		 */

		auth_tries = 0;

auth_retry:
		if (request) {
			if (auth_tries)
				data[0] = request;				// Got from inside the loop = retry (must free ourselves)
			else
				data[0] = dup_rr_data(request);			// Got from caller (make a dup, caller will free)
			request = NULL;						// Next time, just alloc empty structure
		} else {
			data[0] = new_rr_data();
		}
		data[1] = new_rr_data();

		rsocket[0] = wsocket[1] = &cd;
		rsocket[1] = wsocket[0] = &sd;

		proxy_alive = 0;
		conn_alive = 0;

		for (loop = 0; loop < 2; ++loop) {
			if (data[loop]->empty) {				// Isn't this the first loop with request supplied by caller?
				if (debug) {
					printf("\n******* Round %d C: %d, S: %d (authok=%d, noauth=%d) *******\n", loop+1, cd, sd, authok, noauth);
					printf("Reading headers (%d)...\n", *rsocket[loop]);
				}
				if (!headers_recv(*rsocket[loop], data[loop])) {
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					rc = (void *)-1;
					/* error page */
					goto bailout;
				}
			}

			/*
			 * Check whether this new request still talks to the same server as previous.
			 * If no, return request to caller, he must decide on forward or direct
			 * approach.
			 *
			 * If we're here, previous request loop must have been proxy keep-alive
			 * (we're looping only if proxy_alive) or this is the first loop since
			 * we were called. If former, set proxy_alive=1 to cache the connection.
			 */
			if (loop == 0 && hostname && data[0]->hostname
					&& strcasecmp(hostname, data[0]->hostname)) {
				if (debug)
					printf("\n******* F RETURN: %s *******\n", data[0]->url);

				if (authok)
					proxy_alive = 1;
				rc = dup_rr_data(data[0]);
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				goto bailout;
			}

			if (debug && !auth_tries)
				hlist_dump(data[loop]->headers);

			if (loop == 0 && data[0]->req && !auth_tries)
				syslog(LOG_DEBUG, "%s %s %s", inet_ntoa(caddr.sin_addr), data[0]->method, data[0]->url);

shortcut:
			/*
			 * Modify request headers.
			 *
			 * Try to request keep-alive for every connection. We keep them in a pool
			 * for future reuse.
			 */
			if (loop == 0 && data[0]->req) {
				/*
				 * NTLM-to-Basic
				 */
				if (http_parse_basic(data[loop]->headers, "Proxy-Authorization", tcreds) > 0) {
					if (debug)
						printf("NTLM-to-basic: Credentials parsed: %s\\%s at %s\n", tcreds->domain, tcreds->user, tcreds->workstation);
				} else if (ntlmbasic) {
					if (debug)
						printf("NTLM-to-basic: Returning client auth request.\n");

					tmp = gen_407_page(data[loop]->http);
					w = write(cd, tmp, strlen(tmp));
					free(tmp);

					free_rr_data(data[0]);
					free_rr_data(data[1]);
					rc = (void *)-1;
					goto bailout;
				}

				/*
				 * Header replacement implementation
				 */
				tl = header_list;
				while (tl) {
					data[0]->headers = hlist_mod(data[0]->headers, tl->key, tl->value, 0);
					tl = tl->next;
				}

				/*
				 * Also remove runaway P-A from the client (e.g. Basic from N-t-B), which might 
				 * cause some ISAs to deny us, even if the connection is already auth'd.
				 */
				data[0]->headers = hlist_mod(data[0]->headers, "Proxy-Connection", "keep-alive", 1);

				/*
				 * Remove all Proxy-Authorization headers from client
				 */
				while (hlist_get(data[loop]->headers, "Proxy-Authorization")) {
					data[loop]->headers = hlist_del(data[loop]->headers, "Proxy-Authorization");
				}
			}

			/*
			 * Got request from client and connection is not yet authenticated?
			 * This happens only for non-cached connections!
			 */
			if (loop == 0 && data[0]->req && !authok && !noauth) {
				if (!proxy_authenticate(*wsocket[0], data[0], data[1], tcreds)) {
					if (debug)
						printf("Proxy auth connection error.\n");
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					rc = (void *)-1;
					/* error page */
					goto bailout;
				}

				/*
				 * !!! data[1] is now filled by proxy_authenticate() !!!
				 * !!! with proxy's reply to our first (auth) req.   !!!
				 * !!! that's why we reset data[1] below             !!!
				 *
				 * Reply to auth request wasn't 407? Then auth is not required,
				 * let's jump into the next loop and forward it to client
				 * Also just forward if proxy doesn't reply with keep-alive,
				 * because without it, NTLM auth wouldn't work anyway.
				 *
				 * Let's decide proxy doesn't want any auth if it returns a
				 * non-error reply. Next rounds will be faster.
				 */
				if (data[1]->code != 407 || !hlist_subcmp(data[1]->headers, "Proxy-Connection", "keep-alive")) {
					if (debug)
						printf("Proxy auth not requested - just forwarding.\n");
					if (data[1]->code < 400)
						noauth = 1;
					loop = 1;
					goto shortcut;
				}

				/*
				 * If we're continuing normally, we have to free possible
				 * auth response from proxy_authenticate() in data[1]
				 */
				reset_rr_data(data[1]);
			}

			/*
			 * Is final reply from proxy still 407 denied? If this is a chached
			 * connection, make a new connection and try to auth one more time.
			 * It must have timed out (because it was auth'd before).
			 *
			 * Let's jump to auth_retry: and pass the original request as if we were
			 * just called with a new "request".  Remember that this is a second try
			 * (auth_tries++) and if we get here again without success, return error
			 * to the client.
			 */
			if (loop == 1 && data[1]->code == 407 && was_cached && !auth_tries) {
				if (debug)
					printf("\nCached connection timed out - retrying.\n");

				close(sd);
				sd = proxy_connect(tcreds);
				was_cached = 0;
				authok = 0;
				if (sd <= 0) {
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					rc = (void *)-1;
					/* error page */
					goto bailout;
				}

				request = dup_rr_data(data[0]);
				auth_tries++;
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				goto auth_retry;
			}

			/*
			 * Was the request first and did we authenticate with proxy?
			 * Remember not to authenticate this connection any more.
			 */
			if (loop == 1 && !noauth && data[1]->code != 407)
				authok = 1;

			/*
			 * This is to make the ISA AV scanner bullshit transparent. If the page
			 * returned is scan-progress-html-fuck instead of requested file/data, parse
			 * it, wait for completion, make a new request to ISA for the real data and
			 * substitute the result for the original response html-fuck response.
			 */
			plugin = PLUG_ALL;
			if (loop == 1 && scanner_plugin) {
				plugin = scanner_hook(data[0], data[1], tcreds, *wsocket[loop], rsocket[loop], scanner_plugin_maxsize);
			}

			/*
			 * Check if we should loop for another request.  Required for keep-alive
			 * connections, client might really need a non-interrupted conversation.
			 *
			 * We check only server reply for keep-alive, because client may want it,
			 * but it's not gonna happen unless server agrees.
			 */
			if (loop == 1) {
				conn_alive = hlist_subcmp(data[1]->headers, "Connection", "keep-alive");
				if (!conn_alive)
					data[1]->headers = hlist_mod(data[1]->headers, "Connection", "close", 1);

				/*
				 * Remove all Proxy-Authenticate headers from proxy
				 */
				while (hlist_get(data[loop]->headers, "Proxy-Authenticate")) {
					data[loop]->headers = hlist_del(data[loop]->headers, "Proxy-Authenticate");
				}

				/*
				 * Are we returning 407 to the client? Substitute his request
				 * by our BASIC translation request.
				 */
				if (data[1]->code == 407) {
					data[1]->headers = hlist_mod(data[1]->headers, "Proxy-Authenticate", "basic realm=\"Cntlm for parent\"", 1);
				}
			}

			if (plugin & PLUG_SENDHEAD) {
				if (debug) {
					printf("Sending headers (%d)...\n", *wsocket[loop]);
					if (loop == 0)
						hlist_dump(data[loop]->headers);
				}

				/*
				 * Forward client's headers to the proxy and vice versa; proxy_authenticate()
				 * might have by now prepared 1st and 2nd auth steps and filled our headers with
				 * the 3rd, final, NTLM message.
				 */
				if (!headers_send(*wsocket[loop], data[loop])) {
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					rc = (void *)-1;
					/* error page */
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
				free_rr_data(data[0]);
				free_rr_data(data[1]);
				rc = (void *)-1;
				goto bailout;
			}

			if (plugin & PLUG_SENDDATA) {
				if (!http_body_send(*wsocket[loop], *rsocket[loop], data[0], data[1])) {
					free_rr_data(data[0]);
					free_rr_data(data[1]);
					rc = (void *)-1;
					goto bailout;
				}
			}

			/*
			 * Proxy-Connection: keep-alive is taken care of in our caller as I said,
			 * but we do return when we see proxy is closing. Next headers_recv() would
			 * fail and we'd exit anyway.
			 *
			 * This way, we also tell our caller that proxy keep-alive is impossible.
			 */
			if (loop == 1) {
				proxy_alive = hlist_subcmp(data[loop]->headers, "Proxy-Connection", "keep-alive");
				if (!proxy_alive) {
					if (debug)
						printf("PROXY CLOSING CONNECTION\n");
					rc = (void *)-1;
				}
			}
		}

		free_rr_data(data[0]);
		free_rr_data(data[1]);

	/*
	 * Checking conn_alive && proxy_alive is sufficient,
	 * so_closed() just eliminates loops that we know would fail.
	 */
	} while (conn_alive && proxy_alive && !so_closed(sd) && !so_closed(cd) && !serialize);

bailout:

	if (hostname)
		free(hostname);

	if (debug) {
		printf("forward_request: palive=%d, authok=%d, ntlm=%d, closed=%d\n", proxy_alive, authok, ntlmbasic, so_closed(sd));
		printf("\nThread finished.\n");
	}

	if (proxy_alive && authok && !ntlmbasic && !so_closed(sd)) {
		if (debug)
			printf("Storing the connection for reuse (%d:%d).\n", cd, sd);
		pthread_mutex_lock(&connection_mtx);
		connection_list = plist_add(connection_list, sd, (void *)tcreds);
		pthread_mutex_unlock(&connection_mtx);
	} else {
		free(tcreds);
		close(sd);
	}

	return rc;
}

/*
 * Auth connection "sd" and try to return negotiated CONNECT
 * connection to a remote host:port (thost).
 *
 * Return 1 for success, 0 failure.
 */
int prepare_http_connect(int sd, struct auth_s *credentials, const char *thost) {
	rr_data_t data1, data2;
	int rc = 0;
	hlist_t tl;

	if (!sd || !thost || !strlen(thost))
		return 0;

	data1 = new_rr_data();
	data2 = new_rr_data();

	data1->req = 1;
	data1->method = strdup("CONNECT");
	data1->url = strdup(thost);
	data1->http = strdup("1");
	data1->headers = hlist_mod(data1->headers, "Proxy-Connection", "keep-alive", 1);

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

	if (proxy_authenticate(sd, data1, data2, credentials)) {
		/*
		 * Let's try final auth step, possibly changing data2->code
		 */
		if (data2->code == 407) {
			if (debug) {
				printf("Sending real request:\n");
				hlist_dump(data1->headers);
			}
			if (!headers_send(sd, data1)) {
				printf("Sending request failed!\n");
				goto bailout;
			}

			if (debug)
				printf("\nReading real response:\n");
			reset_rr_data(data2);
			if (!headers_recv(sd, data2)) {
				if (debug)
					printf("Reading response failed!\n");
				goto bailout;
			}
			if (debug)
				hlist_dump(data2->headers);
		}

		if (data2->code == 200) {
			if (debug)
				printf("Ok CONNECT response. Tunneling...\n");
			rc = 1;
		} else if (data2->code == 407) {
			syslog(LOG_ERR, "Authentication for tunnel %s failed!\n", thost);
		} else {
			syslog(LOG_ERR, "Request for CONNECT to %s denied!\n", thost);
		}
	} else
		syslog(LOG_ERR, "Tunnel requests failed!\n");

bailout:
	free_rr_data(data1);
	free_rr_data(data2);

	return rc;
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
void *tunnel_thread(void *thread_data) {
	int sd;
	struct auth_s *tcreds;

	int cd = ((struct thread_arg_s *)thread_data)->fd;
	char *thost = ((struct thread_arg_s *)thread_data)->target;
	struct sockaddr_in caddr = ((struct thread_arg_s *)thread_data)->addr;
	free(thread_data);

	tcreds = new_auth();
	sd = proxy_connect(tcreds);

	if (sd <= 0) {
		close(cd);
		free(tcreds);
		return NULL;
	}

	if (debug)
		printf("Tunneling to %s for client %d...\n", thost, cd);
	syslog(LOG_DEBUG, "%s TUNNEL %s", inet_ntoa(caddr.sin_addr), thost);

	if (prepare_http_connect(sd, tcreds, thost)) {
		tunnel(cd, sd);
	}

	close(sd);
	close(cd);
	free(tcreds);

	/*
	 * Add ourself to the "threads to join" list.
	 */
	pthread_mutex_lock(&threads_mtx);
	threads_list = plist_add(threads_list, (unsigned long)pthread_self(), NULL);
	pthread_mutex_unlock(&threads_mtx);

	return NULL;
}

void *socks5_thread(void *thread_data) {
	char *tmp, *thost, *tport, *uname, *upass;
	unsigned short port;
	int ver, r, c, i, w;

	struct auth_s *tcreds = NULL;
	unsigned char *bs = NULL, *auths = NULL, *addr = NULL;
	int found = -1;
	int sd = 0;
	int open = !hlist_count(users_list);

	int cd = ((struct thread_arg_s *)thread_data)->fd;
	struct sockaddr_in caddr = ((struct thread_arg_s *)thread_data)->addr;
	free(thread_data);

	/*
	 * Check client's version, possibly fuck'em
	 */
	bs = (unsigned char *)new(10);
	thost = new(MINIBUF_SIZE);
	tport = new(MINIBUF_SIZE);
	r = read(cd, bs, 2);
	if (r != 2 || bs[0] != 5)
		goto bailout;

	/*
	 * Read offered auth schemes
	 */
	c = bs[1];
	auths = (unsigned char *)new(c+1);
	r = read(cd, auths, c);
	if (r != c)
		goto bailout;

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
		goto bailout;
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
			goto bailout;
		}
		c = bs[1];

		/*
		 * Read username and pass len
		 */
		uname = new(c+1);
		r = read(cd, uname, c+1);
		if (r != c+1) {
			free(uname);
			goto bailout;
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
			goto bailout;
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
			goto bailout;
	}

	/*
	 * Read request type
	 */
	r = read(cd, bs, 4);
	if (r != 4)
		goto bailout;

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
		goto bailout;
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
			goto bailout;
	} else
		goto bailout;

	addr = (unsigned char *)new(c+10 + 1);
	r = read(cd, addr, c);
	if (r != c)
		goto bailout;
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
		goto bailout;
	sprintf(tport, "%d", ntohs(port));
	strlcat(thost, ":", MINIBUF_SIZE);
	strlcat(thost, tport, MINIBUF_SIZE);

	/*
	 * Try connect to parent proxy
	 */
	tcreds = new_auth();
	sd = proxy_connect(tcreds);
	if (sd <= 0 || !prepare_http_connect(sd, tcreds, thost)) {
		/*
		 * No such luck, report failure
		 */
		bs[0] = 5;
		bs[1] = 1;			/* General failure */
		bs[2] = 0;
		bs[3] = 1;			/* Dummy IPv4 */
		memset(bs+4, 0, 6);
		w = write(cd, bs, 10);
		goto bailout;
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

bailout:
	if (addr)
		free(addr);
	if (auths)
		free(auths);
	if (thost)
		free(thost);
	if (tport)
		free(tport);
	if (bs)
		free(bs);
	if (tcreds)
		free(tcreds);
	if (sd)
		close(sd);
	close(cd);

	return NULL;
}

void magic_auth_detect(const char *url) {
	int i, nc, c, ign = 0, found = -1;
	rr_data_t req, res;
	char *tmp, *pos, *host = NULL;

	struct auth_s *tcreds;
	char *authstr[5] = { "NTLMv2", "NTLM2SR", "NT", "NTLM", "LM" };
	int prefs[MAGIC_TESTS][5] = {
		/* NT, LM, NTLMv2, Flags, index to authstr[] */
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

	tcreds = new_auth();
	copy_auth(tcreds, g_creds, /* fullcopy */ 1);

	if (!tcreds->passnt || !tcreds->passlm || !tcreds->passntlm2) {
		printf("Cannot detect NTLM dialect - password or all its hashes must be defined, try -I\n");
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
		req->headers = hlist_add(req->headers, "Proxy-Connection", "keep-alive", HLIST_ALLOC, HLIST_ALLOC);
		if (host)
			req->headers = hlist_add(req->headers, "Host", host, HLIST_ALLOC, HLIST_ALLOC);

		tcreds->hashnt = prefs[i][0];
		tcreds->hashlm = prefs[i][1];
		tcreds->hashntlm2 = prefs[i][2];
		tcreds->flags = prefs[i][3];

		printf("Config profile %2d/%d... ", i+1, MAGIC_TESTS);

		nc = proxy_connect(NULL);
		if (nc <= 0) {
			printf("\nConnection to proxy failed, bailing out\n");
			free_rr_data(res);
			free_rr_data(req);
			close(nc);
			if (host)
				free(host);
			return;
		}

		c = proxy_authenticate(nc, req, res, tcreds);
		if (c && res->code != 407) {
			ign++;
			printf("Auth not required (HTTP code: %d)\n", res->code);
			free_rr_data(res);
			free_rr_data(req);
			close(nc);
			continue;
		}

		reset_rr_data(res);
		if (!headers_send(nc, req) || !headers_recv(nc, res)) {
			printf("Connection closed\n");
		} else {
			if (res->code == 407) {
				printf("Credentials rejected\n");
			} else {
				printf("OK (HTTP code: %d)\n", res->code);
				if (found < 0) {
					found = i;
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
			printf("PassNT          %s\n", tmp=printmem(tcreds->passnt, 16, 8));
			free(tmp);
		}
		if (prefs[found][1]) {
			printf("PassLM          %s\n", tmp=printmem(tcreds->passlm, 16, 8));
			free(tmp);
		}
		if (prefs[found][2]) {
			printf("PassNTLMv2      %s\n", tmp=printmem(tcreds->passntlm2, 16, 8));
			free(tmp);
		}
		printf("------------------------------------------------\n");
	} else if (ign == MAGIC_TESTS) {
		printf("\nYour proxy looks open, you don't need Cntlm proxy.\n");
	} else
		printf("\nWrong credentials, unauthorized URL, or the proxy doesn't support NTLM.\n");

	if (host)
		free(host);
}

