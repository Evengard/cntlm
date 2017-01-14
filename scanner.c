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

#include <ctype.h>
#include <fnmatch.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#include "forward.h"
#include "globals.h"
#include "http.h"
#include "scanner.h"
#include "socket.h"
#include "utils.h"

/*
 * This code is a piece of shit, but it works. Cannot rewrite it now, because
 * I don't have ISA AV filter anymore - wouldn't be able to test it.
 */
int scanner_hook(rr_data_t request, rr_data_t response, struct auth_s *credentials, int cd, int *sd, long maxKBs) {
	char *buf, *line, *pos, *tmp, *pat, *post, *isaid, *uurl;
	int bsize, lsize, size, len, i, w, nc;
	rr_data_t newreq, newres;
	plist_t list;

	int ok = 1;
	int done = 0;
	int headers_initiated = 0;
	long c, progress = 0, filesize = 0;

	/*
	 * Let's limit the responses we examine to an absolute minimum
	 */
	if (!request->req || response->code != 200 || http_has_body(request, response) != -1 || hlist_subcmp(response->headers, "Transfer-Encoding", "chunked") || !hlist_subcmp(response->headers, "Proxy-Connection", "close"))
		return PLUG_SENDHEAD | PLUG_SENDDATA;

	tmp = hlist_get(request->headers, "User-Agent");
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
	buf = new (bsize);

	len = 0;
	do {
		size = read(*sd, buf + len, SAMPLE - len - 1);
		if (debug)
			printf("scanner_hook: read %d of %d\n", size, SAMPLE - len);
		if (size > 0)
			len += size;
	} while (size > 0 && len < SAMPLE - 1);

	if (strstr(buf, "<title>Downloading status</title>") && (pos = strstr(buf, "ISAServerUniqueID=")) && (pos = strchr(pos, '"'))) {
		pos++;
		c = strlen(pos);
		for (i = 0; i < c && pos[i] != '"'; ++i)
			;

		if (pos[i] == '"') {
			isaid = substr(pos, 0, i);
			if (debug)
				printf("scanner_hook: ISA id = %s\n", isaid);

			lsize = BUFSIZE;
			line = new (lsize);
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

				if (i >= 0 && (((pos = strstr(line, "UpdatePage(")) && isdigit(pos[11])) ||
				               ((pos = strstr(line, "DownloadFinished(")) && isdigit(pos[17]) && (done = 1)))) {
					if (debug)
						printf("scanner_hook: %s", line);

					if ((pos = strstr(line, "To be downloaded"))) {
						filesize = atol(pos + 16);
						if (debug) {
							if (filesize > 0) {
								printf("scanner_hook: file size detected: %ld KiBs (max: %ld)\n", filesize / 1024, maxKBs);
							} else {
								printf("scanner_hook: file size unknown -- quitting\n");
								break;
							}
						}

						if (maxKBs && (maxKBs == 1 || filesize / 1024 > maxKBs))
							break;

						/*
						 * We have to send HTTP protocol ID so we can send the notification
						 * headers during downloading. Once we've done that, it cannot appear
						 * again, which it would if we returned PLUG_SENDHEAD, so we must
						 * remember to not include it.
						 */
						headers_initiated = 1;
						tmp = new (MINIBUF_SIZE);
						snprintf(tmp, MINIBUF_SIZE, "%s 200 OK\r\n", request->http);
						w = write(cd, tmp, strlen(tmp));
						// We don't really care about the result - shut up GCC warning (unused-but-set-variable)
						if (!w)
							w = 1;
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
						tmp = new (MINIBUF_SIZE);
						progress = atol(line + 12);
						snprintf(tmp, MINIBUF_SIZE, "ISA-Scanner: %ld of %ld\r\n", progress, filesize);
						w = write(cd, tmp, strlen(tmp));
						free(tmp);
					}

					/*
					 * If download size is unknown beforehand, stop when downloaded amount is over ISAScannerSize
					 */
					if (!filesize && maxKBs && maxKBs != 1 && progress / 1024 > maxKBs)
						break;
				}
			} while (i > 0 && !done);

			if (i >= 0 && done && (pos = strstr(line, "\",\"") + 3) && (c = strchr(pos, '"') - pos) > 0) {
				tmp = substr(pos, 0, c);
				pos = urlencode(tmp);
				free(tmp);

				uurl = urlencode(request->url);

				post = new (BUFSIZE);
				snprintf(post, BUFSIZE - 1, "%surl=%s&%sSaveToDisk=YES&%sOrig=%s", isaid, pos, isaid, isaid, uurl);

				if (debug)
					printf("scanner_hook: Getting file with URL data = %s\n", request->url);

				tmp = new (MINIBUF_SIZE);
				snprintf(tmp, MINIBUF_SIZE, "%d", (int)strlen(post));

				newres = new_rr_data();
				newreq = dup_rr_data(request);

				free(newreq->method);
				newreq->method = strdup("POST");
				hlist_mod(newreq->headers, "Referer", request->url, 1);
				hlist_mod(newreq->headers, "Content-Type", "application/x-www-form-urlencoded", 1);
				hlist_mod(newreq->headers, "Content-Length", tmp, 1);
				free(tmp);

				nc = proxy_connect(credentials);
				c = proxy_authenticate(&nc, newreq, newres, credentials);
				if (c && newres->code == 407) {
					if (debug)
						printf("scanner_hook: Authentication OK, getting the file...\n");
				} else {
					if (debug)
						printf("scanner_hook: Authentication failed or refused!\n");
					close(nc);
					nc = 0;
				}

				/*
				 * The POST request for the real file
				 */
				reset_rr_data(newres);
				if (nc && headers_send(nc, newreq) && write(nc, post, strlen(post)) && headers_recv(nc, newres)) {
					if (debug)
						hlist_dump(newres->headers);

					/*
					 * We always know the filesize here. Send it to the client, because ISA doesn't!!!
					 * The clients progress bar doesn't work without it and it stinks!
					 */
					if (filesize || progress) {
						tmp = new (20);
						snprintf(tmp, 20, "%ld", filesize ? filesize : progress);
						newres->headers = hlist_mod(newres->headers, "Content-Length", tmp, 1);
					}

					/*
					 * Here we remember if previous code already sent some headers
					 * to the client. In such case, do not include the HTTP/1.x ID.
					 */
					newres->skip_http = headers_initiated;
					copy_rr_data(response, newres);
					close(*sd);
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
			hlist_dump(response->headers);
		}

		if (!headers_send(cd, response)) {
			if (debug)
				printf("scanner_hook: failed to send headers\n");
			free(buf);
			return PLUG_ERROR;
		}

		size = write(cd, buf, len);
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
