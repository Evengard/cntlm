/*
 * Static HTML page generators for CNTLM
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

#include "utils.h"
#include "string.h"
#include "stdio.h"

char *gen_auth_page(char *http) {
	char *tmp;

	tmp = new(BUFSIZE);
	snprintf(tmp, BUFSIZE, "HTTP/1.%s 407 Access denied.\r\n", http);
	strcat(tmp, "Proxy-Authenticate: Basic realm=\"Cntlm Proxy\"\r\n");
	strcat(tmp, "Content-Type: text/html\r\n\r\n");
	strcat(tmp, "<html><body><h1>Authentication error</h1><p><a href='http://cntlm.sf.net/'>Cntlm</a> "
		"proxy has NTLM-to-basic feature enabled. You have to enter correct credentials to continue "
		"(try Ctrl-R or F5).</p></body></html>");

	return tmp;
}


char *gen_denied_page(char *ip) {
	char *tmp;

	tmp = new(BUFSIZE);
	snprintf(tmp, BUFSIZE, "HTTP/1.0 407 Access denied.\r\nContent-Type: text/html\r\n\r\n"
		"<html><body><h1>Access denied</h1><p>Your request has been declined, %s "
		"is not allowed to connect.</p></body></html>", ip);

	return tmp;
}
