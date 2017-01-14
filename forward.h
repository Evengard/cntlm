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

#ifndef _FORWARD_H
#define _FORWARD_H

#include "auth.h"
#include "utils.h"

extern int proxy_connect(struct auth_s *credentials);
extern int proxy_authenticate(int *sd, rr_data_t request, rr_data_t response, struct auth_s *creds);
extern int prepare_http_connect(int sd, struct auth_s *credentials, const char *thost);
extern rr_data_t forward_request(void *cdata, rr_data_t request);
extern void forward_tunnel(void *thread_data);
extern void magic_auth_detect(const char *url);

#endif /* _FORWARD_H */
