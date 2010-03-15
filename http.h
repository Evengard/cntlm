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

#ifndef _HTTP_H
#define _HTTP_H

#include "utils.h"

extern int is_http_header(const char *src);
extern char *get_http_header_name(const char *src);
extern char *get_http_header_value(const char *src);
extern int headers_recv(int fd, rr_data_t data);
extern int headers_send(int fd, rr_data_t data);
extern int data_drop(int src, int size);
extern int data_send(int dst, int src, int size);
extern int chunked_data_send(int dst, int src);
extern int tunnel(int cd, int sd);

#endif /* _HTTP_H */
