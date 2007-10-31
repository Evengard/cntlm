/*
 * Credentials related structures and routines for the main module of CNTLM
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

#ifndef _AUTH_H
#define _AUTH_H

#include <stdint.h>

struct auth_s {
	char *user;
	char *domain;
	char *workstation;
	char *passlm;
	char *passnt;
	char *passntlm2;
	int hashntlm2;
	int hashnt;
	int hashlm;
	uint32_t flags;
};

#define auth_strcpy(creds, var, value) \
	if ((creds) && (value)) { \
		if (!((creds)->var)) \
			((creds)->var) = new(MINIBUF_SIZE); \
		strlcpy(((creds)->var), (value), MINIBUF_SIZE); \
	} 

#define auth_strncpy(creds, var, value, len) \
	if ((creds) && (value)) { \
		if (!((creds)->var)) \
			((creds)->var) = new(MINIBUF_SIZE); \
		strlcpy(((creds)->var), (value), MIN(len, MINIBUF_SIZE)); \
	} 

#define auth_memcpy(creds, var, value, len) \
	if ((creds) && (value)) { \
		if (!((creds)->var)) \
			((creds)->var) = new(MINIBUF_SIZE); \
		memcpy(((creds)->var), (value), MIN(len, MINIBUF_SIZE)); \
	} 


extern struct auth_s *new_auth(void);
extern struct auth_s *dup_auth(struct auth_s *creds, int fullcopy);
extern void free_auth(struct auth_s *creds);
extern void dump_auth(struct auth_s *creds);

#endif /* _AUTH_H */
