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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "auth.h"

struct auth_s *new_auth(void) {
	struct auth_s *tmp;

	tmp = (struct auth_s *)new(sizeof(struct auth_s));
	tmp->user = new(MINIBUF_SIZE);
	tmp->domain = new(MINIBUF_SIZE);
	tmp->workstation = new(MINIBUF_SIZE);
	tmp->passntlm2 = 0;
	tmp->passnt = 0;
	tmp->passlm = 0;
	tmp->hashntlm2 = 1;
	tmp->hashnt = 0;
	tmp->hashlm = 0;
	tmp->flags = 0;

	return tmp;
}

struct auth_s *dup_auth(struct auth_s *creds, int fullcopy) {
	struct auth_s *tmp;

	tmp = new_auth();

	tmp->domain = new(MINIBUF_SIZE);
	strlcpy(tmp->domain, creds->domain, MINIBUF_SIZE);

	tmp->workstation = new(MINIBUF_SIZE);
	strlcpy(tmp->workstation, creds->workstation, MINIBUF_SIZE);

	tmp->hashntlm2 = creds->hashntlm2;
	tmp->hashnt = creds->hashnt;
	tmp->hashlm = creds->hashlm;
	tmp->flags = creds->flags;

	if (fullcopy) {
		tmp->user = new(MINIBUF_SIZE);
		strlcpy(tmp->user, creds->user, MINIBUF_SIZE);

		if (creds->passntlm2) {
			tmp->passntlm2 = new(MINIBUF_SIZE);
			memcpy(tmp->passntlm2, creds->passntlm2, MINIBUF_SIZE);
		}

		if (creds->passnt) {
			tmp->passnt = new(MINIBUF_SIZE);
			memcpy(tmp->passnt, creds->passnt, MINIBUF_SIZE);
		}

		if (creds->passlm) {
			tmp->passlm = new(MINIBUF_SIZE);
			memcpy(tmp->passlm, creds->passlm, MINIBUF_SIZE);
		}
	}

	return tmp;
}

void free_auth(struct auth_s *creds) {
	if (!creds)
		return;

	free(creds->domain);
	free(creds->workstation);
	if (creds->user)
		free(creds->user);
	if (creds->passntlm2)
		free(creds->passntlm2);
	if (creds->passnt)
		free(creds->passnt);
	if (creds->passlm)
		free(creds->passlm);
	free(creds);
}

void dump_auth(struct auth_s *creds) {
	char *tmp;

	printf("Credentials structure dump:\n");
	if (!creds) {
		printf("Struct is not allocated!\n");
		return;
	}

	printf("User:       %s\n", creds->user);
	printf("Domain:     %s\n", creds->domain);
	printf("Wks:        %s\n", creds->workstation);
	printf("HashNTLMv2: %d\n", creds->hashntlm2);
	printf("HashNT:     %d\n", creds->hashnt);
	printf("HashLM:     %d\n", creds->hashlm);
	printf("Flags:      %X\n", creds->flags);
	if (creds->passntlm2) {
		tmp = printmem(creds->passntlm2, 16, 8);
		printf("PassNTLMv2: %s\n", tmp);
		free(tmp);
	}

	if (creds->passnt) {
		tmp = printmem(creds->passnt, 16, 8);
		printf("PassNT:     %s\n", tmp);
		free(tmp);
	}

	if (creds->passlm) {
		tmp = printmem(creds->passlm, 16, 8);
		printf("PassLM:     %s\n\n", tmp);
		free(tmp);
	}
}
