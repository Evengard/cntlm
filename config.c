/*
 * These are very basic config file routines for the main module of CNTLM
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "utils.h"

config_t config_open(const char *fname) {
	config_t rc;
	FILE *fp;
	char *buf, *tmp, *key, *value;
	int i, j, len;

	fp = fopen(fname, "r");
	if (!fp)
		return NULL;
	
	buf = new(BUFSIZE);
	rc = (config_t)new(sizeof(struct config_s));
	rc->options = NULL;

	while (!feof(fp)) {
		tmp = fgets(buf, BUFSIZE, fp);
		if (!tmp)
			break;

		len = MIN(BUFSIZE, strlen(buf));
		if (!len || feof(fp))
			continue;

		i = j = 0;
		while (j < len && isspace(buf[j]))
			j++;

		if (j >= len || buf[j] == '#')
			continue;

		i = j;
		while (j < len && isalnum(buf[j]))
			j++;

		if (j >= len || !isspace(buf[j]))
			continue;

		key = substr(buf, i, j-i);
		i = j;
		while (j < len && isspace(buf[j]))
			j++;

		if (j >= len || buf[j] == '#')
			continue;

		value = substr(buf, j, len-j);
		i = strcspn(value, "#");
		if (i != strlen(value))
			value[i] = 0;

		trimr(value);
		rc->options = hlist_add(rc->options, key, value, HLIST_NOALLOC, HLIST_NOALLOC);
	}

	free(buf);
	fclose(fp);

	return rc;
}

void config_set(config_t cf, char *option, char *value) {
	cf->options = hlist_mod(cf->options, option, value, 1);
}

char *config_pop(config_t cf, const char *option) {
	char *tmp;

	tmp = hlist_get(cf->options, option);
	if (tmp) {
		tmp = strdup(tmp);
		cf->options = hlist_del(cf->options, option);
	}
	
	return tmp;
}

int config_count(config_t cf) {
	return hlist_count(cf->options);
}

void config_close(config_t cf) {
	if (cf == NULL)
		return;

	cf->options = hlist_free(cf->options);
	free(cf);
}
