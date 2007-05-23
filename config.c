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

#define alnum(c)	(isalpha(c) || isdigit(c))
#define blank(c)	((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n')

config_t config_open(const char *fname) {
	config_t ret;
	FILE *fp;
	char *buf, *key, *value;
	int i, j, len;

	fp = fopen(fname, "r");
	if (!fp)
		return NULL;
	
	buf = new(BUFSIZE);
	ret = (config_t)new(sizeof(struct config_s));
	ret->options = NULL;

	while (!feof(fp)) {
		fgets(buf, BUFSIZE, fp);
		len = MIN(BUFSIZE, strlen(buf));

		if (!len || feof(fp))
			continue;

		i = j = 0;
		while (j < len && blank(buf[j]))
			j++;

		if (j >= len || buf[j] == '#')
			continue;

		i = j;
		while (j < len && alnum(buf[j]))
			j++;

		if (j >= len || !blank(buf[j]))
			continue;

		key = substr(buf, i, j-i);
		i = j;
		while (j < len && blank(buf[j]))
			j++;

		if (j >= len || buf[j] == '#')
			continue;

		value = substr(buf, j, len-j);
		i = strcspn(value, "#");
		if (i != strlen(value))
			value[i] = 0;

		trimr(value);
		ret->options = hlist_add(ret->options, key, value, 0, 0);
	}

	free(buf);
	fclose(fp);

	return ret;
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
