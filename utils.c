/*
 * These are helping routines for the main module of CNTLM
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

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include "swap.h"
#include "utils.h"
#include "socket.h"

/*
 * Add a new item to a list. Every plist_t variable must be 
 * initialized to NULL (or pass NULL for "list" when adding
 * the first item). This is required to strip down the 
 * complexity to minimum and not to need any plist_new func.
 *
 * This list type allows to store an arbitrary pointer
 * associating it with the key.
 */
plist_t plist_add(plist_t list, unsigned long key, char *aux) {
	plist_t tmp, t = list;

	if (!key)
		return NULL;

	tmp = malloc(sizeof(struct plist_s));
	tmp->key = key;
	tmp->aux = aux;
	tmp->next = NULL;

	if (list == NULL)
		return tmp;

	while (t->next)
		t = t->next;

	t->next = tmp;

	return list;
}

/*
 * Delete an item from the list, possibly returning NULL when
 * the list is empty or nothing was found.
 */
plist_t plist_del(plist_t list, unsigned long key) {
	plist_t ot = NULL, t = list;

	while (t) {
		if (t->key == key)
			break;
		ot = t;
		t = t->next;
	}

	if (t) {
		plist_t tmp = t->next;

		free(t);
		if (ot == NULL)
			return tmp;

		ot->next = tmp;
	}

	return list;
}

/*
 * Return true if an item is present in the list.
 */
int plist_in(plist_t list, unsigned long key) {
	plist_t t = list;

	while (t) {
		if (t->key == key)
			break;
		t = t->next;
	}

	return (t != NULL);
}

/*
 * For debugging purposes - dump the entire contents
 * of a list.
 */
void plist_dump(plist_t list) {
	plist_t t;

	t = list;
	while (t) {
		printf("List data: %lu => %s\n", (unsigned long int)t->key, t->aux);
		t = t->next;
	}
}

/*
 * Return the pointer associated with the key.
 */
char *plist_get(plist_t list, int key) {
	plist_t t = list;

	while (t) {
		if (t->key == key)
			break;
		t = t->next;
	}

	return (t == NULL ? NULL : t->aux);
}

/*
 * Scan the list for an open descriptor (socket), possibly
 * discarding all closed ones on the way. Return the first
 * match.
 *
 * In conjunction with plist_add, the list behaves as a FIFO.
 * This feature is used for rotating cached connections in the
 * list, so that none is left too long unused (proxy timeout).
 * Returns only key, not aux.
 */
int plist_pop(plist_t *list) {
	plist_t tmp, t;
	int id = 0;
	int ok = 0;

	if (list == NULL || *list == NULL)
		return 0;

	t = *list;
	while (!ok && t) {
		id = t->key;
		tmp = t->next;

		if (so_closed(id))
			close(id);
		else
			ok = 1;

		free(t);
		t = tmp;
	}

	*list = t;

	return (ok ? id : 0);
}

/*
 * Free the list.
 */
plist_t plist_free(plist_t list) {
	plist_t t = list;

	while (list) {
		t = list->next;
		if (list->aux)
			free(list->aux);
		free(list);
		list = t;
	}

	return NULL;
}

/*
 * The same as plist_add. Here we have two other arguments.
 * They are treated as booleans - true means to duplicate a
 * key/value, false means to store the pointer directly.
 *
 * Caller decides this on a by-call basis. Part of the manipulation
 * routines is a "free". That method always deallocates both the
 * key and the value. So for static or temporary keys/values,
 * the caller instructs us to duplicate the neccessary amount 
 * of heap. This mechanism is used to minimize memory-related
 * bugs throughout the code and tens of free's in the main
 * module.
 */
hlist_t hlist_add(hlist_t list, char *key, char *value, int allockey, int allocvalue) {
	hlist_t tmp, t = list;

	if (key == NULL || value == NULL)
		return list;

	tmp = malloc(sizeof(struct hlist_s));
	tmp->key = (allockey ? strdupl(key) : key);
	tmp->value = (allocvalue ? strdupl(value) : value);
	tmp->next = NULL;

	if (list == NULL)
		return tmp;

	while (t->next)
		t = t->next;

	t->next = tmp;

	return list;
}

/*
 * Return a duplicate of the list (copy).
 */
hlist_t hlist_dup(hlist_t list) {
	hlist_t tmp = NULL, t = list;

	while (t) {
		tmp = hlist_add(tmp, t->key, t->value, 1, 1);
		t = t->next;
	}

	return tmp;
}

/*
 * Remove an item from the list.
 */
hlist_t hlist_del(hlist_t list, const char *key) {
	hlist_t ot = NULL, t = list;

	while (t) {
		if (!strcasecmp(t->key, key))
			break;
		ot = t;
		t = t->next;
	}

	if (t) {
		hlist_t tmp = t->next;

		free(t->key);
		free(t->value);
		free(t);

		if (ot == NULL)
			return tmp;

		ot->next = tmp;
	}

	return list;
}

/*
 * Change the value of a key. If add is true, we store it in the
 * list if the key is not found. Unlike hlist_add, which offers
 * pointer storage or memory duplication for both the key and the
 * value separately, hlist_mod always duplicates.
 *
 * Used to add a header, which might already be present.
 */
hlist_t hlist_mod(hlist_t list, char *key, char *value, int add) {
	hlist_t t = list;

	while (t) {
		if (!strcasecmp(t->key, key))
			break;
		t = t->next;
	}

	if (t) {
		free(t->value);
		t->value = strdupl(value);
	} else if (add) {
		list = hlist_add(list, key, value, 1, 1);
	}

	return list;
}

/*
 * Return true is the key is in the list.
 */
int hlist_in(hlist_t list, const char *key) {
	hlist_t t = list;

	while (t) {
		if (!strcasecmp(t->key, key))
			break;
		t = t->next;
	}

	return (t != NULL);
}

/*
 * Return the number of items in a list.
 */
int hlist_count(hlist_t list) {
	hlist_t t = list;
	int ret = 0;

	while (t) {
		ret++;
		t = t->next;
	}

	return ret;
}

/*
 * Return the value for the key.
 */
char *hlist_get(hlist_t list, const char *key) {
	hlist_t t = list;

	while (t) {
		if (!strcasecmp(t->key, key))
			break;
		t = t->next;
	}

	return (t == NULL ? NULL : t->value);
}

/*
 * Free the list. For more about list memory management,
 * se hlist_add.
 */
hlist_t hlist_free(hlist_t list) {
	hlist_t t = list;

	while (list) {
		t = list->next;

		free(list->key);
		free(list->value);
		free(list);

		list = t;
	}

	return NULL;
}

/*
 * This is for debugging purposes.
 */
void hlist_dump(hlist_t list) {
	hlist_t t;

	t = list;
	while (t) {
		printf("%-30s => %s\n", t->key, t->value);
		t = t->next;
	}
}

/*
 * Standard substr. To prevent modification of the source
 * (terminating \x0), return the result in a new memory.
 */
char *substr(const char *src, int pos, int len) {
	int l;
	char *tmp;

	if (len == 0)
		len = strlen(src);

	l = MIN(len, strlen(src)-pos);
	if (l <= 0)
		return NULL;

	tmp = new(l+1);
	strlcpy(tmp, src+pos, l+1);

	return tmp;
}

/*
 * Ture if src is a header. This is just a basic check
 * for the colon delimiter. Might eventually become more
 * sophisticated. :)
 */
inline int head_ok(const char *src) {
	return strcspn(src, ":") != strlen(src);
}

/*
 * Extract the header name from the source.
 */
char *head_name(const char *src) {
	int i;

	i = strcspn(src, ":");
	if (i != strlen(src))
		return substr(src, 0, i);
	else
		return NULL;
}

/*
 * Extract the header value from the source.
 */
char *head_value(const char *src) {
	char *sub;

	if ((sub = strchr(src, ':'))) {
		sub++;
		while (*sub == ' ')
			sub++;

		return strdupl(sub);
	} else
		return NULL;
}

/*
 * Allocate memory and initialize a new rr_data_t structure.
 */
rr_data_t new_rr_data(void) {
	rr_data_t data;
	
	data = malloc(sizeof(struct rr_data_s));
	data->req = 0;
	data->code = 0;
	data->headers = NULL;
	data->method = NULL;
	data->url = NULL;
	data->http = NULL;
	data->msg = NULL;

	return data;
}

/*
 * Duplicate the req/res data.
 */
rr_data_t dup_rr_data(rr_data_t data) {
	rr_data_t tmp;

	if (data == NULL)
		return NULL;

	tmp = new_rr_data();
	tmp->req = data->req;
	tmp->code = data->code;
	if (data->headers)
		tmp->headers = hlist_dup(data->headers);
	if (data->method)
		tmp->method = strdupl(data->method);
	if (data->url)
		tmp->url = strdupl(data->url);
	if (data->http)
		tmp->http = strdupl(data->http);
	if (data->msg)
		tmp->msg = strdupl(data->msg);
	
	return tmp;
}

/*
 * Free rr_data_t structure. We also take care of freeing
 * the memory of its members.
 */
void free_rr_data(rr_data_t data) {
	if (data == NULL)
		return;
	
	if (data->headers) hlist_free(data->headers);
	if (data->method) free(data->method);
	if (data->url) free(data->url);
	if (data->http) free(data->http);
	if (data->msg) free(data->msg);
	free(data);
}

/*
 * Cut the whitespace at the end of a string.
 */
char *trimr(char *buf) {
	int i;

	i = strlen(buf)-1;
	while (i >= 0 && (buf[i] == '\r' || buf[i] == '\n' || buf[i] == '\t' || buf[i] == ' '))
		i--;
	buf[i+1] = 0;

	return buf;
}

/*
 * Our implementation of non-POSIX strdup()
 */
char *strdupl(const char *src) {
	size_t len;
	char *tmp;

	len = strlen(src)+1;
	tmp = malloc(len);
	memcpy(tmp, src, len);
	
	return tmp;
}

/*
 * More intuitive version of strncpy with string termination
 * from OpenBSD
 */
size_t strlcpy(char *dst, const char *src, size_t siz) {
        char *d = dst;
        const char *s = src;
        size_t n = siz;

        /* Copy as many bytes as will fit */
        if (n != 0) {
                while (--n != 0) {
                        if ((*d++ = *s++) == '\0')
                                break;
                }
        }

        /* Not enough room in dst, add NUL and traverse rest of src */
        if (n == 0) {
                if (siz != 0)
                        *d = '\0';                /* NUL-terminate dst */
                while (*s++);
        }

        return (s - src - 1);        /* count does not include NUL */
}

/*
 * More intuitive version os strncat with string termination
 * from OpenBSD
 */
size_t strlcat(char *dst, const char *src, size_t siz) {
        char *d = dst;
        const char *s = src;
        size_t n = siz;
        size_t dlen;

        /* Find the end of dst and adjust bytes left but don't go past end */
        while (n-- != 0 && *d != '\0')
                d++;

        dlen = d - dst;
        n = siz - dlen;

        if (n == 0)
                return(dlen + strlen(s));

        while (*s != '\0') {
                if (n != 1) {
                        *d++ = *s;
                        n--;
                }
                s++;
        }
        *d = '\0';

        return (dlen + (s - src));        /* count does not include NUL */
}

/*
 * Shortcut for malloc/memset zero.
 */
inline char *new(size_t size) {
	char *tmp;

	tmp = malloc(size);
	memset(tmp, 0, size);

	return tmp;
}

/*
 * Self-explanatory.
 */
char *lowercase(char *str) {
	int i;

	for (i = 0; i < strlen(str); ++i)
		str[i] = tolower(str[i]);
	
	return str;
}

/*
 * Self-explanatory.
 */
char *uppercase(char *str) {
	int i;

	for (i = 0; i < strlen(str); ++i)
		str[i] = toupper(str[i]);
	
	return str;
}

inline int unicode(char **dst, char *src) {
	char *ret;
	int l, i;

	if (!src) {
		*dst = NULL;
		return 0;
	}

	l = MIN(64, strlen(src));
	ret = new(2*l);
	for (i = 0; i < l; ++i)
		ret[2*i] = src[i];

	*dst = ret;
	return 2*l;
}

/* 
 * BASE64 CODE FROM MUTT BEGIN - ORIGINAL COPYRIGHT APPLIES:
 *
 * Copyright (C) 1996-2001 Michael R. Elkins <me@cs.hmc.edu>
 * Copyright (C) 1996-2001 Brandon Long <blong@fiction.net>
 * Copyright (C) 1997-2001 Thomas Roessler <roessler@guug.de>
 * Copyright (C) 1998-2001 Werner Koch <wk@isil.d.shuttle.de>
 * Copyright (C) 1999-2001 Brendan Cully <brendan@kublai.com>
 * Copyright (C) 1999-2001 Tommi Komulainen <Tommi.Komulainen@iki.fi>
 * Copyright (C) 2000-2001 Edmund Grimley Evans <edmundo@rano.org>
 *
 */

#define BAD     	-1
#define base64val(c)	index64[(unsigned int)(c)]

char base64[64] = {
	'A','B','C','D','E','F','G','H','I','J','K','L','M','N',
	'O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b',
	'c','d','e','f','g','h','i','j','k','l','m','n','o','p',
	'q','r','s','t','u','v','w','x','y','z','0','1','2','3',
	'4','5','6','7','8','9','+','/'
};

int index64[128] = {
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,
	61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,
	14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,
	27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,
	46,47,48,49,50,51,-1,-1,-1,-1,-1
};

void to_base64(unsigned char *out, const unsigned char *in, size_t len, size_t olen) {
	while (len >= 3 && olen > 10) {
		*out++ = base64[in[0] >> 2];
		*out++ = base64[((in[0] << 4) & 0x30) | (in[1] >> 4)];
		*out++ = base64[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
		*out++ = base64[in[2] & 0x3f];
		olen  -= 4;
		len   -= 3;
		in    += 3;
	}

	/* clean up remainder */
	if (len > 0 && olen > 4) {
		unsigned char fragment;

		*out++ = base64[in[0] >> 2];
		fragment = (in[0] << 4) & 0x30;
		if (len > 1)
		fragment |= in[1] >> 4;
		*out++ = base64[fragment];
		*out++ = (len < 2) ? '=' : base64[(in[1] << 2) & 0x3c];
		*out++ = '=';
	}
	*out = '\0';
}

/* Convert '\0'-terminated base 64 string to raw bytes.
 * Returns length of returned buffer, or -1 on error */
int from_base64(char *out, const char *in)
{
	int len = 0;
	register unsigned char digit1, digit2, digit3, digit4;

	do {
		digit1 = in[0];
		if (digit1 > 127 || base64val (digit1) == BAD)
			return -1;

		digit2 = in[1];
		if (digit2 > 127 || base64val (digit2) == BAD)
			return -1;

		digit3 = in[2];
		if (digit3 > 127 || ((digit3 != '=') && (base64val (digit3) == BAD)))
			return -1;

		digit4 = in[3];
		if (digit4 > 127 || ((digit4 != '=') && (base64val (digit4) == BAD)))
			return -1;

		in += 4;

		/* digits are already sanity-checked */
		*out++ = (base64val(digit1) << 2) | (base64val(digit2) >> 4);
		len++;
		if (digit3 != '=') {
			*out++ = ((base64val(digit2) << 4) & 0xf0) | (base64val(digit3) >> 2);
			len++;
			if (digit4 != '=') {
				*out++ = ((base64val(digit3) << 6) & 0xc0) | base64val(digit4);
				len++;
			}
		}
	} while (*in && digit4 != '=');

	return len;
}
/* 
 * CODE FROM MUTT END
 */
