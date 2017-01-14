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

#ifndef _UTILS_H
#define _UTILS_H

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/param.h>
#endif
#include <netinet/in.h>
#include <pthread.h>

#include "config/config.h"

#define BUFSIZE 4096
#define MINIBUF_SIZE 50
#define VAL(var, type, offset) *((type *)(var + offset))
#define MEM(var, type, offset) (type *)(var + offset)

#if !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__OpenBSD__)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/*
#define isalnum(c)	(isalpha(c) || isdigit(c))
#define isspace(c)	((c) == ' ' || (c) == '\f' || (c) == '\t' || (c) == '\r' || (c) == '\n')
*/

/*
 * Solaris doesn't have LOG_PERROR
 */
#ifndef LOG_PERROR
#define LOG_PERROR LOG_CONS
#endif

/*
 * Two single-linked list types. First is for storing headers,
 * second keeps a list of finished threads or cached connections.
 * Each has a different set of manipulation routines.
 */
typedef struct hlist_s *hlist_t;
struct hlist_s {
	char *key;
	char *value;
	int islist;
	struct hlist_s *next;
};

typedef struct plist_s *plist_t;
struct plist_s {
	unsigned long key;
	void *aux;
	struct plist_s *next;
};

typedef enum {
	HLIST_NOALLOC = 0,
	HLIST_ALLOC
} hlist_add_t;

/*
 * Request/response data structure. Complete and parsed req/res is
 * kept in this. See below for (de)allocation routines.
 */
typedef struct rr_data_s *rr_data_t;
struct rr_data_s {
	int req;
	hlist_t headers;
	int code;
	int skip_http;
	int body_len;
	int empty;
	int port;
	int http_version;
	char *method;
	char *url;
	char *rel_url;
	char *hostname;
	char *http;
	char *msg;
	char *body;
	char *errmsg;
};

/*
 * This is used in main() for passing arguments to the thread.
 */
struct thread_arg_s {
	int fd;
	char *target;
	struct sockaddr_in addr;
};

extern void myexit(int rc);
extern void croak(const char *msg, int console);

extern plist_t plist_add(plist_t list, unsigned long key, void *aux);
extern plist_t plist_del(plist_t list, unsigned long key);
extern int plist_in(plist_t list, unsigned long key);
extern void plist_dump(plist_t list);
extern char *plist_get(plist_t list, int key);
extern int plist_pop(plist_t *list, void **aux);
extern int plist_count(plist_t list);
extern plist_t plist_free(plist_t list);

extern hlist_t hlist_add(hlist_t list, char *key, char *value, hlist_add_t allockey, hlist_add_t allocvalue);
extern hlist_t hlist_dup(hlist_t list);
extern hlist_t hlist_del(hlist_t list, const char *key);
extern hlist_t hlist_mod(hlist_t list, char *key, char *value, int add);
extern int hlist_in(hlist_t list, const char *key);
extern int hlist_count(hlist_t list);
extern char *hlist_get(hlist_t list, const char *key);
extern int hlist_subcmp(hlist_t list, const char *key, const char *substr);
extern int hlist_subcmp_all(hlist_t list, const char *key, const char *substr);
extern hlist_t hlist_free(hlist_t list);
extern void hlist_dump(hlist_t list);

extern char *substr(const char *src, int pos, int len);
extern size_t strlcpy(char *dst, const char *src, size_t siz);
extern size_t strlcat(char *dst, const char *src, size_t siz);
extern char *trimr(char *buf);
extern char *lowercase(char *str);
extern char *uppercase(char *str);
extern int unicode(char **dst, char *src);
extern char *new (size_t size);
extern char *urlencode(const char *str);

extern rr_data_t new_rr_data(void);
extern rr_data_t copy_rr_data(rr_data_t dst, rr_data_t src);
extern rr_data_t dup_rr_data(rr_data_t data);
extern rr_data_t reset_rr_data(rr_data_t data);
extern void free_rr_data(rr_data_t data);

extern char *printmem(char *src, size_t len, int bitwidth);
extern char *scanmem(char *src, int bitwidth);

extern void to_base64(unsigned char *out, const unsigned char *in, size_t len, size_t olen);
extern int from_base64(char *out, const char *in);

extern long int random(void);
#if config_gethostname == 1
extern int gethostname(char *name, size_t len);
#endif
#ifndef strdup
extern char *strdup(const char *src);
#endif

#endif /* _UTILS_H */
