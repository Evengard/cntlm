#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdio.h>

#include "utils.h"

#define CFG_OPTION(cf, opt, var, size) { char *__tmp = NULL; if ((__tmp=config_pop(cf, opt))) { strlcpy(var, __tmp, size); } if (__tmp) free(__tmp); }
#define CFG_DEFAULT(cf, opt, var, size) { char *__tmp = NULL; if ((__tmp=config_pop(cf, opt)) && !strlen(var)) { strlcpy(var, __tmp, size); } if (__tmp) free(__tmp); }

typedef struct config_s *config_t;
struct config_s {
	hlist_t options;
};

extern config_t config_open(const char *fname);
extern void config_set(config_t cf, char *option, char *value);
extern char *config_pop(config_t cf, const char *option);
extern int config_count(config_t cf);
extern void config_close(config_t cf);

#endif /* _CONFIG_H */
