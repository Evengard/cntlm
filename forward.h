#include "utils.h"
#include "auth.h"

void magic_auth_detect(const char *url);
void *proxy_thread(void *cdata);
void *tunnel_thread(void *data);
void *socks5_thread(void *data);
int proxy_connect(void);
int proxy_authenticate(int sd, rr_data_t request, rr_data_t response, struct auth_s *creds, int *closed);

