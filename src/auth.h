#ifndef _AUTH_H
#define _AUTH_H
#include <stdbool.h>
#include <time.h>

#include "http.h"

bool auth_token_create(struct http_transaction *ta, char *user, time_t iat, time_t exp);
bool auth_token_parse(struct http_transaction *ta, char *encoded);

#endif
