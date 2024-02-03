#define _GNU_SOURCE
#include <stdio.h>

#include "auth.h"
#include "../deps/include/jwt.h"


static const char * NEVER_EMBED_A_SECRET_IN_CODE = "supa secret";

/**
 * Creates an auth token for a valid user and adds the token to headers.
 * Returns true upon sucessfully adding a token to the headers.
 */
bool
auth_token_create(struct http_transaction *ta, char * user, time_t iat, time_t exp) {
        jwt_t *token;
        jwt_new(&token);

        int rc;
        rc = jwt_add_grant(token, "sub", user);
        if (rc != 0) return false;
        rc = jwt_add_grant_int(token, "iat", iat);
        if (rc != 0) return false;
        rc = jwt_add_grant_int(token, "exp", exp);
        if (rc != 0) return false;
        rc = jwt_set_alg(token, JWT_ALG_HS256, 
                (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, 
                strlen(NEVER_EMBED_A_SECRET_IN_CODE));
        if (rc != 0) return false;

        char *encoded = jwt_encode_str(token);
        if (encoded == NULL) return false;
        jwt_free(token);

        http_add_header(&ta->resp_headers, 
                        "Set-Cookie", "auth=%s; Max-Age=%d; HttpOnly; SameSite=Lax; Path=/",
                        encoded, exp - iat);
        return true;
}

/**
 * Parses an auth token and validates the timestamp.
 * If the token is valid, it sets ta->auth to true.
 * Returns true upon sucessful parsing of the token.
 */
bool
auth_token_parse(struct http_transaction *ta, char *encoded) {
        jwt_t *token;
        int rc = jwt_decode(&token, encoded, 
            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, 
            strlen(NEVER_EMBED_A_SECRET_IN_CODE));
        if (rc != 0) return false;

        int exp = jwt_get_grant_int(token, "exp");
        if (exp >= time(NULL)) {
                ta->auth = true;
        } else {
                ta->auth = false;
        }

        int iat = jwt_get_grant_int(token, "iat");
        const char *usr = jwt_get_grant(token, "sub");
        char *str;
        int len = asprintf(&str, "{\"exp\": %d, \"iat\": %d, \"sub\": \"%s\"}\r\n",
                                exp, iat, usr);
        if (len <= 0) return false;
        ta->json_token = str;
        return true;
}
