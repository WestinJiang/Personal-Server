/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>

#include "auth.h"
#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"
#include "../deps/include/jansson.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)       // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len-2] = '\0';  // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1")) {
        ta->req_version = HTTP_1_1;
        ta->client->keepalive = true;
    } else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        // printf("Header: %s: %s\n", field_name, field_value);
        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */
        if (!strcasecmp(field_name, "Cookie")) {
                char *auth_token = field_value;
                while (*auth_token != '\0' && strncmp(auth_token, "auth=", 5) != 0) {
                        auth_token++;
                }
                if (*auth_token != '\0')
                        auth_token_parse(ta, auth_token + 5);
        }

        if (!strcasecmp(field_name, "Range")) {
                ta->use_range = true;
                // Assuming blindly all requests are in bytes
                field_value += 6;
                char *second_value;
                ta->range[0] = strtol(field_value, &second_value, 10);
                second_value++;
                if (*second_value != '\0') {
                        ta->range[1] = strtol(second_value, NULL, 10);
                }
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction * ta, buffer_t *res)
{
    buffer_init(res, 80);

    if (ta->req_version == HTTP_1_0) {
        buffer_appends(res, "HTTP/1.0 ");
    } else if (ta->req_version == HTTP_1_1) {
            buffer_appends(res, "HTTP/1.1 ");
    }

    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    start_response(ta, &response);
    buffer_appends(&ta->resp_headers, CRLF);

    buffer_t *response_and_headers[2] = {
        &response, &ta->resp_headers
    };

    int rc = bufio_sendbuffers(ta->client->bufio, response_and_headers, 2);
    buffer_delete(&response);
    return rc != -1;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);
    buffer_appends(&ta->resp_headers, CRLF);

    buffer_t response;
    start_response(ta, &response);

    buffer_t *response_and_headers[3] = {
        &response, &ta->resp_headers, &ta->resp_body
    };

    int rc = bufio_sendbuffers(ta->client->bufio, response_and_headers, 3);
    buffer_delete(&response);
    return rc != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    if (!strcasecmp(suffix, ".mp4"))
        return "video/mp4";

    if (!strcasecmp(suffix, ".css"))
        return "text/css";

    if (!strcasecmp(suffix, ".svg"))
            return "image/svg+xml";

    return "text/plain";
}

/* Send Not Found response or default file if fallback in enabled.
 */
static bool
send_not_found(struct http_transaction *ta, char *basedir)
{
        if (html5_fallback) {
                char fname[PATH_MAX];
                snprintf(fname, sizeof fname, "%s%s", basedir, "/index.html");
                struct stat st;
                int rc = stat(fname, &st);
                if (rc == -1)
                    return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

                int filefd = open(fname, O_RDONLY);
                if (filefd == -1) {
                    return send_error(ta, HTTP_INTERNAL_ERROR, "Could not open file.");
                }

                ta->resp_status = HTTP_OK;
                http_add_header(&ta->resp_headers, "Content-Type", "%s", 
                                guess_mime_type(fname));
                off_t from = 0, to = st.st_size - 1;

                off_t content_length = to + 1 - from;
                add_content_length(&ta->resp_headers, content_length);

                if (!send_response_header(ta)) {
                        close(filefd);
                        return false;
                }
                bool success = true;;
                while (success && from <= to)
                    success = bufio_sendfile(ta->client->bufio, filefd, &from, 
                                    to + 1 - from) > 0;
                close(filefd);
                return success;

        } else {
                return send_error(ta, HTTP_NOT_FOUND, "File %s not found", 
                        bufio_offset2ptr(ta->client->bufio, ta->req_path));
        }
}


/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    
    // Lazy attempt: just tell anyone tryig shenaningans to go away.
    if (strstr(req_path, "/../")) {
            return send_error(ta, HTTP_NOT_FOUND, "");
    }
    if (strlen(req_path) == 1 && *req_path == '/') {
            return send_not_found(ta, basedir);
    }
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
            return send_not_found(ta, basedir);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta, basedir);
    }

    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    off_t from, to;
    if (ta->use_range) {
        ta->resp_status = HTTP_PARTIAL_CONTENT;
        from = ta->range[0];
        if (ta->range[1] != 0) {
            to = ta->range[1];
        } else {
            to = st.st_size - 1;
        }

        http_add_header(&ta->resp_headers, "Content-Range", 
                        "bytes %ld-%ld/%zd", from, to, st.st_size);
    } else {
        ta->resp_status = HTTP_OK;
        from = 0, to = st.st_size - 1;
    }

    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

out:
    close(filefd);
    return success;
}


/**
 * Provides an API to login valid users (user0).
 * Returns true upon successful response.
 */
static bool
handle_login_api(struct http_transaction *ta) {
    char *username = "user0";
    char *password = "thepassword";

    http_add_header(&ta->resp_headers, "Content-Type", "application/json");

    if (ta->req_content_len == 0) {
            buffer_t resp;
            if (ta->auth) {
                    resp.buf = ta->json_token;
            } else {
                    resp.buf = "{}";
            }
            size_t len = strlen(resp.buf);
            resp.len = len;
            resp.cap = len;

            http_add_header(&ta->resp_headers, "Content-Length", "%zd", len);
            ta->resp_status = HTTP_OK;
            send_response_header(ta);
            return bufio_sendbuffer(ta->client->bufio, &resp);
    }

    json_error_t err;
    json_t *jresp = json_loadb(bufio_offset2ptr(ta->client->bufio, ta->req_body),
                    ta->req_content_len, 0, &err);
    if (!jresp) {
            return send_error(ta, HTTP_BAD_REQUEST, "Invalid json");
    }

    char *usr, *pwd;
    if (json_unpack(jresp, "{s:s, s:s}", "username", &usr, "password", &pwd) == -1) {
            json_decref(jresp);
            return send_error(ta, HTTP_PERMISSION_DENIED, "");
    }

    if (strncmp(username, usr, strlen(username) + 1) == 0 &&
                    strncmp(password, pwd, strlen(password) + 1) == 0) {

            time_t now = time(NULL);
            time_t expire = now + token_expiration_time;
            auth_token_create(ta, usr, now, expire);

            char *str;
            int len = asprintf(&str, "{\"exp\": %ld, \"iat\": %ld, \"sub\": \"%s\"}",
                            expire, now, usr);
            if (len <= 0 ) return false;

            buffer_t resp;
            resp.buf = str;
            resp.len = len;
            resp.cap = len;

            http_add_header(&ta->resp_headers, "Content-Length", "%zd", len);
            ta->resp_status = HTTP_OK;
            send_response_header(ta);
            bufio_sendbuffer(ta->client->bufio, &resp);
            free(str);
            json_decref(jresp);
            return true;
    } else {
            http_add_header(&ta->resp_headers, "Content-Length", "0");
            ta->resp_status = HTTP_PERMISSION_DENIED;
            send_response_header(ta);
            json_decref(jresp);
            return true;
    }
}

/**
 * Provides and API endpoint that lists all videos in the root directory.
 * Returns true upon success.
 */
static bool
handle_video_api(struct http_transaction *ta) {
        DIR *dir = opendir(server_root);
        buffer_appendc(&ta->resp_body, '[');

        size_t length = 0;
        struct dirent *info;
        bool again = false;
        while ((info = readdir(dir)) != NULL) {
                if (strncmp(info->d_name + strlen(info->d_name) - 4, ".mp4", 4) != 0) {
                        continue;
                }

                char *file_path;
                int rc = asprintf(&file_path, "%s/%s", server_root, info->d_name);
                if (rc <= 0) return false;

                struct stat buf;
                printf("stating %s\n", file_path);
                rc = stat(file_path, &buf);
                free(file_path);
                if (rc != 0) return false;

                char *file_json;
                rc = asprintf(&file_json, "{\"size\": %ld, \"name\": \"%s\"}",
                                buf.st_size, info->d_name);
                if (rc <= 0) {
                        free(file_json);
                        return false;
                }
                length += rc;
                // Not supporting a trailing comma is stupid.
                if (again) {
                        buffer_appendc(&ta->resp_body, ',');
                } else {
                        again = true;
                }
                buffer_appends(&ta->resp_body, file_json);
                free(file_json);
        }
        buffer_appends(&ta->resp_body, "]\r\n");
        
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        http_add_header(&ta->resp_headers, "Content-Length", "%zd", length + 4);
        ta->resp_status = HTTP_OK;
        send_response_header(ta);
        bufio_sendbuffer(ta->client->bufio, &ta->resp_body);

        return true;
}

/**
 * Inform the browser that it should remove the auth cookie.
 * Returns true on success.
 */
static bool
handle_logout_api(struct http_transaction *ta)
{
    http_add_header(&ta->resp_headers, "Set-Cookie", "auth=; Max-Age=0; Path=/");
    http_add_header(&ta->resp_headers, "Content-Type", "application/json");
    http_add_header(&ta->resp_headers, "Content-Length", "0");
    ta->auth = false;
    ta->resp_status = HTTP_OK;
    send_response_header(ta);

    return true;
}

/**
 * Dispatcher for various API endpoints.
 * Returns true on a successful response.
 */
static bool
handle_api(struct http_transaction *ta)
{
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);

    if (strcmp(req_path, "/api/login") == 0) {
            return handle_login_api(ta);
    } else if (strcmp(req_path, "/api/video") == 0) {
            return handle_video_api(ta);
    } else if (strcmp(req_path, "/api/logout") == 0) {
            return handle_logout_api(ta);
    }

    return send_error(ta, HTTP_NOT_FOUND, "Invalid API endpoint");

}

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.auth = false;
    ta.use_range = false;
    ta.client = self;

    if (!http_parse_request(&ta)) {
            ta.client->keepalive = false;
            return false;
    }
    
    if (ta.req_method == HTTP_UNKNOWN) {
            return send_error(&ta, HTTP_NOT_IMPLEMENTED, "");
    }

    if (!http_process_headers(&ta)) {
            ta.client->keepalive = false;
            return false;
    }

    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    http_add_header(&ta.resp_headers, "Accept-Ranges", "bytes");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    if (STARTS_WITH(req_path, "/api")) {
        rc = handle_api(&ta);
    } else if (STARTS_WITH(req_path, "/private")) {
            if (ta.auth) {
                    rc = handle_static_asset(&ta, server_root);
            } else {
                    send_error(&ta, HTTP_PERMISSION_DENIED, "");
            }
    } else {
        rc = handle_static_asset(&ta, server_root);
    }

    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    return rc;
}
