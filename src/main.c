/*
 * Skeleton files for personal server assignment.
 *
 * @author Godmar Back
 * written for CS3214, Spring 2018.
 */

#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "buffer.h"
#include "hexdump.h"
#include "http.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

/* Implement HTML5 fallback.
 * If HTML5 fallback is implemented and activated, the server should
 * treat requests to non-API paths specially.
 * If the requested file is not found, the server will serve /index.html
 * instead; that is, it should treat the request as if it
 * had been for /index.html instead.
 */
bool html5_fallback = false;

// silent_mode. During benchmarking, this will be true
bool silent_mode = false;

// default token expiration time is 1 day
int token_expiration_time = 24 * 60 * 60;

// root from which static files are served
char * server_root;

/**
 * The outermost loop of our per-client server thread.
 * Loops over responding to transactions until no more is sent.
 */
static void *
serve_request(void * arg) {
        int client_socket = *(int *)arg;

        struct http_client client;
        http_setup_client(&client, bufio_create(client_socket));
        http_handle_transaction(&client);
        while (client.keepalive) {
                bufio_truncate(client.bufio);
                http_handle_transaction(&client);
        }
        bufio_close(client.bufio);

        return NULL;
}

/*
 * A concurrent server that serves a reasonable number of clients at a time.
 * For each client, it handles exactly any number of HTTP transactions.
 * Implemented via a thread per client. Inefficent, but epoll is hard.
 */
static void
server_loop(char *port_string)
{
    int accepting_socket = socket_open_bind_listen(port_string, 10000);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    while (accepting_socket != -1) {
        int *client_socket = malloc(sizeof(int));
        *client_socket = socket_accept_client(accepting_socket);
        if (*client_socket == -1)
            return;

        pthread_t th;
        pthread_create(&th, &attr, serve_request, (void *)client_socket);

    }
}

static void
usage(char * av0)
{
    fprintf(stderr, "Usage: %s -p port [-R rootdir] [-h] [-e seconds]\n"
        "  -p port      port number to bind to\n"
        "  -R rootdir   root directory from which to serve files\n"
        "  -e seconds   expiration time for tokens in seconds\n"
        "  -a           enable HTML5 fallback\n"
        "  -h           display this help\n"
        , av0);
    exit(EXIT_FAILURE);
}

int
main(int ac, char *av[])
{
    int opt;
    char *port_string = NULL;
    while ((opt = getopt(ac, av, "ahp:R:se:")) != -1) {
        switch (opt) {
            case 'a':
                html5_fallback = true;
                break;

            case 'p':
                port_string = optarg;
                break;

            case 'e':
                token_expiration_time = atoi(optarg);
                fprintf(stderr, "token expiration time is %d\n", token_expiration_time);
                break;

            case 's':
                silent_mode = true;
                break;

            case 'R':
                server_root = optarg;
                if (*(server_root + strlen(server_root) - 1) == '/') {
                        *(server_root + strlen(server_root) - 1) = '\0';
                }
                break;

            case 'h':
            default:    /* '?' */
                usage(av[0]);
        }
    }

    if (port_string == NULL)
        usage(av[0]);

    /* We ignore SIGPIPE to prevent the process from terminating when it tries
     * to send data to a connection that the client already closed.
     * This may happen, in particular, in bufio_sendfile.
     */ 
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "Using port %s\n", port_string);
    server_loop(port_string);
    exit(EXIT_SUCCESS);
}

