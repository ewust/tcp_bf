#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event-config.h>
#include <event2/util.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/queue.h>
#include "forge_socket.h"
#include <string.h>

#define DEFAULT_SPORT   888
#define RESPONSE "HTTP/1.0 200 OK\r\nContent-type: text/html;\r\n\r\n<html><h1>Hi</h1></html>\n"

void http_req_cb(struct bufferevent *bev, void *ctx)
{
    
    printf("sigh..\n");
    fflush(stdout);
    evbuffer_add(bufferevent_get_output(bev), RESPONSE, strlen(RESPONSE)); 
}

void tcp_events(struct bufferevent *bev, short events, void *ctx)
{
    printf("got some events\n");
}

void tcp_accept(struct evconnlistener *listener, evutil_socket_t sock, 
                struct sockaddr *addr, int len, void *ptr)
{
    struct tcp_state state;
    struct event_base *base = evconnlistener_get_base(listener);
    int state_len = sizeof(state);
/*
    if (getsockopt(sock, IPPROTO_TCP, TCP_STATE, &state, &state_len) < 0) {
        perror("getsockopt");
        return;
    }
    unsigned int isn = state.ack - 1;
    printf("browser ISN: %08x (%u)\n", isn, isn);
*/

    struct bufferevent *bev = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, http_req_cb, NULL, tcp_events, NULL);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    if (evbuffer_add_printf(bufferevent_get_output(bev), RESPONSE) < 0) {
        printf("asdasd\n");
        perror("wtf");
    }
    printf("...\n");
}


int main(int argc, char *argv[])
{
    int c;
    int sport = DEFAULT_SPORT;

    // Get options
    struct option opts[] = {
        {"sport", required_argument, NULL, 's'},
        {0, 0, 0, 0} };

    while ((c = getopt_long(argc, argv, "s:", opts, NULL)) != -1) {
        switch (c) {
        case 's':
            sport = atoi(optarg);
            if (sport < 0 || sport > 65535) {
                fprintf(stderr, "Error: invalid port %d\n", sport);
                return 1;
            }
            break;
        case '?':
        default:
            fprintf(stderr, "Error: need -s sport\n");
            return 1;
        }
    }

    
    struct event_base *base;
    int sock;
    struct sockaddr_in sin;

    base = event_base_new();

    sock = socket(AF_INET, SOCK_STREAM, 0); 
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    int val = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    sin.sin_port        = htons(sport);

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return -1;
    }

/*

    if (listen(sock, 5) < 0) {
        perror("listen");
        return -1;
    }
*/

    struct evconnlistener *evlisten;
    evlisten = evconnlistener_new(base, tcp_accept, base, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, 5, sock);
    if (!evlisten) {
        perror("couldn't create listener");
        return -1;
    }

    event_base_dispatch(base);
    
    return 0;
}
