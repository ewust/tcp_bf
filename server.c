
#include <stdlib.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include "forge_socket.h"
#include <string.h>

#define DEFAULT_SPORT   888

#define RESPONSE "HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\nContent-type: text/html;\r\n\r\n%s\n"

#define HTML_CODE "<html><h1>Hi</h1><script type=\"text/javascript\">setTimeout(function(){document.location=\"http://141.212.109.239:888/\";},100);</script></html>"

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

void on_read(int sock, short type, void *arg)
{
    printf("on_read(%d, %d, %p)\n", sock, type, arg);    
    
}

void echo_read_cb(struct bufferevent *bev, void *ctx)
{
    return;
}

void on_tcp_accept(struct evconnlistener *listener, 
                   evutil_socket_t sock, struct sockaddr *addr, int socklen, void *ptr)
{
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(bev, echo_read_cb, NULL, tcp_events, NULL);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    evbuffer_add_printf(bufferevent_get_output(bev), RESPONSE, strlen(HTML_CODE), HTML_CODE);

    struct tcp_state state;
    int state_len = sizeof(state);    
    if (getsockopt(sock, IPPROTO_TCP, TCP_STATE, &state, &state_len) < 0) {
        perror("getsockopt");
        return;
    }
    unsigned int isn = state.ack - 1;
    printf("accept: %s ISN: %08x (%u)\n", inet_ntoa(((struct sockaddr_in*)addr)->sin_addr), isn, isn);
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

    sock = socket(AF_INET, SOCK_FORGE, 0);
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
    fcntl(sock, F_SETFL, O_NONBLOCK); // Eh, ok.

/*
    if (listen(sock, 5) < 0) {
        perror("listen");
        return -1;
    }
*/
   
    struct evconnlistener *listener;
    listener = evconnlistener_new(base, on_tcp_accept, NULL, LEV_OPT_CLOSE_ON_FREE, -1, sock); 
    
    event_base_dump_events(base, stdout);

    event_base_dispatch(base);
    
    return 0;
}
