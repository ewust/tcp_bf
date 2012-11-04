#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

struct st_stat_ {
    uint32_t addr;
    unsigned long long pkts;
    unsigned long long bytes;
    
    uint32_t max_seq;
};

// A pair of st_stat_ s
struct st_stats {
    struct st_stat_ a;
    struct st_stat_ b;
    unsigned long long first_pkt_time;
};

void process_packet(struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data, struct st_stats *stats)
{
    struct iphdr *ip_ptr = (struct iphdr*)(pkt_data + sizeof(struct ether_header));
    unsigned long pkt_len = (unsigned long)pkt_hdr->len;
    unsigned long long pkt_time;
    struct tcphdr *th = (struct tcphdr *)(pkt_data + sizeof(struct ether_header) + (4*(ip_ptr->ihl)));

    pkt_time = pkt_hdr->ts.tv_sec * 1000000 + pkt_hdr->ts.tv_usec;
     

    if (!stats->a.addr) {
        // first packet
        stats->a.addr = ip_ptr->daddr;
        stats->b.addr = ip_ptr->saddr;
        
        stats->first_pkt_time = pkt_time;
    }
 

    if (stats->a.addr == ip_ptr->saddr) {
        // Server packet(?) 
        //if (((int32_t)((int)ntohl(th->seq) - (int)stats->a.max_seq)) > 0) {
        if (ntohl(th->seq) > stats->a.max_seq || 
            ((ntohl(th->seq) < (1UL << 31)) &&
             stats->a.max_seq > (1UL << 31))) {
            stats->a.max_seq = ntohl(th->seq);
        }

        // Track seq growth over time
        printf("%llu %u %u\n", pkt_time - stats->first_pkt_time, 
                ntohl(th->seq), stats->a.max_seq);
    
        stats->a.pkts++;
        stats->a.bytes += pkt_len;
    } else if (stats->b.addr == ip_ptr->saddr) {
        // client packet
        stats->b.pkts++;
        stats->b.bytes += pkt_len;
    } else {
        struct in_addr in;
        in.s_addr = ip_ptr->saddr;
        fprintf(stderr, "Error: packet from %s??\n", inet_ntoa(in));
        in.s_addr = stats->a.addr;
        fprintf(stderr, "expect %s ", inet_ntoa(in));
        in.s_addr = stats->b.addr;
        fprintf(stderr, "or %s\n", inet_ntoa(in));
        exit(-1);
    }    
}

void print_results(struct st_stats *stats)
{
    struct in_addr in;
    in.s_addr = stats->a.addr;
    fprintf(stderr, "A: %s\n", inet_ntoa(in));
    fprintf(stderr, "  %llu bytes\n", stats->a.bytes);
    fprintf(stderr, "  %llu pkts\n", stats->a.pkts);
    fprintf(stderr, "\n");
    in.s_addr = stats->b.addr;
    fprintf(stderr, "B: %s\n", inet_ntoa(in));
    fprintf(stderr, "  %llu bytes\n", stats->b.bytes);
    fprintf(stderr, "  %llu pkts\n", stats->b.pkts); 
}

int main(int argc, char *argv[])
{

    pcap_t *pc;
    const u_char *pkt_data;
    struct pcap_pkthdr *pkt_hdr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc != 2) {
        printf("Usage:\n\t%s file.pcap\n", argv[0]);
        return -1;
    }

    pc = pcap_open_offline(argv[1], errbuf);
    if (!pc) {
        printf("Error opening file %s: %s\n", argv[1], errbuf);
        return -1;
    } 

    struct st_stats stats;
    int r;
    memset(&stats, 0, sizeof(stats));
    
    while ((r = pcap_next_ex(pc, &pkt_hdr, &pkt_data)==1)) {
        process_packet(pkt_hdr, pkt_data, &stats);
    }
    print_results(&stats);
    return 0;
}
