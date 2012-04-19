#ifndef TCP_SPOOF_H
#define TCP_SPOOF_H

#ifdef __cplusplus
extern "C" {
#endif


#if defined(__linux__)
#define _BSD_SOURCE
#endif
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h> //broken
#include <netinet/tcp.h>
#include <sys/time.h>


#define IP_TCP(ip_hdr)      (struct tcphdr*)(((char *)ip_hdr) + (4 * ip_hdr->ihl))
#define TCP_DATA(tcp_hdr)   (((char *)tcp_hdr) + (4 * tcp_hdr->doff))




//packet format
struct tcp_option_ts {
    uint16_t    nops;       // 0x0101
    uint8_t     op_type;    // 0x08
    uint8_t     op_len;     // 0x0a
    uint32_t    tsval;
    int32_t    tsecr;
} __attribute__((__packed__));

struct pkt_data {
    uint32_t daddr;
    uint32_t saddr;
    uint16_t dport;
    uint16_t sport;
    
    uint16_t id;
    uint8_t ttl;
    
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    uint8_t flags;     

};

void init_sock();
int tcp_forge_xmit(struct pkt_data *pkt, char *payload, int len);

extern int raw_sock;


#ifdef __cplusplus
}
#endif
#endif

