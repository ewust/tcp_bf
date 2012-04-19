#include "tcp_spoof.h"

int raw_sock;

void init_sock()
{
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock == -1) {
        perror("couldn't open socket");
        exit(1);
    }
    return;
}

uint16_t csum(uint16_t *buf, int nwords, uint32_t init_sum)
{
    uint32_t sum;

    for (sum=init_sum; nwords>0; nwords--) {
        sum += ntohs(*buf++);
    }
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t tcp_csum(struct iphdr *ip_hdr)
{
    uint32_t sum = 0;
    int tcp_size = ntohs(ip_hdr->tot_len) - sizeof(struct iphdr);

    sum += ntohs(ip_hdr->saddr&0xffff) + ntohs((ip_hdr->saddr >> 16)&0xffff);
    sum += ntohs(ip_hdr->daddr&0xffff) + ntohs((ip_hdr->daddr >> 16)&0xffff);
    sum += 0x06;    // TCP protocol #define somewhere(?), plz
    sum += tcp_size;

    if (tcp_size%2) { //odd tcp_size,
        sum += (((char*)IP_TCP(ip_hdr))[tcp_size-1] << 8);
    }

    return csum((uint16_t*)IP_TCP(ip_hdr), tcp_size/2, sum);
}


//warning: unlikely integer overflow on tot_len
//maybe place reasonable constraint on len (<= 10000, jumbo frames?)
int tcp_forge_xmit(struct pkt_data *pkt, char *payload, int len)
{
    int tcp_len = sizeof(struct tcphdr);
    int tot_len = len + tcp_len + sizeof(struct iphdr);
    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    char *data;
    struct sockaddr_in sin;
    int res; 
    static int id=1234;
    
    //set up sin destination    
    sin.sin_family = AF_INET;
    sin.sin_port = (pkt->dport);
    sin.sin_addr.s_addr = (pkt->daddr);
   
    
    ip_hdr = malloc(tot_len);
    if (ip_hdr == NULL) {
        return 1;
    }

    //zero-fill headers
    memset(ip_hdr, 0, sizeof(struct iphdr) + tcp_len);

    //no ip options
    tcp_hdr = (struct tcphdr*)(ip_hdr+1);
    data = (char *)(tcp_hdr) + tcp_len;
     
    //copy payload data
    if (payload != NULL)
        memcpy(data, payload, len);

    //fill in ip header
    ip_hdr->ihl         = sizeof(struct iphdr) >> 2;
    ip_hdr->version     = 4;
    ip_hdr->tot_len     = htons(tot_len);
    ip_hdr->frag_off    = htons(0x4000); //don't fragment
    ip_hdr->ttl         = 64; 
    ip_hdr->id          = htons(pkt->id); 
    ip_hdr->protocol    = IPPROTO_TCP;
    ip_hdr->saddr       = (pkt->saddr);
    ip_hdr->daddr       = (pkt->daddr);

    //fill in tcp header
    tcp_hdr->th_sport   = (pkt->sport);
    tcp_hdr->th_dport   = (pkt->dport);
    tcp_hdr->th_seq     = htonl(pkt->seq);
    tcp_hdr->th_ack     = htonl(pkt->ack);
    tcp_hdr->th_off     = tcp_len >> 2;
    tcp_hdr->th_flags   = pkt->flags;
    tcp_hdr->th_win     = htons(pkt->window);

    //if (option_ts)
    //    telex_fill_ts(&fl->tcp, tcp_hdr);

    tcp_hdr->th_sum = htons(tcp_csum(ip_hdr));
    ip_hdr->check = htons(csum((uint16_t*)ip_hdr, sizeof(struct iphdr)/2, 0));

    res = sendto(raw_sock, ip_hdr, tot_len, 0, (struct sockaddr*)&sin, sizeof(sin));

    free(ip_hdr);
    return (res != tot_len);
}
