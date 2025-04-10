#include "packet/header.h"

struct iphdr build_ip_header(unsigned short *datagram, uint32_t saddr, uint32_t daddr, uint8_t protocol)
{
    struct iphdr ip_header = {0};

    ip_header.ihl = 5;
    ip_header.version = 4;
    ip_header.tos = 0;
    ip_header.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip_header.id = htons(54321); // ID of this packet
    ip_header.frag_off = 0;
    ip_header.ttl = 64;
    ip_header.protocol = protocol;
    ip_header.saddr = saddr;
    ip_header.daddr = daddr;
    
    // IP checksum
    ip_header.check = tcp_checksum(
        datagram,
        ip_header.tot_len,
        0, 0);
    return (ip_header);
}