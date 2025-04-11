#include "packet/header.h"

/*
How it Works:

    Sends a UDP packet to each target port.
    If the port is open, there is no response or a specific UDP response.
    If the port is closed, an ICMP Port Unreachable message is received.
    If filtered, no response or ICMP unreachable errors may be received.
*/
bool udp_packet(struct s_req req, struct s_raw_packet *raw_packet)
{
    if (!raw_packet) return false;
    
    uint16_t *datagram = calloc(sizeof(struct iphdr) + sizeof(struct udphdr), sizeof(char));
    if (!datagram) return false;
    
    // Build IP header with UDP protocol
    struct iphdr iph = build_ip_header(datagram, req.src.ip, req.dst.ip, IPPROTO_UDP);
    
    // Build UDP header
    struct udphdr udph = {0};
    udph.source = htons(rand() % 65535);
    udph.dest = htons(req.dst.port);
    udph.len = htons(sizeof(udph));
    udph.check = 0; // Optional for IPv4
    
    memcpy(datagram, &iph, sizeof(iph));
    memcpy(datagram + sizeof(iph), &udph, sizeof(udph));
    
    raw_packet->packet = datagram;
    raw_packet->packet_len = ntohs(iph.tot_len);
    return true;
}