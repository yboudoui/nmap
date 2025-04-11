#include "packet_capture/header.h"

/*
How it Works:

    Sends a UDP packet to each target port.
    If the port is open, there is no response or a specific UDP response.
    If the port is closed, an ICMP Port Unreachable message is received.
    If filtered, no response or ICMP unreachable errors may be received.
*/
uint32_t udp_packet(uint8_t *packet_buf, struct s_req req)
{
    struct iphdr ip_header = build_ip_header(packet_buf, req.src.ip, req.dst.ip, IPPROTO_UDP);
    
    // Build UDP header
    struct udphdr udph = {0};
    udph.source = htons(rand() % 65535);
    udph.dest = htons(req.dst.port);
    udph.len = htons(sizeof(udph));
    udph.check = 0; // Optional for IPv4
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &udph, sizeof(udph));
    return (ip_header.tot_len);
}