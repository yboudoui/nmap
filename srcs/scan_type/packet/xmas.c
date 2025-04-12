#include "packet_capture/header.h"

/*
How it Works:

    Sends a TCP packet with FIN, URG, and PSH flags set (XMAS tree pattern).
    If the port is closed, the target responds with RST.
    If the port is open, there is no response.
    If filtered, there’s no response or an ICMP unreachable message.
*/

#define XMAX_FLAGS FIN_FLAG | PSH_FLAG | URG_FLAG
uint32_t xmas_packet(uint8_t *packet_buf, t_req req)
{
    struct iphdr ip_header = build_ip_header(packet_buf, req.src.ip, req.dst.ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(req.dst.port, req.src.ip, req.dst.ip, XMAX_FLAGS);
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}