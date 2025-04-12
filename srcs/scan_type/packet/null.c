#include "packet_capture/header.h"

/*
How it Works:

    Sends a TCP packet with no flags set (i.e., an empty header).
    If the port is open, there is no response (depends on OS).
    If the port is closed, it sends an RST.
    If filtered, there’s no response or an ICMP unreachable message.
*/
uint32_t null_packet(uint8_t *packet_buf, t_req req)
{
    struct iphdr ip_header = build_ip_header(packet_buf, req.src.ip, req.dst.ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(req.dst.port, req.src.ip, req.dst.ip, 0);
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}