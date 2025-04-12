#include "packet_capture/header.h"

/*
How it Works:

    Sends a SYN packet (like the beginning of a TCP handshake).
    If the port is open, the target responds with SYN-ACK.
    Instead of completing the handshake, Nmap sends an RST (Reset) packet to avoid detection.
    If the port is closed, the target sends an RST.
    If filtered, there’s no response or an ICMP unreachable message.
*/
uint32_t syn_packet(uint8_t *packet_buf, t_req req)
{
    struct iphdr ip_header = build_ip_header(packet_buf, req.src.ip, req.dst.ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(req.dst.port, req.src.ip, req.dst.ip, SYN_FLAG);
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}