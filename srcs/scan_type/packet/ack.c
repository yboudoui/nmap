#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "packet_capture/header.h"

/*
How it Works:

    Sends a TCP packet with the ACK flag set (without a prior SYN).
    If the response is RST, the port is unfiltered (reachable but not necessarily open).
    If there is no response, the port is filtered (blocked by a firewall).
*/

uint32_t ack_packet(uint8_t *packet_buf, t_req req)
{
    struct iphdr ip_header = build_ip_header(packet_buf, req.src.ip, req.dst.ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(req.dst.port, req.src.ip, req.dst.ip, ACK_FLAG);

    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}