// #include <stdio.h>
// #include <unistd.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>

#include <string.h>
#include "packet/builder.h"

/*
How it Works:

    Sends a TCP packet with the ACK flag set (without a prior SYN).
    If the response is RST, the port is unfiltered (reachable but not necessarily open).
    If there is no response, the port is filtered (blocked by a firewall).
*/
uint32_t ack_packet(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t port_dst)
{
    struct iphdr ip_header = build_ip_header(src_ip, dst_ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(port_dst, src_ip, dst_ip, ACK_FLAG);

    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}

/*
How it Works:

    Sends a TCP packet with only the FIN flag set.
    If the port is closed, the target responds with RST.
    If the port is open, there is no response.
    If filtered, there’s no response or an ICMP unreachable message.
*/
uint32_t fin_packet(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t port_dst)
{
    struct iphdr ip_header = build_ip_header(src_ip, dst_ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(port_dst, src_ip, dst_ip, FIN_FLAG);
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}

/*
How it Works:

    Sends a TCP packet with no flags set (i.e., an empty header).
    If the port is open, there is no response (depends on OS).
    If the port is closed, it sends an RST.
    If filtered, there’s no response or an ICMP unreachable message.
*/
uint32_t null_packet(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t port_dst)
{
    struct iphdr ip_header = build_ip_header(src_ip, dst_ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(port_dst, src_ip, dst_ip, 0);
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}

/*
How it Works:

    Sends a SYN packet (like the beginning of a TCP handshake).
    If the port is open, the target responds with SYN-ACK.
    Instead of completing the handshake, Nmap sends an RST (Reset) packet to avoid detection.
    If the port is closed, the target sends an RST.
    If filtered, there’s no response or an ICMP unreachable message.
*/
uint32_t syn_packet(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t port_dst)
{
    struct iphdr ip_header = build_ip_header(src_ip, dst_ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(port_dst, src_ip, dst_ip, SYN_FLAG);
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}

/*
How it Works:

    Sends a UDP packet to each target port.
    If the port is open, there is no response or a specific UDP response.
    If the port is closed, an ICMP Port Unreachable message is received.
    If filtered, no response or ICMP unreachable errors may be received.
*/
uint32_t udp_packet(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t port_dst)
{
    struct iphdr ip_header = build_ip_header(src_ip, dst_ip, IPPROTO_UDP);
    
    // Build UDP header
    struct udphdr udph = {0};
    udph.source = htons(rand() % 65535);
    udph.dest = htons(port_dst);
    udph.len = htons(sizeof(udph));
    udph.check = 0; // Optional for IPv4
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &udph, sizeof(udph));
    return (ip_header.tot_len);
}

/*
How it Works:

    Sends a TCP packet with FIN, URG, and PSH flags set (XMAS tree pattern).
    If the port is closed, the target responds with RST.
    If the port is open, there is no response.
    If filtered, there’s no response or an ICMP unreachable message.
*/
uint32_t xmas_packet(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t port_dst)
{
    struct iphdr ip_header = build_ip_header(src_ip, dst_ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(port_dst, src_ip, dst_ip, XMAX_FLAGS);
    
    memcpy(packet_buf, &ip_header, sizeof(struct iphdr));
    memcpy(packet_buf + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    return (ip_header.tot_len);
}

#include "scan_type/flags.h"

typedef uint32_t (*t_fp_packet_builder)(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t dst_port);

void    build_packet(t_buffer *buffer, t_task task, in_addr_t src_ip)
{
    t_fp_packet_builder builder;

    switch (task.scan_flag) {
    case SCAN_SYN:  builder = syn_packet;   break;
    case SCAN_NULL: builder = null_packet;  break;
    case SCAN_ACK:  builder = ack_packet;   break;
    case SCAN_FIN:  builder = fin_packet;   break;
    case SCAN_XMAS: builder = xmas_packet;  break;
    case SCAN_UDP:  builder = udp_packet;   break;
    default:        builder = NULL;         break;
    }
    if(builder) {
        buffer->count = builder(buffer->data, src_ip, task.ip, task.port);
    }
}