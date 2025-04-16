#include "packet/builder.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <stdlib.h>
#include <string.h>

static uint16_t ip_checksum(uint16_t *buf, int len)
{
    uint64_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    // Add left-over byte, if any
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    // Fold 32-bit sum into 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t tcp_checksum(uint8_t *ptr, int nbytes, in_addr_t src_addr, in_addr_t dst_addr)
{
    uint64_t sum;
    uint16_t oddbyte;
    uint16_t answer;

    struct pseudo_header {
        in_addr_t   src_addr;
        in_addr_t   dst_addr;
        uint8_t     zero;
        uint8_t     protocol;
        uint16_t    tcp_len;
    } __attribute__((packed))
    pheader = {
        .src_addr   = src_addr,
        .dst_addr   = dst_addr,
        .protocol   = IPPROTO_TCP,
        .tcp_len    = htons(nbytes),
    };

    sum = 0;
    uint16_t *psheader = (uint16_t*)&pheader;
    for (int i = 0; i < 6; i++) {
        sum += *psheader++;
    }

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((uint8_t*)&oddbyte) = *(uint8_t*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (uint16_t)~sum;

    return answer;
}

#define DFT_TTL 64
static struct iphdr build_ip_header(in_addr_t src_ip, in_addr_t dst_ip, uint8_t protocol)
{
    struct iphdr ip_header = {
        .saddr = src_ip,       // Source IP
        .daddr = dst_ip,       // Destination IP

        .frag_off = 0,         // No fragmentation

        .check = 0,            // Checksum (kernel calculates this)
        .id = 0,               // Packet ID (kernel assigns if 0)
        .tot_len = 0,          // Total length (kernel fills this)

        .ihl = 5,              // Header length (5 * 32-bit words = 20 bytes)
        .tos = 0,              // Type of service (default)
        .ttl = DFT_TTL,        // Time-to-live (defined as 64)
        .protocol = protocol,  // Transport protocol
        .version = IPVERSION,  // IPv4 (likely defined as 4)
    };
    return (ip_header);
}

static void build_tcp_packet(t_packet_builder_args *args)
{
    struct iphdr    ip_header = build_ip_header(args->src_ip, args->dst_ip, IPPROTO_TCP);

    struct tcphdr tcp_header = {
        .source     = htons(rand() % 65535),    // Source port (random)
        .dest       = htons(args->dst_port),    // Destination port
        // .seq        = htonl(1),            // Random sequence number

        .ack_seq    = htonl(rand()),                 // ACK sequence number
        .doff       = 5,                        // Data offset (5 * 4 = 20 bytes)
        .window     = htons(1024),              // Maximum allowed window size

        .urg_ptr    = 0,                        // TODO: What is it?

        // Set flags according to scan type
        .fin = IS(args->scan_type, FIN_FLAG),
        .syn = IS(args->scan_type, SYN_FLAG),
        .rst = IS(args->scan_type, RST_FLAG),
        .psh = IS(args->scan_type, PSH_FLAG),
        .ack = IS(args->scan_type, ACK_FLAG),
        .urg = IS(args->scan_type, URG_FLAG),
    };

    args->buffer.count = sizeof(struct iphdr) + sizeof(struct tcphdr);

    ip_header.tot_len = htons(args->buffer.count);
    ip_header.check = ip_checksum((uint16_t*)&ip_header, sizeof(struct iphdr));

    tcp_header.check = tcp_checksum(
        (uint8_t *)&tcp_header,
        sizeof(struct tcphdr), 
        args->src_ip, args->dst_ip);

    memcpy(args->buffer.data, &ip_header, sizeof(struct iphdr));
    memcpy(args->buffer.data + sizeof(struct iphdr), &tcp_header, sizeof(struct iphdr));
}

static void build_udp_packet(t_packet_builder_args *args)
{
    struct iphdr    ip_header = build_ip_header(args->src_ip, args->dst_ip, IPPROTO_UDP);
    struct udphdr   udp_header = {
        .source = htons(rand() % 65535),
        .dest   = htons(args->dst_port),
        .len    = htons(sizeof(struct udphdr)),
        .check  = 0, // Optional for IPv4
    };

    args->buffer.count = sizeof(struct iphdr) + sizeof(struct udphdr);

    ip_header.tot_len = htons(args->buffer.count);
    ip_header.check = ip_checksum((uint16_t*)&ip_header, sizeof(struct iphdr));

    memcpy(args->buffer.data, &ip_header, sizeof(struct iphdr));
    memcpy(args->buffer.data + sizeof(struct iphdr), &udp_header, sizeof(struct udphdr));
}


void    build_packet(t_packet_builder_args *args)
{
    switch (SUPPORTED_PROTOCOL & args->scan_type) {
        case PROTOCOL_TCP: return (build_tcp_packet(args));
        case PROTOCOL_UDP: return (build_udp_packet(args));
    }
}