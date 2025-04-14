#include "packet/builder.h"

#define DFT_TTL 64
struct iphdr build_ip_header(in_addr_t src_ip, in_addr_t dst_ip, uint8_t protocol)
{
    struct iphdr ip_header = {0};

    ip_header.saddr = src_ip;       // Source IP
    ip_header.daddr = dst_ip;       // Destination IP

    ip_header.frag_off = 0;         // No fragmentation

    ip_header.check = 0;            // Checksum (kernel calculates this)
    ip_header.id = 0;               // Packet ID (kernel assigns if 0)
    ip_header.tot_len = 0;          // Total length (kernel fills this)

    ip_header.ihl = 5;              // Header length (5 * 32-bit words = 20 bytes)
    ip_header.tos = 0;              // Type of service (default)
    ip_header.ttl = DFT_TTL;        // Time-to-live (defined as 64)
    ip_header.protocol = protocol;  // Transport protocol
    ip_header.version = IPVERSION;  // IPv4 (likely defined as 4)
    
    return (ip_header);
}

struct tcphdr build_tcp_header(uint16_t dst_port, in_addr_t saddr, in_addr_t daddr, uint8_t flags)
{
    struct tcphdr   header = {0};

    header.source = htons(12345); // Source port (random)
    // tcp_header.source = htons(rand() % 65535); // Random source port TODO

    header.dest = htons(dst_port);    // Destination port
    header.seq = htonl(1105024978); // Random sequence number
    // tcp_header.seq = htonl(rand()); TODO
    header.ack_seq = 0;           // ACK sequence number
    header.doff = 5;              // Data offset (5 * 4 = 20 bytes)
    header.window = htons(5840);  // Maximum allowed window size

    header.urg_ptr = 0; // TODO: What is it?

    // Set flags according to scan type
    header.fin = (flags & FIN_FLAG) ? 1 : 0;
    header.syn = (flags & SYN_FLAG) ? 1 : 0;
    header.rst = (flags & RST_FLAG) ? 1 : 0;
    header.psh = (flags & PSH_FLAG) ? 1 : 0;
    header.ack = (flags & ACK_FLAG) ? 1 : 0;
    header.urg = (flags & URG_FLAG) ? 1 : 0;

    header.check = tcp_checksum(
        (uint8_t *)&header,
        sizeof(struct tcphdr), 
        saddr, daddr);
    return (header);
}