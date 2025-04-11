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

struct tcphdr build_tcp_header(uint16_t dst_port, uint32_t saddr, uint32_t daddr, uint8_t flags)
{
    struct tcphdr   header = {0};

    header.source = htons(12345); // Source port (random)
    // tcph.source = htons(rand() % 65535); // Random source port TODO

    header.dest = htons(dst_port);    // Destination port
    header.seq = htonl(1105024978); // Random sequence number
    // tcph.seq = htonl(rand()); TODO
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
        (unsigned short *)&header,
        sizeof(struct tcphdr), 
        saddr, daddr);
    return (header);
}