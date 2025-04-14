#ifndef PACKET_BUILDER_H
#define PACKET_BUILDER_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

uint16_t        ip_checksum(uint8_t *buf, int nwords);
uint16_t        tcp_checksum(uint8_t *ptr, int nbytes, in_addr_t src_addr, in_addr_t dst_addr);

struct iphdr    build_ip_header(in_addr_t src_ip, in_addr_t dst_ip, uint8_t protocol);
struct tcphdr   build_tcp_header(uint16_t dst_port, in_addr_t saddr, in_addr_t daddr, uint8_t flags);

#include "pool/pool.h"
void    build_packet(t_buffer *buffer, t_task task, in_addr_t src_ip);

#endif // PACKET_BUILDER_H