#ifndef HEADER_H
#define HEADER_H

#include "checksum.h"
#include "scan_type.h"

struct iphdr build_ip_header(in_addr_t src_ip, in_addr_t dst_ip, uint8_t protocol);
struct tcphdr build_tcp_header(uint16_t dst_port, uint32_t saddr, uint32_t daddr, uint8_t flags);

#endif // HEADER_H