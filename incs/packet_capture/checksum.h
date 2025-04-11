#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

uint16_t ip_checksum(uint16_t *buf, int nwords);
uint16_t tcp_checksum(uint16_t *ptr, int nbytes, uint64_t src_addr, uint64_t dest_addr);

#endif // CHECKSUM_H
