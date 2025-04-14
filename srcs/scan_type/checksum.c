#include "packet/builder.h"
/*
uint16_t ip_checksum(uint16_t *buf, int len)
{
    uint32_t sum = 0;

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
*/

uint16_t ip_checksum(uint8_t *buf, int nwords)
{
    uint64_t sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

struct pseudo_header {
    in_addr_t    src_addr;
    in_addr_t    dst_addr;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    tcp_len;
} __attribute__((packed));

uint16_t tcp_checksum(uint8_t *ptr, int nbytes, in_addr_t src_addr, in_addr_t dst_addr)
{
    uint64_t sum;
    uint16_t oddbyte;
    uint16_t answer;

    struct pseudo_header pheader = {
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
