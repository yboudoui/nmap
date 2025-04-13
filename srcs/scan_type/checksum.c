#include "packet_capture/checksum.h"

uint16_t ip_checksum(uint8_t *buf, int nwords)
{
    uint64_t sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t tcp_checksum(uint8_t *ptr, int nbytes, uint64_t src_addr, uint64_t dest_addr)
{
    uint64_t sum;
    uint16_t oddbyte;
    uint16_t answer;

    // Pseudo header
    struct pseudo_header {
        unsigned int source_address;
        unsigned int dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } pheader;

    pheader.source_address = src_addr;
    pheader.dest_address = dest_addr;
    pheader.placeholder = 0;
    pheader.protocol = IPPROTO_TCP;
    pheader.tcp_length = htons(nbytes);

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
