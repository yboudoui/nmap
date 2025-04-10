#include "packet/checksum.h"

uint16_t ip_checksum(uint16_t *buf, int nwords)
{
    uint64_t sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}