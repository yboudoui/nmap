#include "packet_capture/info.h"

t_eth_info  build_eth_info(const uint8_t *raw_packet)
{
    t_eth_info   info = {0};

    info.header_ptr = raw_packet;
    info.header = (struct ether_header *)(info.header_ptr);
    info.header_len = sizeof(struct ether_header);
    info.type = ntohs(info.header->ether_type);
    return (info);
}