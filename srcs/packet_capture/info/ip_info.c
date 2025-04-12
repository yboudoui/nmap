#include "packet_capture/info.h"

t_ip_info   build_ip_info(const uint8_t *raw_packet, t_eth_info eth_info)
{
    (void)raw_packet;
    t_ip_info   info = {0};

    info.header_ptr = eth_info.header_ptr + eth_info.header_len;
    info.header = (struct iphdr *)(info.header_ptr);
    info.header_len = info.header->ihl * 4;
    return (info);
}