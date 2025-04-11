#include "packet_capture/info.h"

t_icmp_info build_icmp_info(const unsigned char *raw_packet, t_ip_info ip_info)
{
    (void)raw_packet;
    t_icmp_info  info = {0};

    info.header_ptr = ip_info.header_ptr + ip_info.header_len;
    info.header = (struct icmphdr *)(info.header_ptr);
    return (info);
}