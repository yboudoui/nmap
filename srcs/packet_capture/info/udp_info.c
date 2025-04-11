#include "packet_capture/info.h"

t_udp_info  build_udp_info(const unsigned char *raw_packet, t_ip_info ip_info)
{
    (void)raw_packet;
    t_udp_info  info = {0};

    info.header_ptr = ip_info.header_ptr + ip_info.header_len;
    info.header = (struct udphdr *)(info.header_ptr);
    return (info);
}