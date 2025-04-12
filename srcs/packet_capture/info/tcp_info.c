#include "packet_capture/info.h"

t_tcp_info  build_tcp_info(const uint8_t *raw_packet, t_ip_info ip_info)
{
    (void)raw_packet;
    t_tcp_info  info = {0};

    info.header_ptr = ip_info.header_ptr + ip_info.header_len;
    info.header = (struct tcphdr *)(info.header_ptr);
    info.port.src = ntohs(info.header->source);
    info.port.dst = ntohs(info.header->dest);

    u_int8_t flags = info.header->th_flags;
    if (flags == 0) {
        info.scan_type = SCAN_NULL;
    } 
    else if (flags & TH_SYN && !(flags & TH_ACK)) {
        info.scan_type = SCAN_SYN;
    }
    else if (flags & TH_FIN && flags & TH_URG && flags & TH_PUSH) {
        info.scan_type = SCAN_XMAS;
    }
    else if (flags & TH_FIN && !(flags & TH_ACK)) {
        info.scan_type = SCAN_FIN;
    }
    else if (flags & TH_ACK && !(flags & TH_SYN)) {
        info.scan_type = SCAN_ACK;
    }
    return (info);
}