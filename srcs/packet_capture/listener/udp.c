#include "packet_capture/packet.h"

void on_udp(t_packet *data)
{
    uint16_t src_port, dst_port;

    t_udp_info info = build_udp_info(data->raw_packet, data->ip);
    src_port = ntohs(info.header->source);
    dst_port = ntohs(info.header->dest);

    // if (is_our_scan_response(dst_port) == false)
    // {
    //     return;
    // }
    printf("[UDP Scan] Port %d is OPEN (Received UDP response)\n", src_port);
    save_result(data, NULL);
}