#include "packet/packet.h"
#include "nmap_data.h"

void on_udp(t_packet_info *data)
{
    uint16_t src_port, dst_port;
    src_port = ntohs(data->udp.header->source);
    dst_port = ntohs(data->udp.header->dest);

    // if (is_our_scan_response(dst_port) == false)
    // {
    //     return;
    // }
    printf("[UDP Scan] Port %d is OPEN (Received UDP response)\n", src_port);
    nmap_update(data->user_data, data /* the data */);
}