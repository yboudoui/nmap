#include "packet_capture/packet.h"

void    on_ack(t_packet *data, t_tcp_info *info)
{
    // ACK Scan Response
    if (info->header->rst) { // SCAN_ACK
        printf("[ACK Scan] Port %d is UNFILTERED (Received RST)\n", info->port.src);
        save_result(data, NULL);
    }
}
