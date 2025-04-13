#include "packet_capture/packet.h"

void    on_xmas(t_packet *data, t_tcp_info *info)
{
    write(1, "XMAS\n", 5);

    // XMAS Scan Response
    if (info->header->rst) { // SCAN_XMAS
        printf("[XMAS Scan] Port %d is CLOSED (Received RST)\n", info->port.src);
        save_result(data, NULL);
    }
}

