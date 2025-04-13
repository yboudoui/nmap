#include "packet_capture/packet.h"

void    on_null(t_packet *data, t_tcp_info *info)
{
    write(1, "NULL\n", 5);

    // NULL Scan Response
    if (info->header->rst) { //SCAN_NULL
        printf("[NULL Scan] Port %d is CLOSED (Received RST)\n", info->port.src);
        save_result(data, NULL);
    }
}
