#include "packet_capture/packet.h"

void    on_fin(t_packet *data, t_tcp_info *info)
{
    write(1, "FIN\n", 4);

    // FIN Scan Response
    if (info->header->rst) { //SCAN_FIN
        printf("[FIN Scan] Port %d is CLOSED (Received RST)\n", info->port.src);
        save_result(data, NULL);
    }
}