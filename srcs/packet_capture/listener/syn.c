#include "packet_capture/packet.h"

void    on_syn(t_packet *data, t_tcp_info *info)
{
    write(1, "SYN\n", 4);

    // SYN Scan Response
    if (info->header->syn && info->header->ack) {
        printf("[SYN Scan] Port %d is OPEN (Received SYN-ACK)\n", info->port.src);
        save_result(data, NULL);
    }
}
