#include "packet_capture/packet.h"

void    on_ack(t_packet *data, t_tcp_info *info)
{
    write(1, "ACK: ", 4);

    if (info->header->rst) {
        write(1, "UNFILTERED\n", 11);

        printf("[ACK Scan] Port %d is UNFILTERED (Received RST)\n", info->port.src);
        save_result(data, NULL);
        return ;
    }
    write(1, "FILTERED\n", 9);
    write(1, "\n", 1);
}
