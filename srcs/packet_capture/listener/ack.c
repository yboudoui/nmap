#include "packet/packet.h"
#include "nmap_data.h"

void    on_ack(t_packet_info *data)
{
    write(1, "ACK: ", 4);

    if (data->tcp.header->rst) {
        write(1, "UNFILTERED\n", 11);

        printf("[ACK Scan] Port %d is UNFILTERED (Received RST)\n", data->tcp.port.src);
        nmap_update(data->user_data, data /* the data */);
        return ;
    }
    write(1, "FILTERED\n", 9);
    write(1, "\n", 1);
}
