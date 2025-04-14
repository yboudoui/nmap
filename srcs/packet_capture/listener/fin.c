#include "packet/packet.h"
#include "nmap_data.h"

void    on_fin(t_packet_info *data)
{
    write(1, "FIN\n", 4);

    // FIN Scan Response
    if (data->tcp.header->rst) { //SCAN_FIN
        printf("[FIN Scan] Port %d is CLOSED (Received RST)\n", data->tcp.port.src);
        nmap_update(data->user_data, data /* the data */);
    }
}