#include "packet/packet.h"
#include "nmap_data.h"

void    on_null(t_packet_info *data)
{
    write(1, "NULL\n", 5);

    // NULL Scan Response
    if (data->tcp.header->rst) { //SCAN_NULL
        printf("[NULL Scan] Port %d is CLOSED (Received RST)\n", data->tcp.port.src);
        nmap_update(data->user_data, data /* the data */);
    }
}
