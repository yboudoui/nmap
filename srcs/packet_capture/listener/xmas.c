#include "packet/packet.h"
#include "nmap_data.h"

void    on_xmas(t_packet_info *data)
{
    write(1, "XMAS\n", 5);

    // XMAS Scan Response
    if (data->tcp.header->rst) { // SCAN_XMAS
        printf("[XMAS Scan] Port %d is CLOSED (Received RST)\n", data->tcp.port.src);
        nmap_update(data->user_data, data /* the data */);
    }
}

