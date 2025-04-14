#include "packet/packet.h"
#include "nmap_data.h"

void    on_syn(t_packet_info *data)
{
    write(1, "SYN\n", 4);

    // SYN Scan Response
    if (data->tcp.header->syn && data->tcp.header->ack) {
        printf("[SYN Scan] Port %d is OPEN (Received SYN-ACK)\n", data->tcp.port.src);
        nmap_update(data->user_data, data /* the data */);
    }
}
