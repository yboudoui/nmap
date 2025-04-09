#include "packet.h"

struct udphdr *get_upd_header(t_data *data)
{
    return (struct udphdr *)(data->packet + 14 + data->iphdrlen);
}

void on_udp(t_data data)
{
    unsigned short src_port, dst_port;

    struct udphdr *udp_header = get_upd_header(&data);
    src_port = ntohs(udp_header->source);
    dst_port = ntohs(udp_header->dest);

    // if (is_our_scan_response(dst_port) == false)
    // {
    //     return;
    // }
    printf("[UDP Scan] Port %d is OPEN (Received UDP response)\n", src_port);

    queue_add(data.data, NULL);
    // add_port_result(src_port, 1, 'U');
}