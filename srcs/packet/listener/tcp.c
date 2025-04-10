#include "packet.h"

void    on_syn(t_packet *data, t_tcp_info *info)
{
    // SYN Scan Response
    if (info->header->syn && info->header->ack) {
        printf("[SYN Scan] Port %d is OPEN (Received SYN-ACK)\n", info->port.src);
        save_result(data, NULL);
    }
}

void    on_null(t_packet *data, t_tcp_info *info)
{
    // NULL Scan Response
    if (info->header->rst) { //SCAN_NULL
        printf("[NULL Scan] Port %d is CLOSED (Received RST)\n", info->port.src);
        save_result(data, NULL);
    }
}

void    on_ack(t_packet *data, t_tcp_info *info)
{
    // ACK Scan Response
    if (info->header->rst) { // SCAN_ACK
        printf("[ACK Scan] Port %d is UNFILTERED (Received RST)\n", info->port.src);
        save_result(data, NULL);
    }
}

void    on_fin(t_packet *data, t_tcp_info *info)
{
    // FIN Scan Response
    if (info->header->rst) { //SCAN_FIN
        printf("[FIN Scan] Port %d is CLOSED (Received RST)\n", info->port.src);
        save_result(data, NULL);
    }
}

void    on_xmas(t_packet *data, t_tcp_info *info)
{
    // XMAS Scan Response
    if (info->header->rst) { // SCAN_XMAS
        printf("[XMAS Scan] Port %d is CLOSED (Received RST)\n", info->port.src);
        save_result(data, NULL);
    }
}

void    on_tcp(t_packet *data)
{
    t_tcp_info info = build_tcp_info(data->raw_packet, data->ip);

    // TODO: implement is_our_scan_response
    // Check if this is a response to our scan
    // if (is_our_scan_response(tcp_info.port.dst) == false)
    // {
    //     return;
    // }
    switch (info.scan_type)
    {
    case SCAN_SYN:
        return (on_syn(data, &info));
    case SCAN_NULL:
        return (on_null(data, &info));
    case SCAN_ACK:
        return (on_ack(data, &info));
    case SCAN_FIN:
        return (on_fin(data, &info));
    case SCAN_XMAS:
        return (on_xmas(data, &info));
    default:
        return;
    }
}