#include "packet_capture/packet.h"

static void    on_tcp(t_packet *data)
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

#include "pool/pool.h" // TODO: 1 remove it
void packet_handler(uint8_t *user_data, const struct pcap_pkthdr *pkthdr, const uint8_t *packet)
{
    (void)pkthdr;
    t_pcap_data_wraper  *wraper = (t_pcap_data_wraper*)user_data;
    t_task_state        *state = wraper->user_data; // TODO: remove it (cf 1)
    t_nmap_data         *nd = state->user_data;

    int count = queue_count(nd->queue.in);
    if (count == 0) {
        pcap_breakloop(wraper->handle);
        return ;
    }
    printf("yoo %d\n", count);
    queue_delete_front(nd->queue.in, free);

    t_packet  data = new_packet((void*)nd, packet);

    // if (data.eth.type != ETHERTYPE_IP) return;
    switch (data.ip.header->protocol)
    {
        case IPPROTO_TCP:   // TCP Response Handling
            return (on_tcp(&data));
        case IPPROTO_UDP:   // UDP Response Handling
            return (on_udp(&data));
        case IPPROTO_ICMP:  // ICMP Response Handling (for UDP and filtered ports)
            return (on_icmp(&data));
        default: return;
    }
}