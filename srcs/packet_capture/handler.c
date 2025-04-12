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

#include <net/ethernet.h>
#include "pool/pool.h" // TODO: 1 remove it

static int find_ip(void *incomming, void *t)
{
    struct in_addr  *src = t;
    t_task          *task = incomming;
    struct in_addr  dst = {
        .s_addr = task->dst.ip,
    };

    printf("f src: %s dst: %s\n", inet_ntoa(*src), inet_ntoa(dst));
    return (src->s_addr == dst.s_addr);
}

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
    t_packet  data = new_packet((void*)nd, packet);
    if (data.eth.type != ETHERTYPE_IP) {
        return;
    }
    // printf("IPv4 address: %s\n", inet_ntoa(wraper->device_addr)); // print the ip addr of the device
    // printf("Destination IP: %s\n", inet_ntoa(data.ip.ip->ip_dst));
    if (data.ip.ip->ip_dst.s_addr != wraper->device_addr.s_addr) {
        return;
    }
    t_node *found = queue_find_data(nd->queue.in, &data.ip.ip->ip_src, find_ip);
    // printf("yo %d %p %s\n", count, found, inet_ntoa(data.ip.ip->ip_src));
    if (!found) {
        return;
    }
    queue_remove_node(nd->queue.in, found);
    printf("Source IP: %s\n", inet_ntoa(data.ip.ip->ip_src));
    return;

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