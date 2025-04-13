#include "packet_capture/packet.h"
#include <net/ethernet.h>
#include "pool/pool.h" // TODO: 1 remove it

static int find_ip(void *incomming, void *t)
{
    struct in_addr  *src = t;
    t_task          *task = incomming;
    struct in_addr  dst = {
        .s_addr = task->ip,
    };
    #if 0
    printf("src: %s => %d\n", inet_ntoa(*src), src->s_addr);
    printf("dst: %s => %d\n", inet_ntoa(dst),  dst.s_addr);
    printf("=> %d\n",(src->s_addr == dst.s_addr));
    #endif
    return (!(src->s_addr == dst.s_addr));
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

    if (data.ip.ip->ip_src.s_addr == wraper->device_addr.s_addr) {
        t_node *found = queue_find_data(nd->queue.in, &data.ip.ip->ip_dst, find_ip);
        if (found) {
            printf("Sent %s %p\n\n", inet_ntoa(data.ip.ip->ip_dst), found);
            fflush(stdout);
        }
    }
    
    if (data.ip.ip->ip_dst.s_addr != wraper->device_addr.s_addr) {
        return;
    }

    #if 0
    static size_t packet_count = 0;
    packet_count += 1;
    printf("\033[1A"); // Move cursor up one line
    printf("\033[K");   // Clear the line
    printf("%s %ld\n", inet_ntoa(data.ip.ip->ip_src), packet_count);
    #endif

    t_node *found = queue_find_data(nd->queue.in, &data.ip.ip->ip_src, find_ip);
    if (!found) {
        return;
    }
    queue_remove_node(nd->queue.in, found);

    switch (data.ip.header->protocol) {
        case IPPROTO_TCP: {
            t_tcp_info info = build_tcp_info(data.raw_packet, data.ip);
            switch (info.scan_type) {
            case SCAN_SYN:  return (on_syn(&data, &info));
            case SCAN_NULL: return (on_null(&data, &info));
            case SCAN_ACK:  return (on_ack(&data, &info));
            case SCAN_FIN:  return (on_fin(&data, &info));
            case SCAN_XMAS: return (on_xmas(&data, &info));
            default:        return;
            }
        }   
        case IPPROTO_UDP:   return (on_udp(&data));
        case IPPROTO_ICMP:  return (on_icmp(&data));
        default:            return;
    }
}