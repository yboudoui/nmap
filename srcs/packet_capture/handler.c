#include "packet/packet.h"

static void packet_dispatch(t_packet_info *packet_info)
{
    switch (packet_info->ip.header->protocol) {
        case IPPROTO_TCP: {
            switch (packet_info->tcp.scan_type) {
            case SCAN_SYN:  return (on_syn(packet_info));
            case SCAN_NULL: return (on_null(packet_info));
            case SCAN_ACK:  return (on_ack(packet_info));
            case SCAN_FIN:  return (on_fin(packet_info));
            case SCAN_XMAS: return (on_xmas(packet_info));
            default:        return;
            }
        }   
        case IPPROTO_UDP: {
            return (on_udp(packet_info));
        }
        case IPPROTO_ICMP: {
            switch (packet_info->icmp.header->type) {
                case ICMP_DEST_UNREACH:     return (icmp_on_unreachable(packet_info));
                case ICMP_TIME_EXCEEDED:    return (icmp_on_timeout(packet_info));
            }
        }
        default:            return;
    }
}




#include <net/ethernet.h>
#include "nmap_data.h"
#include "pool/pool.h" // TODO: 1 remove it

void packet_handler(uint8_t *user_data, const struct pcap_pkthdr *pkthdr, const uint8_t *packet)
{
    (void)pkthdr;
    t_pcap_data_wraper  *wraper = (t_pcap_data_wraper*)user_data;
    t_task_state        *state = wraper->user_data; // TODO: remove it (cf 1)
    t_nmap_data         *nd = state->user_data;

    if (nmap_is_input_empty(nd)) {
        pcap_breakloop(wraper->handle);
        return ;
    }
    t_packet_info  data = new_packet((void*)nd, packet);
    if (data.eth.type != ETHERTYPE_IP) {
        return;
    }

    if (data.ip.ip->ip_src.s_addr == wraper->device_addr.s_addr) {
        if (nmap_have_ip(nd, &data.ip.ip->ip_dst.s_addr) == true) {
            printf("Sent %s\n\n", inet_ntoa(data.ip.ip->ip_dst));
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

    if (nmap_have_ip(nd, &data.ip.ip->ip_src.s_addr) == false) {
        return;
    }
    packet_dispatch(&data);
}