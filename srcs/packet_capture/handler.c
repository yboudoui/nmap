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

#include "utils/debug.h"
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
            print_packet_info(&data);
        }
    }

    WITH_DEBUG(0) {
        static size_t packet_count = 0;
        if (packet_count == 0) printf("\n");
        packet_count += 1;
        printf("\033[1A");  // Move cursor up one line
        printf("\033[K");   // Clear the line
        printf("[%zu] -> ", packet_count);
        print_packet_info(&data);
    }
    
    if (data.ip.ip->ip_dst.s_addr != wraper->device_addr.s_addr) {
        return;
    }



    WITH_DEBUG(0) {
        static size_t packet_count = 0;
        if (packet_count == 0) printf("\n");
        packet_count += 1;
        printf("\033[1A");  // Move cursor up one line
        printf("\033[K");   // Clear the line
        printf("[%zu] -> ", packet_count);
        print_packet_info(&data);
    }

    if (nmap_have_ip(nd, &data.ip.ip->ip_src.s_addr) == false) {
        return;
    }
    printf("received :");
    print_packet_info(&data);

    packet_dispatch(&data);
}



