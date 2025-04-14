#include "packet/packet.h"
#include "nmap_data.h"

#include <netinet/tcp.h>

static struct tcphdr *tcp_header_from_ip_header(struct iphdr* ip_header)
{
    uint8_t   *data = (uint8_t*)ip_header;
    uint16_t orig_iphdrlen = ip_header->ihl*4;
    return (struct tcphdr *)(data + orig_iphdrlen);
}

static struct udphdr *udp_header_from_ip_header(struct iphdr* ip_header)
{
    uint8_t   *data = (uint8_t*)ip_header;
    uint16_t orig_iphdrlen = ip_header->ihl*4;
    return (struct udphdr *)(data + orig_iphdrlen);
}

// ICMP Port Unreachable (UDP closed or TCP filtered)
void icmp_on_unreachable(t_packet_info *data)
{
    uint16_t src_port = 0;
    // Get the original IP header from ICMP payload
    struct iphdr *orig_ip = (struct iphdr *)(data->icmp.header_ptr + 8);

    // UDP Port Unreachable
    if (orig_ip->protocol == IPPROTO_UDP && data->icmp.header->code == ICMP_PORT_UNREACH) {
        struct udphdr *orig_udp = udp_header_from_ip_header(orig_ip);
        src_port = ntohs(orig_udp->dest);
        printf("[UDP Scan] Port %d is CLOSED (ICMP Port Unreachable)\n", src_port);
        nmap_update(data->user_data, data /* the data */);
    }
    
    // TCP Filtered (no response to SYN is more common, but some firewalls send ICMP)
    else if (orig_ip->protocol == IPPROTO_TCP) { //SCAN_SYN
        struct tcphdr *orig_tcp = tcp_header_from_ip_header(orig_ip);
        src_port = ntohs(orig_tcp->dest);
        printf("[SYN Scan] Port %d is FILTERED (ICMP Admin Prohibited)\n", src_port);
        nmap_update(data->user_data, data /* the data */);
    }
}

// ICMP Time Exceeded (used by some firewalls)
void icmp_on_timeout(t_packet_info *data)
{
    struct iphdr *orig_ip = (struct iphdr *)(data->icmp.header_ptr + 8);

    if (orig_ip->protocol == IPPROTO_TCP)
    {
        return;
    }
    struct tcphdr *orig_tcp = tcp_header_from_ip_header(orig_ip);
    uint16_t src_port = ntohs(orig_tcp->dest);
    printf("[%s Scan] Port %d is FILTERED (ICMP Time Exceeded)\n",
        "cur" /*scan_type_to_str(current_scan_type)*/,
        src_port
    );
    nmap_update(data->user_data, data /* the data */);
}
