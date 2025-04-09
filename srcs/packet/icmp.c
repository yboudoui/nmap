#include "packet.h"
#include <netinet/tcp.h>

struct icmphdr *get_icmp_header(t_data *data)
{
    return (struct icmphdr *)(data->packet + 14 + data->iphdrlen);
}

static struct iphdr *get_ip_header(t_data *data)
{
    return (struct iphdr *)(data->packet + 14 + data->iphdrlen + 8);
}

static struct tcphdr *tcp_header_from_ip_header(struct iphdr* ip_header)
{
    unsigned char   *data = (unsigned char*)ip_header;
    unsigned short orig_iphdrlen = ip_header->ihl*4;
    return (struct tcphdr *)(data + orig_iphdrlen);
}

static struct udphdr *udp_header_from_ip_header(struct iphdr* ip_header)
{
    unsigned char   *data = (unsigned char*)ip_header;
    unsigned short orig_iphdrlen = ip_header->ihl*4;
    return (struct udphdr *)(data + orig_iphdrlen);
}

static void on_unreachable(struct icmphdr *icmp_header, t_data *data)
{
    unsigned short src_port = 0;

    // Get the original IP header from ICMP payload
    struct iphdr *orig_ip = get_ip_header(data);

    // UDP Port Unreachable
    if (orig_ip->protocol == IPPROTO_UDP && icmp_header->code == ICMP_PORT_UNREACH) {
        struct udphdr *orig_udp = udp_header_from_ip_header(orig_ip);
        src_port = ntohs(orig_udp->dest);
        printf("[UDP Scan] Port %d is CLOSED (ICMP Port Unreachable)\n", src_port);

        queue_add(data->data, NULL);
        // add_port_result(src_port, 0, 'U');
    }
    
    // TCP Filtered (no response to SYN is more common, but some firewalls send ICMP)
    else if (orig_ip->protocol == IPPROTO_TCP) { //SCAN_SYN
        struct tcphdr *orig_tcp = tcp_header_from_ip_header(orig_ip);
        src_port = ntohs(orig_tcp->dest);
        printf("[SYN Scan] Port %d is FILTERED (ICMP Admin Prohibited)\n", src_port);

        queue_add(data->data, NULL);
        // add_port_result(src_port, 2, 'T');
    }
}

static void on_timeout(struct icmphdr *icmp_header, t_data *data)
{
    struct iphdr *orig_ip = get_ip_header(data);
    unsigned short src_port = 0;

    if (orig_ip->protocol == IPPROTO_TCP) {
        struct tcphdr *orig_tcp = tcp_header_from_ip_header(orig_ip);
        src_port = ntohs(orig_tcp->dest);
        printf("[%s Scan] Port %d is FILTERED (ICMP Time Exceeded)\n",
            "cur" /*scan_type_to_str(current_scan_type)*/,
            src_port
        );

        queue_add(data->data, NULL);
        // add_port_result(src_port, 2, 'T');
    }
}

void on_icmp(t_data data)
{
    struct icmphdr *icmp_header = get_icmp_header(&data);
    switch (icmp_header->type)
    {
        case ICMP_DEST_UNREACH: // ICMP Port Unreachable (UDP closed or TCP filtered)
            return (on_unreachable(icmp_header, &data));
        case ICMP_TIME_EXCEEDED: // ICMP Time Exceeded (used by some firewalls)
            return (on_timeout(icmp_header, &data));
    }
}
