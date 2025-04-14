#include "packet/info.h"

static t_eth_info  build_eth_info(const uint8_t *raw_packet)
{
    t_eth_info   info = {0};

    info.header_ptr = raw_packet;
    info.header = (struct ether_header *)(info.header_ptr);
    info.header_len = sizeof(struct ether_header);
    info.type = ntohs(info.header->ether_type);
    return (info);
}

static t_ip_info   build_ip_info(const uint8_t *raw_packet, t_eth_info eth_info)
{
    (void)raw_packet;
    t_ip_info   info = {0};

    info.header_ptr = eth_info.header_ptr + eth_info.header_len;
    info.header = (struct iphdr *)(info.header_ptr);
    info.header_len = info.header->ihl * 4;
    info.ip = (struct ip *)info.header_ptr;
    return (info);
}

static t_tcp_info  build_tcp_info(const uint8_t *raw_packet, t_ip_info ip_info)
{
    (void)raw_packet;
    t_tcp_info  info = {0};

    info.header_ptr = ip_info.header_ptr + ip_info.header_len;
    info.header = (struct tcphdr *)(info.header_ptr);
    info.port.src = ntohs(info.header->source);
    info.port.dst = ntohs(info.header->dest);

    u_int8_t flags = info.header->th_flags;
    if (flags == 0) {
        info.scan_type = SCAN_NULL;
    } 
    else if (flags & TH_SYN && !(flags & TH_ACK)) {
        info.scan_type = SCAN_SYN;
    }
    else if (flags & TH_FIN && flags & TH_URG && flags & TH_PUSH) {
        info.scan_type = SCAN_XMAS;
    }
    else if (flags & TH_FIN && !(flags & TH_ACK)) {
        info.scan_type = SCAN_FIN;
    }
    else if (flags & TH_ACK && !(flags & TH_SYN)) {
        info.scan_type = SCAN_ACK;
    }
    return (info);
}

static t_udp_info  build_udp_info(const uint8_t *raw_packet, t_ip_info ip_info)
{
    (void)raw_packet;
    t_udp_info  info = {0};

    info.header_ptr = ip_info.header_ptr + ip_info.header_len;
    info.header = (struct udphdr *)(info.header_ptr);
    return (info);
}

static t_icmp_info build_icmp_info(const uint8_t *raw_packet, t_ip_info ip_info)
{
    (void)raw_packet;
    t_icmp_info  info = {0};

    info.header_ptr = ip_info.header_ptr + ip_info.header_len;
    info.header = (struct icmphdr *)(info.header_ptr);
    return (info);
}

t_packet_info    new_packet(uint8_t *user_data, const uint8_t *raw_packet)
{
    t_packet_info  packet_info = {0};
    
    packet_info.user_data = user_data;
    packet_info.raw_packet = raw_packet;
    packet_info.eth =  build_eth_info(packet_info.raw_packet);
    packet_info.ip =   build_ip_info(packet_info.raw_packet, packet_info.eth);

    switch (packet_info.ip.header->protocol) {
        case IPPROTO_TCP: {
            packet_info.tcp = build_tcp_info(packet_info.raw_packet, packet_info.ip);
            break;
        }
        case IPPROTO_UDP: {
            packet_info.udp = build_udp_info(packet_info.raw_packet, packet_info.ip);
            break;
        }
        case IPPROTO_ICMP: {
            packet_info.icmp = build_icmp_info(packet_info.raw_packet, packet_info.ip);
        }
    }
    return (packet_info);
}