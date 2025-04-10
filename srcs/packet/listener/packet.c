#include "pool.h"
#include "packet.h"

t_eth_info  build_eth_info(const unsigned char *raw_packet)
{
    t_eth_info   info = {0};

    info.header_ptr = raw_packet;
    info.header = (struct ether_header *)(info.header_ptr);
    info.header_len = sizeof(struct ether_header);
    info.type = ntohs(info.header->ether_type);
    return (info);
}

t_ip_info   build_ip_info(const unsigned char *raw_packet, t_eth_info eth_info)
{
    (void)raw_packet;
    t_ip_info   info = {0};

    info.header_ptr = eth_info.header_ptr + eth_info.header_len;
    info.header = (struct iphdr *)(info.header_ptr);
    info.header_len = info.header->ihl * 4;
    return (info);
}

t_tcp_info  build_tcp_info(const unsigned char *raw_packet, t_ip_info ip_info)
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

t_udp_info  build_udp_info(const unsigned char *raw_packet, t_ip_info ip_info)
{
    (void)raw_packet;
    t_udp_info  info = {0};

    info.header_ptr = ip_info.header_ptr + ip_info.header_len;
    info.header = (struct udphdr *)(info.header_ptr);
    return (info);
}

t_icmp_info build_icmp_info(const unsigned char *raw_packet, t_ip_info ip_info)
{
    (void)raw_packet;
    t_icmp_info  info = {0};

    info.header_ptr = ip_info.header_ptr + ip_info.header_len;
    info.header = (struct icmphdr *)(info.header_ptr);
    return (info);
}

t_packet    new_packet(unsigned char *user_data, const unsigned char *raw_packet)
{
    t_packet  data;
    data.user_data = user_data;
    data.raw_packet = raw_packet;
    data.eth = build_eth_info(data.raw_packet);
    data.ip = build_ip_info(data.raw_packet, data.eth);
    return (data);
}

void        save_result(t_packet *data, void *result)
{
    queue_add(data->user_data, result);
}
