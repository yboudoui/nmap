#include "packet/header.h"

bool create_syn_packet(struct s_req req, struct s_raw_packet *raw_packet)
{
    if (!raw_packet) return false;
    
    uint16_t *datagram = calloc(sizeof(struct iphdr) + sizeof(struct tcphdr), sizeof(char));
    if (!datagram) return false;
    
    struct iphdr iph = build_ip_header(datagram, req.src.ip, req.dst.ip, IPPROTO_TCP);
    struct tcphdr tcph = build_tcp_header(req.dst.port, req.src.ip, req.dst.ip, SYN_FLAG);
    
    tcph.check = tcp_checksum((unsigned short *)&tcph, sizeof(tcph), req.src.ip, req.dst.ip);
    
    memcpy(datagram, &iph, sizeof(iph));
    memcpy(datagram + sizeof(iph), &tcph, sizeof(tcph));
    
    raw_packet->packet = datagram;
    raw_packet->packet_len = ntohs(iph.tot_len);
    return true;
}