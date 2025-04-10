#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "packet/header.h"

bool create_ack_packet(struct s_req req, struct s_raw_packet *raw_packet)
{
    if (raw_packet == NULL)
    {
        return (false);
    }
    uint16_t *datagram = calloc(sizeof(struct iphdr) + sizeof(struct tcphdr), sizeof(char));
    if (datagram == NULL)
    {
        return (false);
    }
    struct iphdr ip_header = build_ip_header(datagram, req.src.ip, req.dst.ip, IPPROTO_TCP);
    struct tcphdr tcp_header = build_tcp_header(req.dst.port, req.src.ip, req.dst.ip, ACK_FLAG);

    memcpy(datagram, &ip_header, sizeof(struct iphdr));
    memcpy(datagram + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));

    raw_packet->packet = datagram;
    raw_packet->packet_len = ip_header.tot_len;
    return (true);
}