#ifndef PACKET_H
#define PACKET_H

#include "info.h"
#include "utils/queue.h"
#include "utils/error.h"

typedef struct s_packet{
    void            *user_data;
    const uint8_t   *raw_packet;
    t_eth_info      eth;
    t_ip_info       ip;
    t_tcp_info      tcp;
} t_packet;

t_packet    new_packet(uint8_t *user_data, const uint8_t *raw_packet);
void        save_result(t_packet *data, void *result);

#include <unistd.h>

void    on_ack(t_packet *data, t_tcp_info *info);
void    on_fin(t_packet *data, t_tcp_info *info);
void    on_null(t_packet *data, t_tcp_info *info);
void    on_syn(t_packet *data, t_tcp_info *info);
void    on_xmas(t_packet *data, t_tcp_info *info);

void on_icmp(t_packet *data);
void on_udp(t_packet *data);

typedef struct s_pcap_data_wraper {
    pcap_t          *handle;
    struct in_addr  device_addr;
    void            *user_data;
} t_pcap_data_wraper;
void packet_handler(uint8_t *user_data, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);
t_error capture_packet(t_error (*user_callback)(t_pcap_data_wraper*), void *data);


#endif // PACKET_H