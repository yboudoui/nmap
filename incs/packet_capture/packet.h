#ifndef PACKET_H
#define PACKET_H

// #include "scan_type.h"
#include "info.h"
#include "utils/queue.h"

typedef struct s_packet{
    void                *user_data;
    const unsigned char *raw_packet;
    t_eth_info  eth;
    t_ip_info   ip;
    t_tcp_info  tcp;
} t_packet;

t_packet    new_packet(unsigned char *user_data, const unsigned char *raw_packet);
void        save_result(t_packet *data, void *result);

void on_icmp(t_packet *data);
void on_tcp(t_packet *data);
void on_udp(t_packet *data);

bool init_pcap(void *data);


#endif // PACKET_H