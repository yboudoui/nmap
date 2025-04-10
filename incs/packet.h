#ifndef PACKET_H
#define PACKET_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <arpa/inet.h>
// #define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "scan_type.h"
#include "queue.h"

typedef struct s_eth_info {
    const unsigned char *header_ptr;
    struct ether_header *header;
    unsigned short      header_len;
    uint16_t            type;
} t_eth_info;
t_eth_info build_eth_info(const unsigned char *raw_packet);

typedef struct s_ip_info {
    const unsigned char *header_ptr;
    struct iphdr        *header;
    unsigned short      header_len;
} t_ip_info;
t_ip_info build_ip_info(const unsigned char *raw_packet, t_eth_info eth_info);

typedef struct s_tcp_info {
    const unsigned char *header_ptr;
    struct tcphdr       *header;
    struct {
        unsigned short src;
        unsigned short dst;
    } port;
    t_scan_type         scan_type;
} t_tcp_info;
t_tcp_info  build_tcp_info(const unsigned char *raw_packet, t_ip_info ip_info);

typedef struct s_udp_info {
    const unsigned char *header_ptr;
    struct udphdr       *header;
} t_udp_info;
t_udp_info  build_udp_info(const unsigned char *raw_packet, t_ip_info ip_info);

typedef struct s_icmp_info {
    const unsigned char *header_ptr;
    struct icmphdr       *header;
} t_icmp_info;
t_icmp_info  build_icmp_info(const unsigned char *raw_packet, t_ip_info ip_info);

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