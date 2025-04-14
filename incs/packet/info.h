#ifndef PACKET_INFO_H
#define PACKET_INFO_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <arpa/inet.h>
#define _DEFAULT_SOURCE 1

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "scan_type/flags.h"
#include "utils/queue.h"

typedef struct s_eth_info {
    const uint8_t       *header_ptr;
    struct ether_header *header;
    uint16_t            header_len;
    uint16_t            type;
} t_eth_info;

typedef struct s_ip_info {
    const uint8_t   *header_ptr;
    struct iphdr    *header;
    uint16_t        header_len;
    struct ip       *ip;
} t_ip_info;

typedef struct s_tcp_info {
    const uint8_t   *header_ptr;
    struct tcphdr   *header;
    struct {
        uint16_t src;
        uint16_t dst;
    } port;
    t_scan_type         scan_type;
} t_tcp_info;

typedef struct s_udp_info {
    const uint8_t   *header_ptr;
    struct udphdr   *header;
} t_udp_info;

typedef struct s_icmp_info {
    const uint8_t   *header_ptr;
    struct icmphdr  *header;
} t_icmp_info;

typedef struct s_packet {
    void            *user_data;
    const uint8_t   *raw_packet;
    t_eth_info      eth;
    t_ip_info       ip;
    t_tcp_info      tcp;
    t_udp_info      udp;
    t_icmp_info     icmp;
} t_packet_info;

t_packet_info    new_packet(uint8_t *user_data, const uint8_t *raw_packet);

#endif // PACKET_INFO_H