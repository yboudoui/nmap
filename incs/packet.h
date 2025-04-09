#ifndef SCAN_TYPE_H
#define SCAN_TYPE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


#include <arpa/inet.h>
#define _BSD_SOURCE 1

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "queue.h"

typedef struct {
    void                *data;
    const unsigned char *packet;
    struct iphdr        *ip_header;
    unsigned short      iphdrlen;
} t_data;
void on_icmp(t_data data);
void on_tcp(t_data data);
void on_udp(t_data data);

bool init_pcap(void *data);


#endif // SCAN_TYPE_H