#ifndef SCAN_TYPE_H
#define SCAN_TYPE_H

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>


#include <pcap.h>
#include <stdint.h>

void    packet_handler(void);
bool    init_packet_handler(void);

#endif // SCAN_TYPE_H