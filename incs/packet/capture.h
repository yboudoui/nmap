#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include "utils/error.h"

#include "info.h"

typedef struct s_pcap_data_wraper {
    pcap_t          *handle;
    struct in_addr  device_addr;
    void            *user_data;
} t_pcap_data_wraper;
void    packet_handler(uint8_t *user_data, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);
t_error capture_packet(t_error (*user_callback)(t_pcap_data_wraper*), void *data);

#endif // PACKET_CAPTURE_H