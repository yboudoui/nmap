#ifndef PACKET_H
#define PACKET_H

#include "info.h"
#include <unistd.h>

void    on_ack(t_packet_info *data);
void    on_fin(t_packet_info *data);
void    on_null(t_packet_info *data);
void    on_syn(t_packet_info *data);
void    on_xmas(t_packet_info *data);

void    icmp_on_unreachable(t_packet_info *data);
void    icmp_on_timeout(t_packet_info *data);

void    on_udp(t_packet_info *data);

#endif // PACKET_H