#ifndef PACKET_BUILDER_H
#define PACKET_BUILDER_H

#include "scan_type.h"
#include "utils/buffer.h"
#include <netinet/in.h>

typedef struct s_packet_builder_args {
    t_buffer    buffer;
    in_addr_t   src_ip;
    in_addr_t   dst_ip;
    uint32_t    dst_port;
    t_scan_type scan_type;
} t_packet_builder_args;

void    build_packet(t_packet_builder_args *args);

#endif // PACKET_BUILDER_H