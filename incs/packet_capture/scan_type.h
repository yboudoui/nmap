#ifndef PACKET_SCAN_TYPE_H
#define PACKET_SCAN_TYPE_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "header.h"
// #include "pool/pool.h"

#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20

struct s_addr {
    in_addr_t   ip;
    uint32_t    port;
};

uint32_t ack_packet (uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t dst_port);
uint32_t fin_packet (uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t dst_port);
uint32_t null_packet(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t dst_port);
uint32_t syn_packet (uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t dst_port);
uint32_t udp_packet (uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t dst_port);
uint32_t xmas_packet(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t dst_port);

typedef uint32_t (*t_fp_packet_builder)(uint8_t *packet_buf, in_addr_t src_ip, in_addr_t dst_ip, uint32_t dst_port);

#endif // PACKET_SCAN_TYPE_H