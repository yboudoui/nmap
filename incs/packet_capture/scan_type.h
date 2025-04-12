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

typedef struct s_req {
    struct s_addr   src;
    struct s_addr   dst;
} t_req;

uint32_t ack_packet(uint8_t *packet_buf, t_req req);
uint32_t fin_packet(uint8_t *packet_buf, t_req req);
uint32_t null_packet(uint8_t *packet_buf, t_req req);
uint32_t syn_packet(uint8_t *packet_buf, t_req req);
uint32_t udp_packet(uint8_t *packet_buf, t_req req);
uint32_t xmas_packet(uint8_t *packet_buf, t_req req);

typedef uint32_t (*t_fp_packet_builder)(uint8_t*, t_req);

#endif // PACKET_SCAN_TYPE_H