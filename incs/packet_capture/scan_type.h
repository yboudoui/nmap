#ifndef PACKET_SCAN_TYPE_H
#define PACKET_SCAN_TYPE_H

#include <stdlib.h>
#include <string.h>

#include "header.h"
#include "pool/pool.h"

#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20

bool ack_packet(struct s_req req, struct s_raw_packet *raw_packet);
bool fin_packet(struct s_req req, struct s_raw_packet *raw_packet);
bool null_packet(struct s_req req, struct s_raw_packet *raw_packet);
bool syn_packet(struct s_req req, struct s_raw_packet *raw_packet);
bool udp_packet(struct s_req req, struct s_raw_packet *raw_packet);
bool xmas_packet(struct s_req req, struct s_raw_packet *raw_packet);

#endif // PACKET_SCAN_TYPE_H