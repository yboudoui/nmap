#ifndef PACKET_SCAN_TYPE_H
#define PACKET_SCAN_TYPE_H

#include <stdlib.h>
#include <string.h>

#include "header.h"
#include "pool.h"

#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20

#endif // PACKET_SCAN_TYPE_H