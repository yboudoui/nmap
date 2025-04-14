#ifndef SCAN_TYPE_H
#define SCAN_TYPE_H

#include "utils/buffer.h"

#define SCAN_NONE 0

// TCP Flags
#define FIN_FLAG (1 << 0)
#define SYN_FLAG (1 << 1)
#define RST_FLAG (1 << 2)
#define PSH_FLAG (1 << 3)
#define ACK_FLAG (1 << 4)
#define URG_FLAG (1 << 5)

#define XMAX_FLAGS  FIN_FLAG | PSH_FLAG | URG_FLAG

typedef enum e_scan_type
{
    SCAN_SYN   = 1 << 0,
    SCAN_NULL  = 1 << 1,
    SCAN_ACK   = 1 << 2,
    SCAN_FIN   = 1 << 3,
    SCAN_XMAS  = 1 << 4,
    SCAN_UDP   = 1 << 5,
} t_scan_type;

char* get_scan_flag_name(t_scan_type scan_type);

#endif // SCAN_TYPE_H