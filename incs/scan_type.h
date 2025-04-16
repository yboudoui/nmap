#ifndef SCAN_TYPE_H
#define SCAN_TYPE_H

#define IS(a, b) ((a & b) == b)

typedef enum e_protocol_type {
    PROTOCOL_TCP = (1 << 0),
    PROTOCOL_UDP = (1 << 1),
} t_protocol_type;

#define SUPPORTED_PROTOCOL 0 \
    | PROTOCOL_TCP \
    | PROTOCOL_UDP

typedef enum e_tcp_flags {
    FIN_FLAG = (1 << 8),
    SYN_FLAG = (1 << 9),
    RST_FLAG = (1 << 10),
    PSH_FLAG = (1 << 11),
    ACK_FLAG = (1 << 12),
    URG_FLAG = (1 << 13),
} t_tcp_flags;

typedef enum e_scan_type {
    SCAN_ACK   = (PROTOCOL_TCP | (1 << 2) | ACK_FLAG),
    SCAN_FIN   = (PROTOCOL_TCP | (1 << 3) | FIN_FLAG),
    SCAN_NULL  = (PROTOCOL_TCP | (1 << 4) | 0),
    SCAN_SYN   = (PROTOCOL_TCP | (1 << 5) | SYN_FLAG),
    SCAN_UDP   = (PROTOCOL_UDP | (1 << 6) | 0),
    SCAN_XMAS  = (PROTOCOL_TCP | (1 << 7) | FIN_FLAG | PSH_FLAG | URG_FLAG),
} t_scan_type;

#endif // SCAN_TYPE_H