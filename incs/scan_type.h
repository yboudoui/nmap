#ifndef SCAN_TYPE_H
#define SCAN_TYPE_H

typedef enum e_scan_type {
    SCAN_NONE  = 0,
    SCAN_SYN   = 1 << 0,
    SCAN_NULL  = 1 << 1,
    SCAN_ACK   = 1 << 2,
    SCAN_FIN   = 1 << 3,
    SCAN_XMAS  = 1 << 4,
    SCAN_UDP   = 1 << 5,
    SCAN_ALL   = 0
        | SCAN_NONE
        | SCAN_SYN
        | SCAN_NULL
        | SCAN_ACK
        | SCAN_FIN
        | SCAN_XMAS
        | SCAN_UDP
} t_scan_type;

#endif // SCAN_TYPE_H