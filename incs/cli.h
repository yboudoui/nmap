#ifndef CLI_H
#define CLI_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <stdio.h>

typedef enum e_range {
    START, END, MAX_RANGE
} t_range;

typedef struct s_arguments {
    enum e_scan_type {
        SCAN_SYN    = 1 << 0,
        SCAN_NULL   = 1 << 1,
        SCAN_ACK    = 1 << 2,
        SCAN_FIN    = 1 << 3,
        SCAN_XMAS   = 1 << 5,
        SCAN_UDP    = 1 << 6,
        MAX_SCAN_TYPE = 7,
        SCAN_ALL = 0 
            | SCAN_SYN 
            | SCAN_NULL 
            | SCAN_ACK 
            | SCAN_FIN 
            | SCAN_XMAS 
            | SCAN_UDP,
    } scan;
    int port_range[MAX_RANGE];
    struct s_ip_list {
        enum {NO_IPS, CMD_IP, CMD_FILE} cmd;
        union {
            struct in_addr  ip;
            FILE*            fs;
        } data;
    } ip_list;
    int             speedup;
} t_arguments;

bool    parse_argument(t_arguments *args, int ac, char* av[]);


#endif // CLI_H
