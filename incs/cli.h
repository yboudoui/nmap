#ifndef CLI_H
#define CLI_H

#include <stdbool.h>
#include <arpa/inet.h>

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
    struct {
        int start, end;
    } port_range;
    struct s_ip_list {
        struct in_addr  *list;
        size_t          count;
    } ip_list;
    int             speedup;
} t_arguments;

bool    parse_argument(t_arguments *args, int ac, char* av[]);
void    show_help(void);


#endif // CLI_H
