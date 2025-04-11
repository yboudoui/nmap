#ifndef CLI_H
#define CLI_H

#include <stdbool.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "scan_type/flags.h"

typedef enum e_output_format {
    FORMAT_NONE,
    FORMAT_RAW,
    FORMAT_CSV,
    FORMAT_PRETTY,
} t_output_format;

typedef enum e_range {
    START, END, MAX_RANGE
} t_range;

typedef struct s_arguments {
    struct s_ip_list {
        enum e_ip_cmd {NO_IPS, CMD_IP, CMD_FILE} cmd;
        union {
            in_addr_t   ip;
            FILE*       fs;
        } data;
    }           ip_list;
    t_scan_type scan_flags;
    int         port_range[MAX_RANGE];

    size_t          speedup;
    t_output_format format;
} t_arguments;

bool    parse_argument(t_arguments *args, int ac, char* av[]);


#endif // CLI_H
