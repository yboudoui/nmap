#ifndef POOL_H
#define POOL_H

#include "cli/cli.h"

typedef struct s_task {
    in_addr_t       ip;
    t_scan_type     scan_flag;
    int             port;
} t_task;

typedef void    (t_fp_callback)(void);
bool pool(t_arguments *args, t_fp_callback callback);

struct s_addr
{
    in_addr_t   ip;
    uint32_t    port;
};

struct s_req
{
    struct s_addr   src;
    struct s_addr   dst;
};

struct s_raw_packet
{
    uint16_t    *packet;
    int         packet_len;
};
#endif // POOL_H
