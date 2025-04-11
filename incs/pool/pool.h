#ifndef POOL_H
#define POOL_H

#include "cli/cli.h"
#include "task_generator.h"

struct s_addr
{
    in_addr_t   ip;
    uint32_t    port;
};

typedef struct s_task {
    t_scan_type     scan_flag;
    struct s_addr   dst;
} t_task;

typedef bool    (t_fp_callback)(void*);
bool pool(t_arguments *args, t_fp_callback user_callback, void *user_data);

struct s_req
{
    struct s_addr   src;
    struct s_addr   dst;
};

void print_task(t_task task);
int send_raw_packet(struct s_addr src, t_task task);
bool get_next_task(t_task *task, t_state *state);

#endif // POOL_H
