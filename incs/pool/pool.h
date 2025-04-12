#ifndef POOL_H
#define POOL_H

#include "nmap_data.h"
#include "packet_capture/scan_type.h"

typedef struct s_task_state {
    size_t          scan_index;
    int             current_port;
    bool            ip_available;
    in_addr_t       ip;
    bool            finish;
    
    void            *user_data;
} t_task_state;

typedef struct s_task {
    t_fp_packet_builder packet_builder;
    t_scan_type         scan_flag;
    struct s_addr       dst;
} t_task;

void    print_task(t_task task);
bool    get_next_task(t_task *task, t_task_state *state);
t_error send_packets_pool(void *user_data);

#endif // POOL_H
