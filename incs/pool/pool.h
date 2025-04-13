#ifndef POOL_H
#define POOL_H

#include "nmap_data.h"
#include "packet_capture/scan_type.h"
#include "packet_capture/packet.h"

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
    in_addr_t           ip;
    uint32_t            port;
} t_task;

void    print_task(t_task task);
bool    get_next_task(t_task *task, t_task_state *state);
t_error send_packets_pool(t_pcap_data_wraper *wrapper);

#endif // POOL_H
