#include <stdio.h>
#include "pool/pool.h"
#include "packet/packet.h"
#include "nmap_data.h"

int main(int ac, char *av[])
{
    t_nmap_data nmap_data = {0};
    t_error     error = 0;

    error = init_nmap_data(&nmap_data, ac, av);
    if (error) {
        return (err_wrap(&error, 1, "unable to init nmap context"));
    }

    t_task_state pool_state = {
        .user_data = &nmap_data
    };
    error = capture_packet(send_packets_pool, &pool_state);
    if (error) {
        clean_nmap_data(&nmap_data);
        return (error);
    }

    clean_nmap_data(&nmap_data);
    return (error);
}

/*
    // data for the queue
    struct s_data {
    int port;
    int status;           // 0=closed, 1=open, 2=filtered
    char type;           // 'T'=TCP, 'U'=UDP
};
*/