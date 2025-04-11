#include <stdio.h>
#include "pool/pool.h"
#include "packet_capture/packet.h"
#include "utils/queue.h"


int main(int ac, char *av[]) {
    t_arguments args;
    t_queue     *queue;

    if (!parse_argument(&args, ac, av)) {
        return (1);
    }
    queue = queue_init();
    if (queue == NULL)
    {
        return (1);
    }
    if (pool(&args, init_pcap, queue) == false)
    {
        queue_destroy(queue);
        return (1);
    }
    queue_destroy(queue);
    return (0);
}
/*
    // data for the queue
    struct s_data {
    int port;
    int status;           // 0=closed, 1=open, 2=filtered
    char type;           // 'T'=TCP, 'U'=UDP
};
*/