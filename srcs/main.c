#include <stdio.h>
#include "pool.h"
#include "packet.h"
#include "queue.h"


int main(int ac, char *av[]) {
    t_arguments args;
    t_queue     *queue;

    if (!parse_argument(&args, ac, av)) {
        return (1);
    }
    queue = queue_init();
    if (!init_pcap(queue)) {
        return (1);
    }

    // if (!pool(&args, packet_handler)) {
    //     return (1);
    // }
    return (0);
}