#include <stdio.h>
#include "pool.h"
#include "packet.h"


int main(int ac, char *av[]) {
    t_arguments args;

    if (!parse_argument(&args, ac, av)) {
        return (1);
    }
    if (!init_packet()) {
        return (1);
    }

    if (!pool(&args, packet_handler)) {
        return (1);
    }
    return (0);
}