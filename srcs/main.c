#include <stdio.h>
#include "pool.h"


int main(int ac, char *av[]) {
    t_arguments args;

    if (!parse_argument(&args, ac, av)) {
        return (1);
    }
    if (!pool(&args)) {
        return (1);
    }
    return (0);
}