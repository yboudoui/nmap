#include <stdio.h>
#include "cli.h"


int main(int ac, char *av[]) {
    t_arguments args;

    if (parse_argument(&args, ac, av) == false) {
        return (1);
    }
    return (0);
}