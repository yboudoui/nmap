#include "cli_utils.h"

#include <string.h>

#define MAX_PARAMETER 6 
static const t_fp_flag    flags[MAX_PARAMETER] = {
    help, ports, ip, speedup, scan, file
};

bool    parse_argument(t_arguments *argument, int ac, char* av[]) {
    memset(argument, 0, sizeof(t_arguments));
    argument->port_range[START] = 1;
    argument->port_range[END] = 1024;
    argument->scan = SCAN_ALL;
    t_arg_helper        helper  = { argument, ac - 1, av + 1 };

    if (ac <= 1) {
        show_help();
        return (false);
    }
    while (helper.ac) {
        int i = 0;
        while(i < MAX_PARAMETER) {
            if (!flags[i](&helper)) {
                printf("%d\n", i);
                return (false);
            }
            i += 1;
        }
        if (i == MAX_PARAMETER) {
            fprintf(stderr, "ERROR: unexpected parameters. Got %s\n", helper.av[0]);
            show_help();
        }
    }
    return (true);
}
// TODO: check if --file and --ip are called together

