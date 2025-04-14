#include "cli/utils.h"

#include <string.h>

static t_fp_flag   get_command(char *str) {
    static const struct s_command_map {
        char        *name;
        t_fp_flag   callback;
    } command_map[] = {
        {"--help",          help},
        {"--ports",         ports},
        {"--ip",            ip},
        {"--speedup",       speedup},
        {"--scan",          scan},
        {"--file",          file},
        {"--output-format", output_format},
        {NULL,              NULL},
    };
    for(int i = 0; command_map[i].name; i++) {
        if (match_with(command_map[i].name, str)) 
            return (command_map[i].callback);
    }
    return (NULL);
}

static void init_arguments(t_arguments* args) {
    #define SCAN_ALL 0  \
    | SCAN_SYN          \
    | SCAN_NULL         \
    | SCAN_ACK          \
    | SCAN_FIN          \
    | SCAN_XMAS         \
    | SCAN_UDP
    
    memset(args, 0, sizeof(t_arguments));
    args->port_range[START] = 1;
    args->port_range[END] = 1024;
    args->scan_flags = SCAN_ALL;
    args->speedup = 1;
}

bool    parse_argument(t_arguments *args, int ac, char* av[]) {
    init_arguments(args);
    t_arg_helper        helper  = { args, ac - 1, av + 1 };

    if (ac <= 1) {
        show_help();
        return (false);
    }
    while (helper.ac) {
        t_fp_flag cmd = get_command(*helper.av);
        if (cmd == NULL) {
            fprintf(stderr, "ERROR: unexpected parameters. Got %s\n", helper.av[0]);
            show_help();
            return (false);
        }
        if (!shift_args_by(&helper, 1)) break;
        if (!cmd(&helper)) return (false);
    }
    return (true);
}
// TODO: check if --file and --ip are called together

