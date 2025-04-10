#include "cli_utils.h"

static bool parse_ip(char *str, in_addr_t *ip) {
    if (inet_pton(AF_INET, str, ip) != 1) {
        fprintf(stderr, "ERROR: malformed ip [%s]\n", str);
        return (false);
    }

    char buffer[INET_ADDRSTRLEN];
    if(!inet_ntop(AF_INET, ip, buffer, INET_ADDRSTRLEN)) {
        fprintf(stderr, "UNEXPECTED ERROR: malformed ip %s -> %s\n", str, buffer);
        return (false);
    }

    if(!match_with(buffer, str)) {
        fprintf(stderr, "ERROR: malformed ip %s\n", str);
        return (false);
    }
    return (true);
}

bool ip(t_arg_helper *args) {
    static size_t   once = 0;
    in_addr_t       ip;

    if (0
        || !call_me_once(&once, "--ip is already used")
        || !expect_at_least_n_args(args, 1, "--ip not enough arguments")
        || !parse_ip(args->av[0], &ip))
        return (false);

    if (args->argument->ip_list.cmd == CMD_FILE) {
        fprintf(stderr, "ERROR: --ip the parameter --file is already used\n");
        return (false);
    }
    args->argument->ip_list.cmd = CMD_IP;
    args->argument->ip_list.data.ip = ip;
    return (shift_args_by(args, 1), true);
}