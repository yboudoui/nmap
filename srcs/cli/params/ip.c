#include "cli_utils.h"


static bool parse_ip(char *str, struct in_addr *ip) {
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
    struct in_addr  ip;

    if (0
        || !call_me_once(&once)
        || !expect_at_least_n_args(args, 1, "--ip not enough arguments")
        || !parse_ip(args->av[0], &ip))
        return (false);

    args->argument->ip_list.cmd = CMD_IP;
    args->argument->ip_list.data.ip = ip;
    return (shift_args_by(args, 1), true);
}