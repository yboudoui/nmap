#include "cli_utils.h"


static bool parse_ip(char *str, struct in_addr *ip) {
    if (inet_pton(AF_INET, str, ip) != 1) {
        fprintf(stderr, "ERROR: malformed ip %s\n", str);
        perror(NULL);
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
    CHECK_ARGS(args, 
        .arg_name = "--ip",
        .minimum_argument_count = 2);

    struct in_addr  ip;
    if (!parse_ip(args->av[1], &ip)) return (false);
    args->argument->ip_list.cmd = CMD_IP;
    args->argument->ip_list.data.ip = ip;
    shift_args_by(args, 2);
    return (true);
}