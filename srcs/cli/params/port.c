#include "cli_utils.h"

static inline bool port_check_bound(t_arg_helper *arg, t_range range) {
    if (arg->argument->port_range[range] < 1 || arg->argument->port_range[range] > 1024) {
        fprintf(stderr, "ERROR: <port> out of range.\nUsage --port: <port> must be between 1 and 1024\n");
        return (false);
    }
    return (true);
}

static inline bool port_is_a_number(t_arg_helper *arg, t_range range, char *src, char **end) {

    arg->argument->port_range[range] = strtol(src, end, 10);
    if (*end == src) {
        fprintf(stderr, 
            "ERROR: <port> is not a number.\n"
            "Usage --port: <port> must be between 1 and 1024\n");
        return (false);
    }
    return (port_check_bound(arg, range));
}

static inline bool port_range_check_order(t_arg_helper *arg) {
    if (arg->argument->port_range[START] > arg->argument->port_range[END]) {
        fprintf(stderr,
            "ERROR: Bad range order.\nUsage --port: <min:max> but you provide <%d:%d>\n",
            arg->argument->port_range[START],
            arg->argument->port_range[END]);
        return(false);
    }
    return (true);
}

bool ports(t_arg_helper *args) {
    CHECK_ARGS(args, 
        .arg_name = "--ports",
        .minimum_argument_count = 2);

    char *tmp = args->av[1];
    char *endptr;

    if (!port_is_a_number(args, START, tmp, &endptr)) {
        return(false);
    }

    if (endptr[0] == '\0') {
        args->argument->port_range[END] = args->argument->port_range[START];
    } else if (endptr[0] != ':' || endptr[0] != '-') {
           fprintf(stderr, 
            "ERROR: Malformed range.\n"
            "Usage --port: <min:max> or <min-max>\n"
            "Got: %s\n",
            tmp);
            return (false);
    }
    if (!port_is_a_number(args, END, endptr + 1, &endptr)) return (false);
    if(endptr[0]) {
            fprintf(stderr, 
            "ERROR: Malformed range.\n"
            "Usage --port: <min:max> or <min-max>\n"
            "Got: %s\n",
            tmp);
            return (false);
    }
    if (!port_range_check_order(args)) return (false);
    shift_args_by(args, 2);
    return (true);
}
