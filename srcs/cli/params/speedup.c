#include "cli_utils.h"

static inline bool speedup_is_number(t_arg_helper *arg) {
    char *end;
    arg->argument->speedup = strtol(arg->av[1], &end, 10);
    return (end != arg->av[1] && end[0] == '\0');
}

static inline bool speedup_check_bound(t_arg_helper *arg) {
    if (arg->argument->speedup < 0 ||  arg->argument->speedup > 250) {
        fprintf(stderr, 
            "ERROR: <speedup> out of bound.\n"
            "Usage --speedup: <speedup> must be between 0 and 250\n"
            "Got: %d\n",
            arg->argument->speedup);
        return (false);
    }
    return (true);
}

bool speedup(t_arg_helper *args) {
    CHECK_ARGS(args, 
        .arg_name = "--speedup",
        .minimum_argument_count = 2);
    printf("llo\n");
    
    if (0
        || !speedup_is_number(args)
        || !speedup_check_bound(args))
        return(false);
    shift_args_by(args, 2);
    return (true);
}