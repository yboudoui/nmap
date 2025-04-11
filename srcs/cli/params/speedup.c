#include "cli/utils.h"

bool speedup(t_arg_helper *args) {
    size_t          speedup;
    static size_t   once = 0;

    if (0
        || !call_me_once(&once, "--speedup is already used")
        || !expect_at_least_n_args(args, 1, "--speedup not enough arguments")
        || !is_only_a_number(args->av[0], &speedup, "--speedup <value> is not a number")
        || !check_bound(speedup, 0, 250, "--speedup <value> out of bound"))
        return(false);

    args->argument->speedup = speedup;
    return (shift_args_by(args, 1), true);
}