#include "cli/utils.h"

static bool file_open(char *file_path, FILE **fs) {
    (*fs) = fopen(file_path, "r");
    if ((*fs) == NULL) {
        fprintf(stderr, "ERROR: unable to open a file %s\n", file_path);
        return(false);
    }
    return (true);
}

bool file(t_arg_helper *args) {
    static size_t   once = 0;
    FILE            *fs = NULL;

    if (0
        || !call_me_once(&once, "--file is already used")
        || !expect_at_least_n_args(args, 1, "--file not enough arguments")
        || !file_open(args->av[0], &fs))
        return (false);

    if (args->argument->ip_list.cmd == CMD_IP) {
        fprintf(stderr, "ERROR: --file the parameter --ip is already used\n");
        return (false);
    }

    args->argument->ip_list.cmd = CMD_FILE;
    args->argument->ip_list.data.fs = fs;
    return (shift_args_by(args, 1), true);
}