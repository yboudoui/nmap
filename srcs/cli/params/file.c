#include "cli_utils.h"

bool file(t_arg_helper *args) {
    CHECK_ARGS(args, 
        .arg_name = "--file",
        .minimum_argument_count = 2);

    FILE *fs = fopen(args->av[1], "r");
    if (fs == NULL) {
        fprintf(stderr, "ERROR: unable to open a file %s\n", args->av[1]);
        perror(NULL);
        return(false);
    }
    args->argument->ip_list.cmd = CMD_FILE;
    args->argument->ip_list.data.fs = fs;
    shift_args_by(args, 2);
    return (true);
}