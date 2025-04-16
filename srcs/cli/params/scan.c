#include "cli/utils.h"

#include <string.h>

static const struct s_scan_type_map {
    char *str; t_scan_type type;
}   scan_map[] = {
    {"SYN",     SCAN_SYN},
    {"NULL",    SCAN_NULL},
    {"ACK",     SCAN_ACK},
    {"FIN",     SCAN_FIN},
    {"XMAS",    SCAN_XMAS},
    {"UDP",     SCAN_UDP},
    {NULL,      NO_SCAN_TYPE}
};

static t_scan_type   get_scan_type(char *str) {
    if (str == NULL) {
        return (NO_SCAN_TYPE);
    }
    for(int i = 0; scan_map[i].str; i++) {
        if (match_with(scan_map[i].str, str)) {
            return (scan_map[i].type);
        }
    }
    return (NO_SCAN_TYPE);
}

bool scan(t_arg_helper *args) {
    t_scan_type     flags = NO_SCAN_TYPE;
    static size_t   once = 0;
    if (0
        || !call_me_once(&once, "--scan is already used")
        || !expect_at_least_n_args(args, 1, "--scan not enough arguments"))
        return (false);
        
    t_scan_type current = get_scan_type(args->av[0]);
    while (current != NO_SCAN_TYPE) {
        flags |= current;
        if(!shift_args_by(args, 1)) {
            break;
        }
        current = get_scan_type(args->av[0]);
    }
    if (flags == NO_SCAN_TYPE) {
        fprintf(stderr, "ERRO: --scan bad parameters\n");
        return (false);
    }
    args->argument->scan_type = flags;
    return (true);
}