#include "cli_utils.h"

#include <string.h>

static const struct s_scan_type_map {
    char *str; int len; enum e_scan_type type;
}   map[MAX_SCAN_TYPE] = {
    {"SYN", strlen("SYN"),  SCAN_SYN},
    {"NULL",strlen("NULL"), SCAN_NULL},
    {"ACK", strlen("ACK"),  SCAN_ACK},
    {"FIN", strlen("FIN"),  SCAN_FIN},
    {"XMAS",strlen("XMAS"), SCAN_XMAS},
    {"UDP", strlen("UDP"),  SCAN_UDP},
};

bool scan(t_arg_helper *args) {
    CHECK_ARGS(args, 
        .arg_name = "--scan",
        .minimum_argument_count = 2);
        
    args->argument->scan = 0;

    int map_index;
    int tmp_i = 0;
    char *tmp = args->av[1];
    while (tmp[tmp_i]) {
        map_index = 0;
        while (map_index < MAX_SCAN_TYPE) {
            if (strncmp(&tmp[tmp_i], map[map_index].str, map[map_index].len) == 0) {
                args->argument->scan |= map[map_index].type;
                tmp_i += map[map_index].len;
                break;
            }
        }
        if (map_index == MAX_SCAN_TYPE) {
            // bad formatting
            return (false);
        }
        if (tmp[tmp_i] == '\0') {
            break;
        }
        if (tmp[tmp_i] != ',') {
            // bad formatting
            return (false);
        } else { tmp_i += 1; }
    }
    shift_args_by(args, 2);
    return (true);
}