#include "cli_utils.h"

#include <string.h>

static const struct s_scan_type_map {
    char *str; t_output_format type;
}   output_format_map[] = {
    {"RAW",     FORMAT_RAW},
    {"CSV",     FORMAT_CSV},
    {"PRETTY",  FORMAT_PRETTY},
    {NULL,      FORMAT_NONE},
};

static t_output_format   get_output_format_type(char *str) {
    if (str == NULL) return (FORMAT_NONE);
    for(int i = 0; output_format_map[i].str; i++) {
        if (match_with(output_format_map[i].str, str))
            return (output_format_map[i].type);
    }
    return (FORMAT_NONE);
}

bool output_format(t_arg_helper *args) {
    static size_t   once = 0;
    if (0
        || !call_me_once(&once, "--output-format is already used")
        || !expect_at_least_n_args(args, 1, "--output-format not enough arguments"))
        return (false);
        
    t_output_format current = get_output_format_type(args->av[0]);
    if (current == FORMAT_NONE) {
        fprintf(stderr, "ERRO: --output-format bad parameters\n");
        return (false);
    }
    args->argument->format = current;
    return (shift_args_by(args, 1), true);
}