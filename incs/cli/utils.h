#ifndef CLI_UTILS_H
#define CLI_UTILS_H

#include "cli.h"
#include <stdlib.h>

typedef struct s_arg_helper {
    t_arguments *argument;
    int     ac;
    char    **av;
} t_arg_helper;

bool shift_args_by(t_arg_helper* args, int n);
bool match_with(const char *ref, char *str);
bool expect_at_least_n_args(t_arg_helper *args, int n, char *error_msg);
bool is_only_a_number(char *str, size_t *v, char *error_msg);
bool check_bound(size_t v, size_t min, size_t max, char *error_msg);


bool call_me_once(size_t *v, char *error_msg);

typedef bool (*t_fp_flag)(t_arg_helper*);

bool help(t_arg_helper*);
bool ports(t_arg_helper*);
bool ip(t_arg_helper*);
bool speedup(t_arg_helper*);
bool scan(t_arg_helper*);
bool file(t_arg_helper*);
bool output_format(t_arg_helper *);


void show_help(void);

typedef void (*t_fp_on_error)(char *fmt, ...);

#endif // CLI_UTILS_H
