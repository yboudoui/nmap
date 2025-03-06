#ifndef CLI_UTILS_H
#define CLI_UTILS_H

#include "cli.h"
#include <stdlib.h>

typedef struct s_arg_helper {
    t_arguments *argument;
    int ac;
    char** av;
} t_arg_helper;

typedef struct s_expected {
    size_t  *once;
    char    *arg_name;
    size_t  minimum_argument_count;
} t_expected;
bool check_args(t_arg_helper *args, t_expected expt);

#define CHECK_ARGS(args, ...) do{ static size_t once = 0;\
    if (!check_args(args, (t_expected){ .once = &once, __VA_ARGS__ })) return (true);\
} while (0)


void shift_args_by(t_arg_helper* args, int n);
bool match_with(const char *ref, char *str);
bool expect_at_least_n_args(t_arg_helper *args, int n);
bool call_me_once(size_t *v);


typedef bool (*t_fp_flag)(t_arg_helper*);

bool help(t_arg_helper*);
bool ports(t_arg_helper*);
bool ip(t_arg_helper*);
bool speedup(t_arg_helper*);
bool scan(t_arg_helper*);
bool file(t_arg_helper*);

void show_help(void);

#endif // CLI_UTILS_H
