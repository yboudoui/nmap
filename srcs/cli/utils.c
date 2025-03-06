#include "cli_utils.h"
#include <string.h>

inline void shift_args_by(t_arg_helper* args, int n) {
    args->ac -= n;
    args->av += n;
}

inline bool match_with(const char *ref, char *str) {
    return (strncmp(ref, str, strlen(ref)) == 0);
}

inline bool expect_at_least_n_args(t_arg_helper *args, int n) {
    if (args->ac < n) {
        fprintf(stderr, "ERROR: not enought arguments\n");
        return (false);
    }
    return (true);
}

inline bool call_me_once(size_t *v) {
    if (*v != 0) return (false);
    return (true);
}

inline bool check_args(t_arg_helper *args, t_expected expt) {
    if (args->ac == 0) return (false);
    return (1
        && call_me_once(expt.once)
        && match_with(expt.arg_name , args->av[0])
        && expect_at_least_n_args(args, expt.minimum_argument_count)
    );
}