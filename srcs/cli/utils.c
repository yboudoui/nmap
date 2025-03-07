#include "cli_utils.h"
#include <string.h>

inline bool shift_args_by(t_arg_helper* args, int n) {
    if ((args->ac - n) < 0) return (false);
    args->ac -= n;
    args->av += n;
    return (true);
}

inline bool match_with(const char *ref, char *str) {
    return (strncmp(ref, str, strlen(ref) + 1) == 0);
}

inline bool expect_at_least_n_args(t_arg_helper *args, int n, char *error_msg) {
    if (args->ac < n) {
        fprintf(stderr, "ERROR: %s\n", error_msg);
        return (false);
    }
    return (true);
}

inline bool is_only_a_number(char *str, size_t *v, char *error_msg) {
    char *end;
    (*v) = strtol(str, &end, 10);
    if (end == str || end[0] != '\0') {
        fprintf(stderr, "ERROR: %s\n", error_msg);
        return (false);
    }
    return (true);
}

inline bool check_bound(size_t v, size_t min, size_t max, char *error_msg) {
    if (v < min ||  v > max) {
        fprintf(stderr, "%s\n", error_msg);
        return (false);
    }
    return (true);
}


inline bool call_me_once(size_t *v) {
    if (*v) return (false);
    (*v) += 1;
    return (true);
}