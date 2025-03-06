#include "cli.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void show_help(void);

typedef struct s_arg_helper {
    t_arguments *argument;
    int ac;
    char** av;
} t_arg_helper;

typedef bool (*t_fp_flag)(t_arg_helper*);

static inline void shift_args_by(t_arg_helper* args, int n) {
    args->ac -= n;
    args->av += n;
}

static inline bool match_with(const char *ref, char *str) {
    return (strncmp(ref, str, strlen(ref) + 1) == 0);
}

static inline bool expect_at_least_n_args(t_arg_helper *args, int n) {
    if (args->ac < n) {
        // error not enought arguments
        return (false);
    }
    return (true);
}

static inline bool call_me_once(size_t *v) {
    if (*v != 0) return (false);
    return (true);
}

typedef struct s_expected {
    size_t  *once;
    char    *arg_name;
    size_t  minimum_argument_count;
} t_expected;

static inline bool check_args(t_arg_helper *args, t_expected expt) {
    return (1
        && call_me_once(expt.once)
        && match_with(expt.arg_name , args->av[0])
        && expect_at_least_n_args(args, expt.minimum_argument_count)
    );
}

#define CHECK_ARGS(args, ...) do{ static size_t once = 0;\
    if (!check_args(args, (t_expected){ .once = &once, __VA_ARGS__ })) return (false);\
} while (0)


// --file FILE
// Need to check if an argument is called twice


static bool help(t_arg_helper *args) {
    CHECK_ARGS(args, .arg_name = "--help");
    show_help();
    return (false);
}

static bool ports(t_arg_helper *args) {
    CHECK_ARGS(args, 
        .arg_name = "--ports",
        .minimum_argument_count = 2);

    char *tmp = args->av[1];
    char *endptr;
    args->argument->port_range.start = strtol(tmp, &endptr, 10);
    if (endptr == tmp) {
        // show error, it's not a number
        return (false);
    }

    if (*endptr == '\0') {
        if (args->argument->port_range.start < 1 || args->argument->port_range.start > 1024) {
            // show error, value out of bound
            return (false);
        }
        args->argument->port_range.end = args->argument->port_range.start;
        shift_args_by(args, 2);
        return (true);
    }

    if (*endptr != ':' || *endptr != '-') {
        // show error, range malformated
        return (false);
    }

    tmp = endptr + 1;
    args->argument->port_range.end = strtol(tmp, &endptr, 10);
    if (endptr == tmp) {
        // show error, it's not a number
        return (false);
    }
    if (*endptr != '\0') {
        // show error, it's not ONLY a number
        return (false);
    }
    if (args->argument->port_range.end < 1 || args->argument->port_range.end > 1024) {
        // show error, value out of bound
        return (false);
    }
    if (args->argument->port_range.start > args->argument->port_range.end) {
        // show error, bad range!
        return (false);
    }
    shift_args_by(args, 2);
    return (true);
}

static bool init_ip_list(t_arg_helper *args, size_t count) {
    args->argument->ip_list.list = calloc(count, sizeof(struct in_addr));
    if (args->argument->ip_list.list) {
        args->argument->ip_list.count = count;
        return (true);
    }
    // fatal error  unable to allocate
    return (false);
}

static bool parse_ip(char *str, struct in_addr *ip) {
    if (inet_pton(AF_INET, str, ip) != 1) {
        // error malformed Ip
        return (false);
    }
    char buffer[INET_ADDRSTRLEN];
    if(!inet_ntop(AF_INET, ip, buffer, INET_ADDRSTRLEN)) {
        // "UNEXPECTED erro while paring ip. Abort!");
        return (false);
    }
    if(!match_with(buffer, str)) {
        // error malformed input IP
        return (false);
    }
    return (true);
}

static bool ip(t_arg_helper *args) {
    CHECK_ARGS(args, 
        .arg_name = "--ip",
        .minimum_argument_count = 2);

    struct in_addr  ip;
    if (parse_ip(args->av[1], &ip) == false) return (false);
    if (init_ip_list(args, 1) == false) return (false);
    args->argument->ip_list.list[0] = ip;
    shift_args_by(args, 2);
    return (true);
}

static bool file(t_arg_helper *args) {
    CHECK_ARGS(args, 
        .arg_name = "--file",
        .minimum_argument_count = 2);

    FILE *fs = fopen(args->av[1], "r");
    if (fs == NULL) {
        perror("fopen");
        return (false);
    }
    ssize_t nread;
    size_t len = 0;
    char *line = NULL;

    struct in_addr  ip;

    while ((nread = getline(&line, &len, fs)) != -1) {
        if (parse_ip(args->av[1], &ip) == false) return (false);
        args->argument->ip_list.list[0] = ip;

        free(line);
        line = NULL;
    }
    if (init_ip_list(args, 1) == false) return (false);

    fclose(fs);
    shift_args_by(args, 2);
    return (true);
}

static bool speedup(t_arg_helper *args) {
    CHECK_ARGS(args, 
        .arg_name = "--speedup",
        .minimum_argument_count = 2);

    char *tmp = args->av[1];
    char *endptr;
    args->argument->speedup = strtol(tmp, &endptr, 10);
    if (endptr == tmp) {
        // show error, it's not a number
        return (false);
    }
    if (*endptr != '\0') {
        // show error, it's not ONLY a number
        return (false);
    }
    if (args->argument->speedup < 0 ||  args->argument->speedup > 250) {
        // show error, value out of bound
        return (false);
    }
    shift_args_by(args, 2);
    return (true);
}

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

static bool scan(t_arg_helper *args) {
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

#define MAX_PARAMETER 6 
static const t_fp_flag    flags[MAX_PARAMETER] = { help, ports, ip, speedup, scan, file };

bool    parse_argument(t_arguments *argument, int ac, char* av[]) {
    memset(argument, 0, sizeof(t_arguments));
    argument->port_range.start = 1;
    argument->port_range.end = 1024;
    argument->scan = SCAN_ALL;
    t_arg_helper        helper  = { argument, ac, av };

    if (ac <= 1) {
        show_help();
        return (false);
    }
    while (helper.ac) {
        for (int i = 0; i < MAX_PARAMETER; i++) {
            if (flags[i](&helper) == false) {
                return (false);
            }
        }
    }
    return (true);
}

void show_help(void) {

}