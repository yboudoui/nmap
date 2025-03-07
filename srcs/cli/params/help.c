#include "cli_utils.h"

void show_help(void) {
    static size_t once = 0;
    call_me_once(&once, NULL);
    printf("help\n");
    printf("--help\n");
    printf("--ip <ip address>\n");
    printf("--ports <value> or <min-max>\n");
    printf("--file <file name>\n");
    printf("--scan <file name>\n");
    printf("\tSYN\n");
    printf("\tNULL\n");
    printf("\tACK\n");
    printf("\tFIN\n");
    printf("\tXMAS\n");
    printf("\tUDP\n");
    printf("--speedup <value>\n");
}

bool help(t_arg_helper *args) {
    (void)args;
    static size_t once = 0;
    if (!call_me_once(&once, NULL)) return (false);
    show_help();
    return (false);
}