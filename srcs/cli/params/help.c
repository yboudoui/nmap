#include "cli_utils.h"

void show_help(void) {
    printf("help\n");
    printf("--help\n");
    printf("--ip <ip address>\n");
    printf("--port <value> or <min:max>\n");
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
    CHECK_ARGS(args, .arg_name = "--help");
    show_help();
    return (false);
}