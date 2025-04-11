#include "cli/utils.h"

void show_help(void) {
    static size_t once = 0;
    call_me_once(&once, NULL);

    printf("help\n");
    printf("--help Print this help screen\n");
    printf("--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n"); // TODO: fix ports
    printf("--ip ip addresses to scan in dot format\n");
    printf("--file File name containing IP addresses to scan,\n");
    printf("--speedup [250 max] number of parallel threads to use\n");
    printf("--scan SYN/NULL/FIN/XMAS/ACK/UDP\n");
    printf("--output-format RAW/CSV/PRETTY\n");
}

bool help(t_arg_helper *args) {
    (void)args;
    static size_t once = 0;
    if (!call_me_once(&once, NULL)) return (false);
    show_help();
    return (false);
}