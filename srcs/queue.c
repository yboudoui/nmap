#include <stdio.h>
#include <stdlib.h>

struct s_data {
    int port;
    int status;           // 0=closed, 1=open, 2=filtered
    char type;           // 'T'=TCP, 'U'=UDP
};