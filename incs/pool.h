#ifndef POOL_H
#define POOL_H

#include "cli.h"

typedef struct s_task {
    struct in_addr  ip;
    t_scan_type     scan_flag;
    int             port;
} t_task;

typedef void    (t_fp_callback)(void);
bool pool(t_arguments *args, t_fp_callback callback);

#endif // POOL_H
