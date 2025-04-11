#include "pool/pool.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct s_state {
    size_t          scan_index;
    int             current_port;
    bool            ip_available;
    in_addr_t  ip;
    t_arguments     *args;
    bool            finish;
} t_state;