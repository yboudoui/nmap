#ifndef NMAP_DATA_H
#define NMAP_DATA_H

#include "cli/cli.h"
#include "utils/queue.h"
#include "socket.h"
#include "utils/error.h"

typedef struct s_nmap_data {
    t_arguments args;
    struct {
        t_queue *in;
        t_queue *out;
    } queue;
    int         sock;
} t_nmap_data;

t_error init_nmap_data(t_nmap_data *nmap_data, int ac, char *av[]);
void    clean_nmap_data(t_nmap_data *nmap_data);

#endif // NMAP_DATA_H