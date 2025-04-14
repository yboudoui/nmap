#ifndef NMAP_DATA_H
#define NMAP_DATA_H

#include "utils/queue.h"
#include "utils/error.h"

#include "cli/cli.h"
#include "socket.h"

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

#include "pool/pool.h"
bool    nmap_is_input_empty(t_nmap_data *nd);
bool    nmap_have_ip(t_nmap_data *nd, in_addr_t *ip);
void    nmap_push_task(t_nmap_data *nd, t_task task);
void    nmap_update(t_nmap_data *nd, void *data);

#endif // NMAP_DATA_H