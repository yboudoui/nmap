#include "nmap_data.h"

t_error init_nmap_data(t_nmap_data *nmap_data, int ac, char *av[])
{
    t_error error = 0;

    if (!parse_argument(&nmap_data->args, ac, av)) {
        err_wrap(&error, 1, "parsing argument");
        return (error);
    }

    error = init_sock(&nmap_data->sock);
    if (error) {
        err_wrap(&error, 2, "unable to create a socket for sending packets");
        return (error);
    }
    
    if (!queue_init(&nmap_data->queue.in)) {
        clean_nmap_data(nmap_data);
        err_wrap(&error, 3, "unable to allocate the queue");
        return (error);
    }

    if (!queue_init(&nmap_data->queue.out)) {
        clean_nmap_data(nmap_data);
        err_wrap(&error, 4, "unable to allocate the queue");
        return (error);
    }
    return (0);
}

void    clean_nmap_data(t_nmap_data *nmap_data)
{
    clean_sock(nmap_data->sock);
    queue_destroy(nmap_data->queue.in, free);
    queue_destroy(nmap_data->queue.out, free);
}