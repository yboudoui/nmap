#include "nmap_data.h"

static t_error create_raw_socket(int *sock)
{
    t_error error = 0;

    (*sock) = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if ((*sock) < 0) {
        err_wrap(&error, 1, "unable to create a raw socket for sending packets");
        return (error);
    }
    return (error);
}

static t_error set_sock_option(int *sock)
{
    t_error error = 0;

    // Tell the socket we're providing the IP header
    int one = 1;
    if (setsockopt(*sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))) {
        err_wrap(&error, 1, "unable to set socket option for sending packets");
        return (error);
    }
    return (error);
}

static void clean_sock(int sock)
{
    close(sock);
}

static t_error init_sock(int *sock)
{
    t_error error = 0;

    error = create_raw_socket(sock);
    if (error) {
        error = WRAP_ERROR(error, 1);
        return (error);
    }
    error = set_sock_option(sock);
    if (error) {
        clean_sock(*sock);
        error = WRAP_ERROR(error, 2);
        return (error);
    }
    return (error);
}

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

bool    nmap_is_input_empty(t_nmap_data *nd)
{
    return (queue_count(nd->queue.in) == 0);
}

static int find_ip(void *data_queue, void *t)
{
    struct in_addr  *src = t;
    t_task          *task = data_queue;

    #if 0
    printf("src: %s\n", inet_ntoa(*src));
    printf("dst: %s\n", inet_ntoa((struct in_addr){task->ip}));
    printf("=> %d\n",(src->s_addr == task->ip));
    #endif
    return (!(src->s_addr == task->ip));
}

bool    nmap_have_ip(t_nmap_data *nd, in_addr_t *ip)
{
    t_node *found;
    
    found = queue_find_data(nd->queue.in, ip, find_ip);
    return (found != NULL);
}

#include <string.h>
static void    *memdup(void *src, size_t size)
{
    uint8_t *mem = calloc(1, size);
    if (!mem) return (NULL);
    return (memcpy(mem, src, size));
}

void    nmap_push_task(t_nmap_data *nd, t_task task)
{
    t_task *cpy = memdup(&task, sizeof(t_task));
    queue_emplace_front(nd->queue.in, cpy);
}

void    nmap_update(t_nmap_data *nd, void *data)
{
    (void)nd;
    (void)data;
    // queue_remove_node(nd->queue.in, found);
    // queue_push_front(data->user_data, result);
}