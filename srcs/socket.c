#include <unistd.h>
#include <netinet/in.h>

#include "socket.h"

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

t_error init_sock(int *sock)
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

void clean_sock(int sock)
{
    close(sock);
}