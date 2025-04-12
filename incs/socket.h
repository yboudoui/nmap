#ifndef SOCKET_H
#define SOCKET_H

#include "nmap_error.h"

t_error init_sock(int *sock);
void    clean_sock(int sock);

#endif // SOCKET_H
