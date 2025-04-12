#include "nmap_error.h"

t_error err_wrap(t_error *error, t_error wrap, const char *msg)
{
    (*error) *= 10;
    (*error) += wrap;
    fprintf(stderr, "ERROR [%d]: %s\n", *error, msg);
    return (*error);
}