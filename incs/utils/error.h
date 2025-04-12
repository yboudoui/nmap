#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>
#include <stdint.h>

typedef uint32_t t_error;
t_error err_wrap(t_error *error, t_error wrap, const char *msg);


#define WRAP_ERROR(t_error, code) ((t_error * 10) + code)
#endif // ERROR_H