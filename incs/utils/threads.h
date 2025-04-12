#ifndef THREADS_H
#define THREADS_H

#include "utils/error.h"

t_error threads_pool(size_t count, void *(*user_routine)(void *),  void *user_data);

#endif // THREADS_H