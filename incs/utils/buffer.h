#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
typedef struct s_buffer {
    uint8_t     *data;
    uint64_t    size;
    uint64_t    capacity;
    uint64_t    count;
} t_buffer;

#endif // BUFFER_H