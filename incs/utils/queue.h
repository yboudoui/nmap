#ifndef QUEUE_H
#define QUEUE_H

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

typedef struct s_node {
    void            *data;
    struct s_node   *prev;
    struct s_node   *next;
} t_node;

typedef struct {
    t_node *head;
    t_node *tail;
    pthread_mutex_t lock;
    int count;
} t_queue;

void        queue_add(t_queue *list, void *data);
int         queue_count(t_queue *list);
void        queue_destroy(t_queue *list);

t_node*     queue_find(t_queue *list, int port);
t_queue*    queue_init(void);
void        queue_print(t_queue *list, void (*fp_print_node_data)(void*));
int         queue_remove(t_queue *list, bool (*fp_equal_node_data)(void*, void*), void *data);

#endif // QUEUE_H
