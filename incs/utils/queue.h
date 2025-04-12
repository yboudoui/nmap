#ifndef QUEUE_H
#define QUEUE_H

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include "node.h"

typedef struct {
    t_node          *head;
    t_node          *tail;
    pthread_mutex_t lock;
    size_t          count;
} t_queue;

void    update_queue_ends(t_queue *queue, t_node *removed_node);

bool    queue_init(t_queue **queue);

t_node  *queue_remove_node(t_queue *queue, t_node *node_to_remove);
void    queue_delete_node(t_queue *queue, t_node *node_to_delete, void (*free_data)(void *));

t_node  *queue_pop_front(t_queue *queue);
t_node  *queue_pop_back(t_queue *queue);

void    queue_delete_front(t_queue *queue, void (*free_data)(void *));
void    queue_delete_back(t_queue *queue, void (*free_data)(void *));

void    queue_destroy(t_queue *list, void (fp_free_data)(void *));

t_node  *queue_push_front(t_queue *queue, t_node *new_node);
t_node  *queue_push_back(t_queue *queue, t_node *new_node);

t_node *queue_emplace_front(t_queue *queue, void *data);
t_node *queue_emplace_back(t_queue *queue, void *data);

size_t queue_count(t_queue *queue);

t_node *queue_find_node(t_queue *queue, t_node *node_ptr);
t_node *queue_find_data(t_queue *queue, void *data_ptr, int (*cmp)(void *, void *));

void    queue_iter_forward(t_queue *queue, void *context, void (*func)(void *data, void *ctx));
void    queue_iter_backward(t_queue *queue, void *context, void (*func)(void *data, void *ctx));

#endif // QUEUE_H
