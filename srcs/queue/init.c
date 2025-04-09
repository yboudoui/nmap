#include "queue.h"

t_queue* queue_init()
{
    t_queue *list = malloc(sizeof(t_queue));
    if (!list) return NULL;
    
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    pthread_mutex_init(&list->lock, NULL);
    return list;
}