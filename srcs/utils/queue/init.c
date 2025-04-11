#include "utils/queue.h"

t_queue* queue_init(void)
{
    t_queue *list = calloc(1, sizeof(t_queue));
    if (list) pthread_mutex_init(&list->lock, NULL);
    return (list);
}