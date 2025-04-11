#include "utils/queue.h"

int queue_count(t_queue *list)
{
    pthread_mutex_lock(&list->lock);
    int count = list->count;
    pthread_mutex_unlock(&list->lock);
    return count;
}