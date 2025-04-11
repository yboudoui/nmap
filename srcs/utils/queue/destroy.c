#include "queue.h"

void queue_destroy(t_queue *list)
{
    pthread_mutex_lock(&list->lock);
    
    t_node *current = list->head;
    while (current != NULL) {
        t_node *next = current->next;
        free(current);
        current = next;
    }
    
    pthread_mutex_unlock(&list->lock);
    pthread_mutex_destroy(&list->lock);
    free(list);
}