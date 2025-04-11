#include "queue.h"

// TODO: review it
t_node* queue_find(t_queue *list, int port)
{
    pthread_mutex_lock(&list->lock);
    
    t_node *current = list->head;
    while (current != NULL) {
        // if (current->port == port) {
        if (1) {
            pthread_mutex_unlock(&list->lock);
            return current;
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&list->lock);
    return NULL;
}