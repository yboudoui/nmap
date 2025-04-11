#include "utils/queue.h"

// TODO: review it
int queue_remove(t_queue *list, bool (*fp_equal_node_data)(void*, void*), void *data)
{
    pthread_mutex_lock(&list->lock);
    
    t_node *current = list->head;
    while (current != NULL) {
        if (fp_equal_node_data(current->data, data))
        {
            if (current->prev != NULL) {
                current->prev->next = current->next;
            } else {
                list->head = current->next;
            }
            
            if (current->next != NULL) {
                current->next->prev = current->prev;
            } else {
                list->tail = current->prev;
            }
            
            free(current);
            list->count--;
            pthread_mutex_unlock(&list->lock);
            return 1; // Success
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&list->lock);
    return 0; // Not found
}