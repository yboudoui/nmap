#include "utils/queue.h"

void queue_print(t_queue *list, void (*fp_print_node_data)(void*))
{
    pthread_mutex_lock(&list->lock);
    
    t_node *current = list->head;
    while (current != NULL) {
        fp_print_node_data(current->data);
        current = current->next;
    }
    
    pthread_mutex_unlock(&list->lock);
}