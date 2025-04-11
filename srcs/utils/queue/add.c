#include "queue.h"

void queue_add(t_queue *list, void *data)
{
    t_node *new_node = malloc(sizeof(t_node));
    if (!new_node) return;
    
    new_node->data = data;
    new_node->prev = NULL;
    new_node->next = NULL;
    
    // Lock the mutex for thread safety
    pthread_mutex_lock(&list->lock);
    
    if (list->head == NULL) {
        // First element in the list
        list->head = new_node;
        list->tail = new_node;
    } else {
        // Append to the end of the list
        new_node->prev = list->tail;
        list->tail->next = new_node;
        list->tail = new_node;
    }
    list->count++;
    
    pthread_mutex_unlock(&list->lock);
}