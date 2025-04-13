#include "utils/queue.h"

/**
 * Updates queue head/tail pointers after node removal
 * @param queue The queue to update
 * @param removed_node The node that was just removed
 */
void    update_queue_ends(t_queue *queue, t_node *removed_node)
{
    if (!queue || !removed_node) {
        return ;
    }
    if (removed_node == queue->head) {
        queue->head = removed_node->next;
    }
    if (removed_node == queue->tail) {
        queue->tail = removed_node->prev;
    }
}

/**
 * Thread-safe queue removal using remove_node()
 * @param queue The queue to remove from
 * @param node_to_remove The node to remove
 * @return The removed node (or NULL if not found)
 */
t_node  *queue_remove_node(t_queue *queue, t_node *node_to_remove)
{
    if (!queue || !node_to_remove) {
        return NULL;
    }

    pthread_mutex_lock(&queue->lock);
    
    t_node *found_node = NULL;
    for (t_node *current = queue->head; current; current = current->next) {
        if (current == node_to_remove) {
            found_node = current;
            update_queue_ends(queue, node_remove(found_node));
            queue->count -= 1;
            break;
        }
    }

    pthread_mutex_unlock(&queue->lock);
    return (found_node);
}

/**
 * Completely deletes a node from the thread-safe queue
 * @param queue The queue to delete from
 * @param node_to_delete The node to delete
 * @param free_data Function to free node data (can be NULL)
 */
void    queue_delete_node(t_queue *queue, t_node *node_to_delete, void (*free_data)(void *))
{
    node_destroy(queue_remove_node(queue, node_to_delete), free_data);
}

/**
 * Completely destroys a queue and all its nodes
 * @param queue The queue to destroy (pointer will be invalid after call)
 * @param free_data Function to free node data (NULL uses standard free())
 */
void    queue_destroy(t_queue *list, void (free_data)(void *))
{
    if (!list) {
        return;
    }

    pthread_mutex_lock(&list->lock);
    
    t_node *current = list->head;
    t_node *next = NULL;
    while (current) {
        next = current->next;
        node_delete(current, free_data);
        current = next;
    }

    pthread_mutex_unlock(&list->lock);
    pthread_mutex_destroy(&list->lock);
    free(list);
}

/**
 * Removes and returns the node at the head of the queue
 * @param queue The queue to modify
 * @return The removed node (caller must handle memory) or NULL if empty
 */
t_node  *queue_pop_front(t_queue *queue)
{
    if (!queue) {
        return (NULL);
    }

    pthread_mutex_lock(&queue->lock);
    
    t_node *removed = NULL;
    if (queue->head) {
        removed = queue->head;
        queue->head = removed->next;
        
        if (queue->head) {
            queue->head->prev = NULL;
        } else {
            queue->tail = NULL; // Queue is now empty
        }
        
        queue->count -= 1;
        node_isolate(removed);
    }

    pthread_mutex_unlock(&queue->lock);
    return (removed);
}

/**
 * Removes and returns the node at the tail of the queue
 * @param queue The queue to modify
 * @return The removed node (caller must handle memory) or NULL if empty
 */
t_node  *queue_pop_back(t_queue *queue)
{
    if (!queue) {
        return (NULL);
    }

    pthread_mutex_lock(&queue->lock);
    
    t_node *removed = NULL;
    if (queue->tail) {
        removed = queue->tail;
        queue->tail = removed->prev;
        
        if (queue->tail) {
            queue->tail->next = NULL;
        } else {
            queue->head = NULL; // Queue is now empty
        }
        
        queue->count -= 1;
        node_isolate(removed);
    }

    pthread_mutex_unlock(&queue->lock);
    return (removed);
}

/**
 * Removes and deletes the head node
 * @param queue The queue to modify
 * @param free_data Function to free node data (NULL uses no cleanup)
 */
void    queue_delete_front(t_queue *queue, void (*free_data)(void *))
{
    node_destroy(queue_pop_front(queue), free_data);
}

/**
 * Removes and deletes the tail node
 * @param queue The queue to modify
 * @param free_data Function to free node data (NULL uses no cleanup)
 */
void    queue_delete_back(t_queue *queue, void (*free_data)(void *))
{
    node_destroy(queue_pop_back(queue), free_data);
}

/**
 * Adds a node to the front of the queue
 * @param queue The queue to modify
 * @param new_node The node to add
 * @return The added node
 */
t_node  *queue_push_front(t_queue *queue, t_node *new_node)
{
    if (!queue || !new_node) {
        return (NULL);
    }

    node_isolate(new_node); // Ensure clean state
    pthread_mutex_lock(&queue->lock);

    if (queue->head) {
        new_node->next = queue->head;
        queue->head->prev = new_node;
    } else {
        queue->tail = new_node; // First node in empty queue
    }
    
    queue->head = new_node;
    queue->count += 1;
    pthread_mutex_unlock(&queue->lock);
    return (new_node);
}

/**
 * Adds a node to the back of the queue
 * @param queue The queue to modify
 * @param new_node The node to add
 * @return The added node
 */
t_node  *queue_push_back(t_queue *queue, t_node *new_node)
{
    if (!queue || !new_node) {
        return (NULL);
    }

    node_isolate(new_node); // Ensure clean state
    pthread_mutex_lock(&queue->lock);

    if (queue->tail) {
        new_node->prev = queue->tail;
        queue->tail->next = new_node;
    } else {
        queue->head = new_node; // First node in empty queue
    }
    
    queue->tail = new_node;
    queue->count += 1;
    pthread_mutex_unlock(&queue->lock);
    return (new_node);
}

/**
 * Creates and adds a new node to front
 * @param queue The queue to modify
 * @param data The data to store
 * @return Pointer to new node, or NULL on failure
 */
t_node  *queue_emplace_front(t_queue *queue, void *data)
{
    return (queue_push_front(queue,  node_new(data)));
}

/**
 * Creates and adds a new node to back
 * @param queue The queue to modify
 * @param data The data to store
 * @return Pointer to new node, or NULL on failure
 */
t_node  *queue_emplace_back(t_queue *queue, void *data)
{
    return (queue_push_back(queue,  node_new(data)));
}

/**
 * @brief Gets the current number of nodes in the thread-safe queue
 * 
 * @param queue Pointer to the queue structure (must not be NULL)
 * @return size_t The current node count (0 if queue is empty or invalid)
 * 
 * @note This function is thread-safe and provides atomic access to the count
 * @warning The queue pointer must be properly initialized - undefined behavior if NULL
 * 
 * @example
 *   size_t items = queue_count(my_queue);
 *   printf("Queue contains %zu items\n", items);
 */
size_t  queue_count(t_queue *queue)
{
    if (!queue) return 0;  // Defensive programming
    
    pthread_mutex_lock(&queue->lock);
    size_t count = queue->count;  // Atomic read
    pthread_mutex_unlock(&queue->lock);
    
    return count;
}

/**
 * @brief Finds a node by its memory address in the queue
 * @param queue The queue to search (must not be NULL)
 * @param node_ptr The exact node pointer to find
 * @return Pointer to the found node, or NULL if not found
 *
 * @note This performs an exact pointer comparison, not data comparison
 * @warning The node_ptr must be a pointer that was previously in the queue
 * @threadsafe Uses queue's internal mutex for thread safety
 *
 * @example
 *   t_node *found = queue_find_node(queue, suspect_node);
 *   if (found) { // handle found node  }
 */
t_node *queue_find_node(t_queue *queue, t_node *node_ptr)
{
    if (!queue || !node_ptr) return NULL;

    pthread_mutex_lock(&queue->lock);
    t_node *current = queue->head;
    while (current) {
        if (current == node_ptr) break;
        current = current->next;
    }
    pthread_mutex_unlock(&queue->lock);
    return current;
}

/**
 * @brief Finds the first node containing matching data
 * @param queue The queue to search (must not be NULL)
 * @param data_ptr The data to compare against
 * @param cmp Comparison function (return 0 for match)
 * @return Pointer to first matching node, or NULL if not found
 *
 * @note The cmp function should return 0 when items match
 * @warning cmp function must be thread-safe if queue is shared
 * @threadsafe Uses queue's internal mutex for thread safety
 *
 * @example
 *   // Find node containing "target_value"
 *   t_node *found = queue_find_data(queue, target_value, 
 *       [](void *a, void *b){ return strcmp(a,b); });
 */
t_node *queue_find_data(t_queue *queue, void *data_ptr, int (*cmp)(void *, void *))
{
    if (!queue || !cmp) {
        return (NULL);
    }

    pthread_mutex_lock(&queue->lock);
    t_node *current = queue->head;
    while (current) {
        if (cmp(current->data, data_ptr) == 0) break;
        current = current->next;
    }
    pthread_mutex_unlock(&queue->lock);
    return (current);
}

/**
 * @brief Iterates through queue forward (head to tail)
 * @param queue Queue to iterate
 * @param context User context pointer
 * @param func Callback (return false to stop iteration)
 * 
 * @note Callback receives (data, context) and returns continue flag
 * @threadsafe Locks queue during entire iteration
 */
void    queue_iter_forward(t_queue *queue, void *context, void (*func)(void *data, void *ctx))
{
    if (!queue || !func) {
        return;
    }

    pthread_mutex_lock(&queue->lock);
    t_node *current = queue->head;
    
    while (current) {
        func(current->data, context);
        current = current->next;
    }
    
    pthread_mutex_unlock(&queue->lock);
    return;
}

/**
 * @brief Iterates through queue backward (tail to head)
 * @param queue Queue to iterate
 * @param context User context pointer
 * @param func Callback (return false to stop iteration)
 */
void    queue_iter_backward(t_queue *queue, void *context, void (*func)(void *data, void *ctx))
{
    if (!queue || !func) {
        return;
    }

    pthread_mutex_lock(&queue->lock);
    t_node *current = queue->tail;
    
    while (current) {
        func(current->data, context);
        current = current->prev;
    }
    
    pthread_mutex_unlock(&queue->lock);
    return;
}

/**
 * @brief Initializes a new thread-safe queue structure
 * 
 * @param queue Double pointer to the queue to initialize (will be allocated)
 * @return true if initialization succeeded, false on failure
 * 
 * @details This function:
 * - Allocates memory for the queue structure
 * - Initializes all members to zero/NULL
 * - Prepares the internal mutex for thread-safe operations
 * 
 * @note The caller must destroy the queue using queue_destroy() when done
 * @warning Passing an uninitialized pointer will cause memory leaks
 * @warning Never call this on an already initialized queue
 * 
 * @errors Possible failure cases:
 * - Memory allocation failure (returns false)
 * - Mutex initialization failure (returns false after cleanup)
 * 
 * @threadsafe This initialization routine is thread-safe for first-time calls
 * 
 * @example
 * t_queue *q;
 * if (!queue_init(&q)) {
 *     // Handle error
 * }
 * // Use queue...
 * queue_destroy(&q);
 */
bool queue_init(t_queue **queue)
{
    if (!queue) {
        return (false);
    }

    (*queue) = calloc(1, sizeof(t_queue));
    if (!(*queue)) {
        return (false);
    }

    if (pthread_mutex_init(&(*queue)->lock, NULL) != 0) {
        free(*queue);
        (*queue) = NULL;
        return (false);
    }
    return (true);
}