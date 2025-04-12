#include "utils/node.h"

/**
 * Destroys a node and optionally its data
 * @param node The node to destroy
 * @param free_data Function to free node data (can be NULL)
 */
void node_destroy(t_node *node, void (*free_data)(void *))
{
    if (!node) {
        return;
    }
    
    if (free_data) {
        free_data(node->data);
    }
    free(node);
}

/**
 * Updates neighboring nodes' pointers to bypass the given node
 * @param node The node to be removed from the chain
 * @return The updated neighbore nodes' pointer
 */
t_node *node_update_neighbor_pointers(t_node *node)
{
    if (!node) {
        return (NULL);
    };

    // Update previous node's next pointer
    if (node->prev) {
        node->prev->next = node->next;
    }

    // Update next node's previous pointer
    if (node->next) {
        node->next->prev = node->prev;
    }
    return (node);
}

/**
 * Isolates a node by nullifying its pointers
 * @param node The node to isolate
 * @return The isolated node (for chaining)
 */
t_node *node_isolate(t_node *node)
{
    if (!node) {
        return (NULL);
    }
    node->prev = NULL;
    node->next = NULL;
    return (node);
}

/**
 * Removes a node from the doubly linked list (does NOT free memory)
 * @param node_to_remove The node to remove from the list
 * @return The removed node (caller must handle memory)
 */
t_node *node_remove(t_node *node_to_remove)
{
    return (node_isolate(node_update_neighbor_pointers(node_to_remove)));
}

/**
 * Completely deletes a node and optionally its data
 * @param node_to_delete The node to delete
 * @param free_data Function to free the node's data (can be NULL)
 */
void node_delete(t_node *node_to_delete, void (*free_data)(void *))
{
    if (!node_to_delete) {
        return;
    }
    node_destroy(node_remove(node_to_delete), free_data);
}

/**
 * Creates a new node with given data
 * @param data The data to store in the node
 * @return Pointer to new node, or NULL on failure
 */
t_node *node_new(void *data)
{
    t_node *new_node = malloc(sizeof(t_node));
    if (!new_node) return NULL;
    
    new_node->data = data;
    new_node->prev = NULL;
    new_node->next = NULL;
    return new_node;
}