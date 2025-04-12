#ifndef NODE_H
#define NODE_H

#include <stdlib.h>

typedef struct s_node {
    void            *data;
    struct s_node   *prev;
    struct s_node   *next;
} t_node;

t_node *node_update_neighbor_pointers(t_node *node);
t_node *node_isolate(t_node *node);

t_node *node_remove(t_node *node_to_remove);
void    node_destroy(t_node *node, void (*free_data)(void *));
void    node_delete(t_node *node_to_delete, void (*free_data)(void *));

t_node *node_new(void *data);

#endif // NODE_H
