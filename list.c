#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// Structure for list nodes
typedef struct ListNode {
    int port;
    int status;           // 0=closed, 1=open, 2=filtered
    char type;           // 'T'=TCP, 'U'=UDP
    struct ListNode *prev;
    struct ListNode *next;
} ListNode;

// Structure for the thread-safe list
typedef struct {
    ListNode *head;
    ListNode *tail;
    pthread_mutex_t lock;
    int count;
} ThreadSafeList;

// Initialize an empty list
ThreadSafeList* list_init() {
    ThreadSafeList *list = malloc(sizeof(ThreadSafeList));
    if (!list) return NULL;
    
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    pthread_mutex_init(&list->lock, NULL);
    return list;
}

// Add a new node to the list (thread-safe)
void list_add(ThreadSafeList *list, int port, int status, char type) {
    ListNode *new_node = malloc(sizeof(ListNode));
    if (!new_node) return;
    
    new_node->port = port;
    new_node->status = status;
    new_node->type = type;
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

// Remove a node from the list (thread-safe)
int list_remove(ThreadSafeList *list, int port) {
    pthread_mutex_lock(&list->lock);
    
    ListNode *current = list->head;
    while (current != NULL) {
        if (current->port == port) {
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

// Find a node in the list (thread-safe)
ListNode* list_find(ThreadSafeList *list, int port) {
    pthread_mutex_lock(&list->lock);
    
    ListNode *current = list->head;
    while (current != NULL) {
        if (current->port == port) {
            pthread_mutex_unlock(&list->lock);
            return current;
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&list->lock);
    return NULL;
}

// Get list count (thread-safe)
int list_count(ThreadSafeList *list) {
    pthread_mutex_lock(&list->lock);
    int count = list->count;
    pthread_mutex_unlock(&list->lock);
    return count;
}

// Print the list contents (thread-safe)
void list_print(ThreadSafeList *list) {
    pthread_mutex_lock(&list->lock);
    
    printf("Port Scan Results (%d items):\n", list->count);
    ListNode *current = list->head;
    while (current != NULL) {
        printf("Port %5d (%c): ", current->port, current->type);
        switch(current->status) {
            case 0: printf("CLOSED\n"); break;
            case 1: printf("OPEN\n"); break;
            case 2: printf("FILTERED\n"); break;
            default: printf("UNKNOWN\n");
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&list->lock);
}

// Destroy the list and free memory (thread-safe)
void list_destroy(ThreadSafeList *list) {
    pthread_mutex_lock(&list->lock);
    
    ListNode *current = list->head;
    while (current != NULL) {
        ListNode *next = current->next;
        free(current);
        current = next;
    }
    
    pthread_mutex_unlock(&list->lock);
    pthread_mutex_destroy(&list->lock);
    free(list);
}

// Example usage
int main() {
    // Create a thread-safe list
    ThreadSafeList *results = list_init();
    
    // Add items from multiple threads (in real usage)
    list_add(results, 80, 1, 'T');    // TCP port 80 open
    list_add(results, 22, 1, 'T');    // TCP port 22 open
    list_add(results, 53, 1, 'U');    // UDP port 53 open
    list_add(results, 8080, 0, 'T');  // TCP port 8080 closed
    
    // Print results
    list_print(results);
    
    // Find a specific port
    ListNode *found = list_find(results, 22);
    if (found) {
        printf("\nFound port 22: %s\n", found->status == 1 ? "OPEN" : "CLOSED");
    }
    
    // Remove an item
    list_remove(results, 53);
    printf("\nAfter removing port 53:\n");
    list_print(results);
    
    // Clean up
    list_destroy(results);
    
    return 0;
}