#include "pool.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct s_state {
    size_t          scan_index;
    int             current_port;
    bool            ip_available;
    struct in_addr  ip;
    t_arguments     *args;
    bool            finish;
} t_state;

static bool get_next_ip(t_state *state, t_task *task) {
    char line[INET_ADDRSTRLEN];

    if (state->finish) {
        return (false);
        // if (state->ip_available) {
        //     state->ip_available = false;
        //     return (true);
        // } else return (false);
    }

    // if (state->finish) {
    //     state->ip_available = false;
    //     return (false);
    // }

    switch (state->args->ip_list.cmd) {
    case CMD_IP: {
        // if (state->ip_available) {
        //     state->finish = true;
        //     // state->args->ip_list.cmd = NO_IPS;
        //     // state->ip_available = false;
        //     return (false);
        // }
        task->ip = state->args->ip_list.data.ip;
        state->ip_available = true;
        state->ip = state->args->ip_list.data.ip;
        state->finish = true;
        return (true);
    }
    case CMD_FILE: {
        if (!fgets(line, sizeof(line), state->args->ip_list.data.fs)) {
            fclose(state->args->ip_list.data.fs);
            state->ip_available = true;
            state->current_port = 0;
            return (false);
        }
        line[strcspn(line, "\n")] = 0;
        if (inet_pton(AF_INET, line, &task->ip) == 1) {
            return (true); 
        } else {
            fprintf(stderr, "Invalid IP address format: %s\n", line); // Error handling
            state->current_port = 0;

            return false; // Invalid IP format
        }
    }
    default: {
        state->current_port = 0;
        return (false);
    }
    }
}

static bool get_next_port(t_state *state, t_task *task) {    
    if (state->ip_available == false) return (false);

    if (state->current_port == 0) {
        state->current_port = state->args->port_range[START];
    }

    if (state->current_port <= state->args->port_range[END]) {
        task->port = state->current_port;
        state->current_port += 1;
        return (true);
    }
    state->current_port = 0;
    return (false);
}

static bool get_next_scan_type(t_state *state, t_task *task) {
    if (state->current_port == 0) return (false);
    
    static const t_scan_type    all[] =  {
        SCAN_SYN, SCAN_NULL, SCAN_ACK,
        SCAN_FIN, SCAN_XMAS, SCAN_UDP,
        SCAN_NONE,
    };
    while(all[state->scan_index] != SCAN_NONE) {
        if (state->args->scan_flags & all[state->scan_index]) {
            task->scan_flag = all[state->scan_index];
            state->scan_index += 1;
            return (true);
        }
        state->scan_index += 1;
    }
    state->scan_index = 0;
    return (false);
}

// #define PRINT_DEBUG
#ifdef PRINT_DEBUG
#define DEBUG(fmt , ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG(fmt , ...) do{}while(0)
#endif


static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static bool get_next_task(t_task *task, t_state *state) {
    pthread_mutex_lock(&mutex);

    DEBUG("try get_next_scan_type\n");

    if (!get_next_scan_type(state, task)) {
        DEBUG("try get_next_port\n");
        if (!get_next_port(state, task)) {
            DEBUG("try get_next_ip\n");
            DEBUG("available %d finish %d\n", state->ip_available, state->finish);
            
            if (!get_next_ip(state, task)) {
                state->ip_available = false;
                // state->finish = true;

                pthread_mutex_unlock(&mutex);
                return (false);
            }
            DEBUG("retry get_next_port\n");
            if (!get_next_port(state, task)) {
                pthread_mutex_unlock(&mutex);
                return (false);
            }
        } else {
            task->ip = state->ip;
        }
        DEBUG("retry get_next_scan_type\n");
        if (!get_next_scan_type(state, task)) {
            pthread_mutex_unlock(&mutex);
            return (false);
        }
    }
    task->ip = state->ip;
    task->port = state->current_port;
    pthread_mutex_unlock(&mutex);
    return (true);
}


#include <stdio.h>

static char* get_scan_flag_name(t_scan_type scan_type) {
    switch (scan_type){
    case SCAN_SYN:  return ("SCAN_SYN");
    case SCAN_NULL: return ("SCAN_NULL");
    case SCAN_ACK:  return ("SCAN_ACK");
    case SCAN_FIN:  return ("SCAN_FIN");
    case SCAN_XMAS: return ("SCAN_XMAS");
    case SCAN_UDP:  return ("SCAN_UDP");
    default: return (NULL);
    }
}

static void print_task(t_task task) {
    static int i = 1;
    char ip_str[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &task.ip, ip_str, sizeof(ip_str));
    printf("%d - %s:%d %s\n", i, ip_str, task.port, get_scan_flag_name(task.scan_flag)); 
    i += 1;
}

static pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;

static void* routine(void *data) {
    t_task      task = {};
    while (get_next_task(&task, data)) {

        pthread_mutex_lock(&mutex_print);
        print_task(task);
        pthread_mutex_unlock(&mutex_print);
    }
    return (NULL);
}

static bool run_pool(size_t threads_count, void *data) {
    pthread_t	*threads = calloc(threads_count, sizeof(pthread_t));
    if (threads == NULL) return (false);
    for(size_t i = 0; i < threads_count; i++) {
        pthread_create(&threads[i], NULL, routine, data);
    }
    for(size_t i = 0; i < threads_count; i++) {
		pthread_join(threads[i], NULL);
    }
    return (free(threads), true);
}

bool    pool(t_arguments *args) {
    t_state pool_state = {
        .args = args
    };
    return (run_pool(args->speedup, &pool_state));
}