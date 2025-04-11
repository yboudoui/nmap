#include "pool/pool.h"

static bool get_next_ip(t_state *state, t_task *task) {
    char line[INET_ADDRSTRLEN];

    if (state->finish) {
        return (false);
    }

    switch (state->args->ip_list.cmd) {
    case CMD_IP: {
        task->dst.ip = state->args->ip_list.data.ip;
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
        if (inet_pton(AF_INET, line, &task->dst.ip) == 1) {
            return (true); 
        } else {
            fprintf(stderr, "Invalid IP address format: %s\n", line); // TODO: Error handling
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
        task->dst.port = state->current_port;
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
bool get_next_task(t_task *task, t_state *state)
{
    pthread_mutex_lock(&mutex);

    DEBUG("try get_next_scan_type\n");

    if (!get_next_scan_type(state, task)) {
        DEBUG("try get_next_port\n");
        if (!get_next_port(state, task)) {
            DEBUG("try get_next_ip\n");
            DEBUG("available %d finish %d\n", state->ip_available, state->finish);
            
            if (!get_next_ip(state, task)) {
                state->ip_available = false;
                pthread_mutex_unlock(&mutex);
                return (false);
            }
            DEBUG("retry get_next_port\n");
            if (!get_next_port(state, task)) {
                pthread_mutex_unlock(&mutex);
                return (false);
            }
        } else {
            task->dst.ip = state->ip;
        }
        DEBUG("retry get_next_scan_type\n");
        if (!get_next_scan_type(state, task)) {
            pthread_mutex_unlock(&mutex);
            return (false);
        }
    }
    task->dst.ip = state->ip;
    task->dst.port = state->current_port;
    pthread_mutex_unlock(&mutex);
    return (true);
}