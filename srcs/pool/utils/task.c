#include "pool/pool.h"
#include "nmap_data.h"

#include <string.h>

static bool get_next_ip(t_task_state *state, t_task *task)
{
    char                line[INET_ADDRSTRLEN];
    t_nmap_data         *nmap_data = state->user_data;
    struct s_ip_list    ip_list = nmap_data->args.ip_list;

    if (state->finish) {
        return (false);
    }

    switch (ip_list.cmd) {
    case CMD_IP: {
        task->ip = ip_list.data.ip;
        state->ip_available = true;
        state->ip = ip_list.data.ip;
        state->finish = true;
        return (true);
    }
    case CMD_FILE: {
        if (!fgets(line, sizeof(line), ip_list.data.fs)) {
            fclose(ip_list.data.fs);
            state->ip_available = true;
            state->current_port = 0;
            return (false);
        }
        line[strcspn(line, "\n")] = 0;
        if (inet_pton(AF_INET, line, &task->ip) == 1) {
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

static bool get_next_port(t_task_state *state, t_task *task)
{
    t_nmap_data *nmap_data = state->user_data;

    if (state->ip_available == false) {
        return (false);
    }

    if (state->current_port == 0) {
        state->current_port = nmap_data->args.port_range[START];
        task->port = state->current_port;
        return (true);
    } else if (state->current_port < nmap_data->args.port_range[END]) {
        task->port = state->current_port;
        state->current_port += 1;
        return (true);
    }

    state->current_port = 0;
    return (false);
}

static bool get_next_scan_type(t_task_state *state, t_task *task)
{
    t_nmap_data *nmap_data = state->user_data;

    if (state->current_port == 0) {
        return (false);
    }
    
    static const t_scan_type    all[] =  {
        SCAN_SYN, SCAN_NULL, SCAN_ACK,
        SCAN_FIN, SCAN_XMAS, SCAN_UDP,
        NO_SCAN_TYPE,
    };
    while(all[state->scan_index] != NO_SCAN_TYPE) {
        if (IS(nmap_data->args.scan_type, all[state->scan_index])) {
            task->scan_flag = all[state->scan_index];
            state->scan_index += 1;
            return (true);
        }
        state->scan_index += 1;
    }
    state->scan_index = 0;
    return (false);
}

#include "utils/debug.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
bool get_next_task(t_task *task, t_task_state *state)
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