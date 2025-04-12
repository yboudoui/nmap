#include "pool/pool.h"

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
        task->dst.ip = ip_list.data.ip;
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

static bool get_next_port(t_task_state *state, t_task *task)
{
    t_nmap_data *nmap_data = state->user_data;

    if (state->ip_available == false) {
        return (false);
    }

    if (state->current_port == 0) {
        state->current_port = nmap_data->args.port_range[START];
    }

    if (state->current_port <= nmap_data->args.port_range[END]) {
        task->dst.port = state->current_port;
        state->current_port += 1;
        return (true);
    }
    state->current_port = 0;
    return (false);
}

static t_fp_packet_builder switch_packet_builder(t_scan_type type)
{
    switch (type)
    {
    case SCAN_SYN:
        return (syn_packet);
    case SCAN_NULL:
        return (null_packet);
    case SCAN_ACK:
        return (ack_packet);
    case SCAN_FIN:
        return (fin_packet);
    case SCAN_XMAS:
        return (xmas_packet);
    case SCAN_UDP:
        return (udp_packet);
    default:
        return (NULL);
    }
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
        SCAN_NONE,
    };
    while(all[state->scan_index] != SCAN_NONE) {
        if (nmap_data->args.scan_flags & all[state->scan_index]) {
            task->scan_flag = all[state->scan_index];
            task->packet_builder = switch_packet_builder(task->scan_flag);
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