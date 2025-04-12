#include "pool/pool.h"
#include "utils/threads.h"

void    *memdup(void *src, size_t size)
{
    uint8_t *mem = calloc(1, size);
    if (!mem) return (NULL);
    return (memcpy(mem, src, size));
}

static void* routine(void *data)
{
    t_task_state     *state = data;
    t_nmap_data *nd = state->user_data;

    t_task              task = {0};

    struct sockaddr_in  dest = {
        .sin_family = AF_INET,
    };
    uint8_t     packet_buf[4096] = {0};
    uint32_t    packet_len = 0;

    while (get_next_task(&task, state)) {

        t_task *cpy = memdup(&task, sizeof(t_task));
        queue_emplace_front(nd->queue.in, cpy);

        dest.sin_addr.s_addr = task.dst.ip;

        // packet_len = task.packet_builder(packet_buf, (t_req){ .dst = task.dst, .src = src });
        packet_len = task.packet_builder(packet_buf, (t_req){ .dst = task.dst});
        
        // Send the packet
        int sent = sendto(nd->sock, packet_buf, packet_len, 0, (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {}

        // print_task(task);
    }
    return (NULL);
}

t_error send_packets_pool(void *user_data)
{
    t_error         error = 0;
    t_task_state    *state = user_data;
    t_nmap_data     *data = state->user_data;

    error = threads_pool(data->args.speedup, routine, state);
    if (error) {
        return (err_wrap(&error, 1, "unable send or capture packets"));
    }
    return (error);
}
