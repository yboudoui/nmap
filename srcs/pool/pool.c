#include "pool/pool.h"
#include "utils/threads.h"

void    *memdup(void *src, size_t size)
{
    uint8_t *mem = calloc(1, size);
    if (!mem) return (NULL);
    return (memcpy(mem, src, size));
}

static void* routine(void *user_data)
{
    t_pcap_data_wraper  *wrapper = user_data;
    t_task_state        *state = wrapper->user_data;
    t_nmap_data         *nd = state->user_data;
    t_task              task = {0};

    struct sockaddr_in  dest = {
        .sin_family = AF_INET,
    };
    uint8_t     packet_buf[IP_MAXPACKET] = {0};
    uint32_t    packet_len = 0;

    while (get_next_task(&task, state)) {

        t_task *cpy = memdup(&task, sizeof(t_task));
        queue_emplace_front(nd->queue.in, cpy);

        dest.sin_addr.s_addr = task.ip;

        packet_len = task.packet_builder(
            packet_buf,
            wrapper->device_addr.s_addr,
            task.ip, task.port
        );

        // Send the packet
        int sent = sendto(nd->sock,
            packet_buf, packet_len,
            0,
            (struct sockaddr *)&dest, sizeof(dest)
        );
        if (sent < 0) {
            printf("Error on sendto\n");
        }

        print_task(task);
    }
    return (NULL);
}

t_error send_packets_pool(t_pcap_data_wraper *wrapper)
{
    t_error             error = 0;
    t_task_state        *state = wrapper->user_data;
    t_nmap_data         *data = state->user_data;

    error = threads_pool(data->args.speedup, routine, wrapper);
    if (error) {
        return (err_wrap(&error, 1, "unable send or capture packets"));
    }
    return (error);
}
