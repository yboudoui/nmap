#include "pool/pool.h"
#include "utils/threads.h"
#include "utils/buffer.h"
#include "nmap_data.h"

#include "packet/builder.h"
#include <string.h>
#include <errno.h>
#include "utils/debug.h"

bool    send_packet(int sock, t_buffer *buffer, in_addr_t dst_ip)
{
    int                 sent;
    struct sockaddr_in  dst;
        
    dst.sin_family = AF_INET,
    dst.sin_addr.s_addr = dst_ip,

    sent = sendto(sock, buffer->data, buffer->count, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (sent >= 0) {
        return (true);
    }
    printf("send_packet error: %s\n", strerror(errno));
    return (false);
}
#include <arpa/inet.h>
#include <stdio.h>
static void* routine(void *user_data)
{
    t_pcap_data_wraper  *wrapper = user_data;
    t_task_state        *state = wrapper->user_data;
    t_nmap_data         *nd = state->user_data;
    t_task              task = {0};

    uint8_t             packet_buf[IP_MAXPACKET];
    t_packet_builder_args builder = {
        .buffer     = {
            .data       = packet_buf,
            .size       = sizeof(uint8_t),
            .capacity   = IP_MAXPACKET,
        },
        .src_ip     = wrapper->device_addr.s_addr,
    };
    while (get_next_task(&task, state)) {
        WITH_DEBUG(1) {
            print_task(task);
        }
        builder.dst_ip     = task.ip,
        builder.dst_port   = task.port,
        builder.scan_type  = task.scan_flag,
        build_packet(&builder);
        if(send_packet(nd->sock, &builder.buffer, task.ip)) {
            nmap_push_task(nd, task);
        }
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
        return (err_wrap(&error, 1, "unable send packets"));
    }
    return (error);
}
