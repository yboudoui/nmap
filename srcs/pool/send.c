#include "pool/pool.h"
#include "packet_capture/scan_type.h"

#include "unistd.h"

int send_raw_packet(struct s_addr src, t_task task)
{
    int                 sent;
    t_fp_packet_builder builder;
    uint8_t             packet_buf[4096] = {0};
    uint32_t            packet_len;    
    
    builder = switch_packet_builder(task.scan_flag);
    if (!builder) return (-1);
    packet_len = builder(
        packet_buf,
        (struct s_req){
            .dst = task.dst,
            .src = src,
        });

    // Create destination address structure
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = task.dst.ip;

    // Create raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return (-1);
    }

    // Tell the socket we're providing the IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)))
    {
        perror("setsockopt");
        close(sock);
        return -1;
    }

    // Send the packet
    sent = sendto(sock, packet_buf, packet_len, 0,
        (struct sockaddr *)&dest, sizeof(dest));
    
    if (sent < 0) {
        perror("sendto");
    }

    close(sock);
    return (sent);
}