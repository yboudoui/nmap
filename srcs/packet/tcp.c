#include "packet.h"
// #define __FAVOR_BSD
#include <netinet/tcp.h>

static struct tcphdr *get_tcp_header(t_data *data)
{
    return (struct tcphdr *)(data->packet + 14 + data->iphdrlen);
}

void on_tcp(t_data data)
{
    unsigned short src_port, dst_port;
    struct tcphdr *tcp_header = get_tcp_header(&data);
    src_port = ntohs(tcp_header->source);
    dst_port = ntohs(tcp_header->dest);
    
    // TODO: implement is_our_scan_response
    // Check if this is a response to our scan
    // if (is_our_scan_response(dst_port) == false)
    // {
    //     return;
    // }
    printf("flag %d\n", flags);
    u_int8_t flags = tcp_header->th_flags;
    if (flags == 0) {
        printf("[NULL/NONE Scan] No flags set\n");
    } 
    else if (flags & TH_SYN && !(flags & TH_ACK)) {
        printf("[SYN Scan] SYN flag set\n");
    }
    else if (flags & TH_FIN && flags & TH_URG && flags & TH_PUSH) {
        printf("[XMAS Scan] FIN/URG/PSH flags set\n");
    }
    else if (flags & TH_FIN && !(flags & TH_ACK)) {
        printf("[FIN Scan] FIN flag set\n");
    }
    else if (flags & TH_ACK && !(flags & TH_SYN)) {
        printf("[ACK Scan] ACK flag set\n");
    }
    
    // SYN Scan Response
    if (tcp_header->syn && tcp_header->ack) {
        printf("[SYN Scan] Port %d is OPEN (Received SYN-ACK)\n", src_port);

        queue_add(data.data, NULL);
        // add_port_result(src_port, 1, 'T');
    }
    // NULL Scan Response
    else if (tcp_header->rst) { //SCAN_NULL
        printf("[NULL Scan] Port %d is CLOSED (Received RST)\n", src_port);

        queue_add(data.data, NULL);
        // add_port_result(src_port, 0, 'T');
    }
    // ACK Scan Response
    else if (tcp_header->rst) { // SCAN_ACK
        printf("[ACK Scan] Port %d is UNFILTERED (Received RST)\n", src_port);

        queue_add(data.data, NULL);
        // add_port_result(src_port, 1, 'T'); // 1=unfiltered in this context
    }
    // FIN Scan Response
    else if (tcp_header->rst) { //SCAN_FIN
        printf("[FIN Scan] Port %d is CLOSED (Received RST)\n", src_port);

        queue_add(data.data, NULL);
        // add_port_result(src_port, 0, 'T');
    }
    // XMAS Scan Response
    else if (tcp_header->rst) { // SCAN_XMAS
        printf("[XMAS Scan] Port %d is CLOSED (Received RST)\n", src_port);

        queue_add(data.data, NULL);
        // add_port_result(src_port, 0, 'T');
    }
    // No response case handled by timeout
}