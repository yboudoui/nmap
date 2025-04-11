#include "packet_capture/scan_type.h"

t_fp_packet_builder switch_packet_builder(t_scan_type type)
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