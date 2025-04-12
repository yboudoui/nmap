#include "packet_capture/packet.h"

t_packet    new_packet(uint8_t *user_data, const uint8_t *raw_packet)
{
    t_packet  data;
    data.user_data = user_data;
    data.raw_packet = raw_packet;
    data.eth = build_eth_info(data.raw_packet);
    data.ip = build_ip_info(data.raw_packet, data.eth);
    return (data);
}

void save_result(t_packet *data, void *result)
{
    queue_push_front(data->user_data, result);
}