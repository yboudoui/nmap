#include "pool/pool.h"
#include "packet_capture/packet.h"

t_packet    new_packet(unsigned char *user_data, const unsigned char *raw_packet)
{
    t_packet  data;
    data.user_data = user_data;
    data.raw_packet = raw_packet;
    data.eth = build_eth_info(data.raw_packet);
    data.ip = build_ip_info(data.raw_packet, data.eth);
    return (data);
}

void        save_result(t_packet *data, void *result)
{
    queue_add(data->user_data, result);
}
