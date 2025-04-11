
int send_raw_packet(int raw_sock, const char *ip, int port)
{
    char *packet;
    int packet_len;
    
    if (create_ack_packet(ip, port, &packet, &packet_len) != 0) {
        return -1;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip);
    dest.sin_port = htons(port);

    int sent = sendto(raw_sock, packet, packet_len, 0,
                     (struct sockaddr *)&dest, sizeof(dest));
    
    free(packet);
    return sent;
}