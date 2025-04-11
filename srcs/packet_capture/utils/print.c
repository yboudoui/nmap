void    print_mac_address(uint8_t ether_host[ETH_ALEN]) {
    printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        ether_host[0], ether_host[1], ether_host[2],
        ether_host[3], ether_host[4], ether_host[5]);
}

void print_packet_header(const struct pcap_pkthdr *header) {
    printf("Timestamp: %ld.%ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
    printf("Packet Length: %d bytes\n", header->len);
}

void print_packet(struct ether_header *eth_header) {
    print_mac_address(eth_header->ether_shost);
    print_mac_address(eth_header->ether_dhost);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)((char*)eth_header + sizeof(struct ether_header));
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    }
}

void packet_handler(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    printf("\n--- Packet Captured ---\n");
    print_packet_header(header);
    print_packet(packet);
}