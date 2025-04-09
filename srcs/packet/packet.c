#include "pool.h"
#include "packet.h"

t_data  new_data(unsigned char *user_data, const unsigned char *packet)
{
    t_data  data;
    data.data = user_data;
    data.packet = packet;
    data.ip_header = (struct iphdr *)(data.packet + 14), // Skip Ethernet header
    data.iphdrlen = data.ip_header->ihl*4;
    return (data);
}

static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    (void)pkthdr;

    t_data  data = new_data(user_data, packet);
    switch (data.ip_header->protocol)
    {
        case IPPROTO_TCP:   // TCP Response Handling
            return (on_tcp(data));
        case IPPROTO_UDP:   // UDP Response Handling
            return (on_udp(data));
        case IPPROTO_ICMP:  // ICMP Response Handling (for UDP and filtered ports)
            return (on_icmp(data));
        default: return;
    }
}

bool init_pcap(void *data)
{
    char        errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t   *devices;
    pcap_t      *handle;
    int         activate_error;

    if (pcap_findalldevs(&devices, errbuf) == PCAP_ERROR)
    {
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return (false);
    }
    if (devices == NULL)
    {
        fprintf(stderr, "No device found\n");
        return (false);
    }

    handle = pcap_create(devices->name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        pcap_freealldevs(devices);
        return (false);
    }

    int status = pcap_set_timeout(handle, 1000);  // Timeout in milliseconds
    if (status != 0) {
        fprintf(stderr, "Warning: Couldn't set timeout\n");
    }

/*
    // Essential for scanning
    pcap_set_promisc(handle, 1);       // Promiscuous mode
    pcap_set_snaplen(handle, 65535);   // Full packet capture
    pcap_set_timeout(handle, 1000);    // 1s timeout

    // Advanced optimizations (if supported)
    pcap_set_immediate_mode(handle, 1);      // Reduce latency
    pcap_set_buffer_size(handle, 10*1024*1024);  // 10MB buffer
*/

    activate_error = pcap_activate(handle);
    if (activate_error != 0)
    {
        fprintf(stderr, "Error activating device: %s\n", pcap_statustostr(activate_error));
        pcap_close(handle);
        pcap_freealldevs(devices);
        return (false);
    }
    
    printf("START %s\n", __FUNCTION__);
    if (pcap_loop(handle, 10, packet_handler, data) < 0)
    {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
    }
    printf("END %s\n", __FUNCTION__);


    pcap_close(handle);
    pcap_freealldevs(devices);
    return (true);
}