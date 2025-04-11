#include "packet_capture/packet.h"

#define MAX_PACKET_PROCESSED 10

static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    printf("yoo\n");
    (void)pkthdr;
    t_packet  data = new_packet(user_data, packet);

    if (data.eth.type != ETHERTYPE_IP) return;
    switch (data.ip.header->protocol)
    {
        case IPPROTO_TCP:   // TCP Response Handling
            return (on_tcp(&data));
        case IPPROTO_UDP:   // UDP Response Handling
            return (on_udp(&data));
        case IPPROTO_ICMP:  // ICMP Response Handling (for UDP and filtered ports)
            return (on_icmp(&data));
        default: return;
    }
}

static bool ft_pcap_find_devices(pcap_if_t **devices)
{
    char    errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(devices, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return (false);
    }
    if (devices == NULL) {
        fprintf(stderr, "No device found\n");
        return (false);
    }
    return (true);
}

static bool ft_pcap_create_handle(pcap_if_t *devices, pcap_t **handle)
{
    char    errbuf[PCAP_ERRBUF_SIZE];

    (*handle) = pcap_create(devices->name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        pcap_freealldevs(devices);
        return (false);
    }
    return (true);
}

static bool ft_pcap_set_handle(pcap_t *handle)
{
    int status;
    
    status = pcap_set_timeout(handle, 1000);  // Timeout in milliseconds
    if (status != 0) {
        fprintf(stderr, "Warning: Couldn't set timeout\n");
        return (false);
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
    return (true);
}

static bool ft_pcap_activate_handle(pcap_t *handle)
{
    int error;

    error = pcap_activate(handle);
    if (error != 0) {
        fprintf(stderr, "Error activating device: %s\n", pcap_statustostr(error));
        return (false);
    }
    return (true);
}

static void ft_pcap_clean(pcap_t **handle, pcap_if_t **devices)
{
    if (*handle) {
        pcap_close(*handle);
        (*handle) = NULL;
    }
    if (*devices) {
        pcap_freealldevs(*devices);
        (*devices) = NULL;
    }
}

static bool ft_pcap_init(pcap_if_t **devices, pcap_t **handle)
{
    (*devices) = NULL;
    (*handle) = NULL;
    if (!ft_pcap_find_devices(devices)) {
        return (false);
    }
    if (!ft_pcap_create_handle(*devices, handle)) {
        ft_pcap_clean(handle, devices);
        return (false);
    }
    if (!ft_pcap_set_handle(*handle)) {
        ft_pcap_clean(handle, devices);
        return (false);
    }
    if (!ft_pcap_activate_handle(*handle)) {
        ft_pcap_clean(handle, devices);
        return (false);
    }
    return (true);
}

typedef struct s_pcap_data_wraper {
    pcap_t  *handle;
    void    *user_data;
} t_pcap_data_wraper;

static void *ft_pcap_routine(void *user_data)
{
    t_pcap_data_wraper  *wrapper = user_data;

    if (pcap_loop(wrapper->handle, MAX_PACKET_PROCESSED, packet_handler, wrapper->user_data) < 0) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(wrapper->handle));
    }
    return (NULL);
}

bool init_pcap(void *user_data)
{
    pcap_if_t   *devices = NULL;
    pcap_t      *handle = NULL;
    pthread_t   thread = {0};

    if (!ft_pcap_init(&devices, &handle)) {
        return (false);
    }
    
    t_pcap_data_wraper  wraper = {
        .handle = handle,
        .user_data = user_data,
    };
    pthread_create(&thread, NULL, ft_pcap_routine, &wraper);
    pthread_join(thread, NULL);
    ft_pcap_clean(&handle, &devices);
    return (true);
}