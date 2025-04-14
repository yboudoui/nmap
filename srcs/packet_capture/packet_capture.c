#include "packet/capture.h"

#define MAX_PACKET_PROCESSED 0

static t_error  ft_pcap_find_devices(pcap_if_t **devices)
{
    char    errbuf[PCAP_ERRBUF_SIZE];
    t_error error = 0;

    if (pcap_findalldevs(devices, errbuf) == PCAP_ERROR) {
        // err_wrap(&error, 1, "unable to allocate the queue");
        error = 1;
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return (error);
    }
    if (devices == NULL) {
        err_wrap(&error, 2, "no device found");
        return (error);
    }
    return (error);
}

static bool device_filter_flag(int flags)
{
    return (0
        || !(flags & PCAP_IF_UP)
        || !(flags & PCAP_IF_RUNNING)
        || ((flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_DISCONNECTED)
    );
}

static t_error  ft_pcap_select_device(pcap_if_t **devices, pcap_addr_t **addresse)
{
    t_error error = 0;

    pcap_if_t *dev = (*devices);
    for (; dev; dev = dev->next) {
        if (device_filter_flag(dev->flags)) {
            continue;
        }
        pcap_addr_t *addr = dev->addresses;
        for (; addr; addr = addr->next) {
            if (addr->addr->sa_family == AF_INET) {
                (*addresse) = addr;
                return (error);
            }
        }
    }
    return (err_wrap(&error, 1, "no usable device found"));
}

static t_error  ft_pcap_create_handle(pcap_if_t *devices, pcap_t **handle)
{
    char    errbuf[PCAP_ERRBUF_SIZE];
    t_error error = 0;

    (*handle) = pcap_create(devices->name, errbuf);
    if (handle == NULL) {
        error = 1;
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        // err_wrap(&error, 1, "opening device");
        return (error);
    }
    return (error);
}

static t_error  ft_pcap_set_handle(pcap_t *handle)
{
    int status;
    t_error error = 0;
    
    status = pcap_set_timeout(handle, 1000);  // Timeout in milliseconds
    if (status != 0) {
        return (err_wrap(&error, 1, "unable to set handle timeout"));
    }

/*
    // Essential for scanning
    pcap_set_promisc(handle, 1);       // Promiscuous mode
    pcap_set_snaplen(handle, 65535);   // Full packet capture

    // Advanced optimizations (if supported)
    pcap_set_immediate_mode(handle, 1);      // Reduce latency
    pcap_set_buffer_size(handle, 10*1024*1024);  // 10MB buffer
*/
    return (error);
}

static t_error  ft_pcap_activate_handle(pcap_t *handle)
{
    int error;

    error = pcap_activate(handle);
    if (error != 0) {
        fprintf(stderr, "Error activating device: %s\n", pcap_statustostr(error));
        return (1);
    }
    return (0);
}

static void     ft_pcap_clean(pcap_t **handle, pcap_if_t **devices)
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

static t_error  ft_pcap_init(pcap_if_t **devices, pcap_t **handle, pcap_addr_t **addr)
{
    (*devices) = NULL;
    (*handle) = NULL;
    (*addr) = NULL;
    t_error error = 0;

    error = ft_pcap_find_devices(devices);
    if (error) {
        return (err_wrap(&error, 1, "unable to find any devices for capturing packets"));
    }

    error = ft_pcap_select_device(devices, addr);
    if (error) {
        return (err_wrap(&error, 2, "unable to find a usable devices for capturing packets"));
    }

    error = ft_pcap_create_handle(*devices, handle);
    if (error) {
        ft_pcap_clean(handle, devices);
        return (err_wrap(&error, 3, "unable to create a handle for capturing packets"));
    }

    error = ft_pcap_set_handle(*handle);
    if (error) {
        ft_pcap_clean(handle, devices);
        return (err_wrap(&error, 4, "unable to set the handle for capturing packets"));
    }

    error = ft_pcap_activate_handle(*handle);
    if (error) {
        ft_pcap_clean(handle, devices);
        return (err_wrap(&error, 5, "unable to activate the handle for capturing packets"));
    }
    return (error);
}

static void *ft_pcap_routine(void *user_data)
{
    t_pcap_data_wraper  *wrapper = user_data;

    int pcap_loop_error = pcap_loop(
        wrapper->handle,
        MAX_PACKET_PROCESSED,
        packet_handler,
        (uint8_t*)wrapper
    );
    if (pcap_loop_error != PCAP_ERROR_BREAK) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(wrapper->handle));
    }
    return (NULL);
}

t_error capture_packet(t_error (*user_callback)(t_pcap_data_wraper*), void *user_data)
{
    pcap_if_t   *devices = NULL;
    pcap_t      *handle = NULL;
    pcap_addr_t *addr = NULL;
    t_error     error = 0;

    error = ft_pcap_init(&devices, &handle, &addr);
    if (error) {
        return (err_wrap(&error, 1, "unable to init the capture packets"));
    }

    pthread_t           thread = {0};
    t_pcap_data_wraper  wraper = {
        .handle = handle,
        .device_addr = ((struct sockaddr_in *)addr->addr)->sin_addr,
        .user_data = user_data,
    };
    printf("Capture packet from IP: %s\n", inet_ntoa(wraper.device_addr));

    printf("looking for packets\n");
    pthread_create(&thread, NULL, ft_pcap_routine, &wraper);
    printf("sending start\n");
    error = user_callback(&wraper);
    printf("sending stop\n");
    pthread_join(thread, NULL);
    ft_pcap_clean(&handle, &devices);
    return (error);
}