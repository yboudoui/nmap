#include "packet_capture/packet.h"

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

static t_error  ft_pcap_create_handle(pcap_if_t *devices, pcap_t **handle)
{
    char    errbuf[PCAP_ERRBUF_SIZE];
    t_error error = 0;

    (*handle) = pcap_create(devices->name, errbuf);
    if (handle == NULL) {
        pcap_freealldevs(devices);
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
    pcap_set_timeout(handle, 1000);    // 1s timeout

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

static t_error  ft_pcap_init(pcap_if_t **devices, pcap_t **handle)
{
    (*devices) = NULL;
    (*handle) = NULL;
    t_error error = 0;

    error = ft_pcap_find_devices(devices);
    if (error) {
        error = WRAP_ERROR(error, 1);
        fprintf(stderr, "ERROR [%d]: unable to find devices for capturing packets\n", error);
        return (error);
    }

    error = ft_pcap_create_handle(*devices, handle);
    if (error) {
        ft_pcap_clean(handle, devices);
        error = WRAP_ERROR(error, 2);
        fprintf(stderr, "ERROR [%d]: unable to create a handle for capturing packets\n", error);
        return (error);
    }

    error = ft_pcap_set_handle(*handle);
    if (error) {
        ft_pcap_clean(handle, devices);
        error = WRAP_ERROR(error, 3);
        fprintf(stderr, "ERROR [%d]: unable to set the handle for capturing packets\n", error);
        return (error);
    }

    error = ft_pcap_activate_handle(*handle);
    if (error) {
        ft_pcap_clean(handle, devices);
        error = WRAP_ERROR(error, 4);
        fprintf(stderr, "ERROR [%d]: unable to activate the handle for capturing packets\n", error);
        return (error);
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

t_error capture_packet(t_error (*user_callback)(void*), void *user_data)
{
    pcap_if_t   *devices = NULL;
    pcap_t      *handle = NULL;

    t_error error = ft_pcap_init(&devices, &handle);
    if (error) {
        return (err_wrap(&error, 1, "unable to init the capture packets"));
    }

    pthread_t   thread = {0};
    t_pcap_data_wraper  wraper = {
        .handle = handle,
        .user_data = user_data,
    };
    t_error user_callback_success = 0;
    pthread_create(&thread, NULL, ft_pcap_routine, &wraper);
    printf("sending start\n");
    user_callback_success = user_callback(user_data);
    printf("sending stop\n");
    pthread_join(thread, NULL);
    ft_pcap_clean(&handle, &devices);
    return (user_callback_success);
}