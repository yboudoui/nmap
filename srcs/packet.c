#include "pool.h"
#include "packet.h"

static pcap_t   *handle;
static char     *device;
static char     errbuf[PCAP_ERRBUF_SIZE];

static bool get_network_device(void) {
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return (false);
    }
    return (true);
}

static bool open_device(void) {
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return (false);
    }
    return (true);
}

bool init_packet_handler(void) {
    if (!get_network_device())  return (false);
    if (!open_device())         return (false);
    return (true);
}

static void handler(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    enqueue_packet(header, packet);
}

void    packet_handler(void) {
    pcap_loop(handle, 0, handler, NULL);
    pcap_close(handle);
}