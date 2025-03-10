#include "scan_type.h"

/*
How it Works:

    Sends a TCP packet with FIN, URG, and PSH flags set (XMAS tree pattern).
    If the port is closed, the target responds with RST.
    If the port is open, there is no response.
    If filtered, there’s no response or an ICMP unreachable message.
*/

void xmas(void) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
    pcap_t *handle; // Session handle
    char *dev; // Network device

    // Find a suitable network device
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return;
    }
    printf("Using device: %s\n", dev);

    // Open the device for live packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return;
    }

    printf("Capturing packets...\n");

    // Capture packets in a loop (-1 means infinite loop)
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup (this part is never reached in this example)
    pcap_close(handle);
    return;
}


/*
int main() {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
    pcap_t *handle; // Session handle
    char *dev; // Network device

    // Find a suitable network device
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return EXIT_FAILURE;
    }
    printf("Using device: %s\n", dev);

    // Open the device for live packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    printf("Capturing packets...\n");

    // Capture packets in a loop (-1 means infinite loop)
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup (this part is never reached in this example)
    pcap_close(handle);
    return EXIT_SUCCESS;
}
*/







#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <unistd.h>

// Define a structure for a packet node in the queue
typedef struct PacketNode {
    struct pcap_pkthdr header;
    u_char *packet;
    struct PacketNode *next;
} PacketNode;

// Queue structure for packets
typedef struct {
    PacketNode *front, *rear;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} PacketQueue;

PacketQueue queue = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

// Function to enqueue a packet
void enqueue_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    PacketNode *newNode = (PacketNode *)malloc(sizeof(PacketNode));
    if (!newNode) return;

    newNode->header = *header;
    newNode->packet = (u_char *)malloc(header->caplen);
    if (!newNode->packet) {
        free(newNode);
        return;
    }

    memcpy(newNode->packet, packet, header->caplen);
    newNode->next = NULL;

    pthread_mutex_lock(&queue.lock);
    if (queue.rear == NULL) {
        queue.front = queue.rear = newNode;
    } else {
        queue.rear->next = newNode;
        queue.rear = newNode;
    }
    pthread_cond_signal(&queue.cond);
    pthread_mutex_unlock(&queue.lock);
}

// Function to dequeue a packet
PacketNode *dequeue_packet() {
    pthread_mutex_lock(&queue.lock);
    while (queue.front == NULL) {
        pthread_cond_wait(&queue.cond, &queue.lock);
    }

    PacketNode *node = queue.front;
    queue.front = queue.front->next;
    if (queue.front == NULL) queue.rear = NULL;

    pthread_mutex_unlock(&queue.lock);
    return node;
}

// Packet capture callback function (runs in capture thread)
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    enqueue_packet(header, packet);
}

// Packet processing function (Thread 2)
void *process_packets(void *arg) {
    while (1) {
        PacketNode *node = dequeue_packet();
        if (node) {
            struct ether_header *eth_header = (struct ether_header *)node->packet;
            printf("\n--- Packet Captured ---\n");
            printf("Timestamp: %ld.%ld\n", node->header.ts.tv_sec, node->header.ts.tv_usec);
            printf("Packet Length: %d bytes\n", node->header.len);

            printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
                   eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);

            printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
                   eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

            if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
                struct ip *ip_header = (struct ip *)(node->packet + sizeof(struct ether_header));
                printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            }

            free(node->packet);
            free(node);
        }
    }
    return NULL;
}

// Packet logging function (Thread 3)
void *log_packets(void *arg) {
    FILE *logfile = fopen("packets.log", "a");
    if (!logfile) {
        perror("Error opening log file");
        return NULL;
    }

    while (1) {
        PacketNode *node = dequeue_packet();
        if (node) {
            struct ether_header *eth_header = (struct ether_header *)node->packet;
            fprintf(logfile, "\n--- Packet Logged ---\n");
            fprintf(logfile, "Timestamp: %ld.%ld\n", node->header.ts.tv_sec, node->header.ts.tv_usec);
            fprintf(logfile, "Packet Length: %d bytes\n", node->header.len);

            fprintf(logfile, "Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
                    eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);

            fprintf(logfile, "Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
                    eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

            fflush(logfile);
            free(node->packet);
            free(node);
        }
    }

    fclose(logfile);
    return NULL;
}