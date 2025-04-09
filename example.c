#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>

// Scan type definitions
#define SCAN_SYN  1
#define SCAN_NULL 2
#define SCAN_ACK  3
#define SCAN_FIN  4
#define SCAN_XMAS 5
#define SCAN_UDP  6

// Configuration
#define MAX_PORTS 1024
#define MAX_IPS 256
#define THREAD_POOL_SIZE 10
#define SNAP_LEN 1518
#define TIMEOUT_MS 1000

typedef struct {
    struct in_addr ip;
    uint16_t port;
    uint8_t scan_type;
} t_task;

typedef struct {
    struct in_addr *ips;
    int ip_count;
    int current_ip;
    
    uint16_t *ports;
    int port_count;
    int current_port;
    
    uint8_t *scan_types;
    int scan_type_count;
    int current_scan_type;
    
    bool running;
} t_state;

typedef struct {
    int port;
    int status;  // 0=closed, 1=open, 2=filtered
    char type;   // 'T'=TCP, 'U'=UDP
    struct ListNode *prev;
    struct ListNode *next;
} ListNode;

typedef struct {
    ListNode *head;
    ListNode *tail;
    pthread_mutex_t lock;
    int count;
} ThreadSafeList;

// Global variables
static pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;
static ThreadSafeList *results;
static pcap_t *pcap_handle;
static t_state scanner_state;

// Thread-safe list implementation
ThreadSafeList* list_init() {
    ThreadSafeList *list = malloc(sizeof(ThreadSafeList));
    if (!list) return NULL;
    
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    pthread_mutex_init(&list->lock, NULL);
    return list;
}

void list_add(ThreadSafeList *list, int port, int status, char type) {
    ListNode *new_node = malloc(sizeof(ListNode));
    if (!new_node) return;
    
    new_node->port = port;
    new_node->status = status;
    new_node->type = type;
    new_node->prev = NULL;
    new_node->next = NULL;
    
    pthread_mutex_lock(&list->lock);
    
    if (list->head == NULL) {
        list->head = new_node;
        list->tail = new_node;
    } else {
        new_node->prev = list->tail;
        list->tail->next = new_node;
        list->tail = new_node;
    }
    list->count++;
    
    pthread_mutex_unlock(&list->lock);
}

void list_print(ThreadSafeList *list) {
    pthread_mutex_lock(&list->lock);
    
    printf("Scan Results (%d items):\n", list->count);
    ListNode *current = list->head;
    while (current != NULL) {
        printf("Port %5d (%c): ", current->port, current->type);
        switch(current->status) {
            case 0: printf("CLOSED\n"); break;
            case 1: printf("OPEN\n"); break;
            case 2: printf("FILTERED\n"); break;
            default: printf("UNKNOWN\n");
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&list->lock);
}

// Task distribution
bool get_next_ip(t_state *state, t_task *task) {
    if (state->current_ip >= state->ip_count) return false;
    task->ip = state->ips[state->current_ip++];
    return true;
}

bool get_next_port(t_state *state, t_task *task) {
    if (state->current_port >= state->port_count) return false;
    task->port = state->ports[state->current_port++];
    return true;
}

bool get_next_scan_type(t_state *state, t_task *task) {
    if (state->current_scan_type >= state->scan_type_count) return false;
    task->scan_type = state->scan_types[state->current_scan_type++];
    return true;
}

bool get_next_task(t_task *task, t_state *state) {
    pthread_mutex_lock(&task_mutex);
    
    bool success = false;
    if (get_next_ip(state, task)) {
        if (get_next_port(state, task)) {
            if (get_next_scan_type(state, task)) {
                success = true;
            } else {
                state->current_scan_type = 0;
                task->scan_type = 0;
                if (!get_next_scan_type(state, task)) {
                    state->current_port = 0;
                    task->port = 0;
                    if (!get_next_port(state, task)) {
                        state->current_ip = 0;
                        task->ip.s_addr = 0;
                        if (!get_next_ip(state, task)) {
                            pthread_mutex_unlock(&task_mutex);
                            return false;
                        }
                    }
                }
            }
        }
    }
    
    pthread_mutex_unlock(&task_mutex);
    return success;
}

// Packet crafting
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void send_tcp_packet(int sockfd, struct in_addr src_ip, struct in_addr dst_ip, 
                    uint16_t src_port, uint16_t dst_port, uint8_t scan_type) {
    char packet[4096] = {0};
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Build IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = src_ip.s_addr;
    iph->daddr = dst_ip.s_addr;
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // Build TCP header
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(12345);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->res1 = 0;
    
    // Set flags based on scan type
    switch(scan_type) {
        case SCAN_SYN: tcph->syn = 1; break;
        case SCAN_ACK: tcph->ack = 1; break;
        case SCAN_FIN: tcph->fin = 1; break;
        case SCAN_XMAS: tcph->fin = tcph->psh = tcph->urg = 1; break;
        default: break; // NULL scan has no flags
    }
    
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // TCP checksum
    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header;

    pseudo_header.src_addr = iph->saddr;
    pseudo_header.dst_addr = iph->daddr;
    pseudo_header.reserved = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &pseudo_header, sizeof(pseudo_header));
    memcpy(pseudo_packet + sizeof(pseudo_header), tcph, sizeof(struct tcphdr));
    
    tcph->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

    // Send packet
    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = dst_ip;
    
    sendto(sockfd, packet, iph->tot_len, 0, 
          (struct sockaddr *)&dest_addr, sizeof(dest_addr));
}

// PCAP packet handling
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);
    unsigned short iphdrlen = ip_header->ihl*4;
    uint16_t src_port, dst_port;

    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + iphdrlen);
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);

        if (tcp_header->syn && tcp_header->ack) {
            list_add(results, src_port, 1, 'T');
        } else if (tcp_header->rst) {
            list_add(results, src_port, 0, 'T');
        }
    }
    else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + iphdrlen);
        list_add(results, ntohs(udp_header->source), 1, 'U');
    }
    else if (ip_header->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + iphdrlen);
        if (icmp_header->type == ICMP_DEST_UNREACH && icmp_header->code == ICMP_PORT_UNREACH) {
            struct iphdr *orig_ip = (struct iphdr *)(packet + 14 + iphdrlen + 8);
            if (orig_ip->protocol == IPPROTO_UDP) {
                struct udphdr *orig_udp = (struct udphdr *)(packet + 14 + iphdrlen + 8 + orig_ip->ihl*4);
                list_add(results, ntohs(orig_udp->dest), 0, 'U');
            }
        }
    }
}

// Worker thread function
void *scan_worker(void *arg) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        return NULL;
    }

    t_task task;
    while (scanner_state.running && get_next_task(&task, &scanner_state)) {
        if (task.scan_type == SCAN_UDP) {
            // UDP scan implementation would go here
        } else {
            send_tcp_packet(sockfd, (struct in_addr){htonl(INADDR_LOOPBACK)}, 
                          task.ip, 54321, task.port, task.scan_type);
        }
        usleep(1000); // Rate limiting
    }
    
    close(sockfd);
    return NULL;
}

int main(int argc, char *argv[]) {
    // Initialize results list
    results = list_init();
    
    // Initialize scanner state
    struct in_addr ips[MAX_IPS] = {{htonl(INADDR_LOOPBACK)}};
    uint16_t ports[MAX_PORTS] = {22, 80, 443, 8080};
    uint8_t scan_types[] = {SCAN_SYN, SCAN_ACK};
    
    scanner_state.ips = ips;
    scanner_state.ip_count = 1;
    scanner_state.current_ip = 0;
    
    scanner_state.ports = ports;
    scanner_state.port_count = 4;
    scanner_state.current_port = 0;
    
    scanner_state.scan_types = scan_types;
    scanner_state.scan_type_count = 2;
    scanner_state.current_scan_type = 0;
    
    scanner_state.running = true;
    
    // Initialize PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live("lo", SNAP_LEN, 1, TIMEOUT_MS, errbuf);
    if (!pcap_handle) {
        fprintf(stderr, "PCAP error: %s\n", errbuf);
        exit(1);
    }
    
    // Start PCAP thread
    pthread_t pcap_thread;
    pthread_create(&pcap_thread, NULL, (void *)pcap_loop, 
                  (void *)(intptr_t)pcap_handle, -1, packet_handler, NULL);
    
    // Start worker threads
    pthread_t workers[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&workers[i], NULL, scan_worker, NULL);
    }
    
    // Wait for workers to finish
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(workers[i], NULL);
    }
    
    // Stop scanning
    scanner_state.running = false;
    pcap_breakloop(pcap_handle);
    pthread_join(pcap_thread, NULL);
    
    // Print results
    list_print(results);
    
    // Cleanup
    pcap_close(pcap_handle);
    // Additional cleanup would go here
    
    return 0;
}