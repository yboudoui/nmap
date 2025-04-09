#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

// Scan type definitions
#define SCAN_SYN  1
#define SCAN_NULL 2
#define SCAN_ACK  3
#define SCAN_FIN  4
#define SCAN_XMAS 5
#define SCAN_UDP  6

// Calculate checksum for TCP/UDP packets
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Create raw socket for packet sending
int create_raw_socket() {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == -1) {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }
    
    // Tell the kernel we'll provide the IP header
    int one = 1;
    const int *val = &one;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(s);
        exit(EXIT_FAILURE);
    }
    
    return s;
}

// Build IP header
void build_ip_header(struct iphdr *iph, const char *src_ip, const char *dst_ip, int data_len) {
    iph->ihl = 5;            // Header length in 32-bit words
    iph->version = 4;        // IPv4
    iph->tos = 0;            // Type of service
    iph->tot_len = sizeof(struct iphdr) + data_len;
    iph->id = htons(54321);  // Identification
    iph->frag_off = 0;       // Fragment offset
    iph->ttl = 255;          // Time to live
    iph->protocol = IPPROTO_TCP; // Default to TCP, changed for UDP scans
    iph->check = 0;          // Checksum (calculated later)
    
    // Convert and set source and destination IP addresses
    inet_pton(AF_INET, src_ip, (void *)&iph->saddr);
    inet_pton(AF_INET, dst_ip, (void *)&iph->daddr);
    
    // Calculate IP header checksum
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
}

// Build TCP header based on scan type
void build_tcp_header(struct tcphdr *tcph, int src_port, int dst_port, int scan_type) {
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(12345);  // Sequence number
    tcph->ack_seq = 0;         // Acknowledgement number
    tcph->doff = 5;            // Data offset (5 * 4 = 20 bytes)
    tcph->res1 = 0;            // Reserved
    
    // Set TCP flags based on scan type
    switch(scan_type) {
        case SCAN_SYN:
            tcph->syn = 1;
            break;
        case SCAN_NULL:
            // All flags cleared
            break;
        case SCAN_ACK:
            tcph->ack = 1;
            break;
        case SCAN_FIN:
            tcph->fin = 1;
            break;
        case SCAN_XMAS:
            tcph->fin = 1;
            tcph->psh = 1;
            tcph->urg = 1;
            break;
        default:
            tcph->syn = 1;  // Default to SYN scan
    }
    
    tcph->window = htons(5840);  // Window size
    tcph->check = 0;             // Checksum (calculated later)
    tcph->urg_ptr = 0;           // Urgent pointer
}

// Build UDP header
void build_udp_header(struct udphdr *udph, int src_port, int dst_port, int len) {
    udph->source = htons(src_port);
    udph->dest = htons(dst_port);
    udph->len = htons(len);
    udph->check = 0;  // Checksum (optional for IPv4)
}

// Send raw TCP packet
void send_tcp_packet(int sockfd, const char *src_ip, const char *dst_ip, 
                     int src_port, int dst_port, int scan_type) {
    char packet[4096] = {0};
    
    // IP header
    struct iphdr *iph = (struct iphdr *)packet;
    
    // TCP header (right after IP header)
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    // Build IP header
    build_ip_header(iph, src_ip, dst_ip, sizeof(struct tcphdr));
    
    // Build TCP header based on scan type
    build_tcp_header(tcph, src_port, dst_port, scan_type);
    
    // TCP checksum needs pseudo header
    struct pseudo_tcp {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char reserved;
        unsigned char protocol;
        unsigned short tcp_length;
        struct tcphdr tcp;
    } pseudo_tcp;
    
    memset(&pseudo_tcp, 0, sizeof(pseudo_tcp));
    pseudo_tcp.src_addr = iph->saddr;
    pseudo_tcp.dst_addr = iph->daddr;
    pseudo_tcp.reserved = 0;
    pseudo_tcp.protocol = IPPROTO_TCP;
    pseudo_tcp.tcp_length = htons(sizeof(struct tcphdr));
    memcpy(&pseudo_tcp.tcp, tcph, sizeof(struct tcphdr));
    
    // Calculate TCP checksum
    tcph->check = checksum((unsigned short *)&pseudo_tcp, sizeof(pseudo_tcp));
    
    // Destination address for sendto()
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = iph->daddr;
    
    // Send the packet
    if (sendto(sockfd, packet, iph->tot_len, 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto() failed");
    }
}

// Send raw UDP packet
void send_udp_packet(int sockfd, const char *src_ip, const char *dst_ip, 
                     int src_port, int dst_port) {
    char packet[4096] = {0};
    
    // IP header
    struct iphdr *iph = (struct iphdr *)packet;
    
    // UDP header (right after IP header)
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    
    // Build IP header with UDP protocol
    build_ip_header(iph, src_ip, dst_ip, sizeof(struct udphdr));
    iph->protocol = IPPROTO_UDP;
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
    
    // Build UDP header
    build_udp_header(udph, src_port, dst_port, sizeof(struct udphdr));
    
    // UDP checksum is optional for IPv4, but we'll calculate it
    struct pseudo_udp {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char reserved;
        unsigned char protocol;
        unsigned short udp_length;
        struct udphdr udp;
    } pseudo_udp;
    
    memset(&pseudo_udp, 0, sizeof(pseudo_udp));
    pseudo_udp.src_addr = iph->saddr;
    pseudo_udp.dst_addr = iph->daddr;
    pseudo_udp.reserved = 0;
    pseudo_udp.protocol = IPPROTO_UDP;
    pseudo_udp.udp_length = htons(sizeof(struct udphdr));
    memcpy(&pseudo_udp.udp, udph, sizeof(struct udphdr));
    
    // Calculate UDP checksum
    udph->check = checksum((unsigned short *)&pseudo_udp, sizeof(pseudo_udp));
    
    // Destination address for sendto()
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = iph->daddr;
    
    // Send the packet
    if (sendto(sockfd, packet, iph->tot_len, 0, 
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto() failed");
    }
}

// Main function to send packets based on scan type
void send_raw_packet(const char *src_ip, const char *dst_ip, 
                     int src_port, int dst_port, int scan_type) {
    int sockfd = create_raw_socket();
    
    switch(scan_type) {
        case SCAN_SYN:
        case SCAN_NULL:
        case SCAN_ACK:
        case SCAN_FIN:
        case SCAN_XMAS:
            send_tcp_packet(sockfd, src_ip, dst_ip, src_port, dst_port, scan_type);
            break;
        case SCAN_UDP:
            send_udp_packet(sockfd, src_ip, dst_ip, src_port, dst_port);
            break;
        default:
            fprintf(stderr, "Unknown scan type\n");
    }
    
    close(sockfd);
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        printf("Usage: %s <src_ip> <dst_ip> <src_port> <dst_port> <scan_type>\n", argv[0]);
        printf("Scan types: SYN, NULL, ACK, FIN, XMAS, UDP\n");
        return 1;
    }
    
    const char *src_ip = argv[1];
    const char *dst_ip = argv[2];
    int src_port = atoi(argv[3]);
    int dst_port = atoi(argv[4]);
    const char *scan_type_str = argv[5];
    
    int scan_type;
    if (strcmp(scan_type_str, "SYN") == 0) {
        scan_type = SCAN_SYN;
    } else if (strcmp(scan_type_str, "NULL") == 0) {
        scan_type = SCAN_NULL;
    } else if (strcmp(scan_type_str, "ACK") == 0) {
        scan_type = SCAN_ACK;
    } else if (strcmp(scan_type_str, "FIN") == 0) {
        scan_type = SCAN_FIN;
    } else if (strcmp(scan_type_str, "XMAS") == 0) {
        scan_type = SCAN_XMAS;
    } else if (strcmp(scan_type_str, "UDP") == 0) {
        scan_type = SCAN_UDP;
    } else {
        fprintf(stderr, "Unknown scan type: %s\n", scan_type_str);
        return 1;
    }
    
    printf("Sending %s packet from %s:%d to %s:%d\n", 
           scan_type_str, src_ip, src_port, dst_ip, dst_port);
    
    send_raw_packet(src_ip, dst_ip, src_port, dst_port, scan_type);
    
    return 0;
}
// ./scanner <src_ip> <dst_ip> <src_port> <dst_port> <scan_type>
// ./scanner 192.168.1.100 192.168.1.1 54321 80 SYN