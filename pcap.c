#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <unistd.h>

#define FILTER_EXPRESSION "tcp or icmp or udp"
#define SNAP_LEN 1518
#define TIMEOUT_MS 1000
#define MAX_PACKETS 100

// Structure to track scan results
typedef struct {
    int port;
    int status;  // 0=closed, 1=open, 2=filtered
    char type;   // 'T'=TCP, 'U'=UDP
} PortStatus;

// Global variables for pcap handling
pcap_t *handle;
PortStatus port_results[MAX_PACKETS];
int result_count = 0;

// Function to add a port result
void add_port_result(int port, int status, char type) {
    if (result_count < MAX_PACKETS) {
        port_results[result_count].port = port;
        port_results[result_count].status = status;
        port_results[result_count].type = type;
        result_count++;
    }
}

// Callback function for pcap_loop
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + 14); // Skip Ethernet header
    unsigned short iphdrlen = ip_header->ihl*4;

    // Check if it's TCP
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + iphdrlen);
        
        // Check if it's a response to our scan (dest port matches our src port)
        unsigned short dest_port = ntohs(tcp_header->dest);
        
        // Determine port status based on TCP flags
        if (tcp_header->syn && tcp_header->ack) {
            printf("Port %d is OPEN (TCP)\n", ntohs(tcp_header->source));
            add_port_result(ntohs(tcp_header->source), 1, 'T');
        } else if (tcp_header->rst) {
            printf("Port %d is CLOSED (TCP)\n", ntohs(tcp_header->source));
            add_port_result(ntohs(tcp_header->source), 0, 'T');
        }
    }
    // Check if it's UDP
    else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + iphdrlen);
        
        // Any UDP response means the port is open
        printf("Port %d is OPEN (UDP)\n", ntohs(udp_header->source));
        add_port_result(ntohs(udp_header->source), 1, 'U');
    }
    // Check if it's ICMP (for UDP unreachable or filtered ports)
    else if (ip_header->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + iphdrlen);
        
        // ICMP Port Unreachable means UDP port is closed
        if (icmp_header->type == ICMP_DEST_UNREACH && icmp_header->code == ICMP_PORT_UNREACH) {
            // The original IP header is embedded in the ICMP payload
            struct iphdr *orig_ip = (struct iphdr *)(packet + 14 + iphdrlen + 8);
            unsigned short orig_iphdrlen = orig_ip->ihl*4;
            
            if (orig_ip->protocol == IPPROTO_UDP) {
                struct udphdr *orig_udp = (struct udphdr *)(packet + 14 + iphdrlen + 8 + orig_iphdrlen);
                printf("Port %d is CLOSED (UDP)\n", ntohs(orig_udp->dest));
                add_port_result(ntohs(orig_udp->dest), 0, 'U');
            }
        }
    }
}

/*
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_bytes *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + 14); // Skip Ethernet header
    unsigned short iphdrlen = ip_header->ihl*4;
    unsigned short src_port, dst_port;

    // TCP Response Handling
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + iphdrlen);
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);

        // Check if this is a response to our scan
        if (is_our_scan_response(dst_port)) {  // You need to implement this
            // SYN Scan Response
            if (tcp_header->syn && tcp_header->ack) {
                printf("[SYN Scan] Port %d is OPEN (Received SYN-ACK)\n", src_port);
                add_port_result(src_port, 1, 'T');
            }
            // NULL Scan Response
            else if (tcp_header->rst && current_scan_type == SCAN_NULL) {
                printf("[NULL Scan] Port %d is CLOSED (Received RST)\n", src_port);
                add_port_result(src_port, 0, 'T');
            }
            // ACK Scan Response
            else if (tcp_header->rst && current_scan_type == SCAN_ACK) {
                printf("[ACK Scan] Port %d is UNFILTERED (Received RST)\n", src_port);
                add_port_result(src_port, 1, 'T'); // 1=unfiltered in this context
            }
            // FIN Scan Response
            else if (tcp_header->rst && current_scan_type == SCAN_FIN) {
                printf("[FIN Scan] Port %d is CLOSED (Received RST)\n", src_port);
                add_port_result(src_port, 0, 'T');
            }
            // XMAS Scan Response
            else if (tcp_header->rst && current_scan_type == SCAN_XMAS) {
                printf("[XMAS Scan] Port %d is CLOSED (Received RST)\n", src_port);
                add_port_result(src_port, 0, 'T');
            }
            // No response case handled by timeout
        }
    }
    // UDP Response Handling
    else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + iphdrlen);
        src_port = ntohs(udp_header->source);
        dst_port = ntohs(udp_header->dest);

        if (is_our_scan_response(dst_port)) {
            printf("[UDP Scan] Port %d is OPEN (Received UDP response)\n", src_port);
            add_port_result(src_port, 1, 'U');
        }
    }
    // ICMP Response Handling (for UDP and filtered ports)
    else if (ip_header->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_header = (struct icmphdr *)(packet + 14 + iphdrlen);
        
        // ICMP Port Unreachable (UDP closed or TCP filtered)
        if (icmp_header->type == ICMP_DEST_UNREACH) {
            // Get the original IP header from ICMP payload
            struct iphdr *orig_ip = (struct iphdr *)(packet + 14 + iphdrlen + 8);
            unsigned short orig_iphdrlen = orig_ip->ihl*4;
            src_port = 0;

            // UDP Port Unreachable
            if (orig_ip->protocol == IPPROTO_UDP && icmp_header->code == ICMP_PORT_UNREACH) {
                struct udphdr *orig_udp = (struct udphdr *)(packet + 14 + iphdrlen + 8 + orig_iphdrlen);
                src_port = ntohs(orig_udp->dest);
                printf("[UDP Scan] Port %d is CLOSED (ICMP Port Unreachable)\n", src_port);
                add_port_result(src_port, 0, 'U');
            }
            // TCP Filtered (no response to SYN is more common, but some firewalls send ICMP)
            else if (orig_ip->protocol == IPPROTO_TCP && current_scan_type == SCAN_SYN) {
                struct tcphdr *orig_tcp = (struct tcphdr *)(packet + 14 + iphdrlen + 8 + orig_iphdrlen);
                src_port = ntohs(orig_tcp->dest);
                printf("[SYN Scan] Port %d is FILTERED (ICMP Admin Prohibited)\n", src_port);
                add_port_result(src_port, 2, 'T');
            }
        }
        // ICMP Time Exceeded (used by some firewalls)
        else if (icmp_header->type == ICMP_TIME_EXCEEDED) {
            struct iphdr *orig_ip = (struct iphdr *)(packet + 14 + iphdrlen + 8);
            if (orig_ip->protocol == IPPROTO_TCP) {
                struct tcphdr *orig_tcp = (struct tcphdr *)(packet + 14 + iphdrlen + 8 + orig_ip->ihl*4);
                src_port = ntohs(orig_tcp->dest);
                printf("[%s Scan] Port %d is FILTERED (ICMP Time Exceeded)\n", 
                      scan_type_to_str(current_scan_type), src_port);
                add_port_result(src_port, 2, 'T');
            }
        }
    }
}

// Global variable to track current scan type
int current_scan_type = SCAN_SYN;

// Function to check if packet is a response to our scan
int is_our_scan_response(unsigned short dst_port) {
    // You should maintain a list of ports you've scanned
    // This is simplified - implement your own port tracking
    return (dst_port >= 32768 && dst_port <= 60999); // Typical ephemeral port range
}

// Function to convert scan type to string
const char *scan_type_to_str(int scan_type) {
    switch(scan_type) {
        case SCAN_SYN: return "SYN";
        case SCAN_NULL: return "NULL";
        case SCAN_ACK: return "ACK";
        case SCAN_FIN: return "FIN";
        case SCAN_XMAS: return "XMAS";
        case SCAN_UDP: return "UDP";
        default: return "UNKNOWN";
    }
}
*/

// Initialize pcap
void init_pcap(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the network device for packet capture
    handle = pcap_open_live(device, SNAP_LEN, 1, TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);
    }
    
    // Compile and apply the filter
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, FILTER_EXPRESSION, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER_EXPRESSION, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER_EXPRESSION, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    pcap_freecode(&fp);
}

// Main capture function
void capture_packets(int packet_count) {
    printf("Starting packet capture...\n");
    pcap_loop(handle, packet_count, packet_handler, NULL);
}

// Print summary of results
void print_results() {
    printf("\nScan Results:\n");
    printf("-------------\n");
    for (int i = 0; i < result_count; i++) {
        printf("Port %5d (%c): ", port_results[i].port, port_results[i].type);
        switch(port_results[i].status) {
            case 0: printf("CLOSED\n"); break;
            case 1: printf("OPEN\n"); break;
            case 2: printf("FILTERED\n"); break;
            default: printf("UNKNOWN\n");
        }
    }
}

// Cleanup
void cleanup_pcap() {
    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        printf("Example: %s eth0\n", argv[0]);
        return 1;
    }
    
    const char *device = argv[1];
    
    // Initialize pcap
    init_pcap(device);
    
    // Start capturing packets (0 means loop forever)
    capture_packets(0);
    
    // Print results (won't reach here if loop is infinite)
    print_results();
    
    // Cleanup
    cleanup_pcap();
    
    return 0;
}