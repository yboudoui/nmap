#include "pool/pool.h"

static char* get_scan_flag_name(t_scan_type scan_type)
{
    switch (scan_type) {
    case SCAN_SYN:  return ("SYN");
    case SCAN_NULL: return ("NULL");
    case SCAN_ACK:  return ("ACK");
    case SCAN_FIN:  return ("FIN");
    case SCAN_XMAS: return ("XMAS");
    case SCAN_UDP:  return ("UDP");
    default: return (NULL);
    }
}

static pthread_mutex_t mutex_print = PTHREAD_MUTEX_INITIALIZER;
void print_task(t_task task)
{
    pthread_mutex_lock(&mutex_print);
    static int i = 1;
    char ip_str[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &task.ip, ip_str, sizeof(ip_str));
    printf("%d - %s:%d %s\n", i, ip_str, task.port, get_scan_flag_name(task.scan_flag)); 
    i += 1;
    pthread_mutex_unlock(&mutex_print);
}