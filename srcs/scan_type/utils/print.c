static char* get_scan_flag_name(t_scan_type scan_type)
{
    switch (scan_type){
    case SCAN_SYN:  return ("SYN");
    case SCAN_NULL: return ("NULL");
    case SCAN_ACK:  return ("ACK");
    case SCAN_FIN:  return ("FIN");
    case SCAN_XMAS: return ("XMAS");
    case SCAN_UDP:  return ("UDP");
    default: return (NULL);
    }
}