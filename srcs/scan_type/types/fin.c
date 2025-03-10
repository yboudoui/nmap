

/*
How it Works:

    Sends a TCP packet with only the FIN flag set.
    If the port is closed, the target responds with RST.
    If the port is open, there is no response.
    If filtered, there’s no response or an ICMP unreachable message.
*/