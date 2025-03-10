

/*
How it Works:

    Sends a TCP packet with the ACK flag set (without a prior SYN).
    If the response is RST, the port is unfiltered (reachable but not necessarily open).
    If there is no response, the port is filtered (blocked by a firewall).
*/