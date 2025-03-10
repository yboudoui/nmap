

/*
How it Works:

    Sends a UDP packet to each target port.
    If the port is open, there is no response or a specific UDP response.
    If the port is closed, an ICMP Port Unreachable message is received.
    If filtered, no response or ICMP unreachable errors may be received.
*/