

/*
How it Works:

    Sends a TCP packet with no flags set (i.e., an empty header).
    If the port is open, there is no response (depends on OS).
    If the port is closed, it sends an RST.
    If filtered, there’s no response or an ICMP unreachable message.
*/