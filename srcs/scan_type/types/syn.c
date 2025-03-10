
/*
How it Works:

    Sends a SYN packet (like the beginning of a TCP handshake).
    If the port is open, the target responds with SYN-ACK.
    Instead of completing the handshake, Nmap sends an RST (Reset) packet to avoid detection.
    If the port is closed, the target sends an RST.
    If filtered, there’s no response or an ICMP unreachable message.
*/