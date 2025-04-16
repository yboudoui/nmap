# ACK
    Sends a TCP packet with the ACK flag set (without a prior SYN).
    If the response is RST, the port is unfiltered (reachable but not necessarily open).
    If there is no response, the port is filtered (blocked by a firewall).

# FIN
    Sends a TCP packet with only the FIN flag set.
    If the port is closed, the target responds with RST.
    If the port is open, there is no response.
    If filtered, there’s no response or an ICMP unreachable message.

# NULL
    Sends a TCP packet with no flags set (i.e., an empty header).
    If the port is open, there is no response (depends on OS).
    If the port is closed, it sends an RST.
    If filtered, there’s no response or an ICMP unreachable message.

# SYN
    Sends a SYN packet (like the beginning of a TCP handshake).
    If the port is open, the target responds with SYN-ACK.
    Instead of completing the handshake, Nmap sends an RST (Reset) packet to avoid detection.
    If the port is closed, the target sends an RST.
    If filtered, there’s no response or an ICMP unreachable message.

# UDP
    Sends a UDP packet to each target port.
    If the port is open, there is no response or a specific UDP response.
    If the port is closed, an ICMP Port Unreachable message is received.
    If filtered, no response or ICMP unreachable errors may be received.

# XMAS
    Sends a TCP packet with FIN, URG, and PSH flags set (XMAS tree pattern).
    If the port is closed, the target responds with RST.
    If the port is open, there is no response.
    If filtered, there’s no response or an ICMP unreachable message.