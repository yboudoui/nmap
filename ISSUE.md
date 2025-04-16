# Unable yet to receive a response packet
While testing against `nmap` with `tcpdump` I saw that this implementation is unable the receive any packet. 
Here the following command used to test.
```bash
IP=127.0.0.1
PORT=53

sudo tcpdump -ni any "host ${IP} and (tcp or icmp)"

nmap ${IP} -p ${PORT} -sA
./ft_nmap --ports ${PORT} --ip ${IP} --scan ACK    
```

It's probably du to the fact that the tcp packet sent is ill formed, or the immediate mode `pcap_set_immediate_mode` is not set.
Need to check:
- the ack value
- the seq value
- the hole tcp checksum

# Missing feature
## Fully Qualified Domain Name (FQDN)
I should parse the input argument and now if it's a domain name in order to resolve it with `getaddrinfo`

# Ressources
- https://www.ietf.org/rfc/rfc793.txt
- https://www.tcpdump.org/
- https://www.man7.org/linux/man-pages/man7/raw.7.html
- https://github.com/nmap/nmap
    - https://github.com/nmap/nmap/blob/master/FPEngine.cc#L1632
    - https://github.com/nmap/nmap/blob/master/nping/ProbeMode.cc#L773
    - https://github.com/nmap/nmap/blob/master/traceroute.cc#L691
    - https://github.com/nmap/nmap/blob/master/traceroute.cc#L691
    - https://github.com/nmap/nmap/blob/master/nbase/nbase_rnd.c#L217 <- for generating the ack (maybe the problem come from here)
        - https://github.com/nmap/nmap/blob/master/nping/NpingOps.cc#L2892
        - https://github.com/nmap/nmap/blob/master/scan_engine.h#L153