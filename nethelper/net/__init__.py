"""
Network building blocks used by the checks. Each module does one job and has
no knowledge of the check/registry framework, so it can be reused directly
(and unit-tested in isolation):

  icmp.py        ping (Windows API, unprivileged ICMP sockets, or system ping)
  traceroute.py  hop-by-hop path discovery
  dnswire.py     a small DNS client speaking the DNS wire protocol (UDP/TCP/DoT/DoH)
  tcp.py         TCP connect tests and service banners
  httpcheck.py   HTTP(S) fetch with a per-phase timing breakdown
  x509.py        minimal certificate parser (subject, issuer, dates, SANs)
  tlscheck.py    TLS handshake inspection
  ntp.py         SNTP clock-offset query
  mtu.py         path-MTU discovery
  publicip.py    public IP / ASN lookup
  bandwidth.py   download/upload throughput and iperf3
  discovery.py   mDNS and SSDP LAN service discovery
  dhcp.py        DHCP DISCOVER probe (rogue DHCP server detection)
  arp.py         ARP resolution and LAN sweep
  oui.py         MAC address -> vendor lookup
  pcap.py        pcap/pcapng reader+writer and packet summaries
  l2proto.py     LLDP and CDP frame parsers (switch/port/VLAN info)
  capture.py     packet capture via dumpcap/tshark/tcpdump/pktmon/raw sockets
  remediate.py   opt-in repair actions (flush DNS, renew DHCP, ...)
"""
