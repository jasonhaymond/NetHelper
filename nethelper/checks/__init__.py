"""
The diagnostic checks themselves, one module per report section:

  local.py         Local host: interfaces, routing, DNS config, DHCP, proxy, VPN,
                   firewall, Wi-Fi, hosts file, listening ports
  connectivity.py  Connectivity ladder, ping, traceroute, outbound ports, MTU, IPv6
  dns_checks.py    Resolver comparison, records, reverse DNS, hijacking, DNSSEC,
                   encrypted DNS, captive portal
  app.py           Site targets, HTTP(S), TLS certificates, public IP, clock (NTP),
                   speed test, mail/directory services
  lan.py           Gateway MAC/ARP spoofing, neighbours, duplicate IP, rogue DHCP,
                   mDNS/SSDP discovery, subnet sweep
  layer2.py        Link speed/duplex, local VLAN config, switchport (LLDP/CDP),
                   VLAN validation, tagged frames, inter-VLAN reachability

Each check is a function decorated with @check(...) (see core/registry.py)
that receives the shared Context and returns an Outcome. Checks never print;
they only return findings, so the same check feeds the console, JSON, HTML and
the verdict engine.
"""
