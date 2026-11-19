"""
Parser tests for OS-specific command output, using real samples captured
from Windows, Linux and macOS. These run on ANY OS, so the macOS and Linux
collectors are verified even when the suite runs on Windows (and vice versa).
"""

from __future__ import annotations

import json

from nethelper.checks.layer2 import parse_lldpctl_json
from nethelper.net import icmp, traceroute
from nethelper.system import linux, macos, windows
from nethelper.system.model import Snapshot, classify


def test_windows_powershell_json():
    """Windows cmdlet JSON becomes interfaces, routes, DNS, DHCP, neighbours and connections."""
    data = {
        "adapters": [{"Name": "Ethernet", "InterfaceDescription": "Intel(R) Ethernet I219-LM", "ifIndex": 7,
                      "Status": "Up", "MacAddress": "E8-6A-64-DE-9A-E2", "ReceiveLinkSpeed": 1000000000,
                      "MediaType": "802.3", "PhysicalMediaType": "802.3", "VlanID": 0, "FullDuplex": True,
                      "MtuSize": 1500, "Virtual": False}],
        "ipaddrs": [{"InterfaceAlias": "Ethernet", "InterfaceIndex": 7, "IPAddress": "10.0.20.15", "PrefixLength": 24,
                     "AddressFamily": "IPv4", "PrefixOrigin": "Dhcp", "SuffixOrigin": "Dhcp", "AddressState": "Duplicate"}],
        "ipifs": [{"ifIndex": 7, "AddressFamily": "IPv4", "NlMtu": 1500, "Dhcp": "Enabled", "ConnectionState": "Connected",
                   "InterfaceMetric": 25}],
        "routes": [{"DestinationPrefix": "0.0.0.0/0", "NextHop": "10.0.20.1", "InterfaceAlias": "Ethernet",
                    "RouteMetric": 0, "InterfaceMetric": 25, "AddressFamily": "IPv4"}],
        "dns": [{"InterfaceAlias": "Ethernet", "AddressFamily": "IPv4", "ServerAddresses": ["10.0.0.10", "10.0.0.11"]}],
        "dnsglobal": ["acme.local"],
        "dhcp": [{"InterfaceIndex": 7, "DHCPEnabled": True, "DHCPServer": "10.0.0.10", "Obtained": "2026-11-18T08:00:00",
                  "Expires": "2026-11-19T08:00:00"}],
        "firewall": [{"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "Block"}],
        "neighbors": [{"IPAddress": "10.0.20.1", "LinkLayerAddress": "00-11-22-33-44-55", "InterfaceAlias": "Ethernet",
                       "State": "Reachable"},
                      {"IPAddress": "224.0.0.22", "LinkLayerAddress": "01-00-5E-00-00-16", "State": "Permanent"}],
        "tcp": [{"LocalAddress": "0.0.0.0", "LocalPort": 3389, "RemoteAddress": "0.0.0.0", "RemotePort": 0,
                 "State": "Listen", "OwningProcess": 1234}],
        "procs": [{"Id": 1234, "ProcessName": "svchost"}],
        "uptime": [3600],
        "vlanprops_error": "not supported",
    }
    snap = Snapshot()
    windows.parse_ps_json(data, snap)
    eth = snap.interface("Ethernet")
    assert eth.kind == "ethernet" and eth.speed_mbps == 1000 and eth.duplex == "full"
    assert eth.addresses[0].state == "duplicate" and eth.dhcp is True
    assert snap.default_gateway() == "10.0.20.1"
    assert snap.dns_servers == ["10.0.0.10", "10.0.0.11"] and snap.dns_search == ["acme.local"]
    assert snap.dhcp[0].server == "10.0.0.10"
    assert len(snap.neighbors) == 1  # multicast entry filtered out
    assert snap.connections[0].process == "svchost" and snap.uptime_s == 3600
    assert any("vlanprops" in e for e in snap.errors)


NETSH = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : Office
    AP BSSID               : 84:78:48:c2:8f:3f
    Band                   : 5 GHz
    Channel                : 44
    Radio type             : 802.11ax
    Authentication         : WPA2-Enterprise
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 960
    Signal                 : 58%
    Rssi                   : -61
"""


def test_windows_netsh_wlan():
    """Wi-Fi details (SSID, BSSID, band, channel, signal, RSSI, rates) parse from netsh."""
    w = windows.parse_netsh_wlan(NETSH)[0]
    assert (w.ssid, w.bssid, w.band, w.channel) == ("Office", "84:78:48:c2:8f:3f", "5 GHz", 44)
    assert w.signal_pct == 58 and w.rssi_dbm == -61 and w.rx_mbps == 1201 and w.radio == "802.11ax"


IP_ADDR = json.dumps([
    {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "mtu": 65536, "operstate": "UNKNOWN",
     "link_type": "loopback", "address": "00:00:00:00:00:00",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
    {"ifindex": 2, "ifname": "enp3s0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "mtu": 1500,
     "operstate": "UP", "link_type": "ether", "address": "52:54:00:12:34:56",
     "addr_info": [{"family": "inet", "local": "10.0.20.30", "prefixlen": 24, "scope": "global", "dynamic": True},
                   {"family": "inet6", "local": "fe80::5054:ff:fe12:3456", "prefixlen": 64, "scope": "link"}]},
    {"ifindex": 3, "ifname": "enp3s0.30", "link": "enp3s0", "flags": ["UP", "LOWER_UP"], "mtu": 1500, "operstate": "UP",
     "link_type": "ether", "address": "52:54:00:12:34:56",
     "linkinfo": {"info_kind": "vlan", "info_data": {"protocol": "802.1Q", "id": 30}},
     "addr_info": [{"family": "inet", "local": "10.0.30.5", "prefixlen": 24, "scope": "global"}]},
])


def test_linux_ip_addr_route_and_vlan_subinterface():
    """`ip -j -d addr` yields interfaces, DHCP origin, and 802.1Q sub-interfaces with their VLAN id."""
    ifaces = linux.parse_ip_addr(json.loads(IP_ADDR))
    by = {i.name: i for i in ifaces}
    assert by["lo"].kind == "loopback"
    assert by["enp3s0"].kind == "ethernet" and by["enp3s0"].dhcp and by["enp3s0"].addresses[0].origin == "dhcp"
    assert by["enp3s0.30"].vlan_id == 30 and by["enp3s0.30"].vlan_parent == "enp3s0"
    routes = linux.parse_ip_route([{"dst": "default", "gateway": "10.0.20.1", "dev": "enp3s0", "metric": 100},
                                   {"dst": "10.0.20.0/24", "dev": "enp3s0"}], 4)
    assert routes[0].is_default and routes[0].gateway == "10.0.20.1"


def test_linux_dns_ss_iw_nmcli():
    """resolv.conf/resolvectl, ss, iw and nmcli outputs parse correctly."""
    servers, search = linux.parse_resolv_conf("# comment\nnameserver 127.0.0.53\nsearch acme.local corp.local\n")
    assert servers == ["127.0.0.53"] and search == ["acme.local", "corp.local"]
    real, per = linux.parse_resolvectl("Global:\nLink 2 (enp3s0): 10.0.0.10 10.0.0.11\nLink 3 (wg0):\n")
    assert real == ["10.0.0.10", "10.0.0.11"] and per == {"enp3s0": ["10.0.0.10", "10.0.0.11"]}
    ss = ('tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))\n'
          "tcp   ESTAB  0 0   10.0.20.30:22 10.0.20.9:51234\n"
          "udp   UNCONN 0 0   [::]:5353 [::]:*\n")
    conns = linux.parse_ss(ss)
    assert conns[0].process == "sshd" and conns[0].pid == 812 and conns[0].state == "listen"
    assert conns[1].state == "established" and conns[1].remote == "10.0.20.9"
    iw = ("Connected to 84:78:48:c2:8f:3f (on wlan0)\n\tSSID: Office\n\tfreq: 5220\n\tsignal: -58 dBm\n"
          "\trx bitrate: 866.7 MBit/s VHT-MCS 9\n\ttx bitrate: 780.0 MBit/s\n")
    w = linux.parse_iw_link(iw, "wlan0")
    assert w.ssid == "Office" and w.channel == 44 and w.band == "5 GHz" and w.rssi_dbm == -58
    nm = linux.parse_nmcli_wifi("yes:Office:84\\:78\\:48\\:C2\\:8F\\:3F:44:540 Mbit/s:70:WPA2:wlan0\nno:Other:::::::\n")
    assert nm[0].bssid == "84:78:48:c2:8f:3f" and nm[0].signal_pct == 70


IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether a4:83:e7:11:22:33
\tinet6 fe80::1c2b:3d4e:5f60:7182%en0 prefixlen 64 secured scopeid 0x4
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
\tmedia: autoselect (1000baseT <full-duplex>)
\tstatus: active
vlan0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether a4:83:e7:11:22:33
\tvlan: 20 parent interface: en0
\tinet 10.0.20.7 netmask 0xffffff00 broadcast 10.0.20.255
\tstatus: active
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:00:00:01
\tstatus: inactive
"""


def test_macos_ifconfig_netstat_scutil_arp_airport():
    """macOS text outputs parse: interfaces (incl. VLAN + duplex), routes, DNS, ARP, Wi-Fi."""
    ifaces = {i.name: i for i in macos.parse_ifconfig(IFCONFIG, {"en1"})}
    assert ifaces["en0"].speed_mbps == 1000 and ifaces["en0"].duplex == "full" and ifaces["en0"].addresses[1].prefix == 24
    assert ifaces["vlan0"].vlan_id == 20 and ifaces["vlan0"].vlan_parent == "en0"
    assert ifaces["en1"].kind == "wifi" and not ifaces["en1"].up
    routes = macos.parse_netstat_routes("Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n"
                                        "default 192.168.1.1 UGScg en0\n127 127.0.0.1 UCS lo0\n", 4)
    assert routes[0].is_default and routes[0].gateway == "192.168.1.1"
    servers, search = macos.parse_scutil_dns("DNS configuration\n\nresolver #1\n  search domain[0] : acme.local\n"
                                             "  nameserver[0] : 192.168.1.1\n  nameserver[1] : 1.1.1.1\n"
                                             "DNS configuration (for scoped queries)\n  nameserver[0] : 9.9.9.9\n")
    assert servers == ["192.168.1.1", "1.1.1.1"] and search == ["acme.local"]
    arp = macos.parse_arp("? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n"
                          "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n")
    assert len(arp) == 1 and arp[0].mac == "00:11:22:33:44:55"
    airport = json.dumps({"SPAirPortDataType": [{"spairport_airport_interfaces": [{"_name": "en1",
        "spairport_current_network_information": {"_name": "Office", "spairport_network_channel": "44 (5GHz, 80MHz)",
                                                  "spairport_signal_noise": "-52 dBm / -94 dBm",
                                                  "spairport_network_rate": 866}}]}]})
    w = macos.parse_airport_json(airport)[0]
    assert w.ssid == "Office" and w.channel == 44 and w.rssi_dbm == -52


def test_traceroute_and_tracepath_text():
    """Text traceroute output (Linux/macOS/Windows tracert) parses into hops."""
    tr = (" 1  192.168.1.1  0.512 ms  0.433 ms\n 2  * *\n 3  10.20.0.1  4.1 ms  3.9 ms\n 4  1.1.1.1  8.0 ms  7.9 ms\n")
    hops = traceroute.parse_traceroute(tr, "1.1.1.1")
    assert [h.address for h in hops] == ["192.168.1.1", None, "10.20.0.1", "1.1.1.1"] and hops[-1].reached
    win = "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n  2     4 ms     3 ms     4 ms  203.0.113.2\n"
    assert traceroute.parse_traceroute(win, "x")[0].address == "192.168.1.1"
    tp = (" 1?: [LOCALHOST]                      pmtu 1500\n 1:  192.168.1.1   0.468ms\n 2:  no reply\n"
          " 3:  1.1.1.1   8.1ms reached\n")
    hops = traceroute.parse_tracepath(tp, "1.1.1.1")
    assert hops[0].address == "192.168.1.1" and hops[-1].reached


def test_system_ping_output_parsing():
    """System ping output (all three OSes) is interpreted correctly, including TTL-exceeded replies."""
    assert icmp.parse_system_ping("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=7.83 ms", 1, "1.1.1.1").rtt_ms == 7.83
    assert icmp.parse_system_ping("Reply from 1.1.1.1: bytes=32 time<1ms TTL=57", 1, "1.1.1.1").status == icmp.OK
    r = icmp.parse_system_ping("From 10.0.0.1 icmp_seq=1 Time to live exceeded", 1, "x")
    assert r.status == icmp.TTL_EXPIRED and r.from_ip == "10.0.0.1"
    assert icmp.parse_system_ping("Request timed out.", 1, "x").status == icmp.TIMEOUT


def test_lldpctl_json_parsing():
    """lldpd's JSON (used non-elevated on Linux) is mapped to the common neighbour format."""
    text = json.dumps({"lldp": {"interface": {"eth0": {"via": "LLDP", "chassis": {"core-sw-01": {
        "id": {"type": "mac", "value": "00:11:22:33:44:55"}, "descr": "Aruba", "mgmt-ip": "10.0.0.2"}},
        "port": {"id": {"type": "ifname", "value": "1/1/12"}, "descr": "desk 12"},
        "vlan": {"vlan-id": "20", "pvid": True, "value": "DATA"}}}}})
    n = parse_lldpctl_json(text, "eth0")[0]
    assert n["system_name"] == "core-sw-01" and n["port_id"] == "1/1/12" and n["native_vlan"] == 20
    assert n["mgmt_addresses"] == ["10.0.0.2"]


def test_interface_classification():
    """Adapters are classified sensibly from names/descriptions."""
    assert classify("Wi-Fi", "Intel Wi-Fi 6") == "wifi"
    assert classify("Local Area Connection", "TAP-Windows Adapter V9") == "vpn"
    assert classify("wg0") == "vpn"
    assert classify("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter") == "virtual"
    assert classify("enp3s0") == "ethernet"
    assert classify("lo") == "loopback"
