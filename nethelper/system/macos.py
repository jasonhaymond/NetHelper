"""
macOS collector: gathers local network facts into a model.Snapshot.

macOS has no JSON-producing equivalent of Linux's `ip -j`, so this parses the
text output of the standard tools (stable for many macOS releases):
  ifconfig -a                        interfaces, MACs, addresses, media/duplex, VLANs
  networksetup -listallhardwareports which device is Wi-Fi / Ethernet / Thunderbolt
  netstat -rn                        routing tables
  scutil --dns / --proxy             DNS resolvers and proxy settings
  ipconfig getpacket <if>            DHCP lease (server, lease time)
  arp -an                            ARP table
  socketfilterfw --getglobalstate    application firewall state
  system_profiler SPAirPortDataType  Wi-Fi details (slow-ish; SSID may be
                                     hidden by macOS privacy unless Location
                                     Services are allowed for the terminal)
  lsof -nP -i                        sockets with processes (own processes
                                     only unless run with sudo)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from nethelper.core import cmd
from nethelper.core.privileges import is_elevated
from nethelper.system.linux import parse_resolv_conf  # noqa: F401 - re-exported for tests
from nethelper.system.model import (Address, Connection, DhcpLease, Interface, Neighbor, Route,
                                    Snapshot, WifiInfo, classify, normalize_mac)
from nethelper.system.windows import parse_hosts

# Regex: first line of an ifconfig block, e.g.
#   "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500"
_IF_HEAD = re.compile(r"^(\S+?):\s+flags=\w+<([^>]*)>.*?mtu\s+(\d+)")


def parse_ifconfig(text: str, wifi_devices: set[str] | None = None) -> list[Interface]:
    """Parse `ifconfig -a` (macOS/BSD format) into Interface objects."""
    wifi_devices = wifi_devices or set()
    out: list[Interface] = []
    cur: Interface | None = None
    for line in text.splitlines():
        m = _IF_HEAD.match(line)
        if m:
            name = m.group(1)
            flags = m.group(2).split(",")
            cur = Interface(name=name, up="UP" in flags and "RUNNING" in flags, mtu=int(m.group(3)),
                            kind=classify(name, "", name in wifi_devices))
            if "LOOPBACK" in flags:
                cur.kind = "loopback"
            out.append(cur)
            continue
        if cur is None:
            continue
        parts = line.strip().split()
        if not parts:
            continue
        if parts[0] == "ether" and len(parts) > 1:
            cur.mac = normalize_mac(parts[1])
        elif parts[0] == "inet" and len(parts) >= 4:
            # netmask is hex, e.g. 0xffffff00 -> count the 1 bits = prefix length 24.
            prefix = bin(int(parts[3], 16)).count("1") if parts[2] == "netmask" else 32
            cur.addresses.append(Address(ip=parts[1], prefix=prefix, family=4,
                                         origin="link-local" if parts[1].startswith("169.254.") else None))
        elif parts[0] == "inet6" and len(parts) >= 4:
            ip = parts[1].split("%")[0]
            prefix = int(parts[parts.index("prefixlen") + 1]) if "prefixlen" in parts else 64
            cur.addresses.append(Address(ip=ip, prefix=prefix, family=6,
                                         origin="link-local" if ip.lower().startswith("fe80") else None))
        elif parts[0] == "media:":
            text_media = line.lower()
            if "full-duplex" in text_media:
                cur.duplex = "full"
            elif "half-duplex" in text_media:
                cur.duplex = "half"
            # Regex: speed inside media, e.g. "1000baseT" or "10Gbase-T" -> 1000 / 10000 Mb/s.
            sm = re.search(r"\((\d+)(g?)base", text_media)
            if sm:
                cur.speed_mbps = float(sm.group(1)) * (1000 if sm.group(2) else 1)
        elif parts[0] == "status:":
            cur.up = cur.up and parts[1] == "active"
        elif parts[0] == "vlan:" and len(parts) >= 2:
            try:
                cur.vlan_id = int(parts[1])
            except ValueError:
                pass
            if "interface:" in parts:
                cur.vlan_parent = parts[parts.index("interface:") + 1]
            cur.kind = "ethernet"
    for iface in out:
        if iface.kind != "ethernet":
            iface.duplex = None
    return out


def parse_hardware_ports(text: str) -> dict[str, str]:
    """Parse `networksetup -listallhardwareports` into {device: port name}."""
    result, port = {}, None
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            result[line.split(":", 1)[1].strip()] = port
    return result


def parse_netstat_routes(text: str, family: int) -> list[Route]:
    """Parse `netstat -rn -f inet|inet6` lines: Destination Gateway Flags Netif ..."""
    routes = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] in ("Destination", "Routing", "Internet:", "Internet6:"):
            continue
        dest, gw, iface = parts[0], parts[1], parts[3]
        if dest == "default":
            dest = "0.0.0.0/0" if family == 4 else "::/0"
        if gw.startswith("link#") or ":" in gw and family == 4:
            gw = None
        elif gw:
            gw = gw.split("%")[0]
        routes.append(Route(destination=dest, gateway=gw, interface=iface, family=family))
    return routes


def parse_scutil_dns(text: str) -> tuple[list[str], list[str]]:
    """Parse `scutil --dns`: nameservers and search domains from the main section."""
    servers, search = [], []
    main = text.split("DNS configuration (for scoped queries)")[0]
    for line in main.splitlines():
        line = line.strip()
        if line.startswith("nameserver["):
            ip = line.split(":", 1)[1].strip()
            if ip not in servers:
                servers.append(ip)
        elif line.startswith("search domain["):
            dom = line.split(":", 1)[1].strip()
            if dom not in search:
                search.append(dom)
    return servers, search


def parse_arp(text: str) -> list[Neighbor]:
    """Parse `arp -an`: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"."""
    out = []
    for line in text.splitlines():
        # Regex: captures IP in parentheses, the MAC after "at", and interface after "on".
        m = re.search(r"\(([\d.]+)\) at ([0-9a-fA-F:]+) on (\S+)", line)
        if m:
            # macOS drops leading zeros ("0:11:22:..."), so pad each byte to 2 digits.
            mac = normalize_mac(":".join(part.zfill(2) for part in m.group(2).split(":")))
            if mac and mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):
                out.append(Neighbor(m.group(1), mac, m.group(3), "permanent" if "permanent" in line else "reachable"))
    return out


def parse_airport_json(text: str) -> list[WifiInfo]:
    """Parse `system_profiler -json SPAirPortDataType` for the current network."""
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for entry in data.get("SPAirPortDataType", []):
        for iface in entry.get("spairport_airport_interfaces", []):
            cur = iface.get("spairport_current_network_information")
            if not cur:
                continue
            info = WifiInfo(interface=iface.get("_name", "en0"), ssid=cur.get("_name"))
            # Channel looks like "44 (5GHz, 80MHz)".
            chan = str(cur.get("spairport_network_channel", ""))
            m = re.match(r"(\d+)\s*\(([\d.]+GHz)", chan)
            if m:
                info.channel, info.band = int(m.group(1)), m.group(2).replace("GHz", " GHz")
            # Signal looks like "-52 dBm / -94 dBm" (signal / noise).
            sig = re.match(r"(-?\d+)\s*dBm", str(cur.get("spairport_signal_noise", "")))
            if sig:
                info.rssi_dbm = int(sig.group(1))
                info.signal_pct = max(0, min(100, 2 * (info.rssi_dbm + 100)))
            try:
                info.tx_mbps = float(cur.get("spairport_network_rate"))
            except (TypeError, ValueError):
                pass
            info.radio = cur.get("spairport_network_phymode")
            info.security = cur.get("spairport_security_mode")
            if info.ssid in (None, "<redacted>"):
                info.note = "SSID hidden by macOS privacy - allow Location Services for your terminal app"
            out.append(info)
    return out


def parse_lsof(text: str) -> list[Connection]:
    """Parse `lsof -nP -iTCP -iUDP` output into Connection objects."""
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proc, pid, proto, name = parts[0], parts[1], parts[7].lower(), parts[8]
        state = parts[9].strip("()").lower() if len(parts) > 9 else ("listen" if proto == "udp" else None)
        local, _, remote = name.partition("->")
        lhost, _, lport = local.rpartition(":")
        rhost, _, rport = remote.rpartition(":") if remote else ("", "", "")
        try:
            out.append(Connection(proto, lhost.strip("[]"), int(lport), rhost.strip("[]") or None,
                                  int(rport) if rport.isdigit() else None, state, int(pid), proc))
        except ValueError:
            continue
    return out


def collect(snap: Snapshot) -> None:
    """Run all macOS collectors, filling `snap` in place."""
    root = is_elevated()
    hw = cmd.run(["networksetup", "-listallhardwareports"], timeout=10)
    ports = parse_hardware_ports(hw.stdout)
    wifi_devs = {dev for dev, port in ports.items() if "wi-fi" in port.lower() or "airport" in port.lower()}
    res = cmd.run(["ifconfig", "-a"], timeout=10)
    snap.raw["ifconfig -a"] = res.transcript()
    snap.interfaces = parse_ifconfig(res.stdout, wifi_devs)
    for iface in snap.interfaces:
        iface.description = ports.get(iface.name, "")
        if iface.description:
            iface.kind = classify(iface.name, iface.description, iface.name in wifi_devs)

    for fam, flag in ((4, "inet"), (6, "inet6")):
        r = cmd.run(["netstat", "-rn", "-f", flag], timeout=10)
        snap.raw[f"netstat -rn {flag}"] = r.transcript()
        snap.routes.extend(parse_netstat_routes(r.stdout, fam))

    d = cmd.run(["scutil", "--dns"], timeout=10)
    snap.raw["scutil --dns"] = d.transcript()
    snap.dns_servers, snap.dns_search = parse_scutil_dns(d.stdout)

    for iface in snap.interfaces:
        if not iface.usable or iface.kind in ("loopback", "vpn", "virtual"):
            continue
        p = cmd.run(["ipconfig", "getpacket", iface.name], timeout=10)
        if p.ok and "server_identifier" in p.stdout:
            iface.dhcp = True
            lease = DhcpLease(interface=iface.name)
            for line in p.stdout.splitlines():
                if line.startswith("server_identifier"):
                    lease.server = line.split(":", 1)[1].strip()
                elif line.startswith("lease_time"):
                    try:
                        lease.expires = f"lease time {int(line.split(':', 1)[1].strip(), 16)} s"
                    except ValueError:
                        pass
            snap.dhcp.append(lease)

    px = cmd.run(["scutil", "--proxy"], timeout=10)
    proxy: dict = {}
    for line in px.stdout.splitlines():
        key, _, value = line.strip().partition(" : ")
        if key in ("HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort",
                   "ProxyAutoConfigEnable", "ProxyAutoConfigURLString", "ProxyAutoDiscoveryEnable"):
            proxy[key] = value
    snap.proxy = {"system": proxy}

    fw = cmd.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], timeout=10)
    snap.firewall = {"backend": "macOS Application Firewall",
                     "enabled": "enabled" in fw.stdout.lower() if fw.ok else None}

    a = cmd.run(["arp", "-an"], timeout=10)
    snap.neighbors = parse_arp(a.stdout)

    if wifi_devs:
        sp = cmd.run(["system_profiler", "-json", "SPAirPortDataType"], timeout=30)
        snap.wifi = parse_airport_json(sp.stdout)

    if cmd.which("lsof"):
        ls = cmd.run(["lsof", "-nP", "-iTCP", "-iUDP"], timeout=20)
        snap.connections = [c for c in parse_lsof(ls.stdout) if c.state in ("listen", "established")]
        if not root:
            snap.raw["connections-note"] = "process list limited to your own processes (run with sudo for all)"

    bt = cmd.run(["sysctl", "-n", "kern.boottime"], timeout=5)
    m = re.search(r"sec = (\d+)", bt.stdout)
    if m:
        import time

        snap.uptime_s = time.time() - int(m.group(1))
    snap.hosts_entries = parse_hosts(Path("/etc/hosts"))
