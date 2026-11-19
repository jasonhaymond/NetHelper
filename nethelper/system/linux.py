"""
Linux collector: gathers local network facts into a model.Snapshot.

Sources (all readable without root unless noted):
  ip -j -d addr      interfaces, MACs, MTU, state, addresses, VLAN sub-interfaces
                     (-j = JSON output, -d = details such as the 802.1Q VLAN id)
  ip -j route        IPv4 and IPv6 routing tables
  ip -j neigh        ARP / IPv6 neighbour table
  /sys/class/net/*   link speed, duplex, and whether an interface is wireless
  /etc/resolv.conf   DNS servers and search domains; when it points at the
                     systemd-resolved stub (127.0.0.53), `resolvectl dns` is
                     asked for the real upstream servers
  nmcli / systemd-networkd / dhclient lease files   DHCP lease details
  iw / nmcli         Wi-Fi association details
  ss -tunap          sockets; process names for other users' sockets need root
  ufw / firewall-cmd / nft   firewall state (ufw and nft need root)
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from nethelper.core import cmd
from nethelper.core.privileges import is_elevated
from nethelper.system.model import (Address, Connection, DhcpLease, Interface, Neighbor, Route,
                                    Snapshot, WifiInfo, classify, is_unspecified, normalize_mac)
from nethelper.system.windows import parse_hosts


def _read(path: str) -> str | None:
    """Read a small text file (e.g. under /sys), returning None if unavailable."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def parse_ip_addr(data: list[dict]) -> list[Interface]:
    """Convert `ip -j -d addr` JSON into Interface objects."""
    out: list[Interface] = []
    for item in data:
        name = item.get("ifname", "")
        wireless = os.path.isdir(f"/sys/class/net/{name}/wireless")
        linkinfo = item.get("linkinfo") or {}
        iface = Interface(
            name=name, index=item.get("ifindex"), mac=normalize_mac(item.get("address")),
            up=item.get("operstate") == "UP" or ("UP" in item.get("flags", []) and "LOWER_UP" in item.get("flags", [])),
            mtu=item.get("mtu"), kind=classify(name, linkinfo.get("info_kind", ""), wireless),
        )
        if item.get("link_type") == "loopback":
            iface.kind = "loopback"
        if linkinfo.get("info_kind") == "vlan":
            iface.vlan_id = (linkinfo.get("info_data") or {}).get("id")
            iface.vlan_parent = item.get("link")
            if iface.kind == "other":
                iface.kind = "ethernet"
        for a in item.get("addr_info") or []:
            fam = 6 if a.get("family") == "inet6" else 4
            scope = a.get("scope")
            origin = "dhcp" if a.get("dynamic") and fam == 4 else ("link-local" if scope == "link" else
                                                                    ("slaac" if a.get("dynamic") else "manual"))
            state = "tentative" if a.get("tentative") else ("deprecated" if a.get("deprecated") else
                                                            ("duplicate" if a.get("dadfailed") else "preferred"))
            iface.addresses.append(Address(ip=a.get("local", ""), prefix=int(a.get("prefixlen", 0)),
                                           family=fam, origin=origin, state=state))
        if any(a.origin == "dhcp" for a in iface.addresses):
            iface.dhcp = True
        out.append(iface)
    return out


def parse_ip_route(data: list[dict], family: int) -> list[Route]:
    """Convert `ip -j route` JSON into Route objects."""
    routes = []
    for r in data:
        dst = r.get("dst", "")
        if dst == "default":
            dst = "0.0.0.0/0" if family == 4 else "::/0"
        elif "/" not in dst and dst:
            dst = f"{dst}/{32 if family == 4 else 128}"
        routes.append(Route(destination=dst, gateway=r.get("gateway"), interface=r.get("dev"),
                            metric=r.get("metric"), family=family))
    return routes


def parse_resolvectl(text: str) -> tuple[list[str], dict[str, list[str]]]:
    """
    Parse `resolvectl dns`, e.g.:
        Global: 1.1.1.1
        Link 2 (eth0): 10.0.0.1 10.0.0.2
    Returns (all servers, per-interface map).
    """
    all_servers: list[str] = []
    per: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, rest = line.partition(":")
        # Regex: interface name inside "Link 2 (eth0)" - captures "eth0".
        m = re.search(r"\(([^)]+)\)", label)
        servers = [s for s in rest.split() if s]
        if not servers:
            continue
        per[m.group(1) if m else label.strip()] = servers
        for s in servers:
            if s not in all_servers:
                all_servers.append(s)
    return all_servers, per


def parse_resolv_conf(text: str) -> tuple[list[str], list[str]]:
    """Parse /etc/resolv.conf: returns (nameservers, search domains)."""
    servers, search = [], []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])
        elif parts and parts[0] in ("search", "domain"):
            search.extend(parts[1:])
    return servers, search


def parse_iw_link(text: str, iface: str) -> WifiInfo | None:
    """Parse `iw dev <iface> link` output; None when not connected."""
    if "Not connected" in text or not text.strip():
        return None
    info = WifiInfo(interface=iface)
    # Regex: "Connected to aa:bb:cc:dd:ee:ff" - the access point's BSSID.
    m = re.search(r"Connected to ([0-9a-fA-F:]{17})", text)
    if m:
        info.bssid = normalize_mac(m.group(1))
    for line in text.splitlines():
        key, _, value = line.strip().partition(":")
        value = value.strip()
        if key == "SSID":
            info.ssid = value
        elif key == "freq":
            freq = float(value.split()[0])
            info.band = "2.4 GHz" if freq < 3000 else ("5 GHz" if freq < 5925 else "6 GHz")
            info.channel = _freq_to_channel(freq)
        elif key == "signal":
            info.rssi_dbm = int(float(value.split()[0]))
            info.signal_pct = max(0, min(100, 2 * (info.rssi_dbm + 100)))
        elif key == "rx bitrate":
            info.rx_mbps = float(value.split()[0])
        elif key == "tx bitrate":
            info.tx_mbps = float(value.split()[0])
    return info


def _freq_to_channel(freq_mhz: float) -> int | None:
    """Convert a Wi-Fi centre frequency (MHz) to its channel number."""
    f = int(freq_mhz)
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5000 <= f < 5925:
        return (f - 5000) // 5
    if 5925 <= f <= 7125:
        return (f - 5950) // 5
    return None


def parse_nmcli_wifi(text: str) -> list[WifiInfo]:
    """
    Parse `nmcli -t -f ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY,DEVICE dev wifi`.
    Terse (-t) mode separates fields with ':' and escapes literal colons as '\\:'.
    """
    out = []
    for line in text.splitlines():
        fields = [f.replace("\\:", ":") for f in re.split(r"(?<!\\):", line)]
        if len(fields) < 8 or fields[0] != "yes":
            continue
        info = WifiInfo(interface=fields[7], ssid=fields[1] or None, bssid=normalize_mac(fields[2]))
        try:
            info.channel = int(fields[3])
            info.band = "2.4 GHz" if info.channel <= 14 else "5 GHz"
            info.rx_mbps = float(fields[4].split()[0])
            info.signal_pct = int(fields[5])
            info.rssi_dbm = int(info.signal_pct / 2 - 100)
        except (ValueError, IndexError):
            pass
        info.security = fields[6] or None
        out.append(info)
    return out


# Regex: process info in ss output, e.g. users:(("sshd",pid=812,fd=3)) -> name, pid.
_SS_PROC = re.compile(r'\(\("([^"]+)",pid=(\d+)')


def _split_hostport(value: str) -> tuple[str, int]:
    """Split "10.0.0.1:22", "[::1]:631" or "*:68" into (host, port)."""
    host, _, port = value.rpartition(":")
    host = host.strip("[]")
    if "%" in host:
        host = host.split("%")[0]
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def parse_ss(text: str) -> list[Connection]:
    """Parse `ss -tunapH` (no header) output into Connection objects."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        proto, state = parts[0], parts[1].lower()
        if state not in ("listen", "estab", "unconn"):
            continue
        lhost, lport = _split_hostport(parts[4])
        rhost, rport = _split_hostport(parts[5])
        m = _SS_PROC.search(line)
        out.append(Connection(proto=proto, local=lhost, local_port=lport,
                              remote=None if rhost == "*" or is_unspecified(rhost) else rhost,
                              remote_port=rport or None,
                              state={"estab": "established", "unconn": "listen"}.get(state, state),
                              pid=int(m.group(2)) if m else None, process=m.group(1) if m else None))
    return out


def _dhcp_leases(snap: Snapshot) -> None:
    """Find DHCP lease details via NetworkManager, systemd-networkd, or dhclient."""
    for iface in snap.interfaces:
        if not iface.dhcp:
            continue
        lease = DhcpLease(interface=iface.name)
        if cmd.which("nmcli"):
            res = cmd.run(["nmcli", "-t", "-f", "DHCP4", "device", "show", iface.name], timeout=10)
            for line in res.stdout.splitlines():
                if "dhcp_server_identifier" in line:
                    lease.server = line.rsplit("=", 1)[-1].strip()
                elif "expiry" in line:
                    lease.expires = line.rsplit("=", 1)[-1].strip()
        networkd = _read(f"/run/systemd/netif/leases/{iface.index}")
        if networkd and not lease.server:
            for line in networkd.splitlines():
                if line.startswith("SERVER_ADDRESS="):
                    lease.server = line.split("=", 1)[1]
                elif line.startswith("LIFETIME="):
                    lease.expires = f"lifetime {line.split('=', 1)[1]} s"
        if not lease.server:
            for path in sorted(Path("/var/lib/dhcp").glob(f"dhclient*{iface.name}*.lease*")) if Path("/var/lib/dhcp").is_dir() else []:
                text = _read(str(path)) or ""
                # Regex: "option dhcp-server-identifier 10.0.0.1;" in a dhclient lease file.
                m = re.findall(r"dhcp-server-identifier\s+([\d.]+);", text)
                e = re.findall(r"expire \d+ ([^;]+);", text)
                if m:
                    lease.server, lease.expires = m[-1], (e[-1] if e else None)
        snap.dhcp.append(lease)


def collect(snap: Snapshot) -> None:
    """Run all Linux collectors, filling `snap` in place."""
    root = is_elevated()
    res = cmd.run(["ip", "-j", "-d", "addr", "show"], timeout=10)
    snap.raw["ip -d addr"] = res.transcript()
    if res.ok:
        try:
            snap.interfaces = parse_ip_addr(json.loads(res.stdout))
        except (json.JSONDecodeError, TypeError) as exc:
            snap.errors.append(f"could not parse ip addr: {exc}")
    else:
        snap.errors.append(f"ip addr failed: {res.error or res.stderr.strip()}")
    for iface in snap.interfaces:
        speed = _read(f"/sys/class/net/{iface.name}/speed")
        if speed and speed.lstrip("-").isdigit() and int(speed) > 0:
            iface.speed_mbps = float(speed)
        duplex = _read(f"/sys/class/net/{iface.name}/duplex")
        if duplex in ("full", "half") and iface.kind == "ethernet":
            iface.duplex = duplex

    for fam, extra in ((4, []), (6, ["-6"])):
        r = cmd.run(["ip", "-j", *extra, "route", "show"], timeout=10)
        snap.raw[f"ip -{fam} route"] = r.transcript()
        if r.ok and r.stdout.strip():
            try:
                snap.routes.extend(parse_ip_route(json.loads(r.stdout), fam))
            except (json.JSONDecodeError, TypeError):
                pass

    r = cmd.run(["ip", "-j", "neigh", "show"], timeout=10)
    if r.ok and r.stdout.strip():
        try:
            for n in json.loads(r.stdout):
                mac = normalize_mac(n.get("lladdr"))
                states = [s.lower() for s in n.get("state", [])]
                if mac and "failed" not in states and "incomplete" not in states:
                    snap.neighbors.append(Neighbor(n.get("dst", ""), mac, n.get("dev"), ",".join(states)))
        except (json.JSONDecodeError, TypeError):
            pass

    resolv = _read("/etc/resolv.conf") or ""
    snap.raw["/etc/resolv.conf"] = resolv
    servers, snap.dns_search = parse_resolv_conf(resolv)
    snap.dns_servers = servers
    if any(s.startswith("127.0.0.53") for s in servers) and cmd.which("resolvectl"):
        rc = cmd.run(["resolvectl", "dns"], timeout=10)
        snap.raw["resolvectl dns"] = rc.transcript()
        real, per = parse_resolvectl(rc.stdout)
        if real:
            snap.dns_servers = real
            snap.dns_by_interface = per

    _dhcp_leases(snap)

    snap.proxy = {"env": {k: v for k, v in os.environ.items()
                          if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}}

    fw: dict = {"backend": None}
    if cmd.which("ufw") and root:
        u = cmd.run(["ufw", "status", "verbose"], timeout=10)
        fw.update(backend="ufw", enabled="Status: active" in u.stdout, detail=u.stdout.strip()[:2000])
    elif cmd.which("firewall-cmd"):
        f = cmd.run(["firewall-cmd", "--state"], timeout=10)
        fw.update(backend="firewalld", enabled=f.stdout.strip() == "running")
    elif cmd.which("nft") and root:
        n = cmd.run(["nft", "list", "ruleset"], timeout=10)
        fw.update(backend="nftables", enabled=bool(n.stdout.strip()), rules=n.stdout.count("\n"))
    if not root and fw["backend"] in (None,) and (cmd.which("ufw") or cmd.which("nft")):
        fw["note"] = "firewall status needs root (ufw/nft)"
    snap.firewall = fw

    for iface in snap.interfaces:
        if iface.kind != "wifi" or not iface.up:
            continue
        info = None
        if cmd.which("iw"):
            w = cmd.run(["iw", "dev", iface.name, "link"], timeout=10)
            snap.raw[f"iw {iface.name}"] = w.transcript()
            info = parse_iw_link(w.stdout, iface.name)
        if info is None and cmd.which("nmcli"):
            w = cmd.run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY,DEVICE",
                         "dev", "wifi"], timeout=15)
            found = [i for i in parse_nmcli_wifi(w.stdout) if i.interface == iface.name]
            info = found[0] if found else None
        if info:
            snap.wifi.append(info)

    if cmd.which("ss"):
        s = cmd.run(["ss", "-tunapH"], timeout=10)
        snap.connections = parse_ss(s.stdout)

    up = _read("/proc/uptime")
    if up:
        snap.uptime_s = float(up.split()[0])
    snap.hosts_entries = parse_hosts(Path("/etc/hosts"))
