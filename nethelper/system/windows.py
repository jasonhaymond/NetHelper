"""
Windows collector: gathers local network facts into a model.Snapshot.

Approach: one PowerShell invocation runs the built-in networking cmdlets
(Get-NetAdapter, Get-NetIPAddress, Get-NetRoute, ...) and returns everything as
a single JSON document. JSON output is language-independent, unlike parsing
`ipconfig /all` text, which changes with the Windows display language.
Starting PowerShell costs ~1-2 s, so doing it once (not per cmdlet) matters.

Every cmdlet is wrapped in try/catch inside the script, so one failing piece
(e.g. Wi-Fi on a server without the WLAN service) can't block the rest.
None of these cmdlets need Administrator rights.

Also used: `netsh wlan show interfaces` (Wi-Fi details), the registry via
Python's built-in `winreg` module (per-user proxy settings), and the hosts file.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from nethelper.core import cmd
from nethelper.system.model import (Address, Connection, DhcpLease, Interface, Neighbor, Route,
                                    Snapshot, WifiInfo, classify, is_unspecified, normalize_mac)

# The PowerShell script. Enum values are converted to strings ("$(...)") so
# the JSON contains "IPv4"/"Dhcp"/"Preferred" rather than opaque numbers.
PS_SCRIPT = r"""
$r = [ordered]@{}
function Get-Part([string]$name, [scriptblock]$block) {
  try { $r[$name] = @(& $block) } catch { $r[$name + '_error'] = $_.Exception.Message }
}
Get-Part adapters { Get-NetAdapter | Select-Object Name, InterfaceDescription, ifIndex,
  @{n='Status';e={"$($_.Status)"}}, MacAddress, ReceiveLinkSpeed, TransmitLinkSpeed,
  @{n='MediaType';e={"$($_.MediaType)"}}, @{n='PhysicalMediaType';e={"$($_.PhysicalMediaType)"}},
  VlanID, FullDuplex, MtuSize, Virtual, HardwareInterface }
Get-Part ipaddrs { Get-NetIPAddress | Select-Object InterfaceAlias, InterfaceIndex, IPAddress, PrefixLength,
  @{n='AddressFamily';e={"$($_.AddressFamily)"}}, @{n='PrefixOrigin';e={"$($_.PrefixOrigin)"}},
  @{n='SuffixOrigin';e={"$($_.SuffixOrigin)"}}, @{n='AddressState';e={"$($_.AddressState)"}} }
Get-Part ipifs { Get-NetIPInterface | Select-Object ifIndex, InterfaceAlias,
  @{n='AddressFamily';e={"$($_.AddressFamily)"}}, NlMtu, @{n='Dhcp';e={"$($_.Dhcp)"}},
  @{n='ConnectionState';e={"$($_.ConnectionState)"}}, InterfaceMetric }
Get-Part routes { Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, ifIndex,
  RouteMetric, InterfaceMetric, @{n='AddressFamily';e={"$($_.AddressFamily)"}} }
Get-Part dns { Get-DnsClientServerAddress | Select-Object InterfaceAlias, InterfaceIndex,
  @{n='AddressFamily';e={"$($_.AddressFamily)"}}, ServerAddresses }
Get-Part dnsglobal { (Get-DnsClientGlobalSetting).SuffixSearchList }
Get-Part dnsclient { Get-DnsClient | Select-Object InterfaceAlias, ConnectionSpecificSuffix }
Get-Part dhcp { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' |
  Select-Object Description, InterfaceIndex, DHCPEnabled, DHCPServer,
  @{n='Obtained';e={ if ($_.DHCPLeaseObtained) { $_.DHCPLeaseObtained.ToString('s') } }},
  @{n='Expires';e={ if ($_.DHCPLeaseExpires) { $_.DHCPLeaseExpires.ToString('s') } }} }
Get-Part firewall { Get-NetFirewallProfile | Select-Object Name, @{n='Enabled';e={"$($_.Enabled)"}},
  @{n='DefaultInboundAction';e={"$($_.DefaultInboundAction)"}},
  @{n='DefaultOutboundAction';e={"$($_.DefaultOutboundAction)"}} }
Get-Part neighbors { Get-NetNeighbor | Where-Object { "$($_.State)" -notin 'Unreachable','Incomplete' } |
  Select-Object IPAddress, LinkLayerAddress, InterfaceAlias, @{n='State';e={"$($_.State)"}},
  @{n='AddressFamily';e={"$($_.AddressFamily)"}} }
Get-Part tcp { Get-NetTCPConnection | Where-Object { "$($_.State)" -in 'Listen','Established' } |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{n='State';e={"$($_.State)"}}, OwningProcess }
Get-Part udp { Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess }
Get-Part procs { Get-Process | Select-Object Id, ProcessName }
Get-Part uptime { [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds }
Get-Part vlanprops { Get-NetAdapterAdvancedProperty -RegistryKeyword 'VlanID','VLANID','*VlanID' -ErrorAction SilentlyContinue |
  Select-Object Name, RegistryKeyword, @{n='Value';e={"$($_.RegistryValue)"}} }
$r | ConvertTo-Json -Depth 6 -Compress
"""


def _family(value: str | None) -> int:
    """Map PowerShell's "IPv4"/"IPv6" (or numeric 2/23) to 4 or 6."""
    return 6 if str(value) in ("IPv6", "23") else 4


def _speed(bits: object) -> float | None:
    """Convert a link speed in bits/second to Mb/s."""
    try:
        value = float(bits)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return round(value / 1_000_000, 1) if value > 0 else None


def parse_ps_json(data: dict, snap: Snapshot) -> None:
    """
    Fill `snap` from the JSON produced by PS_SCRIPT. Separated from collect()
    so it can be unit-tested with saved JSON on any OS.
    """
    for key, value in data.items():
        if key.endswith("_error"):
            snap.errors.append(f"{key[:-6]}: {value}")

    vlan_by_name: dict[str, int] = {}
    for prop in data.get("vlanprops") or []:
        try:
            vid = int(prop.get("Value") or 0)
        except ValueError:
            vid = 0
        if vid:
            vlan_by_name[prop.get("Name", "")] = vid

    ifaces: dict[int, Interface] = {}
    for a in data.get("adapters") or []:
        name = a.get("Name") or ""
        desc = a.get("InterfaceDescription") or ""
        wireless = "802.11" in (a.get("PhysicalMediaType") or "") or "Native 802.11" in (a.get("MediaType") or "")
        iface = Interface(
            name=name, index=a.get("ifIndex"), description=desc,
            mac=normalize_mac(a.get("MacAddress")), up=(a.get("Status") == "Up"),
            mtu=a.get("MtuSize"), speed_mbps=_speed(a.get("ReceiveLinkSpeed") or a.get("TransmitLinkSpeed")),
            duplex=("full" if a.get("FullDuplex") else "half") if a.get("FullDuplex") is not None and a.get("Status") == "Up" else None,
            kind=classify(name, desc, wireless),
            vlan_id=(a.get("VlanID") or None) or vlan_by_name.get(name),
        )
        if a.get("Virtual") and iface.kind in ("ethernet", "other"):
            iface.kind = "virtual"
        if iface.kind != "ethernet":
            iface.duplex = None  # duplex only means something on wired Ethernet
        ifaces[iface.index] = iface

    for ipif in data.get("ipifs") or []:
        iface = ifaces.get(ipif.get("ifIndex"))
        if iface is None:
            # Loopback and some virtual interfaces exist only at the IP layer.
            name = ipif.get("InterfaceAlias") or f"if{ipif.get('ifIndex')}"
            iface = Interface(name=name, index=ipif.get("ifIndex"), kind=classify(name),
                              up=ipif.get("ConnectionState") == "Connected")
            ifaces[iface.index] = iface
        if _family(ipif.get("AddressFamily")) == 4:
            iface.dhcp = ipif.get("Dhcp") == "Enabled"
            iface.metric = ipif.get("InterfaceMetric")
            mtu = ipif.get("NlMtu")
            # Loopback reports 4294967295 ("unlimited"); keep only real values.
            iface.mtu = mtu if mtu and mtu <= 65535 else iface.mtu

    origin_map = {"Dhcp": "dhcp", "Manual": "manual", "WellKnown": "link-local",
                  "RouterAdvertisement": "slaac", "Other": "other"}
    for ip in data.get("ipaddrs") or []:
        iface = ifaces.get(ip.get("InterfaceIndex"))
        if iface is None:
            continue
        origin = origin_map.get(ip.get("PrefixOrigin") or "", (ip.get("PrefixOrigin") or "").lower() or None)
        if ip.get("SuffixOrigin") == "Link" and ip.get("PrefixOrigin") == "WellKnown":
            origin = "link-local"
        iface.addresses.append(Address(
            ip=str(ip.get("IPAddress", "")).split("%")[0], prefix=int(ip.get("PrefixLength") or 0),
            family=_family(ip.get("AddressFamily")), origin=origin,
            state=(ip.get("AddressState") or "").lower() or None))
    snap.interfaces = sorted(ifaces.values(), key=lambda i: (i.index or 0))

    for rt in data.get("routes") or []:
        gw = rt.get("NextHop")
        metric = (rt.get("RouteMetric") or 0) + (rt.get("InterfaceMetric") or 0)
        snap.routes.append(Route(destination=rt.get("DestinationPrefix", ""),
                                 gateway=None if not gw or is_unspecified(gw) else gw,
                                 interface=rt.get("InterfaceAlias"), metric=metric,
                                 family=_family(rt.get("AddressFamily"))))

    up_names = {i.name for i in snap.interfaces if i.up}
    for d in data.get("dns") or []:
        servers = d.get("ServerAddresses") or []
        if isinstance(servers, str):
            servers = [servers]
        alias = d.get("InterfaceAlias") or ""
        # Skip Windows' placeholder "fec0:0:0:ffff::N" site-local resolvers.
        servers = [s for s in servers if not s.lower().startswith("fec0:0:0:ffff::")]
        if servers:
            snap.dns_by_interface.setdefault(alias, []).extend(servers)
            if alias in up_names:
                for s in servers:
                    if s not in snap.dns_servers:
                        snap.dns_servers.append(s)
    search = data.get("dnsglobal") or []
    snap.dns_search = [s for s in search if s]
    for c in data.get("dnsclient") or []:
        suffix = c.get("ConnectionSpecificSuffix")
        if suffix and suffix not in snap.dns_search and c.get("InterfaceAlias") in up_names:
            snap.dns_search.append(suffix)

    by_index = {i.index: i.name for i in snap.interfaces}
    for d in data.get("dhcp") or []:
        if d.get("DHCPEnabled"):
            snap.dhcp.append(DhcpLease(interface=by_index.get(d.get("InterfaceIndex"), d.get("Description", "")),
                                       server=d.get("DHCPServer"), obtained=d.get("Obtained"),
                                       expires=d.get("Expires")))

    snap.firewall = {"backend": "Windows Defender Firewall", "profiles": [
        {"name": f.get("Name"), "enabled": f.get("Enabled") == "True",
         "inbound": f.get("DefaultInboundAction"), "outbound": f.get("DefaultOutboundAction")}
        for f in data.get("firewall") or []]}

    for n in data.get("neighbors") or []:
        mac = normalize_mac(n.get("LinkLayerAddress"))
        ip = n.get("IPAddress", "")
        # Skip broadcast/multicast entries - they aren't real hosts.
        if not mac or mac == "ff:ff:ff:ff:ff:ff" or mac.startswith(("01:00:5e", "33:33")):
            continue
        snap.neighbors.append(Neighbor(ip=ip, mac=mac, interface=n.get("InterfaceAlias"),
                                       state=(n.get("State") or "").lower()))

    procs = {p.get("Id"): p.get("ProcessName") for p in data.get("procs") or []}
    for t in data.get("tcp") or []:
        pid = t.get("OwningProcess")
        snap.connections.append(Connection("tcp", t.get("LocalAddress"), t.get("LocalPort"),
                                           t.get("RemoteAddress"), t.get("RemotePort"),
                                           (t.get("State") or "").lower(), pid, procs.get(pid)))
    for u in data.get("udp") or []:
        pid = u.get("OwningProcess")
        snap.connections.append(Connection("udp", u.get("LocalAddress"), u.get("LocalPort"),
                                           state="listen", pid=pid, process=procs.get(pid)))
    up = data.get("uptime")
    if isinstance(up, list) and up:
        snap.uptime_s = float(up[0])


# Regex: "    Name    : value" lines in `netsh wlan show interfaces` output.
_NETSH_LINE = re.compile(r"^\s{2,}([^:]+?)\s+:\s(.*)$")


def parse_netsh_wlan(text: str) -> list[WifiInfo]:
    """
    Parse `netsh wlan show interfaces`. Field names are English; on other
    display languages most fields won't match and are left empty.
    """
    infos: list[WifiInfo] = []
    current: WifiInfo | None = None
    for line in text.splitlines():
        m = _NETSH_LINE.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if key == "name":
            current = WifiInfo(interface=value)
            infos.append(current)
        elif current is None:
            continue
        elif key == "ssid":
            current.ssid = value
        elif key in ("bssid", "ap bssid"):
            current.bssid = normalize_mac(value) or current.bssid
        elif key == "signal":
            current.signal_pct = int(value.rstrip("%") or 0)
            # Windows reports %, approximately linear from -100 dBm (0%) to -50 dBm (100%).
            current.rssi_dbm = int(current.signal_pct / 2 - 100)
        elif key == "rssi":
            try:
                current.rssi_dbm = int(value)
            except ValueError:
                pass
        elif key == "channel":
            try:
                current.channel = int(value)
            except ValueError:
                pass
        elif key == "band":
            current.band = value
        elif key == "radio type":
            current.radio = value
        elif key == "receive rate (mbps)":
            current.rx_mbps = float(value or 0)
        elif key == "transmit rate (mbps)":
            current.tx_mbps = float(value or 0)
        elif key == "authentication":
            current.security = value
        elif key == "state" and value.lower() != "connected":
            current.note = f"state: {value}"
    return infos


def _proxy_settings() -> dict:
    """
    Read proxy configuration from the three places Windows apps get it:
      - per-user Internet Settings in the registry (browsers, most apps)
      - WinHTTP machine proxy (services, Windows Update) via netsh
      - HTTP(S)_PROXY environment variables (CLI tools, Python, git)
    """
    out: dict = {"env": {k: v for k, v in os.environ.items()
                         if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}}
    try:
        import winreg

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        with key:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"):
                try:
                    out.setdefault("user", {})[name] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    pass
    except (ImportError, OSError):
        pass
    res = cmd.run(["netsh", "winhttp", "show", "proxy"], timeout=10)
    if res.ok:
        text = res.stdout.strip()
        out["winhttp"] = "direct" if "Direct access" in text else text
    return out


def _hosts_entries() -> list[tuple[str, str]]:
    """Active (non-comment) lines of the Windows hosts file as (ip, name) pairs."""
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return parse_hosts(path)


def parse_hosts(path: Path) -> list[tuple[str, str]]:
    """Parse any hosts-format file: "IP name [alias...]  # comment"."""
    entries: list[tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return entries
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2:
            for name in parts[1:]:
                entries.append((parts[0], name))
    return entries


# The subset of PS_SCRIPT needed to know interfaces, addresses, routes and DNS
# (about 1-2 s instead of ~10 s): used by quick single-shot commands like
# `ping -i Wi-Fi` that only need an adapter's IP or gateway.
_LIGHT_PARTS = ("adapters", "ipaddrs", "ipifs", "routes", "dns")


def _light_script() -> str:
    """Build the reduced PowerShell script from the Get-Part blocks named in _LIGHT_PARTS."""
    lines = PS_SCRIPT.strip().splitlines()
    out, keep = [], True
    for line in lines:
        if line.startswith("Get-Part "):
            keep = line.split()[1] in _LIGHT_PARTS
        elif line.startswith("$r |") or line.startswith("$r =") or line.startswith("function") \
                or line.startswith("  try") or line.startswith("}"):
            keep = True
        if keep:
            out.append(line)
    return "\n".join(out)


def collect(snap: Snapshot, light: bool = False) -> None:
    """Run the Windows collectors, filling `snap` in place (light=True: interfaces/routes/DNS only)."""
    res = cmd.powershell(_light_script() if light else PS_SCRIPT, timeout=60)
    snap.raw["powershell-facts"] = res.transcript()[:200_000]
    if res.ok and res.stdout.strip():
        try:
            parse_ps_json(json.loads(res.stdout), snap)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            snap.errors.append(f"could not parse PowerShell output: {exc}")
    else:
        snap.errors.append(f"PowerShell facts failed: {res.error or res.stderr.strip()[:200]}")
    if light:
        return

    if any(i.kind == "wifi" for i in snap.interfaces):
        wl = cmd.run(["netsh", "wlan", "show", "interfaces"], timeout=15)
        snap.raw["netsh wlan"] = wl.transcript()
        snap.wifi = parse_netsh_wlan(wl.stdout)
        if not snap.wifi and "location" in (wl.stdout + wl.stderr).lower():
            snap.wifi = [WifiInfo(interface="Wi-Fi", note="Windows requires Location permission for Wi-Fi details "
                                                          "(Settings > Privacy & security > Location)")]
    snap.proxy = _proxy_settings()
    snap.hosts_entries = _hosts_entries()
