"""
"Local host" checks: is the problem on this machine itself?

These read the system snapshot (ctx.facts) - interfaces, routes, DNS settings,
DHCP lease, proxy, VPN, firewall, Wi-Fi, hosts file and listening sockets -
and flag configurations that commonly break connectivity: no IP address, a
self-assigned 169.254.x.x address (DHCP failed), no default gateway, no DNS
servers, a hosts-file override, a forgotten proxy, a full-tunnel VPN, or a
weak Wi-Fi signal. None of them send network traffic.
"""

from __future__ import annotations

import datetime as dt
import ipaddress

from nethelper.checks._util import first_ipv4, relevant_interfaces
from nethelper.core.context import Context
from nethelper.core.privileges import elevation_hint
from nethelper.core.registry import Admin, check
from nethelper.core.result import Outcome, Status, worst
from nethelper.core.runner import PRIVILEGE_NOTE
from nethelper.system.model import is_unspecified


@check("local.system", "System", "local", modes=("quick", "full"))
def system_info(ctx: Context) -> Outcome:
    """Host name, OS, uptime, privilege level and which helper tools are available."""
    snap = ctx.facts
    caps = ctx.caps
    uptime = f"{snap.uptime_s / 86400:.1f} days" if snap.uptime_s else "unknown"
    backends = [f"{n}{'' if ok else ' (needs admin)'}" for n, ok, _ in caps.capture_backends()]
    details = {
        "hostname": snap.hostname, "os": caps.os_detail, "python": caps.python,
        "elevated": caps.elevated, "uptime": uptime,
        "capture_backends": backends or ["none"],
        "tools": sorted(caps.tools),
    }
    advice = []
    status = Status.INFO
    if snap.errors:
        details["collector_errors"] = snap.errors
        status = Status.WARN
        advice.append("Some system information could not be collected; related checks may be incomplete.")
    if not caps.elevated:
        # Informational only (not PRIVILEGE_NOTE): this check itself isn't limited.
        details["elevation"] = "not elevated: switchport/VLAN capture, rogue-DHCP probe and some details are limited"
    level = "elevated" if caps.elevated else "standard user"
    return Outcome(status, f"{snap.hostname} - {caps.os_detail}, up {uptime}, running as {level}",
                   details, advice)


@check("local.interfaces", "Network interfaces", "local", modes=("quick", "full"))
def interfaces(ctx: Context) -> Outcome:
    """Active adapters and their addresses; flags no-IP, self-assigned (APIPA) and duplicate addresses."""
    snap = ctx.facts
    ifaces = relevant_interfaces(ctx)
    rows, advice, problems = [], [], []
    status = Status.PASS
    for i in ifaces:
        v4 = [f"{a.ip}/{a.prefix}" for a in i.ipv4]
        v6 = [f"{a.ip}/{a.prefix}" for a in i.ipv6 if not a.is_link_local]
        rows.append({"name": i.name, "kind": i.kind, "mac": i.mac, "mtu": i.mtu, "speed_mbps": i.speed_mbps,
                     "dhcp": i.dhcp, "ipv4": v4, "ipv6": v6, "vlan_id": i.vlan_id, "description": i.description})
        if i.kind in ("ethernet", "wifi"):
            if i.ipv4 and all(a.is_apipa for a in i.ipv4):
                status = Status.FAIL
                problems.append(f"{i.name} has only a self-assigned 169.254.x.x address")
                advice.append(f"{i.name}: DHCP failed - check the cable/Wi-Fi association, the switch port/VLAN, "
                              "and that the DHCP server is up and has free leases.")
            elif not i.ipv4 and not v6:
                status = worst([status, Status.WARN])  # keep FAIL if already failing
                problems.append(f"{i.name} is up but has no IP address")
        dups = [a.ip for a in i.addresses if a.state == "duplicate"]
        if dups:
            status = Status.FAIL
            problems.append(f"{i.name}: address conflict on {', '.join(dups)}")
            advice.append("Another device is using the same IP address. Find it with 'nethelper lan' (ARP table) "
                          "and fix the static assignment or DHCP reservation.")
    usable = [i for i in ifaces if i.usable and i.kind not in ("loopback", "virtual")]
    if not usable:
        status = Status.FAIL
        problems.insert(0, "no active network connection with a usable IP address")
        advice.insert(0, "Connect a cable or join Wi-Fi; check the adapter isn't disabled (and airplane mode is off).")
    physical_up = [i for i in ifaces if i.kind in ("ethernet", "wifi") and i.usable]
    if len(physical_up) > 1:
        advice.append("Both wired and Wi-Fi are connected; traffic uses the lower-metric route, which can "
                      "make results depend on which one is active.")
    primary = snap.primary_interface()
    summary = "; ".join(problems) if problems else (
        f"{len(usable)} active: " + ", ".join(f"{i.name} {first_ipv4(i) or (i.ipv6[0].ip if i.ipv6 else '')}"
                                              for i in usable))
    return Outcome(status, summary, {"interfaces": rows, "primary": primary.name if primary else None}, advice)


@check("local.routing", "Default gateway & routes", "local", modes=("quick", "full"))
def routing(ctx: Context) -> Outcome:
    """Checks there is exactly one sensible default route and that the gateway sits in the interface's subnet."""
    snap = ctx.facts
    defaults = snap.default_routes(4)
    v6 = snap.default_routes(6)
    details = {"default_routes_v4": [vars(r) for r in defaults], "default_routes_v6": [vars(r) for r in v6],
               "route_count": len(snap.routes)}
    if not defaults:
        return Outcome(Status.FAIL, "no IPv4 default gateway", details,
                       ["Without a default gateway nothing outside the local subnet is reachable. Check DHCP "
                        "(option 3 'router') or the static IP configuration."])
    best = defaults[0]
    status, advice, notes = Status.PASS, [], []
    iface = snap.interface(best.interface)
    if iface:
        nets = [ipaddress.ip_interface(f"{a.ip}/{a.prefix}").network for a in iface.ipv4 if not a.is_apipa]
        if nets and not any(ipaddress.ip_address(best.gateway) in n for n in nets):
            status = Status.WARN
            notes.append(f"gateway {best.gateway} is outside {iface.name}'s subnet(s) {', '.join(map(str, nets))}")
            advice.append("A gateway outside the local subnet usually means a wrong subnet mask or gateway setting.")
    same_metric = [r for r in defaults[1:] if r.metric == best.metric and r.interface != best.interface]
    if same_metric:
        status = Status.WARN
        notes.append("multiple default routes with equal metric: " + ", ".join(
            f"{r.gateway} via {r.interface}" for r in [best, *same_metric]))
        advice.append("Equal-cost default routes on different adapters cause traffic to flip between networks.")
    exp = ctx.profile.expected.gateway
    if exp and exp != best.gateway:
        status = Status.FAIL
        notes.append(f"gateway is {best.gateway}, expected {exp}")
        advice.append("This machine got the wrong gateway: likely on the wrong VLAN/subnet or served by a rogue DHCP server.")
    summary = f"{best.gateway} via {best.interface}" + (f" (+{len(defaults) - 1} more)" if len(defaults) > 1 else "")
    if notes:
        summary += " - " + "; ".join(notes)
    return Outcome(status, summary, details, advice)


@check("local.dns_config", "DNS configuration", "local", modes=("quick", "full"))
def dns_config(ctx: Context) -> Outcome:
    """Which DNS servers and search domains are configured, compared with the profile's expectation."""
    snap = ctx.facts
    servers = snap.dns_servers
    details = {"servers": servers, "search_domains": snap.dns_search, "per_interface": snap.dns_by_interface}
    if not servers:
        return Outcome(Status.FAIL, "no DNS servers configured", details,
                       ["Nothing can be looked up by name. Check DHCP option 6 or the static DNS settings."])
    status, advice = Status.PASS, []
    exp = ctx.profile.expected.dns_servers
    if exp:
        missing = [s for s in exp if s not in servers]
        extra = [s for s in servers if s not in exp]
        if missing or extra:
            status = Status.WARN
            advice.append(f"DNS servers differ from the site profile (expected {', '.join(exp)}). Wrong DNS breaks "
                          "internal names (file shares, domain logon) even when the internet works.")
            details["unexpected"] = extra
            details["missing"] = missing
    public = [s for s in servers if _is_public(s)]
    if public and snap.dns_search:
        advice.append("Public DNS servers are configured alongside a search domain - internal (AD/local) names "
                      "won't resolve through public resolvers.")
    summary = ", ".join(servers[:4]) + (f" (+{len(servers) - 4})" if len(servers) > 4 else "")
    if snap.dns_search:
        summary += f"; search: {', '.join(snap.dns_search[:3])}"
    return Outcome(status, summary, details, advice)


def _is_public(ip: str) -> bool:
    """True if the address is a public (internet-routable) IP."""
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_global
    except ValueError:
        return False


# Hosts-file entries that are normal and shouldn't be flagged.
_BENIGN_HOSTS = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "broadcasthost",
                 "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "host.docker.internal",
                 "gateway.docker.internal", "kubernetes.docker.internal"}
# Domains whose presence in a hosts file is suspicious (malware/adware redirect targets).
_SENSITIVE = ("google.", "microsoft.", "windowsupdate.", "office", "live.com", "apple.", "bank", "paypal.",
              "amazon.", "facebook.", "outlook.", "windows.")


@check("local.hosts_file", "Hosts file", "local", modes=("quick", "full"))
def hosts_file(ctx: Context) -> Outcome:
    """Looks for hosts-file entries that silently override DNS for important or tested names."""
    snap = ctx.facts
    custom = [(ip, name) for ip, name in snap.hosts_entries
              if name.lower() not in _BENIGN_HOSTS and not name.lower().endswith(".localdomain")]
    tested = {n.lower() for n in ctx.profile.dns_names}
    tested |= {t.host.lower() for t in ctx.profile.targets if t.host}
    flagged = [(ip, n) for ip, n in custom if n.lower() in tested or any(s in n.lower() for s in _SENSITIVE)]
    details = {"custom_entries": custom[:200], "flagged": flagged}
    if flagged:
        return Outcome(Status.WARN, f"{len(flagged)} entr{'y' if len(flagged) == 1 else 'ies'} override important names: "
                       + ", ".join(f"{n} -> {ip}" for ip, n in flagged[:3]), details,
                       ["Hosts-file entries bypass DNS entirely. Remove stale entries; unexpected ones for big-name "
                        "sites can indicate adware/malware."])
    if custom:
        return Outcome(Status.INFO, f"{len(custom)} custom entr{'y' if len(custom) == 1 else 'ies'} (none affect tested names)", details)
    return Outcome(Status.PASS, "no custom entries", details)


@check("local.dhcp", "DHCP lease", "local", modes=("full",))
def dhcp_lease(ctx: Context) -> Outcome:
    """DHCP server and lease times per interface; flags expired leases and unexpected DHCP servers."""
    snap = ctx.facts
    leases = [vars(lease) for lease in snap.dhcp]
    if not leases:
        statics = [i.name for i in relevant_interfaces(ctx, ("ethernet", "wifi")) if i.dhcp is False]
        return Outcome(Status.INFO, "no DHCP leases (static addressing)" if statics else "no DHCP lease information",
                       {"static_interfaces": statics})
    status, advice, notes = Status.PASS, [], []
    now = dt.datetime.now()
    for lease in snap.dhcp:
        if lease.expires and lease.expires[:4].isdigit():
            try:
                if dt.datetime.fromisoformat(lease.expires[:19]) < now:
                    status = Status.WARN
                    notes.append(f"{lease.interface}: lease expired at {lease.expires}")
                    advice.append("The lease expired without renewing - the DHCP server may be unreachable. "
                                  "Try 'nethelper fix renew-dhcp'.")
            except ValueError:
                pass
    exp = ctx.profile.expected.dhcp_servers
    for lease in snap.dhcp:
        if exp and lease.server and lease.server not in exp:
            status = Status.FAIL
            notes.append(f"{lease.interface}: lease from {lease.server}, not an approved DHCP server")
            advice.append("A lease from an unapproved DHCP server suggests a rogue DHCP server. Run "
                          "'nethelper dhcp' (elevated) to list every server answering.")
    summary = "; ".join(notes) or ", ".join(f"{lz.interface}: server {lz.server or '?'}" for lz in snap.dhcp)
    return Outcome(status, summary, {"leases": leases}, advice)


@check("local.proxy", "Proxy settings", "local", modes=("quick", "full"))
def proxy(ctx: Context) -> Outcome:
    """System, per-user and environment proxy settings that redirect web traffic."""
    p = ctx.facts.proxy
    active = []
    if p.get("env"):
        active.append("environment: " + ", ".join(f"{k}={v}" for k, v in p["env"].items()))
    user = p.get("user", {})
    if user.get("ProxyEnable"):
        active.append(f"user proxy: {user.get('ProxyServer')}")
    if user.get("AutoConfigURL"):
        active.append(f"PAC file: {user['AutoConfigURL']}")
    if p.get("winhttp") and p["winhttp"] != "direct":
        active.append("WinHTTP (system services) proxy set")
    system = p.get("system", {})
    if system.get("HTTPEnable") == "1" or system.get("HTTPSEnable") == "1":
        active.append(f"system proxy: {system.get('HTTPSProxy') or system.get('HTTPProxy')}")
    if system.get("ProxyAutoConfigEnable") == "1":
        active.append(f"PAC file: {system.get('ProxyAutoConfigURLString')}")
    if not active:
        return Outcome(Status.PASS, "no proxy configured (direct connection)", {"proxy": p})
    return Outcome(Status.INFO, "; ".join(active), {"proxy": p},
                   ["A proxy is configured. If web access fails, confirm the proxy is reachable; leftover proxy "
                    "settings from another network are a common cause of 'no internet in the browser'."])


@check("local.vpn", "VPN / tunnels", "local", modes=("quick", "full"))
def vpn(ctx: Context) -> Outcome:
    """Detects active VPN adapters and whether they carry all traffic (full tunnel) or only some (split)."""
    snap = ctx.facts
    tunnels = [i for i in snap.interfaces if i.kind == "vpn" and i.up]
    if not tunnels:
        return Outcome(Status.INFO, "no active VPN", {})
    best = snap.default_routes(4)
    via = best[0].interface if best else None
    names = [t.name for t in tunnels]
    mode = "full tunnel (all traffic through VPN)" if via in names else "split tunnel (only some routes via VPN)"
    vpn_routes = [r.destination for r in snap.routes if r.interface in names and not r.is_default][:30]
    return Outcome(Status.INFO, f"{', '.join(names)} - {mode}",
                   {"tunnels": [{"name": t.name, "description": t.description, "ipv4": [a.ip for a in t.ipv4]}
                                for t in tunnels], "mode": mode, "vpn_routes": vpn_routes},
                   ["Results reflect the VPN path. To test the local network itself, disconnect the VPN and re-run."])


@check("local.firewall", "Local firewall", "local", modes=("full",), admin=Admin.PARTIAL)
def firewall(ctx: Context) -> Outcome:
    """Host firewall state (Windows Defender Firewall profiles, ufw/firewalld/nftables, macOS application firewall)."""
    fw = ctx.facts.firewall
    details = {"firewall": fw}
    if fw.get("note"):
        details[PRIVILEGE_NOTE] = f"{fw['note']} - {elevation_hint()}"
    profiles = fw.get("profiles")
    if profiles:
        off = [p["name"] for p in profiles if not p.get("enabled")]
        if off:
            return Outcome(Status.WARN, f"disabled for profile(s): {', '.join(off)}", details,
                           ["Turning the firewall off is a security risk; prefer an allow rule for the specific app/port."])
        return Outcome(Status.PASS, "enabled for all profiles (" + ", ".join(p["name"] for p in profiles) + ")", details)
    if fw.get("enabled") is True:
        return Outcome(Status.PASS, f"{fw.get('backend')} enabled", details)
    if fw.get("enabled") is False:
        return Outcome(Status.INFO, f"{fw.get('backend')} not enabled", details)
    return Outcome(Status.INFO, "firewall state unknown" + (f" ({fw['note']})" if fw.get("note") else ""), details)


@check("local.wifi", "Wi-Fi", "local", modes=("quick", "full"))
def wifi(ctx: Context) -> Outcome:
    """Wi-Fi network, signal strength, band/channel and link rate; warns on weak signal."""
    infos = ctx.facts.wifi
    if not infos:
        if any(i.kind == "wifi" and i.up for i in ctx.facts.interfaces):
            return Outcome(Status.INFO, "Wi-Fi is up but details are unavailable", {})
        return Outcome(Status.SKIP, "no active Wi-Fi connection", {})
    th = ctx.threshold
    status, advice, parts = Status.PASS, [], []
    for w in infos:
        if w.note and not w.ssid:
            parts.append(w.note)
            status = Status.INFO
            continue
        desc = f"{w.ssid or '?'}"
        if w.rssi_dbm is not None:
            desc += f", {w.rssi_dbm} dBm"
        if w.signal_pct is not None:
            desc += f" ({w.signal_pct}%)"
        if w.band:
            desc += f", {w.band}"
        if w.channel:
            desc += f" ch {w.channel}"
        if w.rx_mbps or w.tx_mbps:
            desc += f", {w.rx_mbps or w.tx_mbps:g} Mb/s"
        parts.append(desc)
        weak = (w.rssi_dbm is not None and w.rssi_dbm < th.wifi_warn_dbm) or \
               (w.signal_pct is not None and w.signal_pct < th.wifi_warn_pct)
        if weak:
            status = Status.WARN
            advice.append("Weak Wi-Fi signal causes slowness, packet loss and drop-outs. Move closer to the access "
                          "point, remove obstructions, or use a wired connection to confirm.")
        if w.band and w.band.startswith("2.4") and (w.rx_mbps or 999) < 72:
            advice.append("Connected on 2.4 GHz at a low link rate; 5 GHz (if available) is usually much faster.")
    return Outcome(status, "; ".join(parts), {"wifi": [vars(w) for w in infos]}, advice)


# Services that are risky when exposed on all interfaces.
_RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 111: "rpcbind", 135: "MS-RPC", 139: "NetBIOS",
                445: "SMB", 1433: "SQL Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}


@check("local.listening", "Listening ports", "local", modes=("full",), admin=Admin.PARTIAL)
def listening(ctx: Context) -> Outcome:
    """Services listening for incoming connections, with owning process; highlights commonly-attacked ports."""
    conns = ctx.facts.connections
    listen = [c for c in conns if c.state == "listen" and c.proto.startswith("tcp")]
    established = [c for c in conns if c.state == "established"]
    # "Listening on all interfaces" = bound to the unspecified address (or "*").
    exposed = [c for c in listen if (c.local in ("*", "") or is_unspecified(c.local)) and c.local_port in _RISKY_PORTS]
    rows = sorted({(c.local_port, c.local, c.process or "?") for c in listen})[:200]
    details = {"tcp_listening": [{"port": p, "address": a, "process": n} for p, a, n in rows],
               "established_count": len(established),
               "udp_listening": sorted({c.local_port for c in conns if c.proto.startswith("udp")})[:100]}
    missing_proc = sum(1 for c in listen if not c.process)
    if missing_proc and not ctx.caps.elevated and ctx.caps.os != "windows":
        details[PRIVILEGE_NOTE] = f"process names hidden for {missing_proc} sockets owned by other users - {elevation_hint()}"
    summary = f"{len(rows)} TCP listening, {len(established)} established connections"
    if exposed:
        names = sorted({f"{_RISKY_PORTS[c.local_port]}/{c.local_port}" for c in exposed})
        details["exposed_risky"] = names
        return Outcome(Status.INFO, summary + f"; listening on all interfaces: {', '.join(names)}", details,
                       ["These services accept connections from the network. That's expected for servers but "
                        "worth confirming on workstations (firewall rules may still block them)."])
    return Outcome(Status.INFO, summary, details)
