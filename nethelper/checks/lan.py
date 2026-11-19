"""
"Local network (LAN)" checks: what's on this network segment, and is
anything on it impersonating infrastructure?

  lan.gateway_mac   who the gateway really is (MAC + vendor); detects ARP
                    spoofing (a man-in-the-middle answering for the gateway)
                    and pinned-MAC mismatches
  lan.neighbors     ARP/neighbour table with vendors; IP conflicts
  lan.duplicate_ip  is someone else using this machine's IP?
  lan.dhcp_servers  rogue DHCP server detection (DISCOVER probe)
  lan.mdns / ssdp   printers, NAS, TVs, cameras announcing themselves
  lan.sweep         active scan of the local subnet (opt-in: --allow-intrusive)
"""

from __future__ import annotations

import ipaddress

from nethelper.checks._util import first_ipv4, wired_interface
from nethelper.core import cmd, validate
from nethelper.core.context import Context
from nethelper.core.privileges import elevation_hint
from nethelper.core.registry import Admin, check
from nethelper.core.result import Outcome, Status
from nethelper.core.runner import PRIVILEGE_NOTE
from nethelper.net import arp, dhcp, discovery, oui


@check("lan.gateway_mac", "Gateway identity (ARP)", "lan", modes=("quick", "full"), timeout=30)
def gateway_mac(ctx: Context) -> Outcome:
    """Resolves the gateway's MAC and vendor and checks it against the profile/baseline to catch ARP spoofing."""
    snap = ctx.facts
    gw = snap.default_gateway()
    if not gw:
        return Outcome(Status.SKIP, "no default gateway")
    mac = next((n.mac for n in snap.neighbors if n.ip == gw), None) or arp.resolve_mac(gw)
    if not mac:
        return Outcome(Status.WARN, f"could not resolve the MAC address of {gw}", {"gateway": gw},
                       ["The gateway didn't answer ARP: it's offline, on a different VLAN, or the subnet mask is wrong."])
    vend = oui.vendor(mac)
    details = {"gateway": gw, "mac": mac, "vendor": vend}
    # Other IPs in the ARP table using the gateway's MAC = possible ARP spoofing
    # (or legitimately proxy-ARP / a firewall with several IPs).
    shared = sorted({n.ip for n in snap.neighbors if n.mac == mac and n.ip != gw and ":" not in n.ip})
    details["other_ips_with_gateway_mac"] = shared
    expected = ctx.profile.expected.gateway_mac
    if expected and expected != mac:
        return Outcome(Status.FAIL, f"{gw} is at {mac}, expected {expected}", details,
                       ["The gateway's MAC differs from the pinned value: the router was replaced, a failover "
                        "unit took over, or another device is impersonating the gateway (ARP spoofing). Verify "
                        "before trusting this network."])
    base = (ctx.options.baseline or {}).get("lan.gateway_mac", {}).get("details", {})
    if base.get("mac") and base.get("gateway") == gw and base["mac"] != mac:
        return Outcome(Status.WARN, f"{gw} MAC changed since baseline: {base['mac']} -> {mac}", details,
                       ["Gateway hardware changed since the baseline was saved. Expected after a router swap; "
                        "otherwise investigate possible ARP spoofing."])
    if len(shared) >= 2:
        return Outcome(Status.WARN, f"{gw} at {mac}, but {len(shared)} other IPs share that MAC: {', '.join(shared[:4])}",
                       details, ["Several IPs mapping to the gateway's MAC can indicate ARP spoofing (or proxy ARP "
                                 "on the router). Compare with the router's real MAC."])
    return Outcome(Status.PASS, f"{gw} at {mac}" + (f" ({vend})" if vend else ""), details)


@check("lan.neighbors", "ARP / neighbour table", "lan", modes=("full",))
def neighbors(ctx: Context) -> Outcome:
    """Devices this machine has recently talked to on the LAN, with hardware vendors; flags IP conflicts."""
    snap = ctx.facts
    rows = []
    by_ip: dict[str, set[str]] = {}
    for n in snap.neighbors:
        if ":" in n.ip and n.ip.lower().startswith("ff"):
            continue
        rows.append({"ip": n.ip, "mac": n.mac, "vendor": oui.vendor(n.mac), "interface": n.interface, "state": n.state})
        by_ip.setdefault(n.ip, set()).add(n.mac or "")
    conflicts = {ip: sorted(m) for ip, m in by_ip.items() if len(m) > 1}
    details = {"neighbors": rows, "conflicts": conflicts, "oui_database_entries": oui.database_size()}
    advice = []
    if not oui.database_size():
        advice.append("Vendor names need a MAC vendor database: run 'nethelper oui update' once.")
    if conflicts:
        return Outcome(Status.WARN, f"IP(s) seen with multiple MACs: {', '.join(conflicts)}", details,
                       advice + ["Two devices claiming one IP = an address conflict (or ARP spoofing)."])
    v4 = [r for r in rows if ":" not in r["ip"]]
    return Outcome(Status.INFO, f"{len(v4)} IPv4 neighbour(s) in the ARP table", details, advice)


@check("lan.duplicate_ip", "Duplicate IP detection", "lan", modes=("full",), admin=Admin.PARTIAL, timeout=20)
def duplicate_ip(ctx: Context) -> Outcome:
    """Checks whether another device is using this machine's IP (OS conflict detection, or arping -D when root)."""
    snap = ctx.facts
    dups = [(i.name, a.ip) for i in snap.interfaces for a in i.addresses if a.state == "duplicate"]
    if dups:
        return Outcome(Status.FAIL, "address conflict: " + ", ".join(f"{ip} on {n}" for n, ip in dups),
                       {"duplicates": dups}, ["Another device has this IP. Locate it via the ARP table/switch MAC "
                                              "table and fix its static IP or the DHCP reservation."])
    primary = snap.primary_interface()
    ip = first_ipv4(primary)
    if ctx.caps.os == "linux" and ip and primary:
        if ctx.caps.elevated and ctx.caps.has("arping"):
            # arping -D = Duplicate Address Detection: exit code 1 means someone answered for our IP.
            res = cmd.run(["arping", "-D", "-c", "2", "-w", "3", "-I", validate.interface(primary.name), ip], timeout=10)
            if res.returncode == 1:
                return Outcome(Status.FAIL, f"another device answers ARP for {ip}", {"arping": res.stdout[-500:]})
            return Outcome(Status.PASS, f"no other device answers for {ip} (arping -D)", {})
        note = f"active duplicate probe needs root + arping - {elevation_hint()}" if not ctx.caps.elevated else \
            "install arping for an active duplicate probe"
        return Outcome(Status.PASS, "no conflicts reported by the OS", {PRIVILEGE_NOTE: note} if not ctx.caps.elevated else {"note": note})
    return Outcome(Status.PASS, "no address conflicts reported by the OS", {})


@check("lan.dhcp_servers", "DHCP servers (rogue check)", "lan", modes=("full",), admin=Admin.PARTIAL, timeout=25)
def dhcp_servers(ctx: Context) -> Outcome:
    """Broadcasts a DHCP DISCOVER and lists every server that offers an address - more than one usually means a rogue."""
    snap = ctx.facts
    iface = wired_interface(ctx) or snap.primary_interface()
    if not iface or not iface.mac:
        return Outcome(Status.SKIP, "no suitable interface with a MAC address")
    try:
        offers = dhcp.discover(iface.mac, timeout=5.0)
    except PermissionError:
        return Outcome(Status.SKIP, f"binding UDP port 68 requires elevation - {elevation_hint()}",
                       {PRIVILEGE_NOTE: "rogue DHCP probe needs elevation"})
    except OSError as exc:
        hint = ("the Windows DHCP Client service holds UDP 68" if ctx.caps.os == "windows" else "another DHCP client holds UDP 68")
        return Outcome(Status.SKIP, f"cannot bind UDP port 68 ({exc.strerror or exc}); {hint}",
                       {PRIVILEGE_NOTE: "rogue DHCP probe unavailable"} if not ctx.caps.elevated else {})
    rows = [vars(o) for o in offers]
    servers = sorted({o.server_id or o.from_ip for o in offers})
    details = {"interface": iface.name, "offers": rows, "servers": servers}
    if not offers:
        return Outcome(Status.WARN, "no DHCP offers received", details,
                       ["No DHCP server answered on this segment: static network, DHCP relay (ip helper) missing "
                        "on this VLAN, or the server is down/out of leases."])
    allowed = set(ctx.profile.expected.dhcp_servers)
    rogue = [s for s in servers if allowed and s not in allowed]
    if rogue or len(servers) > 1:
        return Outcome(Status.FAIL, f"{len(servers)} DHCP server(s) answering: {', '.join(servers)}"
                       + (f" (unapproved: {', '.join(rogue)})" if rogue else ""), details,
                       ["Multiple DHCP servers on one segment hand out conflicting gateways/DNS. Find the rogue "
                        "by its MAC/IP (switch MAC table), remove it, and enable DHCP snooping on the switches."])
    o = offers[0]
    return Outcome(Status.PASS, f"one DHCP server: {servers[0]} (offers {o.offered_ip}, gw {', '.join(o.routers) or '?'}, "
                   f"dns {', '.join(o.dns) or '?'})", details)


@check("lan.mdns", "mDNS / Bonjour devices", "lan", modes=("full",), timeout=30)
def mdns(ctx: Context) -> Outcome:
    """Lists devices announcing services over mDNS/Bonjour (printers, AirPlay, Chromecast, NAS...)."""
    devices = discovery.mdns_browse(timeout=3.0)
    rows = [{"ip": d.ip, "names": sorted(d.names)[:5], "services": sorted(d.services)[:10]} for d in devices]
    if not rows:
        return Outcome(Status.INFO, "no mDNS responders (none present, or multicast is filtered/isolated)", {"devices": []})
    sample = ", ".join((sorted(d.names) or [d.ip])[0] for d in devices[:5])
    return Outcome(Status.INFO, f"{len(rows)} device(s): {sample}", {"devices": rows})


@check("lan.ssdp", "UPnP / SSDP devices", "lan", modes=("full",), timeout=20)
def ssdp(ctx: Context) -> Outcome:
    """Lists devices answering UPnP discovery (routers, smart TVs, media servers, cameras)."""
    devices = discovery.ssdp_search(timeout=3.0)
    if not devices:
        return Outcome(Status.INFO, "no UPnP/SSDP responders", {"devices": []})
    igd = [d["ip"] for d in devices if any("InternetGatewayDevice" in t for t in d["types"])]
    advice = ["The router answers UPnP (automatic port forwarding). Disable it if not needed - malware can "
              "use it to open inbound ports."] if igd else []
    return Outcome(Status.INFO, f"{len(devices)} device(s): " + ", ".join(
        f"{d['ip']} ({(d.get('server') or '?')[:30]})" for d in devices[:4]), {"devices": devices}, advice)


@check("lan.sweep", "Subnet sweep", "lan", modes=("full",), intrusive=True, timeout=300, exclusive=True)
def sweep(ctx: Context) -> Outcome:
    """Actively probes every address in the local subnet (ARP, ping, common TCP ports) to inventory devices."""
    primary = ctx.facts.primary_interface()
    addr = next((a for a in (primary.ipv4 if primary else []) if a.is_global and not a.is_apipa), None)
    if not addr:
        return Outcome(Status.SKIP, "no IPv4 subnet to sweep")
    net = ipaddress.ip_network(addr.network)
    if net.num_addresses > 1024:  # cap: sweep only this host's /22 neighbourhood
        net = ipaddress.ip_network(f"{addr.ip}/22", strict=False)
    validate.cidr(str(net))
    hosts = arp.sweep(net, timeout=1.0)
    rows = [vars(h) for h in hosts]
    return Outcome(Status.INFO, f"{len(hosts)} live host(s) in {net}", {"network": str(net), "hosts": rows})
