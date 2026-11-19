"""
"Connectivity" checks: can packets get from here to there, and how well?

The centrepiece is the connectivity LADDER, which tests each layer outward
and reports the first rung that breaks:
    1 loopback (127.0.0.1)  -> the TCP/IP stack itself works
    2 own IP address         -> the adapter is up and configured
    3 default gateway        -> the LAN path to the router works
    4 public IP (1.1.1.1...) -> the router/ISP forwards traffic to the internet
    5 public hostname        -> DNS resolution + HTTPS port reachable
The first failing rung pinpoints where to look, which answers most
"the internet is down" calls on its own.

Other checks measure quality (latency, jitter, loss), map the path
(traceroute), probe outbound firewall filtering (common ports), find MTU
black holes, and detect broken IPv6.
"""

from __future__ import annotations

import socket

from nethelper.checks._util import first_ipv4, judge_ping, ms, ping_summary
from nethelper.core.context import Context
from nethelper.core.registry import check
from nethelper.core.result import Outcome, Status
from nethelper.net import arp, icmp, mtu, tcp, traceroute


def _gateway_mac(ctx: Context, gw: str) -> str | None:
    """MAC of the gateway from the ARP table, or by asking ARP directly."""
    for n in ctx.facts.neighbors:
        if n.ip == gw and n.mac:
            return n.mac
    return ctx.memo(f"arp:{gw}", lambda: arp.resolve_mac(gw))


@check("conn.ladder", "Connectivity ladder", "connectivity", modes=("quick", "full"), timeout=60)
def ladder(ctx: Context) -> Outcome:
    """Tests loopback -> own IP -> gateway -> internet IP -> internet hostname and reports the first broken step."""
    snap = ctx.facts
    t = ctx.options.timeout
    steps: list[dict] = []

    def step(name: str, target: str | None, ok: bool | None, detail: str) -> bool:
        steps.append({"step": name, "target": target, "ok": ok, "detail": detail})
        return bool(ok)

    # 1. Loopback
    r = icmp.echo("127.0.0.1", timeout=t)
    step("Loopback", "127.0.0.1", r.status == icmp.OK, ms(r.rtt_ms) if r.status == icmp.OK else r.status)

    # 2. Own address
    primary = snap.primary_interface()
    own = first_ipv4(primary)
    if own:
        r = icmp.echo(own, timeout=t)
        step("Own IP", own, r.status == icmp.OK, f"{primary.name}: " + (ms(r.rtt_ms) if r.status == icmp.OK else r.status))
    else:
        step("Own IP", None, False, "no usable IPv4 address on any adapter")

    # 3. Gateway (ICMP, falling back to ARP: many routers ignore ping)
    gw = snap.default_gateway()
    gw_ok = False
    if gw:
        stats = icmp.ping(gw, count=3, timeout=t, interval=0.1)
        if stats.received:
            gw_ok = step("Gateway", gw, True, ping_summary(stats))
        else:
            mac = _gateway_mac(ctx, gw)
            gw_ok = step("Gateway", gw, None if mac else False,
                         f"no ping reply, but present on the LAN (MAC {mac})" if mac else "no ping reply and no ARP answer")
            gw_ok = gw_ok or bool(mac)
    else:
        step("Gateway", None, False, "no default gateway configured")

    # 4. Internet by IP (ICMP, then TCP 443/53 in case ICMP is filtered)
    inet_ok = False
    for target in ctx.profile.public_ping:
        stats = icmp.ping(target, count=3, timeout=t, interval=0.1)
        if stats.received:
            inet_ok = step("Internet IP", target, True, f"ping {ping_summary(stats)}")
            break
        for port in (443, 53):
            res = tcp.connect(target, port, timeout=t)
            if res.state in ("open", "refused"):
                inet_ok = step("Internet IP", target, True, f"ICMP blocked, but TCP/{port} reachable ({ms(res.connect_ms)})")
                break
        if inet_ok:
            break
    if not inet_ok:
        step("Internet IP", ", ".join(ctx.profile.public_ping), False, "no ICMP or TCP response from any public IP")

    # 5. Internet by name (DNS + HTTPS port)
    host = ctx.profile.public_hostname
    try:
        ip = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)[0][4][0]
        res = tcp.connect(ip, 443, timeout=t)
        step("Internet name", host, res.state == "open",
             f"resolved to {ip}; TCP/443 {res.state}" + (f" ({ms(res.connect_ms)})" if res.connect_ms else ""))
    except OSError as exc:
        step("Internet name", host, False, f"DNS lookup failed: {exc}")

    first_bad = next((s for s in steps if s["ok"] is False), None)
    advice_map = {
        "Loopback": "The TCP/IP stack itself is broken. On Windows try 'nethelper fix reset-winsock' then reboot.",
        "Own IP": "No usable address: check the cable/Wi-Fi, adapter state, and DHCP.",
        "Gateway": "The router is unreachable from this machine: check cable/patch/switch port/Wi-Fi, the VLAN "
                   "assignment, and whether the gateway IP is correct for this subnet.",
        "Internet IP": "The LAN works but traffic isn't getting past the router: check the router's WAN link, "
                       "ISP outage, or an upstream firewall blocking outbound traffic.",
        "Internet name": "The internet is reachable by IP but not by name: a DNS problem (see the DNS section), "
                         "or outbound HTTPS is blocked.",
    }
    details = {"steps": steps}
    if first_bad:
        return Outcome(Status.FAIL, f"breaks at '{first_bad['step']}': {first_bad['detail']}", details,
                       [advice_map[first_bad["step"]]])
    if any(s["ok"] is None for s in steps):
        # Not a fault: many routers simply don't answer ping to themselves.
        return Outcome(Status.PASS, "all steps OK (gateway ignores ping but answers ARP)", details)
    return Outcome(Status.PASS, "loopback, own IP, gateway, internet IP and internet name all OK", details)


@check("conn.gateway_ping", "Gateway latency & loss", "connectivity", modes=("quick", "full"), timeout=45)
def gateway_ping(ctx: Context) -> Outcome:
    """Repeated pings to the default gateway: on a healthy LAN expect ~0% loss and low, steady latency."""
    gw = ctx.facts.default_gateway()
    if not gw:
        return Outcome(Status.SKIP, "no default gateway")
    stats = icmp.ping(gw, count=ctx.options.ping_count, timeout=ctx.options.timeout, interval=0.2)
    details = stats.to_dict()
    if not stats.received:
        mac = _gateway_mac(ctx, gw)
        if mac:
            return Outcome(Status.INFO, f"{gw} does not answer ping (present on LAN, MAC {mac})", details,
                           ["Many routers/firewalls block ping to themselves; this alone isn't a fault."])
        return Outcome(Status.FAIL, f"{gw}: no replies", details,
                       ["The gateway is unreachable: check physical link, switch port, VLAN and gateway address."])
    # A LAN hop should be much better than internet thresholds: loss > 0 and >30 ms deserve attention.
    lan_latency = 30.0 if ctx.facts.primary_interface() and ctx.facts.primary_interface().kind != "wifi" else 60.0
    status, reasons = judge_ping(stats, lan_latency, 0.0, 15.0)
    advice = []
    if reasons:
        advice.append("Loss or high/erratic latency to the gateway points at the local link: Wi-Fi signal or "
                      "interference, a bad cable/port, duplex mismatch, or an overloaded router.")
    return Outcome(status, f"{gw}: {ping_summary(stats)}" + (f" - {'; '.join(reasons)}" if reasons else ""),
                   details, advice)


@check("conn.internet_ping", "Internet latency & loss", "connectivity", modes=("quick", "full"), timeout=60)
def internet_ping(ctx: Context) -> Outcome:
    """Repeated pings to public anycast resolvers (1.1.1.1, 8.8.8.8 by default) judged against profile thresholds."""
    th = ctx.threshold
    results, parts, statuses, all_reasons = [], [], [], []
    for target in ctx.profile.public_ping:
        stats = icmp.ping(target, count=ctx.options.ping_count, timeout=ctx.options.timeout, interval=0.2)
        status, reasons = judge_ping(stats, th.latency_warn_ms, th.loss_warn_pct, th.jitter_warn_ms)
        results.append(stats.to_dict())
        statuses.append(status)
        parts.append(f"{target} {ping_summary(stats)}")
        all_reasons += [f"{target}: {r}" for r in reasons if r != "no replies"]
    details = {"targets": results}
    if all(s is Status.FAIL for s in statuses):
        return Outcome(Status.FAIL, "no replies from any public target", details,
                       ["Either the internet is down or ICMP is filtered upstream - see the connectivity ladder, "
                        "which also tries TCP."])
    if any(s is not Status.PASS for s in statuses):
        return Outcome(Status.WARN, "; ".join(parts), details,
                       ["Elevated loss/latency/jitter to the internet but not the gateway usually means a saturated "
                        "or degraded WAN link (ISP), or heavy uploads/downloads on the network."] if all_reasons else [])
    return Outcome(Status.PASS, "; ".join(parts), details)


@check("conn.traceroute", "Traceroute", "connectivity", modes=("full",), timeout=120)
def trace(ctx: Context) -> Outcome:
    """Maps each router hop to the trace target, flagging where latency jumps or the path stops."""
    res = traceroute.trace(ctx.profile.trace_target, max_hops=30, timeout=min(ctx.options.timeout, 2.0))
    details = res.to_dict()
    raw = {"traceroute": res.raw} if res.raw else {}
    if res.error and not res.hops:
        return Outcome(Status.ERROR, res.error, details, raw=raw)
    hops_desc = " > ".join(h.address or "*" for h in res.hops[:12])
    notes, advice = [], []
    prev = None
    for hop in res.hops:
        if hop.avg_ms is not None and prev is not None and hop.avg_ms - prev > 50:
            notes.append(f"latency jumps {ms(prev)} -> {ms(hop.avg_ms)} at hop {hop.ttl} ({hop.address})")
            break
        if hop.avg_ms is not None:
            prev = hop.avg_ms
    private = 0
    for hop in res.hops:
        if hop.address and not _is_public(hop.address):
            private += 1
        elif hop.address:
            break
    if private >= 2:
        notes.append(f"{private} private hops before the internet (double NAT or internal routing)")
        advice.append("Two or more private hops often means a second router behind the ISP modem ('double NAT'), "
                      "which breaks port forwards, some VPNs and gaming/VoIP.")
    status = Status.PASS if res.reached else Status.WARN
    if not res.reached:
        advice.append("The trace didn't reach the target. Trailing '*' hops are common (routers ignoring "
                      "probes); only worry if the connectivity ladder also fails.")
    summary = (f"{'reached' if res.reached else 'did not reach'} {res.address} in {len(res.hops)} hops "
               f"({res.method}): {hops_desc}")
    if notes:
        summary += " - " + "; ".join(notes)
    return Outcome(status, summary, details, advice, raw)


def _is_public(ip: str) -> bool:
    """True for internet-routable addresses (not private, not carrier-grade NAT)."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        # 100.64.0.0/10 is carrier-grade NAT space - counts as "not yet public".
        return addr.is_global and addr not in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


# Outbound ports commonly blocked by restrictive firewalls / guest networks.
EGRESS_TESTS = [
    ("HTTP", "www.cloudflare.com", 80), ("HTTPS", "www.cloudflare.com", 443),
    ("DNS over TCP", "1.1.1.1", 53), ("DNS over TLS", "1.1.1.1", 853),
    ("SSH", "github.com", 22), ("SMTP submission", "smtp.gmail.com", 587),
    ("IMAPS", "imap.gmail.com", 993), ("OpenVPN/alt-HTTPS", "portquiz.net", 8443),
]


@check("conn.egress", "Outbound port filtering", "connectivity", modes=("full",), timeout=60)
def egress(ctx: Context) -> Outcome:
    """Connects to well-known public services on common ports to reveal outbound firewall filtering."""
    pairs = [(h, p) for _, h, p in EGRESS_TESTS]
    results = tcp.connect_many(pairs, timeout=ctx.options.timeout)
    rows, blocked = [], []
    for (label, host, port), res in zip(EGRESS_TESTS, results, strict=True):
        rows.append({"service": label, "host": host, "port": port, "state": res.state, "ms": res.connect_ms})
        if res.state not in ("open",):
            blocked.append(f"{label} ({port})")
    details = {"ports": rows}
    if len(blocked) == len(rows):
        return Outcome(Status.FAIL, "no outbound connections succeeded", details,
                       ["Nothing gets out - see the connectivity ladder."])
    if blocked:
        return Outcome(Status.WARN, f"blocked or unreachable: {', '.join(blocked)}", details,
                       ["Selective failures indicate outbound filtering (corporate/guest firewall, ISP port block "
                        "e.g. on 25/587). If an app needs one of these ports, request a firewall rule."])
    return Outcome(Status.PASS, f"all {len(rows)} common outbound ports open", details)


@check("conn.mtu", "Path MTU", "connectivity", modes=("full",), timeout=90)
def path_mtu(ctx: Context) -> Outcome:
    """Finds the largest packet that reaches the internet unfragmented; detects MTU 'black holes'."""
    res = mtu.discover(ctx.profile.trace_target, timeout=min(ctx.options.timeout, 2.0))
    details = vars(res)
    if res.error:
        return Outcome(Status.SKIP, res.error, details)
    if res.mtu and res.mtu >= 1500:
        return Outcome(Status.PASS, f"{res.mtu} bytes (full Ethernet MTU)", details)
    status = Status.WARN if (res.mtu or 0) < ctx.threshold.mtu_warn or res.black_hole else Status.INFO
    advice = [f"Path MTU is {res.mtu} (typical: PPPoE 1492, VPNs 1300-1420)."]
    if res.black_hole:
        advice.append("Oversized packets are silently dropped (no 'fragmentation needed' replies): a classic cause "
                      "of pages half-loading and stalled file transfers over VPN. Lower the MTU/MSS on the "
                      "tunnel or router, or allow ICMP type 3 code 4 through the firewall.")
    return Outcome(status, f"{res.mtu} bytes" + (" - black hole detected" if res.black_hole else ""), details, advice)


@check("conn.ipv6", "IPv6", "connectivity", modes=("full",), timeout=40)
def ipv6(ctx: Context) -> Outcome:
    """Whether IPv6 is configured and, if so, actually works (broken IPv6 makes sites load slowly)."""
    snap = ctx.facts
    v6_global = [a.ip for i in snap.interfaces if i.up for a in i.ipv6 if a.is_global and not a.is_link_local]
    v6_route = snap.default_routes(6)
    details = {"global_addresses": v6_global, "default_route": [vars(r) for r in v6_route]}
    if not v6_global:
        return Outcome(Status.INFO, "IPv6 not configured (IPv4 only)", details)
    target = "2606:4700:4700::1111"
    res = tcp.connect(target, 443, timeout=ctx.options.timeout, family=socket.AF_INET6)
    reply = icmp.echo(target, timeout=ctx.options.timeout)
    details["tcp443"] = res.state
    details["ping"] = reply.status
    if res.state == "open" or reply.status == icmp.OK:
        return Outcome(Status.PASS, f"working ({len(v6_global)} global address(es); TCP/443 {res.state}, ping {reply.status})", details)
    return Outcome(Status.FAIL, "IPv6 is configured but cannot reach the internet", details,
                   ["Broken IPv6 makes apps try IPv6 first and wait for a timeout - pages feel slow. Fix the "
                    "router's IPv6 (or the ISP's) or disable IPv6 on the router until it works."])
