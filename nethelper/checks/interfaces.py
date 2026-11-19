"""
Multi-interface and Wi-Fi environment checks.

  conn.per_interface  tests EACH active adapter's own path: its gateway, the
                      internet (ping + HTTPS port) and DNS, with traffic forced
                      out of that adapter by binding to its IP address. Answers
                      "is it the Wi-Fi or the cable?" and "does the backup
                      link / second NIC actually work?" in one run.
  local.wifi_env      scans nearby Wi-Fi networks: channel congestion on the
                      current channel, a better channel recommendation, and
                      possible "evil twin" networks (same name, different security).

Source binding note: Windows and macOS send from the interface owning the
bound address. On Linux without root the kernel may still route by its table
(policy routing); as root SO_BINDTODEVICE pins the interface exactly. The
check states which method was used.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from nethelper.checks._util import first_ipv4, interface_gateway, ms, ping_summary, usable_test_interfaces
from nethelper.core.context import Context
from nethelper.core.registry import check
from nethelper.core.result import Outcome, Status
from nethelper.net import dnswire, icmp, tcp, wifi


def _test_interface(ctx: Context, iface) -> dict:
    """Run the per-interface path tests for one adapter."""
    src = first_ipv4(iface)
    row: dict = {"interface": iface.name, "kind": iface.kind, "source_ip": src, "steps": {}}
    if not src:
        row["error"] = "no usable IPv4 address"
        return row
    device = iface.name if ctx.caps.os == "linux" and ctx.caps.elevated else None
    row["binding"] = "SO_BINDTODEVICE + source IP" if device else "source IP"
    t = ctx.options.timeout
    gw = interface_gateway(ctx, iface)
    row["gateway"] = gw
    if gw:
        s = icmp.ping(gw, count=3, timeout=t, interval=0.1, source=src, device=device)
        row["steps"]["gateway"] = {"ok": s.received > 0, "detail": ping_summary(s), "avg_ms": s.avg_ms}
    else:
        row["steps"]["gateway"] = {"ok": None, "detail": "no default route on this interface"}
    target = ctx.profile.public_ping[0] if ctx.profile.public_ping else "1.1.1.1"
    s = icmp.ping(target, count=3, timeout=t, interval=0.1, source=src, device=device)
    row["steps"]["internet_ping"] = {"ok": s.received > 0, "detail": f"{target}: {ping_summary(s)}", "avg_ms": s.avg_ms}
    res = tcp.connect(target, 443, timeout=t, source=src, device=device)
    row["steps"]["internet_tcp"] = {"ok": res.state in ("open", "refused"),
                                    "detail": f"{target}:443 {res.state}" + (f" in {ms(res.connect_ms)}" if res.connect_ms else "")}
    servers = ctx.facts.dns_by_interface.get(iface.name) or ctx.facts.dns_servers[:1]
    name = ctx.profile.dns_names[0] if ctx.profile.dns_names else "www.google.com"
    if servers:
        try:
            r = dnswire.query(name, "A", server=servers[0], timeout=t, source=src)
            row["steps"]["dns"] = {"ok": r.rcode == "NOERROR" and bool(r.answers),
                                   "detail": f"{name} via {servers[0]}: {r.rcode} in {ms(r.rtt_ms)}"}
        except (OSError, dnswire.DnsError) as exc:
            row["steps"]["dns"] = {"ok": False, "detail": f"{name} via {servers[0]}: {exc or type(exc).__name__}"}
    return row


@check("conn.per_interface", "Per-interface paths", "connectivity", modes=("quick", "full"), timeout=90)
def per_interface(ctx: Context) -> Outcome:
    """Tests gateway, internet and DNS separately through EACH active adapter (Ethernet vs Wi-Fi vs VPN)."""
    ifaces = usable_test_interfaces(ctx)
    if not ifaces:
        return Outcome(Status.SKIP, "no active interfaces with an IPv4 address")
    if len(ifaces) == 1 and not ctx.options.interfaces:
        return Outcome(Status.SKIP, f"only one active interface ({ifaces[0].name}) - covered by the connectivity ladder; "
                       "use -i <name> or -i all to force")
    with ThreadPoolExecutor(max_workers=min(len(ifaces), 4)) as pool:
        rows = list(pool.map(lambda i: _test_interface(ctx, i), ifaces))
    parts, broken, partial = [], [], []
    for row in rows:
        steps = row["steps"]
        bad = [k for k, v in steps.items() if v.get("ok") is False]
        if row.get("error"):
            broken.append(row["interface"])
            parts.append(f"{row['interface']}: {row['error']}")
        elif bad and len(bad) == len([v for v in steps.values() if v.get("ok") is not None]):
            broken.append(row["interface"])
            parts.append(f"{row['interface']}: no connectivity ({', '.join(bad)} failed)")
        elif bad:
            partial.append(row["interface"])
            parts.append(f"{row['interface']}: {', '.join(bad)} failed")
        else:
            inet = steps.get("internet_ping", {}).get("avg_ms")
            parts.append(f"{row['interface']}: OK" + (f" (internet {ms(inet)})" if inet else ""))
    details = {"interfaces": rows}
    advice = []
    if broken or partial:
        advice.append("An adapter that fails here while another works has its own problem: check that link's "
                      "cable/Wi-Fi association, its gateway/DHCP, and its DNS servers. A VPN adapter often has "
                      "no default route by design (split tunnel) - that's expected.")
    if ctx.caps.os == "linux" and not ctx.caps.elevated:
        details["privilege_note"] = "without root, Linux may route source-bound tests via the main table (no SO_BINDTODEVICE)"
    status = Status.FAIL if broken and len(broken) == len(rows) else (Status.WARN if broken or partial else Status.PASS)
    return Outcome(status, "; ".join(parts), details, advice)


@check("local.wifi_env", "Wi-Fi environment", "local", modes=("full",), timeout=60, exclusive=True)
def wifi_env(ctx: Context) -> Outcome:
    """Scans nearby Wi-Fi: congestion on the current channel, a better channel, and same-name/different-security 'evil twins'."""
    current = [w for w in ctx.facts.wifi if w.ssid or w.bssid]
    has_wifi = any(i.kind == "wifi" for i in ctx.facts.interfaces)
    if not has_wifi:
        return Outcome(Status.SKIP, "no Wi-Fi adapter")
    res = wifi.scan()
    if not res.networks:
        return Outcome(Status.INFO if res.note else Status.SKIP, res.note or "no networks found in scan",
                       {"method": res.method})
    cur = current[0] if current else None
    analysis = wifi.analyze_channels(res.networks, cur.channel if cur else None, own_bssid=cur.bssid if cur else None)
    twins = wifi.evil_twin_suspects(res.networks)
    details = {"method": res.method, "networks": wifi.to_dicts(res.networks[:60]), "channels": analysis,
               "evil_twin_suspects": twins, "note": res.note}
    advice, status = [], Status.PASS
    crowded = analysis["strong_aps_on_or_overlapping_current"]
    summary = f"{len(res.networks)} BSSIDs nearby"
    if cur and cur.channel:
        summary += f"; on channel {cur.channel} with {crowded} strong neighbour AP(s)"
        if crowded >= 3:
            status = Status.WARN
            rec = analysis["recommended_24ghz"] if cur.channel <= 14 else analysis["recommended_5ghz"]
            advice.append(f"Channel {cur.channel} is crowded. Channel {rec} looks least used - set it on the access "
                          "point (or let the controller's auto-channel re-plan), and prefer 5 GHz where possible.")
    if twins:
        status = Status.WARN
        summary += f"; {len(twins)} SSID(s) broadcast with mixed security: " + ", ".join(t["ssid"] for t in twins[:3])
        advice.append("The same network name with different security (e.g. WPA2 and Open) can be a rogue 'evil "
                      "twin' access point - verify every AP broadcasting it belongs to you.")
    return Outcome(status, summary, details, advice, {"wifi scan": res.raw[:20000]})
