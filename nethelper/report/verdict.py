"""
The verdict engine: reads all check results and produces a short, ordered list
of plain-English findings - the "so what?" at the top of every report.

Individual checks report symptoms ("gateway ping FAIL", "DNS resolvers FAIL").
Rules here combine symptoms into likely causes, most fundamental first: if
the network adapter has no IP, there's no point headlining "website slow".
Each rule looks up results by their stable check id. The rules are a simple
ordered list, so adding a site-specific rule means appending one function.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable

from nethelper.core.result import CheckResult, Status


@dataclass
class Finding:
    """
    One diagnosis.
      severity   - "critical" (likely the user's problem), "warning", or "info"
      title      - short headline
      explanation- what the evidence shows, in plain words
      next_steps - concrete actions
      evidence   - check ids that support it
    """

    severity: str
    title: str
    explanation: str
    next_steps: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


Results = dict[str, CheckResult]
Rule = Callable[[Results], "Finding | None"]


def _is(r: Results, cid: str, *statuses: Status) -> bool:
    """True when check `cid` ran and has one of `statuses`."""
    res = r.get(cid)
    return res is not None and res.status in statuses


def _f(sev: str, title: str, cid: str, r: Results, extra: str = "", steps: list[str] | None = None) -> Finding:
    """Build a Finding from a check result, reusing its summary and advice."""
    res = r[cid]
    expl = res.summary + (f" {extra}" if extra else "")
    return Finding(sev, title, expl, steps if steps is not None else list(res.advice), [cid])


def rule_no_connection(r: Results) -> Finding | None:
    if _is(r, "local.interfaces", Status.FAIL):
        res = r["local.interfaces"]
        title = "DHCP failed (self-assigned address)" if "169.254" in res.summary else (
            "IP address conflict" if "conflict" in res.summary else "No usable network connection")
        return _f("critical", title, "local.interfaces", r)
    return None


def rule_no_gateway(r: Results) -> Finding | None:
    if _is(r, "local.routing", Status.FAIL):
        return _f("critical", "Default gateway missing or wrong", "local.routing", r)
    return None


def rule_ladder(r: Results) -> Finding | None:
    if not _is(r, "conn.ladder", Status.FAIL):
        return None
    summary = r["conn.ladder"].summary
    if "'Gateway'" in summary:
        title = "Cannot reach the router (local network problem)"
    elif "'Internet IP'" in summary:
        title = "Local network OK, internet unreachable (router/ISP/firewall)"
    elif "'Internet name'" in summary:
        title = "Internet reachable by IP but not by name (DNS or HTTPS blocked)"
    else:
        title = "Basic connectivity broken on this machine"
    return _f("critical", title, "conn.ladder", r)


def rule_dns(r: Results) -> Finding | None:
    if _is(r, "dns.resolvers", Status.FAIL):
        return _f("critical", "DNS resolution failure", "dns.resolvers", r)
    if _is(r, "dns.resolvers", Status.WARN):
        return _f("warning", "DNS partially failing or slow", "dns.resolvers", r)
    return None


def rule_captive(r: Results) -> Finding | None:
    if _is(r, "dns.captive", Status.FAIL):
        return _f("critical", "Captive portal / web interception", "dns.captive", r)
    return None


def rule_vlan(r: Results) -> Finding | None:
    if _is(r, "l2.vlan_validation", Status.FAIL):
        return _f("critical", "Wrong VLAN, subnet or duplex for this port", "l2.vlan_validation", r)
    if _is(r, "l2.switchport", Status.FAIL):
        return _f("warning", "Patched to an unexpected switch/port", "l2.switchport", r)
    return None


def rule_rogue_dhcp(r: Results) -> Finding | None:
    if _is(r, "lan.dhcp_servers", Status.FAIL):
        return _f("critical", "Rogue / multiple DHCP servers", "lan.dhcp_servers", r)
    if _is(r, "local.dhcp", Status.FAIL):
        return _f("critical", "Lease from an unapproved DHCP server", "local.dhcp", r)
    return None


def rule_arp_spoof(r: Results) -> Finding | None:
    """Only a MAC *mismatch/change/sharing* means spoofing - not merely failing to resolve the MAC."""
    res = r.get("lan.gateway_mac")
    if res is None or res.status not in (Status.FAIL, Status.WARN):
        return None
    text = res.summary
    if "expected" in text or "changed since baseline" in text or "share that MAC" in text:
        sev = "critical" if res.status is Status.FAIL else "warning"
        return _f(sev, "Gateway identity changed - possible ARP spoofing", "lan.gateway_mac", r)
    return None


def rule_per_interface(r: Results) -> Finding | None:
    if _is(r, "conn.per_interface", Status.FAIL, Status.WARN):
        sev = "critical" if r["conn.per_interface"].status is Status.FAIL else "warning"
        return _f(sev, "One or more network adapters can't reach the network", "conn.per_interface", r)
    return None


def rule_wifi_env(r: Results) -> Finding | None:
    if _is(r, "local.wifi_env", Status.WARN):
        title = "Possible evil-twin Wi-Fi network" if "mixed security" in r["local.wifi_env"].summary else "Crowded Wi-Fi channel"
        return _f("warning", title, "local.wifi_env", r)
    return None


def rule_bufferbloat(r: Results) -> Finding | None:
    if _is(r, "app.bandwidth", Status.WARN) and "bufferbloat" in r["app.bandwidth"].summary:
        return _f("warning", "Latency spikes under load (bufferbloat)", "app.bandwidth", r)
    return None


def rule_clock(r: Results) -> Finding | None:
    if _is(r, "app.ntp", Status.FAIL):
        return _f("critical", "System clock badly wrong", "app.ntp", r)
    return None


def rule_tls(r: Results) -> Finding | None:
    if _is(r, "app.tls", Status.FAIL):
        return _f("warning", "TLS certificate problems", "app.tls", r)
    if _is(r, "app.tls", Status.WARN) and "interception" in r["app.tls"].summary:
        return _f("warning", "HTTPS is being intercepted (TLS inspection)", "app.tls", r)
    return None


def rule_targets(r: Results) -> Finding | None:
    if _is(r, "app.targets", Status.FAIL):
        return _f("critical", "Site servers/services unreachable", "app.targets", r)
    if _is(r, "app.services", Status.FAIL):
        return _f("warning", "Mail/directory services unreachable", "app.services", r)
    return None


def rule_web(r: Results) -> Finding | None:
    if _is(r, "app.http", Status.FAIL) and not _is(r, "conn.ladder", Status.FAIL):
        return _f("critical", "Websites fail although the network path works", "app.http", r)
    return None


def rule_link(r: Results) -> Finding | None:
    if _is(r, "l2.link", Status.WARN):
        return _f("warning", "Ethernet link negotiation problem", "l2.link", r)
    return None


def rule_wifi(r: Results) -> Finding | None:
    if _is(r, "local.wifi", Status.WARN):
        return _f("warning", "Weak Wi-Fi signal", "local.wifi", r)
    return None


def rule_local_link_quality(r: Results) -> Finding | None:
    if _is(r, "conn.gateway_ping", Status.WARN, Status.FAIL):
        return _f("warning", "Unstable link to the router (loss/latency on the LAN)", "conn.gateway_ping", r)
    return None


def rule_wan_quality(r: Results) -> Finding | None:
    if _is(r, "conn.internet_ping", Status.WARN) and _is(r, "conn.gateway_ping", Status.PASS, Status.INFO):
        return _f("warning", "Internet link degraded (LAN is fine)", "conn.internet_ping", r)
    return None


def rule_mtu(r: Results) -> Finding | None:
    if _is(r, "conn.mtu", Status.WARN):
        return _f("warning", "Reduced path MTU / MTU black hole", "conn.mtu", r)
    return None


def rule_ipv6(r: Results) -> Finding | None:
    if _is(r, "conn.ipv6", Status.FAIL):
        return _f("warning", "IPv6 configured but broken (causes slow connections)", "conn.ipv6", r)
    return None


def rule_egress(r: Results) -> Finding | None:
    if _is(r, "conn.egress", Status.WARN):
        return _f("info", "Some outbound ports are filtered", "conn.egress", r)
    return None


def rule_hosts_hijack(r: Results) -> Finding | None:
    if _is(r, "local.hosts_file", Status.WARN):
        return _f("warning", "Hosts file overrides important names", "local.hosts_file", r)
    if _is(r, "dns.hijack", Status.WARN):
        return _f("info", "DNS server rewrites non-existent names", "dns.hijack", r)
    return None


def rule_vpn(r: Results) -> Finding | None:
    res = r.get("local.vpn")
    if res and "full tunnel" in res.summary:
        return Finding("info", "Traffic is going through a full-tunnel VPN", res.summary, list(res.advice), ["local.vpn"])
    return None


# Rules in priority order (most fundamental problems first).
RULES: list[Rule] = [
    rule_no_connection, rule_no_gateway, rule_vlan, rule_rogue_dhcp, rule_ladder, rule_captive, rule_dns,
    rule_clock, rule_arp_spoof, rule_per_interface, rule_targets, rule_web, rule_tls, rule_link, rule_wifi,
    rule_wifi_env, rule_local_link_quality, rule_wan_quality, rule_bufferbloat, rule_mtu, rule_ipv6,
    rule_hosts_hijack, rule_egress, rule_vpn,
]


def diagnose(results: list[CheckResult]) -> list[Finding]:
    """
    Apply every rule and return the findings, critical first. Any FAIL/WARN
    not explained by a rule is appended as an "Other issue" so nothing is
    silently dropped. If nothing is wrong, returns a single "all clear".
    """
    by_id: Results = {r.check_id: r for r in results}
    findings: list[Finding] = []
    covered: set[str] = set()
    for rule in RULES:
        finding = rule(by_id)
        if finding:
            findings.append(finding)
            covered.update(finding.evidence)
    for res in results:
        if res.status in (Status.FAIL, Status.WARN, Status.ERROR) and res.check_id not in covered:
            sev = "warning" if res.status is not Status.FAIL else "critical"
            title = f"{res.title}: {'check error' if res.status is Status.ERROR else res.status.value.lower()}"
            findings.append(Finding(sev, title, res.summary, list(res.advice), [res.check_id]))
    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.severity])
    if not any(f.severity in ("critical", "warning") for f in findings):
        ran = [r for r in results if r.status not in (Status.SKIP,)]
        findings.insert(0, Finding("info", "No problems found",
                                   f"{len(ran)} checks ran without failures or warnings.", [], []))
    return findings
