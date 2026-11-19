"""
Small helpers shared by the check modules: formatting numbers for one-line
summaries, judging ping statistics against thresholds, and picking the
interfaces a check should look at.
"""

from __future__ import annotations

from nethelper.core.context import Context
from nethelper.core.result import Status
from nethelper.net.icmp import PingStats
from nethelper.system.model import Interface


def ms(value: float | None) -> str:
    """Format milliseconds for display: 0.4 -> "<1 ms", 12.34 -> "12 ms"."""
    if value is None:
        return "n/a"
    if value < 1:
        return "<1 ms"
    return f"{value:.0f} ms" if value >= 10 else f"{value:.1f} ms"


def ping_summary(stats: PingStats) -> str:
    """One-line ping description: "4 ms avg (3-6), jitter 1 ms, 0% loss"."""
    if stats.error and not stats.received:
        return stats.error
    if not stats.received:
        return f"no replies ({stats.sent} sent, 100% loss)"
    return (f"{ms(stats.avg_ms)} avg ({ms(stats.min_ms)}-{ms(stats.max_ms)}), "
            f"jitter {ms(stats.jitter_ms)}, {stats.loss_pct:g}% loss")


def judge_ping(stats: PingStats, latency_warn: float, loss_warn: float, jitter_warn: float) -> tuple[Status, list[str]]:
    """
    Turn ping stats into a status plus the reasons for any warning.
    100% loss -> FAIL; any threshold exceeded -> WARN; else PASS.
    """
    if not stats.received:
        return Status.FAIL, ["no replies"]
    reasons = []
    if stats.loss_pct > loss_warn:
        reasons.append(f"{stats.loss_pct:g}% packet loss (limit {loss_warn:g}%)")
    if stats.avg_ms is not None and stats.avg_ms > latency_warn:
        reasons.append(f"average latency {ms(stats.avg_ms)} (limit {latency_warn:g} ms)")
    if stats.jitter_ms is not None and stats.jitter_ms > jitter_warn:
        reasons.append(f"jitter {ms(stats.jitter_ms)} (limit {jitter_warn:g} ms)")
    return (Status.WARN if reasons else Status.PASS), reasons


def selected_interfaces(ctx: Context) -> list[Interface] | None:
    """
    The interfaces named with -i / NETHELPER_INTERFACES (that exist), or None
    when the user didn't choose any (automatic). "all" is handled by callers.
    """
    names = [n for n in ctx.options.interfaces if n.lower() != "all"]
    if not names:
        return None
    snap = ctx.facts
    return [i for i in (snap.interface(n) for n in names) if i]


def relevant_interfaces(ctx: Context, kinds: tuple[str, ...] = ("ethernet", "wifi", "vpn", "other")) -> list[Interface]:
    """
    Interfaces a check should examine: the ones chosen with -i if any,
    otherwise every *up* interface of the given kinds.
    """
    chosen = selected_interfaces(ctx)
    if chosen is not None:
        return chosen
    return [i for i in ctx.facts.interfaces if i.up and i.kind in kinds]


def usable_test_interfaces(ctx: Context) -> list[Interface]:
    """
    Interfaces to run per-interface path tests on: the -i selection, else every
    up, addressed, non-loopback/non-virtual adapter (Ethernet, Wi-Fi, VPN...).
    """
    chosen = selected_interfaces(ctx)
    pool = chosen if chosen is not None else ctx.facts.interfaces
    return [i for i in pool if i.usable and i.kind not in ("loopback", "virtual")]


def wired_interfaces(ctx: Context) -> list[Interface]:
    """
    Wired (Ethernet) interfaces for switch/VLAN checks: the wired ones among
    -i if given (or all up Ethernet with -i all), else just the primary wired
    adapter (or the first up Ethernet).
    """
    snap = ctx.facts
    chosen = selected_interfaces(ctx)
    if chosen is not None:
        return [i for i in chosen if i.kind == "ethernet" or i.vlan_id]
    wired = [i for i in snap.interfaces if i.up and i.kind == "ethernet" and i.vlan_parent is None]
    if ctx.options.all_interfaces:
        return wired
    primary = snap.primary_interface()
    if primary and primary.kind == "ethernet":
        return [primary]
    return wired[:1]


def wired_interface(ctx: Context) -> Interface | None:
    """The first interface from wired_interfaces(), or None."""
    wired = wired_interfaces(ctx)
    return wired[0] if wired else None


def interface_gateway(ctx: Context, iface: Interface) -> str | None:
    """
    The default gateway reachable through one specific interface: its own
    default route if it has one, else its DHCP lease's router (from the
    routing table entry that matches its subnet).
    """
    for r in ctx.facts.default_routes(4):
        if r.interface and r.interface.lower() == iface.name.lower():
            return r.gateway
    return None


def first_ipv4(iface: Interface | None) -> str | None:
    """The interface's first non-link-local IPv4 address, if any."""
    if not iface:
        return None
    for addr in iface.ipv4:
        if addr.is_global and not addr.is_apipa:
            return addr.ip
    return None
