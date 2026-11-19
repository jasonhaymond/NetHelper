"""
"DNS" checks: name resolution is behind a huge share of "the network is down"
complaints, and it fails in several distinct ways that need different fixes.

The key technique is COMPARISON: the same names are resolved via
  (a) the operating system resolver (what apps actually use),
  (b) each DNS server configured on this machine, and
  (c) well-known public resolvers (Cloudflare, Google, Quad9),
so the pattern of failures identifies the culprit: local DNS server broken,
outbound DNS blocked, internal-only names, ISP hijacking, and so on.
"""

from __future__ import annotations

import secrets
import socket

from nethelper.checks._util import first_ipv4, ms
from nethelper.core.context import Context
from nethelper.core.registry import check
from nethelper.core.result import Outcome, Status
from nethelper.net import dnswire, httpcheck


def _try_query(name: str, rtype: str, server: str, timeout: float, **kw) -> dict:
    """Run one DNS query and return a small result dict (never raises)."""
    try:
        resp = dnswire.query(name, rtype, server=server, timeout=timeout, **kw)
        return {"server": server, "ok": resp.rcode == "NOERROR" and bool(resp.answers), "rcode": resp.rcode,
                "answers": resp.values(rtype)[:6], "ms": resp.rtt_ms, "ad": resp.ad}
    except (OSError, dnswire.DnsError) as exc:
        return {"server": server, "ok": False, "rcode": "TIMEOUT" if isinstance(exc, socket.timeout) else "ERROR",
                "error": str(exc) or type(exc).__name__, "answers": [], "ms": None}


@check("dns.resolvers", "Resolver comparison", "dns", modes=("quick", "full"), timeout=60)
def resolvers(ctx: Context) -> Outcome:
    """Resolves test names via the OS, each configured DNS server, and public resolvers, then compares."""
    names = ctx.profile.dns_names
    t = ctx.options.timeout
    configured = list(dict.fromkeys(ctx.facts.dns_servers + ctx.profile.extra_resolvers))
    public = ctx.profile.public_resolvers
    rows: list[dict] = []
    sys_ok = cfg_ok = pub_ok = 0
    cfg_total = pub_total = 0
    slow: list[str] = []
    nx_local_only: list[str] = []
    for name in names:
        row: dict = {"name": name}
        try:
            ips, took = dnswire.system_resolve(name)
            row["system"] = {"ok": True, "answers": ips[:6], "ms": took}
            sys_ok += 1
            if took > ctx.threshold.dns_slow_ms:
                slow.append(f"system resolver {ms(took)} for {name}")
        except OSError as exc:
            row["system"] = {"ok": False, "error": str(exc)}
        row["configured"] = []
        for server in configured:
            r = _try_query(name, "A", server, t)
            row["configured"].append(r)
            cfg_total += 1
            cfg_ok += r["ok"]
            if r["ms"] and r["ms"] > ctx.threshold.dns_slow_ms:
                slow.append(f"{server} {ms(r['ms'])}")
            if r["rcode"] == "NXDOMAIN":
                nx_local_only.append(f"{name} via {server}")
        row["public"] = []
        for label, server in public.items():
            r = _try_query(name, "A", server, t)
            r["label"] = label
            row["public"].append(r)
            pub_total += 1
            pub_ok += r["ok"]
        rows.append(row)

    details = {"names": rows, "configured_servers": configured}
    summary = (f"system {sys_ok}/{len(names)}, configured servers {cfg_ok}/{cfg_total}, "
               f"public resolvers {pub_ok}/{pub_total} answered")
    # Diagnose from the pattern of failures.
    if sys_ok == 0 and cfg_ok == 0 and pub_ok == 0:
        return Outcome(Status.FAIL, "no DNS resolution at all - " + summary, details,
                       ["Neither the configured nor public DNS servers answer. Either there's no internet path "
                        "(see the connectivity ladder) or outbound DNS (UDP/TCP 53) is blocked; the 'Encrypted "
                        "DNS' check shows whether DNS-over-HTTPS still works."])
    if cfg_total and cfg_ok == 0 and pub_ok > 0:
        return Outcome(Status.FAIL, "configured DNS server(s) not answering, public DNS works - " + summary, details,
                       [f"The DNS server(s) {', '.join(configured)} are down or unreachable. Restart/fix the DNS "
                        "service (router, domain controller), or correct the DNS setting on this machine."])
    if sys_ok < len(names) and cfg_ok == cfg_total and cfg_total:
        return Outcome(Status.WARN, "configured servers answer but the OS resolver failed - " + summary, details,
                       ["The OS resolver failed where direct queries worked: check the hosts file, VPN DNS "
                        "rules, or a stuck DNS cache ('nethelper fix flush-dns')."])
    if nx_local_only:
        return Outcome(Status.WARN, f"configured DNS says these don't exist: {', '.join(nx_local_only[:3])} - " + summary,
                       details, ["The local DNS server returns NXDOMAIN for names that exist publicly: DNS filtering "
                                 "(content blocker, Pi-hole, security policy) or a split-DNS misconfiguration."])
    if cfg_total and cfg_ok < cfg_total:
        return Outcome(Status.WARN, "some configured DNS servers failed - " + summary, details,
                       ["One of several DNS servers isn't answering. Clients fail over slowly, causing intermittent "
                        "delays - fix or remove the dead server."])
    if slow:
        return Outcome(Status.WARN, f"slow DNS: {', '.join(slow[:3])}", details,
                       ["Slow DNS makes every new connection feel sluggish. Check the DNS server's load and its "
                        "upstream forwarders."])
    return Outcome(Status.PASS, summary, details)


@check("dns.records", "DNS records", "dns", modes=("full",), timeout=45)
def records(ctx: Context) -> Outcome:
    """A, AAAA, MX, NS, TXT, SOA plus SPF/DMARC for the profile's domains (mail and web troubleshooting)."""
    server = (ctx.facts.dns_servers or ["1.1.1.1"])[0]
    out, problems = {}, []
    for domain in ctx.profile.dns_domains:
        recs: dict = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
            r = _try_query(domain, rtype, server, ctx.options.timeout)
            recs[rtype] = r["answers"] if r["ok"] else r["rcode"]
            if r["rcode"] in ("SERVFAIL", "NXDOMAIN") and rtype == "SOA":
                problems.append(f"{domain}: {r['rcode']}")
        txt = recs.get("TXT") if isinstance(recs.get("TXT"), list) else []
        recs["SPF"] = next((t for t in txt if t.lower().startswith("v=spf1")), None)
        dmarc = _try_query(f"_dmarc.{domain}", "TXT", server, ctx.options.timeout)
        recs["DMARC"] = next((t for t in dmarc["answers"] if t.lower().startswith("v=dmarc1")), None)
        out[domain] = recs
    details = {"server": server, "domains": out}
    if problems:
        return Outcome(Status.WARN, "; ".join(problems), details)
    first = ctx.profile.dns_domains[0] if ctx.profile.dns_domains else ""
    mx = out.get(first, {}).get("MX")
    return Outcome(Status.INFO, f"{len(out)} domain(s) looked up via {server}"
                   + (f"; {first} MX: {', '.join(mx[:2])}" if isinstance(mx, list) and mx else ""), details)


@check("dns.reverse", "Reverse DNS", "dns", modes=("full",), timeout=30)
def reverse(ctx: Context) -> Outcome:
    """PTR (IP -> name) lookups for this machine, its gateway and DNS servers - mismatches confuse logs and auth."""
    snap = ctx.facts
    targets = [first_ipv4(snap.primary_interface()), snap.default_gateway(), *snap.dns_servers[:2]]
    server = (snap.dns_servers or ["1.1.1.1"])[0]
    rows = []
    for ip in [t for t in dict.fromkeys(targets) if t]:
        try:
            r = _try_query(dnswire.reverse_name(ip), "PTR", server, ctx.options.timeout)
        except ValueError:
            continue
        rows.append({"ip": ip, "ptr": r["answers"][0] if r["answers"] else None, "rcode": r["rcode"]})
    named = [f"{r['ip']}={r['ptr']}" for r in rows if r["ptr"]]
    return Outcome(Status.INFO, ", ".join(named) if named else "no PTR records found (common on small networks)",
                   {"server": server, "lookups": rows})


@check("dns.hijack", "NXDOMAIN hijacking", "dns", modes=("full",), timeout=30)
def hijack(ctx: Context) -> Outcome:
    """Asks for a random non-existent name; a resolver that 'finds' it is redirecting typos to ad/search pages."""
    name = f"nsl-{secrets.token_hex(8)}.com"
    rows, hijackers = [], []
    for server in ctx.facts.dns_servers[:3]:
        r = _try_query(name, "A", server, ctx.options.timeout)
        rows.append(r)
        if r["ok"] and r["answers"]:
            hijackers.append(f"{server} -> {r['answers'][0]}")
    details = {"test_name": name, "results": rows}
    if hijackers:
        return Outcome(Status.WARN, f"NXDOMAIN rewritten by {', '.join(hijackers)}", details,
                       ["The DNS server returns an address for names that don't exist (ISP 'search assist' or a "
                        "filtering service). This breaks software that relies on 'name not found' and can leak "
                        "internal names; switch DNS or disable the feature."])
    return Outcome(Status.PASS, "non-existent names correctly return NXDOMAIN", details)


@check("dns.dnssec", "DNSSEC validation", "dns", modes=("full",), timeout=30)
def dnssec(ctx: Context) -> Outcome:
    """Whether the configured resolver validates DNSSEC signatures (informational)."""
    server = (ctx.facts.dns_servers or ["1.1.1.1"])[0]
    good = _try_query("cloudflare.com", "A", server, ctx.options.timeout, dnssec=True)
    bad = _try_query("dnssec-failed.org", "A", server, ctx.options.timeout)
    validates = bool(good.get("ad")) and bad["rcode"] == "SERVFAIL"
    details = {"server": server, "signed_domain_ad_flag": good.get("ad"), "broken_domain_rcode": bad["rcode"]}
    if validates:
        return Outcome(Status.PASS, f"{server} validates DNSSEC", details)
    return Outcome(Status.INFO, f"{server} does not validate DNSSEC", details,
                   ["Not a fault - most local/ISP resolvers don't validate. Validation protects against forged "
                    "DNS answers."])


@check("dns.encrypted", "Encrypted DNS (DoT/DoH)", "dns", modes=("full",), timeout=30)
def encrypted(ctx: Context) -> Outcome:
    """Tests DNS-over-TLS (port 853) and DNS-over-HTTPS reachability - distinguishes 'DNS blocked' from 'DNS broken'."""
    details: dict = {}
    try:
        r = dnswire.query("example.com", "A", server="1.1.1.1", transport="dot",
                          tls_hostname="cloudflare-dns.com", timeout=ctx.options.timeout + 2)
        details["dot"] = {"ok": r.rcode == "NOERROR", "ms": r.rtt_ms}
    except (OSError, dnswire.DnsError) as exc:
        details["dot"] = {"ok": False, "error": str(exc)}
    try:
        r = dnswire.query_doh("example.com", timeout=ctx.options.timeout + 3)
        details["doh"] = {"ok": r.rcode == "NOERROR", "ms": r.rtt_ms}
    except (OSError, ValueError, dnswire.DnsError) as exc:
        details["doh"] = {"ok": False, "error": str(exc)}
    dot, doh = details["dot"]["ok"], details["doh"]["ok"]
    summary = f"DoT {'ok' if dot else 'blocked'}, DoH {'ok' if doh else 'blocked'}"
    if dot and doh:
        return Outcome(Status.PASS, summary, details)
    return Outcome(Status.INFO, summary, details,
                   ["Encrypted DNS being blocked is common on managed networks and not a fault by itself. If "
                    "normal DNS fails but DoH works, outbound port 53 is being filtered."])


@check("dns.captive", "Captive portal", "dns", modes=("quick", "full"), timeout=30)
def captive(ctx: Context) -> Outcome:
    """Fetches the same connectivity-check URLs Android/Windows use to detect hotel/guest Wi-Fi login pages."""
    probes = [("http://connectivitycheck.gstatic.com/generate_204", 204, None),
              ("http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test")]
    rows, intercepted, worked = [], [], 0
    for url, code, body in probes:
        res = httpcheck.fetch(url, timeout=ctx.options.timeout + 3)
        first = res.hops[0] if res.hops else None
        row = {"url": url, "status": first.status if first else None, "error": res.error,
               "redirect": first.location if first else None}
        rows.append(row)
        if first is None or first.error:  # couldn't reach it at all - not evidence of a portal
            continue
        worked += 1
        expected = first.status == code and (body is None or body in res.body_sample)
        if not expected:
            intercepted.append(f"{url.split('/')[2]} returned {first.status}"
                               + (f" -> {first.location}" if first.location else ""))
    details = {"probes": rows}
    if intercepted:
        return Outcome(Status.FAIL, "captive portal or interception: " + "; ".join(intercepted), details,
                       ["Open a browser to any http:// site to get the network's login/terms page. If there's no "
                        "portal, a proxy or filter is rewriting web traffic."])
    if worked == 0:
        return Outcome(Status.WARN, "connectivity-check URLs unreachable", details)
    return Outcome(Status.PASS, "no captive portal (connectivity checks returned expected content)", details)
