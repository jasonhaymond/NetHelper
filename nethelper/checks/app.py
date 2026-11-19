"""
"Applications & services" checks: the things users actually notice.

  app.targets     the site profile's own servers (file server, RDP gateway,
                  line-of-business app): resolve, ping, required TCP ports, URLs
  app.http        web fetches with DNS/connect/TLS/first-byte timing
  app.tls         certificate trust, expiry, name match, TLS interception
  app.public_ip   the address/ISP the internet sees (third-party lookup)
  app.ntp         clock offset (TLS and Active Directory logons break when off)
  app.bandwidth   download/upload speed (and iperf3 if configured)
  app.services    mail/directory banners (SMTP, IMAP, LDAP, Kerberos)
"""

from __future__ import annotations

from urllib.parse import urlsplit

from nethelper.checks._util import ms, ping_summary
from nethelper.core import validate
from nethelper.core.context import Context
from nethelper.core.registry import check
from nethelper.core.result import Outcome, Status
from nethelper.net import bandwidth, httpcheck, icmp, ntp, publicip, tcp, tlscheck


def _cli_targets(ctx: Context) -> tuple[list[str], list[tuple[str, int]], list[str]]:
    """
    Split --target values from the command line into URLs, host:port pairs
    and bare hosts. Invalid values are skipped (the CLI validates up front).
    """
    urls, pairs, hosts = [], [], []
    for raw in ctx.options.targets:
        try:
            if "://" in raw:
                urls.append(validate.url(raw))
            elif raw.count(":") == 1:
                h, p = raw.split(":")
                pairs.append((validate.hostname(h), validate.port(p)))
            else:
                hosts.append(validate.hostname(raw))
        except validate.ValidationError:
            continue
    return urls, pairs, hosts


@check("app.targets", "Site targets", "app", modes=("quick", "full"), timeout=90)
def targets(ctx: Context) -> Outcome:
    """Tests every server in the site profile (and --target): name resolution, ping, required ports, URLs."""
    profile_targets = list(ctx.profile.targets)
    urls, pairs, hosts = _cli_targets(ctx)
    from nethelper.core.config import Target

    for u in urls:
        profile_targets.append(Target(name=u, url=u))
    for h, p in pairs:
        profile_targets.append(Target(name=f"{h}:{p}", host=h, ports=[p]))
    for h in hosts:
        profile_targets.append(Target(name=h, host=h, ports=[]))
    if not profile_targets:
        return Outcome(Status.SKIP, "no site targets configured (add [[targets]] to a profile or use --target)")
    rows, failures = [], []
    for t in profile_targets:
        row: dict = {"name": t.name, "host": t.host, "url": t.url}
        if t.host:
            stats = icmp.ping(t.host, count=3, timeout=ctx.options.timeout, interval=0.1)
            row["resolved"] = stats.address
            row["ping"] = ping_summary(stats)
            if stats.address is None:
                failures.append(f"{t.name}: name does not resolve")
            port_rows = []
            for port in t.ports:
                res = tcp.connect(t.host, port, timeout=ctx.options.timeout)
                port_rows.append({"port": port, "state": res.state, "ms": res.connect_ms})
                if res.state != "open":
                    failures.append(f"{t.name}: TCP/{port} {res.state}")
            row["ports"] = port_rows
        if t.url:
            res = httpcheck.fetch(t.url, timeout=ctx.options.timeout + 7)
            row["http"] = {"status": res.status, "error": res.error, "final_url": res.final_url}
            if not res.ok:
                failures.append(f"{t.name}: {res.error or f'HTTP {res.status}'}")
        rows.append(row)
    details = {"targets": rows}
    if failures:
        return Outcome(Status.FAIL, f"{len(failures)} problem(s): " + "; ".join(failures[:4]), details,
                       ["'does not resolve' = DNS (internal names need the internal DNS server/VPN); "
                        "'timeout' = firewall/routing; 'refused' = host up but service not running."])
    return Outcome(Status.PASS, f"all {len(rows)} target(s) reachable", details)


@check("app.http", "Web (HTTP/S)", "app", modes=("quick", "full"), timeout=60)
def http(ctx: Context) -> Outcome:
    """Fetches the profile's URLs, breaking time into DNS, connect, TLS and server response."""
    urls = list(dict.fromkeys(ctx.profile.http_urls + [t.url for t in ctx.profile.targets if t.url]))
    rows, failed, slow = [], [], []
    for url in urls:
        res = httpcheck.fetch(url, timeout=ctx.options.timeout + 7)
        last = res.hops[-1] if res.hops else None
        rows.append({"url": url, "status": res.status, "final_url": res.final_url, "error": res.error,
                     "hops": [vars(h) for h in res.hops]})
        if not res.ok:
            failed.append(f"{urlsplit(url).hostname}: {res.error or res.status}")
        elif last and last.total_ms and last.total_ms > 3000:
            slow.append(f"{urlsplit(url).hostname} {ms(last.total_ms)} (dns {ms(last.dns_ms)}, connect "
                        f"{ms(last.connect_ms)}, tls {ms(last.tls_ms)}, server {ms(last.ttfb_ms)})")
    details = {"requests": rows}
    if failed and len(failed) == len(urls):
        advice = ["No website loads. See the connectivity ladder and DNS sections."]
        if ctx.facts.proxy.get("env") or ctx.facts.proxy.get("user", {}).get("ProxyEnable"):
            advice.append("A proxy is configured; NetHelper connects directly, so a network that REQUIRES the "
                          "proxy will fail here - confirm with the browser.")
        return Outcome(Status.FAIL, "; ".join(failed), details, advice)
    if failed or slow:
        return Outcome(Status.WARN, "; ".join(failed + slow), details,
                       ["The slowest phase tells you where: DNS -> resolver, connect -> network latency/firewall, "
                        "TLS -> inspection appliance or server, server -> the website itself."])
    parts = []
    for row in rows:
        h = row["hops"][-1] if row["hops"] else {}
        parts.append(f"{urlsplit(row['url']).hostname} {row['status']} in {ms(h.get('total_ms'))}")
    return Outcome(Status.PASS, ", ".join(parts), details)


@check("app.tls", "TLS certificates", "app", modes=("full",), timeout=60)
def tls(ctx: Context) -> Outcome:
    """Verifies certificate trust, expiry and hostname for HTTPS targets, and detects TLS interception."""
    hosts: list[tuple[str, int]] = []
    for url in ctx.profile.http_urls + [t.url for t in ctx.profile.targets if t.url]:
        parts = urlsplit(url)
        if parts.scheme == "https" and parts.hostname:
            hosts.append((parts.hostname, parts.port or 443))
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        return Outcome(Status.SKIP, "no HTTPS URLs to inspect")
    rows, fails, warns, intercepted = [], [], [], []
    for host, port in hosts:
        r = tlscheck.inspect(host, port, timeout=ctx.options.timeout + 2)
        rows.append(vars(r))
        if r.error:
            fails.append(f"{host}: {r.error}")
            continue
        if r.interception:
            intercepted.append(f"{host} (issuer: {r.cert.get('issuer', {}).get('O') or r.cert.get('issuer', {}).get('CN')})")
        if not r.trusted:
            fails.append(f"{host}: {r.verify_error}")
        days = r.cert.get("days_left")
        if days is not None and days < 0:
            fails.append(f"{host}: certificate expired {-days} days ago")
        elif days is not None and days < ctx.threshold.cert_warn_days:
            warns.append(f"{host}: expires in {days} days")
    details = {"certificates": rows}
    advice = []
    if intercepted:
        advice.append("TLS interception detected: a firewall/antivirus is decrypting HTTPS and re-signing it with "
                      "its own certificate. Apps that don't trust that CA (or pin certificates) will fail.")
    if any("unable to get local issuer" in f or "self-signed" in f.lower() for f in fails):
        advice.append("Untrusted issuer: the device's trust store is missing the CA (common with interception "
                      "appliances or internal CAs) - deploy the CA certificate or fix the server's chain.")
    if any("expired" in f for f in fails) or any("not yet valid" in f for f in fails):
        advice.append("If many sites show 'expired' or 'not yet valid', check this machine's clock (see Clock check).")
    if fails:
        return Outcome(Status.FAIL, "; ".join(fails[:3]), details, advice)
    if warns or intercepted:
        return Outcome(Status.WARN, "; ".join(warns + [f"interception: {i}" for i in intercepted])[:300], details, advice)
    first = rows[0]
    return Outcome(Status.PASS, f"{len(rows)} certificate(s) valid; e.g. {hosts[0][0]}: {first['tls_version']}, "
                   f"expires in {first['cert'].get('days_left')} days", details)


@check("app.public_ip", "Public IP & ISP", "app", modes=("quick", "full"), external=True, timeout=20)
def public_ip(ctx: Context) -> Outcome:
    """The public address and network owner (ASN/ISP) the internet sees - confirms VPN vs local ISP egress."""
    try:
        info = publicip.lookup(ctx.profile.public_ip_url, timeout=ctx.options.timeout + 3)
    except (OSError, ValueError) as exc:
        return Outcome(Status.WARN, f"lookup failed: {exc}", {})
    v6 = publicip.lookup_v6(timeout=ctx.options.timeout)
    info["ipv6"] = v6
    where = ", ".join(x for x in (info.get("city"), info.get("region"), info.get("country")) if x)
    summary = f"{info.get('ip')}" + (f" - {info['org']}" if info.get("org") else "") + (f" ({where})" if where else "")
    if v6:
        summary += f"; IPv6 {v6}"
    return Outcome(Status.INFO, summary, info)


@check("app.ntp", "Clock (NTP)", "app", modes=("full",), timeout=30)
def clock(ctx: Context) -> Outcome:
    """Compares the local clock with NTP servers; skew breaks TLS, Kerberos/AD logons and MFA codes."""
    results = [ntp.query(s, timeout=ctx.options.timeout) for s in ctx.profile.ntp_servers]
    good = [r for r in results if r.offset_s is not None]
    details = {"servers": [vars(r) for r in results]}
    if not good:
        return Outcome(Status.WARN, "no NTP server answered (UDP 123 blocked?)", details,
                       ["Time sync needs outbound UDP 123, or an internal time source (domain controller)."])
    offset = sorted(r.offset_s for r in good)[len(good) // 2]  # median of answering servers
    direction = "behind" if offset > 0 else "ahead"
    summary = f"local clock {abs(offset):.2f} s {direction} ({good[0].server}, stratum {good[0].stratum})"
    if abs(offset) > 300:
        return Outcome(Status.FAIL, summary, details,
                       ["Clock is off by more than 5 minutes: Kerberos/Active Directory logons and TLS will fail. "
                        "Fix time sync (Windows: w32tm /resync; Linux: timedatectl / chrony)."])
    if abs(offset) > ctx.threshold.clock_warn_s:
        return Outcome(Status.WARN, summary, details, ["Clock drift detected - check the time sync service."])
    return Outcome(Status.PASS, summary, details)


def internet_speed(ctx: Context, latency: bool = True) -> dict:
    """
    Run the HTTPS download + upload test, measuring latency to the gateway and
    a public IP while each runs (bufferbloat). Shared by the check and the
    `speed` command. Never raises; errors are recorded in the result.
    """
    bw = ctx.profile.bandwidth
    targets = [t for t in (ctx.facts.default_gateway(), (ctx.profile.public_ping or ["1.1.1.1"])[0]) if t] if latency else []
    details: dict = {}

    def safe(fn, *args):
        try:
            return fn(*args)
        except (OSError, ValueError) as exc:  # urllib errors are OSError subclasses
            return {"error": f"{type(exc).__name__}: {exc}"}

    for direction, fn, arg1, arg2 in (("download", bandwidth.download, bw.download_url, bw.download_bytes),
                                      ("upload", bandwidth.upload, bw.upload_url, bw.upload_bytes)):
        if targets:
            result, lat = bandwidth.with_latency(targets, lambda f=fn, a=arg1, b=arg2: safe(f, a, b))
            result["latency"] = lat
            worst_inc = max((v["increase_ms"] for v in lat.values() if v["increase_ms"] is not None), default=None)
            result["bufferbloat_grade"] = bandwidth.bufferbloat_grade(worst_inc)
            result["latency_increase_ms"] = worst_inc
        else:
            result = safe(fn, arg1, arg2)
        details[direction] = result
    return details


@check("app.bandwidth", "Speed test", "app", modes=("full",), external=True, timeout=180, exclusive=True)
def speed(ctx: Context) -> Outcome:
    """Internet download/upload over HTTPS with latency-under-load (bufferbloat) grading; iperf3 if configured."""
    details = internet_speed(ctx)
    parts, advice = [], []
    for direction in ("download", "upload"):
        d = details[direction]
        if d.get("error"):
            parts.append(f"{direction} failed")
            continue
        text = f"{'down' if direction == 'download' else 'up'} {d['mbps']:g} Mb/s"
        if d.get("bufferbloat_grade"):
            text += f" (bufferbloat {d['bufferbloat_grade']}, +{d.get('latency_increase_ms')} ms under load)"
        parts.append(text)
        if d.get("bufferbloat_grade") in ("C", "D", "F"):
            advice.append(f"Latency rises by {d['latency_increase_ms']} ms while {direction}ing: the router's queues "
                          "overfill (bufferbloat), so calls and games stutter whenever the link is busy. Enable "
                          "SQM / smart queue management (fq_codel/CAKE; pfSense: Limiters with FQ-CoDel) set "
                          "slightly below the line speed.")
    bw = ctx.profile.bandwidth
    if bw.iperf_server:
        if ctx.caps.has("iperf3"):
            details["iperf_up"] = bandwidth.iperf3(bw.iperf_server, bw.iperf_seconds)
            details["iperf_down"] = bandwidth.iperf3(bw.iperf_server, bw.iperf_seconds, reverse=True)
            parts.append(f"iperf3 {details['iperf_down'].get('mbps', '?')}/{details['iperf_up'].get('mbps', '?')} Mb/s")
        else:
            details["iperf_note"] = "iperf3 server configured but iperf3 is not installed"
    ok = not details["download"].get("error")
    status = (Status.WARN if advice else Status.INFO) if ok else Status.WARN
    if not ok:
        advice.append("Speed test endpoint unreachable (blocked, offline, or a proxy is required).")
    return Outcome(status, ", ".join(parts), details, advice)


@check("app.lan_throughput", "LAN throughput", "app", modes=("full",), timeout=150, exclusive=True)
def lan_throughput(ctx: Context) -> Outcome:
    """Throughput to the configured target (a host or 'gateway') via NetHelper server, iperf3, or ICMP load."""
    from nethelper.net import throughput

    target = ctx.profile.bandwidth.throughput_target
    if not target:
        return Outcome(Status.SKIP, "no throughput target set (NETHELPER_THROUGHPUT_TARGET or [bandwidth] throughput_target)")
    host = ctx.facts.default_gateway() if target.lower() == "gateway" else target
    if not host:
        return Outcome(Status.SKIP, "throughput target 'gateway' but no default gateway")
    res = throughput.auto_test(host, port=ctx.setting("NETHELPER_THROUGHPUT_PORT", throughput.DEFAULT_PORT),
                               seconds=min(ctx.setting("NETHELPER_THROUGHPUT_SECONDS", 10), 10),
                               streams=ctx.setting("NETHELPER_THROUGHPUT_STREAMS", 1),
                               key=ctx.setting("NETHELPER_THROUGHPUT_KEY", ""),
                               iperf_port=ctx.setting("NETHELPER_IPERF_PORT", 5201))
    r = res["results"]
    if res["method"] == "icmp-load":
        i = r["icmp"]
        return Outcome(Status.INFO, f"{host}: ~{i['mbps_echoed']} Mb/s ICMP echo (approximate lower bound), "
                       f"latency under load {i['avg_ms']} ms avg / {i['max_ms']} ms max, {i['loss_pct']}% loss",
                       res, res["notes"][-1:])
    up, down = r.get("upload", {}), r.get("download", {})
    errors = [x.get("error") for x in (up, down) if x.get("error")]
    summary = f"{host} via {res['method']}: up {up.get('mbps')} Mb/s, down {down.get('mbps')} Mb/s"
    return Outcome(Status.WARN if errors else Status.INFO, summary + (f" ({'; '.join(errors)})" if errors else ""), res)


@check("app.services", "Mail & directory services", "app", modes=("full",), timeout=60)
def services(ctx: Context) -> Outcome:
    """Connects to the profile's SMTP/IMAP/LDAP/Kerberos services and reads their greeting banners."""
    svcs = ctx.profile.services
    if not svcs:
        return Outcome(Status.SKIP, "no services configured (add [[services]] to the profile)")
    rows, fails = [], []
    for s in svcs:
        port = s.port or tcp.SERVICE_PORTS.get(s.kind)
        if not port:
            continue
        res = tcp.banner(s.host, port, s.kind, timeout=ctx.options.timeout + 2)
        rows.append({"name": s.name, "host": s.host, "port": port, "kind": s.kind, "state": res.state,
                     "banner": res.banner, "error": res.error})
        if res.state != "open" or res.error:
            fails.append(f"{s.name} ({s.host}:{port}) {res.error or res.state}")
    details = {"services": rows}
    if fails:
        return Outcome(Status.FAIL, "; ".join(fails[:3]), details)
    return Outcome(Status.PASS, f"all {len(rows)} service(s) answering", details)
