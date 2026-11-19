"""
Site profiles: per-client/per-site settings loaded from a TOML file.

A profile tells NetHelper what "normal" looks like at a site and what matters
there: which servers to test (file server, RDP gateway, line-of-business app),
which VLAN and subnet a port should be on, which DHCP servers are legitimate,
alert thresholds, and so on. Without a profile, sensible public defaults are
used so every check still works anywhere.

TOML is a simple "key = value" config format with [sections]; Python reads it
with the built-in `tomllib` module. See profiles/example.toml for every option,
fully commented.

Profile lookup order:
  1. --profile PATH on the command line
  2. NETHELPER_PROFILE (environment variable, or the setting in .env)
  3. <data dir>/profile.toml (see paths.py)
  4. built-in defaults (no file)

Defaults come from the .env settings (settings.py) - speed-test URLs, public
IP service, external lookups, LLDP wait, throughput target - and a profile
that sets the same values overrides them for that site.

SECURITY: a profile is trusted local configuration, but every host, port, URL
and network in it is still validated (validate.py) before use, so a malformed
or tampered profile is rejected with a clear message instead of being acted on.
"""

from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nethelper.core import validate
from nethelper.core.paths import data_dir


@dataclass
class Target:
    """
    A server or service to test at this site.
      name  - label shown in output ("File server")
      host  - hostname or IP to ping/connect to
      ports - TCP ports that must be reachable (e.g. [445] for SMB)
      url   - optional web address to fetch (HTTP/TLS checks)
    """

    name: str
    host: str | None = None
    ports: list[int] = field(default_factory=list)
    url: str | None = None


@dataclass
class Service:
    """
    A mail / directory service to banner-check.
      kind - smtp, smtps, submission, imap, imaps, pop3, ldap, ldaps, kerberos, tcp
    """

    name: str
    host: str
    kind: str
    port: int | None = None


@dataclass
class VlanSpec:
    """
    What one VLAN should look like: its name, IP subnet, gateway, and hosts
    on it that should be reachable from here (tests inter-VLAN routing/ACLs).
    """

    vlan_id: int
    name: str = ""
    subnet: str | None = None
    gateway: str | None = None
    targets: list[str] = field(default_factory=list)


@dataclass
class Expected:
    """
    Values this site *should* have. Each is optional; when set, the matching
    check compares reality against it and FAILs on a mismatch.
    """

    vlan: int | None = None              # access/native VLAN this port should be in
    voice_vlan: int | None = None        # voice VLAN advertised by the switch
    subnet: str | None = None            # e.g. "10.0.20.0/24"
    gateway: str | None = None           # default gateway IP
    gateway_mac: str | None = None       # pins gateway MAC to detect ARP spoofing/swap
    dns_servers: list[str] = field(default_factory=list)
    dhcp_servers: list[str] = field(default_factory=list)  # anything else = rogue
    switch_name: str | None = None       # LLDP/CDP system name of the access switch
    switch_port: str | None = None       # e.g. "Gi1/0/12"
    min_link_mbps: int | None = None     # e.g. 1000 - warns on a 100 Mb/s negotiation


@dataclass
class Thresholds:
    """Limits above/below which a check reports WARN instead of PASS."""

    latency_warn_ms: float = 100.0
    loss_warn_pct: float = 2.0
    jitter_warn_ms: float = 30.0
    dns_slow_ms: float = 300.0
    cert_warn_days: int = 21
    wifi_warn_dbm: int = -70
    wifi_warn_pct: int = 40
    clock_warn_s: float = 2.0
    mtu_warn: int = 1400


@dataclass
class Bandwidth:
    """Speed-test settings. URLs must serve/accept arbitrary bytes over HTTPS."""

    download_url: str = "https://speed.cloudflare.com/__down?bytes={bytes}"
    upload_url: str = "https://speed.cloudflare.com/__up"
    download_bytes: int = 10_000_000
    upload_bytes: int = 2_000_000
    iperf_server: str | None = None
    iperf_seconds: int = 5
    throughput_target: str | None = None  # host or "gateway" for the LAN throughput check


@dataclass
class Profile:
    """
    The complete, validated site profile. Every field has a default, so
    Profile() alone is a working "generic internet" profile.
    """

    site_name: str = ""
    source: str = "built-in defaults"
    targets: list[Target] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    public_ping: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    public_hostname: str = "www.cloudflare.com"
    trace_target: str = "1.1.1.1"
    dns_names: list[str] = field(default_factory=lambda: ["www.google.com", "www.microsoft.com"])
    dns_domains: list[str] = field(default_factory=lambda: ["google.com"])
    public_resolvers: dict[str, str] = field(default_factory=lambda: {
        "Cloudflare": "1.1.1.1", "Google": "8.8.8.8", "Quad9": "9.9.9.9"})
    extra_resolvers: list[str] = field(default_factory=list)
    http_urls: list[str] = field(default_factory=lambda: [
        "https://www.cloudflare.com/", "https://www.microsoft.com/"])
    ntp_servers: list[str] = field(default_factory=lambda: ["pool.ntp.org", "time.windows.com"])
    external_lookups: bool = True
    public_ip_url: str = "https://ipinfo.io/json"
    bandwidth: Bandwidth = field(default_factory=Bandwidth)
    expected: Expected = field(default_factory=Expected)
    vlans: dict[int, VlanSpec] = field(default_factory=dict)
    thresholds: Thresholds = field(default_factory=Thresholds)
    monitor_interval: float = 5.0
    monitor_targets: list[str] = field(default_factory=list)
    switchport_wait: int = 35
    warnings: list[str] = field(default_factory=list)


class ProfileError(ValueError):
    """Raised when a profile file can't be read or contains invalid values."""


def _str_list(raw: Any, key: str, check=None) -> list[str]:
    """Coerce a TOML value to a list of strings, validating each with `check`."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raise ProfileError(f"{key} must be a list")
    out = []
    for item in raw:
        try:
            out.append(check(str(item)) if check else str(item))
        except validate.ValidationError as exc:
            raise ProfileError(f"{key}: {exc}") from exc
    return out


def _opt(raw: dict, key: str, check, label: str):
    """Validate an optional single value from a TOML table."""
    if raw.get(key) in (None, ""):
        return None
    try:
        return check(raw[key])
    except (validate.ValidationError, ValueError, TypeError) as exc:
        raise ProfileError(f"{label}.{key}: {exc}") from exc


def _network(value: str) -> str:
    """Validate a CIDR network string like 10.0.20.0/24 and return it normalised."""
    try:
        return str(ipaddress.ip_network(str(value), strict=False))
    except ValueError as exc:
        raise validate.ValidationError(f"not a valid network: {value!r}") from exc


def _mac(value: str) -> str:
    """Validate a MAC address in any common notation and return aa:bb:cc:dd:ee:ff."""
    hexes = "".join(c for c in str(value) if c.lower() in "0123456789abcdef")
    if len(hexes) != 12:
        raise validate.ValidationError(f"not a valid MAC address: {value!r}")
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).lower()


def _vlan_id(value: Any) -> int:
    """Validate an 802.1Q VLAN id (1-4094)."""
    number = int(value)
    if not 1 <= number <= 4094:
        raise validate.ValidationError(f"VLAN id out of range 1-4094: {number}")
    return number


def find_profile_path(explicit: str | None, settings=None) -> Path | None:
    """Return the profile file to use (see lookup order in the module doc), or None."""
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("NETHELPER_PROFILE") or (settings.get("NETHELPER_PROFILE") if settings else "")
    if env:
        return Path(env).expanduser()
    default = data_dir() / "profile.toml"
    return default if default.exists() else None


def base_from_settings(settings) -> Profile:
    """
    A default Profile whose app-level values come from the .env settings
    (speed-test URLs/sizes, public-IP service, external lookups, LLDP wait,
    throughput target). A site profile loaded on top can still override them.
    """
    p = Profile()
    if settings is None:
        return p
    p.external_lookups = settings.get("NETHELPER_EXTERNAL_LOOKUPS")
    p.public_ip_url = settings.get("NETHELPER_PUBLIC_IP_URL") or p.public_ip_url
    p.switchport_wait = settings.get("NETHELPER_SWITCHPORT_WAIT")
    p.bandwidth.download_url = settings.get("NETHELPER_SPEEDTEST_DOWNLOAD_URL") or p.bandwidth.download_url
    p.bandwidth.upload_url = settings.get("NETHELPER_SPEEDTEST_UPLOAD_URL") or p.bandwidth.upload_url
    p.bandwidth.download_bytes = settings.get("NETHELPER_SPEEDTEST_DOWNLOAD_BYTES")
    p.bandwidth.upload_bytes = settings.get("NETHELPER_SPEEDTEST_UPLOAD_BYTES")
    p.bandwidth.throughput_target = settings.get("NETHELPER_THROUGHPUT_TARGET") or None
    return p


def load_profile(explicit: str | None = None, settings=None) -> Profile:
    """
    Load and validate the active profile, on top of the .env-derived defaults.

    Returns a Profile (defaults if no file exists). Raises ProfileError with
    a readable message if the file is missing (when explicitly requested),
    isn't valid TOML, or has invalid values.
    """
    base = base_from_settings(settings)
    path = find_profile_path(explicit, settings)
    if path is None:
        return base
    if not path.is_file():
        raise ProfileError(f"profile not found: {path}")
    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ProfileError(f"{path}: invalid TOML - {exc}") from exc
    except OSError as exc:
        raise ProfileError(f"cannot read profile {path}: {exc}") from exc
    profile = parse_profile(raw, base)
    profile.source = str(path)
    return profile


def parse_profile(raw: dict[str, Any], base: Profile | None = None) -> Profile:
    """
    Turn the dictionary read from TOML into a validated Profile, starting
    from `base` (defaults, possibly from .env settings).
    Unknown top-level sections are reported in profile.warnings (likely typos)
    rather than silently ignored.
    """
    if not isinstance(raw, dict):
        raise ProfileError("profile must be a TOML table")
    p = base or Profile()
    known = {"site", "targets", "services", "internet", "dns", "http", "ntp", "public",
             "bandwidth", "expected", "vlans", "thresholds", "monitor", "switchport"}
    for key in raw:
        if key not in known:
            p.warnings.append(f"unknown profile section [{key}] ignored")

    site = raw.get("site", {})
    p.site_name = validate.safe_text(site.get("name", ""), 100)

    # [[targets]] - servers/services that matter at this site.
    for i, t in enumerate(raw.get("targets", [])):
        label = f"targets[{i}]"
        name = validate.safe_text(t.get("name", f"Target {i + 1}"), 80)
        host = _opt(t, "host", validate.hostname, label)
        url = _opt(t, "url", validate.url, label)
        try:
            ports = [validate.port(x) for x in t.get("ports", [])]
        except validate.ValidationError as exc:
            raise ProfileError(f"{label}.ports: {exc}") from exc
        if not host and not url:
            raise ProfileError(f"{label} needs a host or a url")
        p.targets.append(Target(name=name, host=host, ports=ports, url=url))

    # [[services]] - mail/directory banner checks.
    allowed_kinds = {"smtp", "smtps", "submission", "imap", "imaps", "pop3", "ldap", "ldaps", "kerberos", "tcp"}
    for i, s in enumerate(raw.get("services", [])):
        label = f"services[{i}]"
        kind = str(s.get("kind", "tcp")).lower()
        if kind not in allowed_kinds:
            raise ProfileError(f"{label}.kind must be one of {sorted(allowed_kinds)}")
        host = _opt(s, "host", validate.hostname, label)
        if not host:
            raise ProfileError(f"{label}.host is required")
        p.services.append(Service(name=validate.safe_text(s.get("name", kind), 80), host=host, kind=kind,
                                  port=_opt(s, "port", validate.port, label)))

    internet = raw.get("internet", {})
    if "ping" in internet:
        p.public_ping = _str_list(internet["ping"], "internet.ping", validate.hostname)
    if internet.get("hostname"):
        p.public_hostname = validate.hostname(internet["hostname"])
    if internet.get("trace_target"):
        p.trace_target = validate.hostname(internet["trace_target"])

    dns = raw.get("dns", {})
    if "names" in dns:
        p.dns_names = _str_list(dns["names"], "dns.names", validate.hostname)
    if "domains" in dns:
        p.dns_domains = _str_list(dns["domains"], "dns.domains", validate.hostname)
    if "extra_resolvers" in dns:
        p.extra_resolvers = _str_list(dns["extra_resolvers"], "dns.extra_resolvers", validate.hostname)
    if "public_resolvers" in dns:
        p.public_resolvers = {validate.safe_text(k, 40): validate.hostname(v)
                              for k, v in dict(dns["public_resolvers"]).items()}

    http = raw.get("http", {})
    if "urls" in http:
        p.http_urls = _str_list(http["urls"], "http.urls", validate.url)

    ntp = raw.get("ntp", {})
    if "servers" in ntp:
        p.ntp_servers = _str_list(ntp["servers"], "ntp.servers", validate.hostname)

    public = raw.get("public", {})
    if "external_lookups" in public:
        p.external_lookups = bool(public["external_lookups"])
    if public.get("ip_lookup_url"):
        p.public_ip_url = validate.url(public["ip_lookup_url"])

    bw = raw.get("bandwidth", {})
    if bw.get("download_url"):
        # The URL may contain a "{bytes}" placeholder filled in at test time;
        # validate it with a dummy number, but store the template unchanged.
        validate.url(bw["download_url"].replace("{bytes}", "1"))
        p.bandwidth.download_url = bw["download_url"]
    if bw.get("upload_url"):
        p.bandwidth.upload_url = validate.url(bw["upload_url"])
    for key in ("download_bytes", "upload_bytes", "iperf_seconds"):
        if key in bw:
            value = int(bw[key])
            if value < 0 or value > 1_000_000_000:
                raise ProfileError(f"bandwidth.{key} out of range")
            setattr(p.bandwidth, key, value)
    p.bandwidth.iperf_server = _opt(bw, "iperf_server", validate.hostname, "bandwidth") or p.bandwidth.iperf_server
    if bw.get("throughput_target"):
        target = str(bw["throughput_target"]).strip()
        p.bandwidth.throughput_target = target if target.lower() == "gateway" else _opt(
            bw, "throughput_target", validate.hostname, "bandwidth")

    exp = raw.get("expected", {})
    e = p.expected
    e.vlan = _opt(exp, "vlan", _vlan_id, "expected")
    e.voice_vlan = _opt(exp, "voice_vlan", _vlan_id, "expected")
    e.subnet = _opt(exp, "subnet", _network, "expected")
    e.gateway = _opt(exp, "gateway", validate.hostname, "expected")
    e.gateway_mac = _opt(exp, "gateway_mac", _mac, "expected")
    e.dns_servers = _str_list(exp.get("dns_servers"), "expected.dns_servers", validate.hostname)
    e.dhcp_servers = _str_list(exp.get("dhcp_servers"), "expected.dhcp_servers", validate.hostname)
    e.switch_name = _opt(exp, "switch_name", lambda v: validate.safe_text(v, 100), "expected")
    e.switch_port = _opt(exp, "switch_port", lambda v: validate.safe_text(v, 100), "expected")
    e.min_link_mbps = _opt(exp, "min_link_mbps", int, "expected")

    # [vlans.<id>] tables, e.g. [vlans.20] name = "Data" subnet = "10.0.20.0/24"
    for key, spec in raw.get("vlans", {}).items():
        try:
            vid = _vlan_id(key)
        except (validate.ValidationError, ValueError) as exc:
            raise ProfileError(f"vlans.{key}: {exc}") from exc
        p.vlans[vid] = VlanSpec(
            vlan_id=vid,
            name=validate.safe_text(spec.get("name", ""), 60),
            subnet=_opt(spec, "subnet", _network, f"vlans.{key}"),
            gateway=_opt(spec, "gateway", validate.hostname, f"vlans.{key}"),
            targets=_str_list(spec.get("targets"), f"vlans.{key}.targets", validate.hostname),
        )

    th = raw.get("thresholds", {})
    for key in Thresholds.__dataclass_fields__:
        if key in th:
            current = getattr(p.thresholds, key)
            try:
                setattr(p.thresholds, key, type(current)(th[key]))
            except (TypeError, ValueError) as exc:
                raise ProfileError(f"thresholds.{key}: {exc}") from exc

    mon = raw.get("monitor", {})
    if "interval" in mon:
        p.monitor_interval = max(1.0, float(mon["interval"]))
    if "targets" in mon:
        p.monitor_targets = _str_list(mon["targets"], "monitor.targets", validate.hostname)

    sw = raw.get("switchport", {})
    if "wait" in sw:
        p.switchport_wait = max(5, min(180, int(sw["wait"])))
    return p
