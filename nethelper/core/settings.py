"""
Application settings stored in a `.env` file, editable from the menu or with
`nethelper config ...`.

What goes where:
  .env (this module)  - how NetHelper itself behaves on THIS machine: default
                        timeout, interfaces, log retention, colour, speed-test
                        URLs, throughput server/port/key, folders...
  site profile (TOML) - what a particular SITE should look like: targets,
                        expected VLAN/subnet, thresholds (see config.py)

Precedence, highest first:
  1. command-line flags          (e.g. --timeout 5)
  2. the site profile            (for the few keys a profile can also set)
  3. process environment vars    (e.g. set NETHELPER_TIMEOUT=5 in a script)
  4. the .env file
  5. built-in defaults (SPECS below)

File location: <data dir>/.env (see paths.py), or a path given with
--env FILE / the NETHELPER_ENV environment variable.

Format: one KEY=VALUE per line; '#' starts a comment; values may be quoted.
Every key is documented in the repo's .env.example, which is generated from
SPECS (a test fails if the two drift apart).

SECURITY: settings marked secret (the throughput key, destination
password/token, S3 secret key, SMTP password) are never printed in full
(shown as '********'), never written to logs (logsetup masks it), and the .env
file is created readable only by the current user where the OS supports it.
Values are validated on load; an invalid value is reported and the default
used instead, so a bad edit can't stop NetHelper from starting.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from nethelper.core import validate
from nethelper.core.paths import data_dir


def _bool(v: str) -> bool:
    """Parse true/false style text."""
    text = str(v).strip().lower()
    if text in ("1", "true", "yes", "on", "y"):
        return True
    if text in ("0", "false", "no", "off", "n", ""):
        return False
    raise ValueError(f"expected true/false, got {v!r}")


def _int_range(lo: int, hi: int) -> Callable[[str], int]:
    """Build a parser for an integer that must be within [lo, hi]."""
    def parse(v: str) -> int:
        n = int(str(v).strip())
        if not lo <= n <= hi:
            raise ValueError(f"must be between {lo} and {hi}")
        return n
    return parse


def _float_range(lo: float, hi: float) -> Callable[[str], float]:
    """Build a parser for a decimal number within [lo, hi]."""
    def parse(v: str) -> float:
        n = float(str(v).strip())
        if not lo <= n <= hi:
            raise ValueError(f"must be between {lo} and {hi}")
        return n
    return parse


def _choice(*options: str) -> Callable[[str], str]:
    """Build a parser accepting one of a fixed set of words."""
    def parse(v: str) -> str:
        text = str(v).strip().lower()
        if text not in options:
            raise ValueError(f"must be one of: {', '.join(options)}")
        return text
    return parse


def _text(v: str) -> str:
    """Free text (control characters stripped)."""
    return validate.safe_text(str(v).strip(), 500)


def _path(v: str) -> str:
    """A filesystem path; empty means 'use the default location'."""
    text = str(v).strip()
    if any(ord(c) < 32 for c in text):
        raise ValueError("path contains control characters")
    return text


def _url_or_empty(v: str) -> str:
    """An http(s) URL (may contain a {bytes} placeholder) or empty."""
    text = str(v).strip()
    if text:
        validate.url(text.replace("{bytes}", "1"))
    return text


def _host_or_empty(v: str) -> str:
    """A hostname/IP, the word 'gateway', or empty."""
    text = str(v).strip()
    if text and text.lower() != "gateway":
        validate.hostname(text)
    return text


def _interfaces(v: str) -> str:
    """Comma-separated interface names, 'all', or empty."""
    text = str(v).strip()
    for part in [p.strip() for p in text.split(",") if p.strip()]:
        if part.lower() != "all":
            validate.interface(part)
    return text


def _destinations(v: str) -> str:
    """';'/','-separated destination list - each entry syntax-checked (security policy applies at use)."""
    from nethelper.core import destinations

    text = str(v).strip()
    for d in [x.strip() for x in re.split(r"\s*[;,]\s*", text) if x.strip()]:
        try:
            destinations.parse(d, allow_insecure=True)
        except destinations.DestinationError as exc:
            raise ValueError(str(exc)) from exc
    return text


def _url_https_or_empty(v: str) -> str:
    """An http(s) base URL such as an S3 endpoint, or empty (http:// is only used if insecure is allowed)."""
    text = str(v).strip().rstrip("/")
    if text:
        if not text.lower().startswith(("https://", "http://")):
            raise ValueError("must start with https:// (e.g. https://s3.eu-central-003.backblazeb2.com)")
        validate.url(text)
    return text


def _region(v: str) -> str:
    """An S3 region name. Regex: lowercase letters, digits and hyphens, e.g. "us-east-1", "eu-central-003"."""
    text = str(v).strip().lower()
    if not re.fullmatch(r"[a-z0-9-]{2,40}", text):
        raise ValueError("expected a region name like us-east-1")
    return text


def _server_port_or_empty(v: str) -> str:
    """A server name/IP with an optional :port (smtp.example.com, smtp.example.com:2525), or empty."""
    text = str(v).strip()
    if text:
        host, _, port = text.rpartition(":") if text.count(":") == 1 else (text, "", "")
        validate.hostname(host)
        if port and not (port.isdigit() and 1 <= int(port) <= 65535):
            raise ValueError("port must be 1-65535")
    return text


def _email_or_empty(v: str) -> str:
    """A plain email address (no display name), or empty."""
    from nethelper.core import destinations

    text = str(v).strip()
    if text and not destinations._EMAIL.fullmatch(text):
        raise ValueError("expected an address like nethelper@example.com")
    return text


def _categories(v: str) -> str:
    """Comma list of output categories."""
    allowed = {"reports", "captures", "logs", "results"}
    items = [x.strip().lower() for x in str(v).split(",") if x.strip()]
    bad = [x for x in items if x not in allowed]
    if bad:
        raise ValueError(f"unknown output type(s) {', '.join(bad)}; use reports, captures, logs, results")
    return ",".join(items)


@dataclass(frozen=True)
class Spec:
    """
    One setting.
      key       - the variable name in .env
      default   - built-in default (as text, exactly as it would appear in .env)
      parse     - validator/converter; raises ValueError on bad input
      help      - one-line description shown in the menu and .env.example
      group     - heading used to organise the menu and .env.example
      secret    - never displayed or logged in full
    """

    key: str
    default: str
    parse: Callable[[str], Any]
    help: str
    group: str
    secret: bool = False


SPECS: list[Spec] = [
    # General behaviour
    Spec("NETHELPER_PROFILE", "", _path, "Default site profile (.toml) used when --profile isn't given", "General"),
    Spec("NETHELPER_TIMEOUT", "3", _float_range(0.5, 30), "Per-probe network timeout in seconds", "General"),
    Spec("NETHELPER_PING_COUNT", "10", _int_range(1, 1000), "Pings per latency test", "General"),
    Spec("NETHELPER_INTERFACES", "", _interfaces, "Default interface(s): comma list, 'all', or empty for automatic", "General"),
    Spec("NETHELPER_EXTERNAL_LOOKUPS", "true", _bool, "Allow third-party lookups (public IP, internet speed test)", "General"),
    Spec("NETHELPER_COLOR", "auto", _choice("auto", "always", "never"), "Coloured output: auto, always or never", "General"),
    Spec("NETHELPER_HIDE_LIMITED", "false", _bool, "Hide checks that need elevation instead of listing them", "General"),
    Spec("NETHELPER_SWITCHPORT_WAIT", "35", _int_range(5, 180), "Seconds to listen for LLDP/CDP (65 for CDP-only switches)", "General"),
    # Logging
    Spec("NETHELPER_LOG_LEVEL", "debug", _choice("debug", "info", "warning"), "Detail level written to each run's log file", "Logging"),
    Spec("NETHELPER_LOG_KEEP", "40", _int_range(1, 10000), "Number of run logs to keep (oldest deleted first)", "Logging"),
    Spec("NETHELPER_LOG_DIR", "", _path, "Folder for run logs (empty = <data dir>/logs)", "Logging"),
    # Output locations
    Spec("NETHELPER_REPORT_DIR", "", _path, "Folder where menu-generated reports are saved (empty = current folder)", "Folders"),
    Spec("NETHELPER_CAPTURE_DIR", "", _path, "Folder for packet captures (empty = <data dir>/captures)", "Folders"),
    # Internet speed test
    Spec("NETHELPER_SPEEDTEST_DOWNLOAD_URL", "https://speed.cloudflare.com/__down?bytes={bytes}", _url_or_empty,
         "Download test URL ({bytes} is replaced with the size)", "Speed test"),
    Spec("NETHELPER_SPEEDTEST_UPLOAD_URL", "https://speed.cloudflare.com/__up", _url_or_empty,
         "Upload test URL (receives a POST)", "Speed test"),
    Spec("NETHELPER_SPEEDTEST_DOWNLOAD_BYTES", "25000000", _int_range(100_000, 1_000_000_000),
         "Bytes to download in the speed test", "Speed test"),
    Spec("NETHELPER_SPEEDTEST_UPLOAD_BYTES", "5000000", _int_range(100_000, 500_000_000),
         "Bytes to upload in the speed test", "Speed test"),
    Spec("NETHELPER_PUBLIC_IP_URL", "https://ipinfo.io/json", _url_or_empty, "Public IP / ISP lookup service", "Speed test"),
    # LAN throughput
    Spec("NETHELPER_THROUGHPUT_TARGET", "", _host_or_empty,
         "Default throughput target for full runs: a host, 'gateway', or empty to skip", "Throughput"),
    Spec("NETHELPER_THROUGHPUT_PORT", "5202", _int_range(1, 65535), "TCP/UDP port for 'nethelper serve' / 'throughput'", "Throughput"),
    Spec("NETHELPER_THROUGHPUT_SECONDS", "10", _int_range(1, 60), "Seconds per throughput test direction", "Throughput"),
    Spec("NETHELPER_THROUGHPUT_STREAMS", "1", _int_range(1, 8), "Parallel TCP streams per throughput test", "Throughput"),
    Spec("NETHELPER_THROUGHPUT_KEY", "", _text, "Shared secret required by 'nethelper serve' (empty = no key)", "Throughput", secret=True),
    Spec("NETHELPER_IPERF_PORT", "5201", _int_range(1, 65535), "Port of iperf3 servers (used as a fallback)", "Throughput"),
    # Output destinations (copies of reports/captures/logs/results)
    Spec("NETHELPER_OUTPUT_DESTINATIONS", "", _destinations,
         "Where to copy outputs after each run, separated by ';' - folder, \\\\server\\share, smb://, sftp://, "
         "webdavs://, https://, ftps://, s3://, mailto:, syslog+tls:// (empty = keep local only)", "Output destinations"),
    Spec("NETHELPER_OUTPUT_INCLUDE", "reports,captures,logs,results", _categories,
         "Which outputs to copy: any of reports, captures, logs, results", "Output destinations"),
    Spec("NETHELPER_OUTPUT_SUBDIR", "{host}/{date}", _text,
         "Sub-folder at each destination ({host}, {date}, {user} are filled in)", "Output destinations"),
    Spec("NETHELPER_SAVE_RESULTS", "false", _bool,
         "Always save each diagnostic's results as JSON in the results folder", "Output destinations"),
    Spec("NETHELPER_RESULTS_DIR", "", _path, "Folder for saved results JSON (empty = <data dir>/results)", "Output destinations"),
    Spec("NETHELPER_DEST_PASSWORD", "", _text,
         "Password / app password for WebDAV, HTTPS (Basic), FTPS or SMB (smbclient) destinations", "Output destinations",
         secret=True),
    Spec("NETHELPER_DEST_TOKEN", "", _text, "Bearer token for HTTPS upload destinations", "Output destinations", secret=True),
    Spec("NETHELPER_HTTP_UPLOAD_METHOD", "put", _choice("put", "post"), "HTTP method for https:// destinations", "Output destinations"),
    Spec("NETHELPER_SSH_KEY", "", _path, "SSH private key for sftp:// / scp:// (empty = ssh-agent/default keys)", "Output destinations"),
    Spec("NETHELPER_SSH_ACCEPT_NEW_HOSTKEYS", "false", _bool,
         "Trust an SSH server's host key on first connection (otherwise it must already be in known_hosts)",
         "Output destinations"),
    Spec("NETHELPER_SSH_KNOWN_HOSTS", "", _path,
         "known_hosts file for sftp:// destinations (empty = your normal ~/.ssh/known_hosts)", "Output destinations"),
    Spec("NETHELPER_DEST_ALLOW_INSECURE", "false", _bool,
         "Allow unencrypted destinations: http://, webdav://, ftp://, syslog:// (UDP), syslog+tcp://, an http:// S3 "
         "endpoint, SMTP security 'none' (not recommended)", "Output destinations"),
    Spec("NETHELPER_DEST_CA_FILE", "", _path,
         "Extra CA certificate file (PEM) trusted for destinations that use an internal/company CA", "Output destinations"),
    # S3-compatible object storage (s3://bucket/prefix destinations)
    Spec("NETHELPER_S3_ENDPOINT", "", _url_https_or_empty,
         "S3 service URL (empty = AWS; e.g. https://minio.example.com:9000, https://s3.us-west-004.backblazeb2.com)",
         "S3 storage"),
    Spec("NETHELPER_S3_REGION", "us-east-1", _region, "S3 region of the bucket (MinIO: usually us-east-1)", "S3 storage"),
    Spec("NETHELPER_S3_ACCESS_KEY", "", _text, "S3 access key ID (empty = AWS_ACCESS_KEY_ID environment variable)",
         "S3 storage"),
    Spec("NETHELPER_S3_SECRET_KEY", "", _text, "S3 secret access key (empty = AWS_SECRET_ACCESS_KEY environment variable)",
         "S3 storage", secret=True),
    Spec("NETHELPER_S3_ADDRESSING", "auto", _choice("auto", "path", "virtual"),
         "Bucket addressing: auto (virtual-host for AWS, path for others), path or virtual", "S3 storage"),
    # Email (mailto: destinations)
    Spec("NETHELPER_SMTP_SERVER", "", _server_port_or_empty,
         "SMTP server for mailto: destinations, optionally with :port (e.g. smtp.office365.com)", "Email"),
    Spec("NETHELPER_SMTP_SECURITY", "starttls", _choice("starttls", "ssl", "none"),
         "starttls (port 587), ssl (port 465) or none (port 25, needs NETHELPER_DEST_ALLOW_INSECURE)", "Email"),
    Spec("NETHELPER_SMTP_USER", "", _text, "SMTP login name (empty = send without logging in, e.g. an internal relay)", "Email"),
    Spec("NETHELPER_SMTP_PASSWORD", "", _text, "SMTP password / app password", "Email", secret=True),
    Spec("NETHELPER_SMTP_FROM", "", _email_or_empty,
         "Sender address (empty = the SMTP login if it is an address, else nethelper@<computer name>)", "Email"),
    Spec("NETHELPER_EMAIL_MAX_MB", "20", _int_range(1, 100),
         "Largest total attachment size per email in MB; bigger files are listed but not attached", "Email"),
    # Syslog / SIEM (syslog:// destinations)
    Spec("NETHELPER_SYSLOG_FACILITY", "local0",
         _choice("kern", "user", "daemon", "auth", "local0", "local1", "local2", "local3", "local4", "local5", "local6",
                 "local7"),
         "Syslog facility for events sent to syslog destinations", "Syslog"),
    Spec("NETHELPER_SYSLOG_FORMAT", "rfc5424", _choice("rfc5424", "json"),
         "rfc5424 (key=value structured data) or json (message body is a JSON object)", "Syslog"),
]
SPEC_BY_KEY = {s.key: s for s in SPECS}
MASK = "********"

# Regex: one KEY=VALUE line, with optional "export " prefix and surrounding spaces.
# Matches: NETHELPER_TIMEOUT=5   export NETHELPER_COLOR = "never"
_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


class Settings:
    """
    Loaded settings: typed values plus where each one came from
    ("default", ".env", "environment"), and any problems found while loading.
    """

    def __init__(self, path: Path):
        self.path = path
        self.values: dict[str, Any] = {}
        self.raw: dict[str, str] = {}
        self.source: dict[str, str] = {}
        self.problems: list[str] = []

    def get(self, key: str) -> Any:
        """Typed value of a setting (KeyError for unknown keys is a programming error)."""
        return self.values[key]

    def display(self, key: str) -> str:
        """Value as text for display - secrets masked."""
        raw = self.raw.get(key, "")
        if SPEC_BY_KEY[key].secret and raw:
            return MASK
        return raw

    def secrets(self) -> list[str]:
        """Secret values currently set (so the logger can mask them)."""
        return [self.raw[s.key] for s in SPECS if s.secret and self.raw.get(s.key)]


def env_path(explicit: str | None = None) -> Path:
    """Where the .env file lives: --env, then NETHELPER_ENV, then <data dir>/.env."""
    if explicit:
        return Path(explicit)
    if os.environ.get("NETHELPER_ENV"):
        return Path(os.environ["NETHELPER_ENV"])
    return data_dir() / ".env"


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a .env file into {KEY: raw text}. Missing file -> empty dict."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (FileNotFoundError, IsADirectoryError):
        return out
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]  # strip matching quotes
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()  # trailing comment on unquoted value
        out[key] = value
    return out


def load(explicit: str | None = None) -> Settings:
    """Load settings from defaults, the .env file and the environment (see precedence above)."""
    path = env_path(explicit)
    s = Settings(path)
    try:
        file_values = read_env_file(path)
    except OSError as exc:
        file_values = {}
        s.problems.append(f"could not read {path}: {exc}")
    for key in file_values:
        if key.startswith("NETHELPER_") and key not in SPEC_BY_KEY and key not in ("NETHELPER_HOME", "NETHELPER_ENV"):
            s.problems.append(f"unknown setting {key} in {path.name} (ignored)")
    for spec in SPECS:
        raw, source = spec.default, "default"
        if spec.key in file_values:
            raw, source = file_values[spec.key], ".env"
        if spec.key in os.environ:
            raw, source = os.environ[spec.key], "environment"
        try:
            value = spec.parse(raw)
        except (ValueError, validate.ValidationError) as exc:
            s.problems.append(f"{spec.key}={'(secret)' if spec.secret else raw!r} is invalid ({exc}); using default")
            raw, source = spec.default, "default"
            value = spec.parse(raw)
        s.values[spec.key], s.raw[spec.key], s.source[spec.key] = value, raw, source
    return s


def _quote(value: str) -> str:
    """Quote a value for .env if it contains spaces, '#' or quotes."""
    if value == "" or re.fullmatch(r"[A-Za-z0-9_./:\\{}@,=?+-]+", value):
        return value
    return '"' + value.replace('"', "'") + '"'


def render(values: dict[str, str], header: str = "NetHelper settings") -> str:
    """Produce .env text with every setting, grouped and commented."""
    lines = [f"# {header}", "#",
             "# One KEY=VALUE per line. Edit with 'nethelper config' or any text editor.",
             "# Empty value = built-in default/automatic. Command-line flags override these.", ""]
    group = None
    for spec in SPECS:
        if spec.group != group:
            group = spec.group
            lines += ["", f"# --- {group} " + "-" * max(0, 60 - len(group))]
        lines.append(f"# {spec.help}" + (" [SECRET]" if spec.secret else "") + f" (default: {spec.default or 'empty'})")
        lines.append(f"{spec.key}={_quote(values.get(spec.key, spec.default))}")
    return "\n".join(lines) + "\n"


def validate_value(key: str, value: str) -> str:
    """Check one proposed value; returns it normalised or raises ValueError with a readable reason."""
    if key not in SPEC_BY_KEY:
        raise ValueError(f"unknown setting {key}; run 'nethelper config show' for the list")
    try:
        SPEC_BY_KEY[key].parse(value)
    except validate.ValidationError as exc:
        raise ValueError(str(exc)) from exc
    return value.strip()


def save(path: Path, values: dict[str, str]) -> Path | None:
    """
    Write a complete .env file. The previous file (if any) is kept as .env.bak.
    The new file is written to a temp file then swapped in, so a crash mid-write
    never leaves a half-written config. Returns the backup path, if one was made.
    """
    for key, value in values.items():
        validate_value(key, value)
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if path.exists():
        backup = path.with_name(path.name + ".bak")
        backup.write_bytes(path.read_bytes())
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(render(values), encoding="utf-8")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600: owner-only (no effect beyond read-only flag on Windows)
    except OSError:
        pass
    tmp.replace(path)
    return backup


def current_file_values(path: Path) -> dict[str, str]:
    """Values for every known key: what the file has, else the default (used before editing)."""
    existing = read_env_file(path)
    return {s.key: existing.get(s.key, s.default) for s in SPECS}
