"""
Output destinations: copy NetHelper's outputs (reports, bundles, captures,
results JSON, run logs) to local or remote places.

A destination is written as one string (in --upload DEST, `nethelper upload`,
or the NETHELPER_OUTPUT_DESTINATIONS setting):

  Local folder / external / mapped drive
      D:\\NetHelper   Z:\\Reports   /mnt/usb/nethelper   ~/reports   file:///srv/out
  Network share (SMB)
      \\\\fileserver\\it\\nethelper        native on Windows (your logon credentials)
      smb://fileserver/it/nethelper       Windows: native; Linux/macOS: smbclient
  SSH (SFTP)
      sftp://tech@backup01/srv/nethelper    absolute path on the server
      scp://tech@backup01:2222/~/nethelper  home-relative path, custom port
      -> uses the system OpenSSH `sftp` in batch mode with KEY authentication
         only (ssh-agent, default keys, or NETHELPER_SSH_KEY); never prompts
  WebDAV (e.g. Nextcloud / ownCloud / SharePoint DAV)
      webdavs://jason@cloud.example.com/remote.php/dav/files/jason/NetHelper
      -> HTTPS PUT/MKCOL; password/app-password from NETHELPER_DEST_PASSWORD
  HTTPS upload endpoint
      https://intake.example.com/upload
      -> PUT (or POST, NETHELPER_HTTP_UPLOAD_METHOD) to <url>/<subdir>/<file>,
         Bearer NETHELPER_DEST_TOKEN or Basic user/password
  FTPS
      ftps://tech@ftp.example.com/nethelper   explicit TLS, protected data channel
  S3-compatible object storage (AWS S3, MinIO, Backblaze B2, Wasabi, Ceph...)
      s3://my-bucket/nethelper
      -> HTTPS PUT signed with AWS Signature Version 4; endpoint, region and
         keys come from the NETHELPER_S3_* settings (or the standard
         AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN env vars)
  Email (SMTP)
      mailto:helpdesk@example.com
      -> one email per run with the files attached, through NETHELPER_SMTP_SERVER
         (STARTTLS by default). Files over NETHELPER_EMAIL_MAX_MB are listed in
         the message but not attached. Run logs are not emailed automatically
         (that would be an email per command) - send one with `nethelper upload`.
  Syslog / SIEM
      syslog+tls://siem.example.com            RFC 5425 syslog over TLS (port 6514)
      syslog://siem.example.com  syslog+tcp://siem.example.com:514   plain UDP / TCP
      -> not a file copy: sends EVENTS. A results JSON becomes one event per
         check plus one per diagnosis finding; a run log forwards its
         WARNING/ERROR lines; any other file becomes one "file produced" event
         (name, size, SHA-256) as an audit trail.

Files go into a per-machine sub-folder (NETHELPER_OUTPUT_SUBDIR, default
"{host}/{date}") so many machines can share one destination.

SECURITY
  - Credentials are never accepted inside a URL ("user:pass@" is refused) -
    passwords/tokens live only in the .env secrets (masked everywhere) or
    environment variables, so they don't leak into shell history or logs.
  - TLS certificates are always verified (WebDAV/HTTPS/FTPS/S3/SMTP/syslog+tls).
    Unencrypted http://, webdav://, ftp://, syslog:// (UDP), syslog+tcp://, an
    http:// S3 endpoint and NETHELPER_SMTP_SECURITY=none are refused unless
    NETHELPER_DEST_ALLOW_INSECURE=true.
  - Email and syslog carry text that came off the network (Wi-Fi names, server
    banners). Control characters and line breaks are stripped from it first so
    it can't forge extra email headers or fake extra syslog lines (log
    injection); email headers are additionally checked by Python's email
    library, which refuses line breaks in header values.
  - SSH runs with BatchMode=yes and strict host-key checking (unknown hosts
    are refused unless NETHELPER_SSH_ACCEPT_NEW_HOSTKEYS=true, which trusts a
    host's key on first use only). No remote shell is used: transfers are
    sftp batch commands, and remote paths are restricted to a safe character
    set so nothing can be smuggled into the commands.
  - Local copies never overwrite: an existing file gets a numeric suffix.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import mimetypes
# Security note (B402): ftplib provides FTP_TLS for ftps:// (encrypted login and
# data channel, certificate verified); plain ftp:// is refused unless the user
# explicitly sets NETHELPER_DEST_ALLOW_INSECURE=true.
import ftplib  # nosec B402
import logging
import os
import re
import shutil
import smtplib
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

from nethelper import __version__
from nethelper.core import cmd, validate
from nethelper.core.result import Status

log = logging.getLogger("nethelper.dest")

KINDS = {
    "file": "local", "smb": "smb", "sftp": "sftp", "scp": "sftp", "webdav": "webdav", "webdavs": "webdav",
    "dav": "webdav", "davs": "webdav", "https": "https", "http": "https", "ftps": "ftps", "ftp": "ftps",
    "s3": "s3", "mailto": "email", "syslog": "syslog", "syslog+udp": "syslog", "syslog+tcp": "syslog",
    "syslog+tls": "syslog",
}
INSECURE = {"http", "webdav", "dav", "ftp", "syslog", "syslog+udp", "syslog+tcp"}
# The encrypted alternative suggested when an insecure scheme is refused.
SECURE_FORM = {"http": "https", "webdav": "webdavs", "dav": "davs", "ftp": "ftps", "syslog": "syslog+tls",
               "syslog+udp": "syslog+tls", "syslog+tcp": "syslog+tls"}
# Default ports per syslog transport: 514 for plain UDP/TCP, 6514 for TLS (RFC 5425).
SYSLOG_PORTS = {"syslog": 514, "syslog+udp": 514, "syslog+tcp": 514, "syslog+tls": 6514}

# Regex: allowed characters in remote paths/file names for SSH/SMB transfers -
# letters, digits, space, and . _ - / ~ + @ (no quotes, ;, |, $, backticks, *).
_SAFE_REMOTE = re.compile(r"^[A-Za-z0-9 ._/~+@-]*$")
# Regex: a Windows drive path like "C:\x", "Z:/y" or just "D:" (mapped/external drive).
_DRIVE = re.compile(r"^[A-Za-z]:([\\/]|$)")
# Regex: an S3 bucket name - 3-63 lowercase letters, digits, dots and hyphens,
# starting and ending with a letter/digit. Matches "my-bucket", "logs.example".
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
# Regex: a plain email address (no display name, no comments, no line breaks).
# Matches "helpdesk@example.com", "j.smith+net@it.example.co.uk".
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}$")


class DestinationError(ValueError):
    """A destination string is invalid or not allowed. Message is user-readable."""


@dataclass
class Destination:
    """
    A parsed destination.
      raw    - what the user wrote (credential-free, safe to show/log)
      kind   - local | smb | sftp | webdav | https | ftps | s3 | email | syslog
      scheme - the URL scheme as written (empty for plain paths)
      host, port, user, path - URL parts (path = local path for kind local;
               host = bucket and path = key prefix for s3; path = the
               recipient address for email)
    """

    raw: str
    kind: str
    scheme: str = ""
    host: str = ""
    port: int | None = None
    user: str | None = None
    path: str = ""

    @property
    def label(self) -> str:
        names = {"local": "folder", "smb": "network share", "sftp": "SSH/SFTP", "webdav": "WebDAV",
                 "https": "HTTPS", "ftps": "FTPS", "s3": "S3", "email": "email", "syslog": "syslog"}
        if self.kind == "local" and self.path.startswith("\\\\"):
            return "network share (UNC)"
        return names[self.kind]


@dataclass
class UploadResult:
    """Outcome for one file at one destination."""

    file: str
    destination: str
    ok: bool
    remote: str = ""
    error: str | None = None


def parse(raw: str, allow_insecure: bool = False) -> Destination:
    """Validate and parse a destination string. Raises DestinationError."""
    text = (raw or "").strip()
    if not text:
        raise DestinationError("destination is empty")
    if any(ord(c) < 32 for c in text):
        raise DestinationError("destination contains control characters")
    # Email: mailto:address (checked before the local-path rule, as it has no "://").
    if text.lower().startswith("mailto:"):
        address = urllib.parse.unquote(text[7:]).strip()
        if "?" in address or "," in address or not _EMAIL.fullmatch(address):
            raise DestinationError(f"{text}: use mailto:one-address@example.com (one recipient per destination; "
                                   "add several mailto: entries for more)")
        return Destination(raw=text, kind="email", scheme="mailto", path=address)
    # Plain local paths: drive letters, UNC shares, absolute/relative/home paths.
    if _DRIVE.match(text) or text.startswith(("\\\\", "/", "~", ".")) or "://" not in text:
        return Destination(raw=text, kind="local", path=text)
    parts = urllib.parse.urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in KINDS:
        raise DestinationError(f"unsupported destination type '{scheme}://' - use a folder path, smb://, sftp://, "
                               "scp://, webdavs://, https://, ftps://, s3://, mailto: or syslog+tls://")
    if parts.password is not None:
        raise DestinationError("don't put passwords in destination URLs - set NETHELPER_DEST_PASSWORD "
                               "(nethelper config set NETHELPER_DEST_PASSWORD ...) instead")
    if scheme in INSECURE and not allow_insecure:
        raise DestinationError(f"{scheme}:// sends data (and credentials) unencrypted; use the secure form "
                               f"({SECURE_FORM[scheme]}://) or set NETHELPER_DEST_ALLOW_INSECURE=true")
    kind = KINDS[scheme]
    if kind == "s3":  # s3://bucket/prefix - the "host" part is the bucket name
        bucket = (parts.netloc or "").lower()
        if "@" in bucket or ":" in bucket or not _BUCKET.fullmatch(bucket) or ".." in bucket:
            raise DestinationError(f"{text}: invalid S3 bucket name (3-63 lowercase letters, digits, '.' and '-'); "
                                   "the server is set with NETHELPER_S3_ENDPOINT, not in the URL")
        prefix = urllib.parse.unquote(parts.path or "").strip("/")
        if not _SAFE_REMOTE.fullmatch(prefix) or ".." in prefix.split("/"):
            raise DestinationError(f"{text}: key prefix may only contain letters, digits, spaces and . _ - / ~ + @")
        return Destination(raw=text, kind="s3", scheme=scheme, host=bucket, path=prefix)
    if kind == "local":  # file:///path or file://C:/path
        path = urllib.parse.unquote(parts.path)
        if re.match(r"^/[A-Za-z]:", path):
            path = path[1:]
        return Destination(raw=text, kind="local", scheme=scheme, path=path)
    if not parts.hostname:
        raise DestinationError(f"{text}: missing server name")
    validate.hostname(parts.hostname)
    try:
        port = parts.port
    except ValueError as exc:
        raise DestinationError(f"{text}: invalid port") from exc
    user = urllib.parse.unquote(parts.username) if parts.username else None
    if user and not re.fullmatch(r"[A-Za-z0-9._@\\-]{1,128}", user):
        raise DestinationError(f"invalid user name in {text}")
    path = urllib.parse.unquote(parts.path or "/")
    if kind in ("sftp", "smb") and not _SAFE_REMOTE.fullmatch(path):
        raise DestinationError(f"{text}: remote path may only contain letters, digits, spaces and . _ - / ~ + @")
    if kind == "smb" and len([p for p in path.split("/") if p]) < 1:
        raise DestinationError(f"{text}: needs at least a share name, e.g. smb://server/share/folder")
    if kind == "syslog":
        if user or path not in ("", "/"):
            raise DestinationError(f"{text}: a syslog destination is just a server and optional port, "
                                   "e.g. syslog+tls://siem.example.com:6514")
        port = port or SYSLOG_PORTS[scheme]
    return Destination(raw=text, kind=kind, scheme=scheme, host=parts.hostname, port=port, user=user, path=path)


def expand_subdir(template: str, when: float | None = None) -> str:
    """
    Fill the per-machine sub-folder template: {host} = this computer's name,
    {date} = YYYY-MM-DD, {user} = login name. Unsafe characters become '_'.
    """
    when = when or time.time()
    try:
        user = os.getlogin()
    except OSError:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    text = (template or "").replace("{host}", socket.gethostname()).replace(
        "{date}", time.strftime("%Y-%m-%d", time.localtime(when))).replace("{user}", user)
    parts = [re.sub(r"[^A-Za-z0-9._ -]", "_", p).strip(" .") for p in text.replace("\\", "/").split("/")]
    return "/".join(p for p in parts if p and p != "..")


def _safe_name(name: str) -> str:
    """A file name safe for every destination type."""
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .") or "file"


# ---------------------------------------------------------------------------
# Transfer implementations
# ---------------------------------------------------------------------------

def _unique(path: Path) -> Path:
    """Add -1, -2... before the extension until the name is free (never overwrite)."""
    if not path.exists():
        return path
    for n in range(1, 10000):
        candidate = path.with_name(f"{path.stem}-{n}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise DestinationError(f"too many files named {path.name}")


def _to_local(dest: Destination, files: list[Path], subdir: str) -> list[UploadResult]:
    """Copy to a local folder, external/mapped drive or UNC share."""
    base = Path(os.path.expandvars(dest.path)).expanduser()
    if dest.kind == "smb":  # smb://server/share/path -> \\server\share\path (Windows only)
        base = Path("\\\\" + dest.host + dest.path.replace("/", "\\"))
    folder = base / subdir if subdir else base
    folder.mkdir(parents=True, exist_ok=True)
    out = []
    for f in files:
        target = _unique(folder / _safe_name(f.name))
        shutil.copy2(f, target)
        out.append(UploadResult(str(f), dest.raw, True, str(target)))
    return out


def _sftp(dest: Destination, files: list[Path], subdir: str, settings) -> list[UploadResult]:
    """Upload with OpenSSH sftp in batch mode (no remote shell)."""
    if not cmd.which("sftp"):
        raise DestinationError("OpenSSH 'sftp' is not installed (Windows: Settings > Optional features > OpenSSH Client)")
    # curl-style paths: sftp://host/~/dir = relative to the login's home; sftp://host/dir = absolute /dir.
    path = dest.path
    if path in ("/~", "/~/"):
        remote_base = ""
    elif path.startswith("/~/"):
        remote_base = path[3:]
    else:
        remote_base = path
    remote = "/".join(p for p in [remote_base.rstrip("/"), subdir] if p) or "."
    if remote_base == "/" and subdir:
        remote = "/" + subdir
    if not _SAFE_REMOTE.fullmatch(remote):
        raise DestinationError("remote path contains unsupported characters")
    lines = []
    acc = "/" if remote.startswith("/") else ""
    for part in [p for p in remote.split("/") if p]:
        acc = f"{acc}{part}" if acc in ("", "/") else f"{acc}/{part}"
        lines.append(f'-mkdir "{acc}"')  # leading '-' = ignore "already exists"
    names = []
    for f in files:
        local = str(f.resolve())
        if '"' in local or "\n" in local:
            raise DestinationError(f"local file name not supported for sftp: {f}")
        name = _safe_name(f.name)
        names.append(name)
        lines.append(f'put "{local}" "{remote}/{name}"')
    argv = ["sftp", "-b", "-", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            "-o", "StrictHostKeyChecking=" + ("accept-new" if settings and settings.get("NETHELPER_SSH_ACCEPT_NEW_HOSTKEYS") else "yes")]
    key = settings.get("NETHELPER_SSH_KEY") if settings else ""
    if key:
        argv += ["-i", str(Path(key).expanduser())]
    known = settings.get("NETHELPER_SSH_KNOWN_HOSTS") if settings else ""
    if known:
        argv += ["-o", f"UserKnownHostsFile={Path(known).expanduser()}"]
    if dest.port:
        argv += ["-P", str(dest.port)]
    argv.append(f"{dest.user}@{dest.host}" if dest.user else dest.host)
    res = cmd.run(argv, timeout=300, input_text="\n".join(lines) + "\n")
    if not res.ok:
        err = (res.stderr or res.error or res.stdout).strip().splitlines()
        msg = err[-1] if err else "sftp failed"
        if "Host key verification failed" in res.stderr or "No ED25519 host key" in res.stderr or "known_hosts" in res.stderr:
            msg += (" - the server's host key isn't trusted yet: connect once with 'ssh "
                    f"{dest.host}' to verify it, or set NETHELPER_SSH_ACCEPT_NEW_HOSTKEYS=true")
        elif "Permission denied" in res.stderr or "Connection closed" in msg:
            msg += (" - key authentication failed: load your key into ssh-agent or set NETHELPER_SSH_KEY; the key "
                    "must have no passphrase (or be in the agent)")
            if sys.platform == "win32":
                msg += ", and on Windows the key file must be readable only by you (icacls KEY /inheritance:r /grant:r %USERNAME%:R)"
        raise DestinationError(msg)
    return [UploadResult(str(f), dest.raw, True, f"{dest.host}:{remote}/{n}") for f, n in zip(files, names, strict=True)]


def _smbclient(dest: Destination, files: list[Path], subdir: str, settings) -> list[UploadResult]:
    """Upload to smb://server/share/path from Linux/macOS with smbclient."""
    if not cmd.which("smbclient"):
        raise DestinationError("smbclient is not installed (apt install smbclient / brew install samba), "
                               "or mount the share and use its folder path")
    parts = [p for p in dest.path.split("/") if p]
    share, rel = parts[0], "/".join(parts[1:] + ([subdir] if subdir else []))
    if not _SAFE_REMOTE.fullmatch(rel):
        raise DestinationError("remote path contains unsupported characters")
    commands, acc = [], ""
    for part in [p for p in rel.split("/") if p]:
        acc = f"{acc}/{part}" if acc else part
        commands.append(f'mkdir "{acc}"')
    if rel:
        commands.append(f'cd "{rel}"')
    names = []
    for f in files:
        local = str(f.resolve())
        if '"' in local or ";" in local:
            raise DestinationError(f"local file name not supported for smbclient: {f}")
        names.append(_safe_name(f.name))
        commands.append(f'put "{local}" "{names[-1]}"')
    password = settings.get("NETHELPER_DEST_PASSWORD") if settings else ""
    authfile = None
    argv = ["smbclient", f"//{dest.host}/{share}"]
    try:
        if password or dest.user:
            # Credentials go in a temporary owner-only file, never on the command line (visible in process lists).
            fd, authfile = tempfile.mkstemp(prefix="nethelper-smb-")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(f"username = {dest.user or ''}\npassword = {password}\n")
            argv += ["-A", authfile]
        else:
            argv.append("-N")  # anonymous / guest
        if dest.port:
            argv += ["-p", str(dest.port)]
        argv += ["-c", "; ".join(commands)]
        res = cmd.run(argv, timeout=300)
    finally:
        if authfile:
            try:
                os.unlink(authfile)
            except OSError:
                pass
    # Any NT_STATUS error other than "folder already exists" (COLLISION from mkdir) is a failure.
    bad = [ln for ln in (res.stdout + res.stderr).splitlines() if "NT_STATUS" in ln and "COLLISION" not in ln]
    if bad or not res.ok:
        raise DestinationError((bad[-1] if bad else (res.error or res.stderr or "smbclient failed")).strip())
    return [UploadResult(str(f), dest.raw, True, f"//{dest.host}/{share}/{rel}/{n}") for f, n in zip(files, names, strict=True)]


def _http_auth(dest: Destination, settings) -> dict:
    """Authorization header: Bearer token if set, else Basic user + password (if any)."""
    token = settings.get("NETHELPER_DEST_TOKEN") if settings else ""
    password = settings.get("NETHELPER_DEST_PASSWORD") if settings else ""
    if token:
        return {"Authorization": f"Bearer {token}"}
    if dest.user:
        cred = base64.b64encode(f"{dest.user}:{password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {cred}"}
    return {}


def _http_base(dest: Destination) -> str:
    """https://host[:port]/path (or http:// for the insecure variants)."""
    secure = dest.scheme in ("https", "webdavs", "davs")
    netloc = dest.host + (f":{dest.port}" if dest.port else "")
    return f"{'https' if secure else 'http'}://{netloc}{urllib.parse.quote(dest.path.rstrip('/'))}"


def _tls_context(settings=None) -> ssl.SSLContext:
    """
    TLS settings for every encrypted destination: certificates are always
    verified against the system's trusted CAs, plus the extra CA file in
    NETHELPER_DEST_CA_FILE (for servers using an internal/company CA). There is
    deliberately no "skip verification" option - that would let anyone on the
    path impersonate the server and collect the uploads and credentials.
    """
    ctx = ssl.create_default_context()
    ca = settings.get("NETHELPER_DEST_CA_FILE") if settings else ""
    if ca:
        ctx.load_verify_locations(cafile=str(Path(ca).expanduser()))
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """
    Refuse to follow HTTP redirects on uploads.

    Python's urllib would otherwise follow a 30x reply and send the SAME
    Authorization header (bearer token / password / S3 signature) to wherever
    the server points - another host, or even plain http:// where anyone on
    the path could read it. Returning None makes the 30x come back as an error
    status, which the callers report (WebDAV treats 301/302 on MKCOL as
    "folder exists").
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102 - see class docstring
        return None


def _request_full(url: str, method: str, headers: dict, data: bytes | None = None, timeout: float = 120,
                  settings=None) -> tuple[int, bytes]:
    """
    Send one HTTP request (certificate verified, redirects NOT followed);
    returns (status code, first 64 KB of the response body).
    """
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": f"NetHelper/{__version__}", **headers})
    # An opener = urllib's request pipeline: our TLS settings + the no-redirect rule above.
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_tls_context(settings)), _NoRedirect)
    try:
        # The URL scheme is http(s) only - built from a validated destination / S3 endpoint.
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536)


def _request(url: str, method: str, headers: dict, data: bytes | None = None, timeout: float = 120,
             settings=None) -> int:
    """Send one HTTP request (certificate verified); returns just the status code."""
    return _request_full(url, method, headers, data, timeout, settings)[0]


def _webdav(dest: Destination, files: list[Path], subdir: str, settings) -> list[UploadResult]:
    """Create folders with MKCOL (one level at a time) and PUT each file."""
    base = _http_base(dest)
    auth = _http_auth(dest, settings)
    url = base
    for part in [p for p in subdir.split("/") if p]:
        url = f"{url}/{urllib.parse.quote(part)}"
        status = _request(url, "MKCOL", auth, settings=settings)
        if status in (401, 403):
            raise DestinationError(f"WebDAV authentication failed (HTTP {status}) - check the user in the URL and "
                                   "NETHELPER_DEST_PASSWORD (Nextcloud: use an app password)")
        if status not in (201, 405, 301, 302):  # 405 = already exists
            raise DestinationError(f"WebDAV MKCOL {status} for {url}")
    out = []
    for f in files:
        target = f"{url}/{urllib.parse.quote(_safe_name(f.name))}"
        status = _request(target, "PUT", {**auth, "Content-Type": "application/octet-stream"}, f.read_bytes(), timeout=600,
                          settings=settings)
        if status not in (200, 201, 204):
            raise DestinationError(f"WebDAV PUT returned HTTP {status}" + (" (authentication)" if status in (401, 403) else ""))
        out.append(UploadResult(str(f), dest.raw, True, target))
    return out


def _https(dest: Destination, files: list[Path], subdir: str, settings) -> list[UploadResult]:
    """PUT (default) or POST each file to <url>/<subdir>/<name>."""
    method = (settings.get("NETHELPER_HTTP_UPLOAD_METHOD") if settings else "put").upper()
    base = _http_base(dest)
    auth = _http_auth(dest, settings)
    out = []
    for f in files:
        name = _safe_name(f.name)
        if method == "PUT":
            target = "/".join([base] + [urllib.parse.quote(p) for p in subdir.split("/") if p] + [urllib.parse.quote(name)])
            headers = {**auth, "Content-Type": "application/octet-stream"}
        else:
            target = base
            headers = {**auth, "Content-Type": "application/octet-stream", "X-NetHelper-Path": f"{subdir}/{name}",
                       "Content-Disposition": f'attachment; filename="{name}"'}
        status = _request(target, method, headers, f.read_bytes(), timeout=600, settings=settings)
        if not 200 <= status < 300:
            raise DestinationError(f"HTTPS {method} returned HTTP {status}" + (" (authentication)" if status in (401, 403) else ""))
        out.append(UploadResult(str(f), dest.raw, True, target))
    return out


def _ftps(dest: Destination, files: list[Path], subdir: str, settings) -> list[UploadResult]:
    """Explicit FTPS (AUTH TLS) with an encrypted data channel (PROT P)."""
    password = settings.get("NETHELPER_DEST_PASSWORD") if settings else ""
    secure = dest.scheme == "ftps"
    # Security note (B321): plain FTP is only reachable when the user explicitly
    # set NETHELPER_DEST_ALLOW_INSECURE=true (parse() refuses ftp:// otherwise).
    ftp = ftplib.FTP_TLS(context=_tls_context(settings), timeout=30) if secure else ftplib.FTP(timeout=30)  # nosec B321
    try:
        ftp.connect(dest.host, dest.port or 21)
        ftp.login(dest.user or "anonymous", password or "")
        if secure:
            ftp.prot_p()  # encrypt file transfers too, not just the login
        remote = "/".join(p for p in [dest.path.rstrip("/"), subdir] if p)
        if remote.startswith("/"):
            ftp.cwd("/")
        for part in [p for p in remote.split("/") if p]:
            try:
                ftp.mkd(part)
            except ftplib.error_perm:
                pass  # exists
            ftp.cwd(part)
        out = []
        for f in files:
            name = _safe_name(f.name)
            with f.open("rb") as fh:
                ftp.storbinary(f"STOR {name}", fh)
            out.append(UploadResult(str(f), dest.raw, True, f"{dest.host}:{remote}/{name}"))
        return out
    finally:
        try:
            ftp.quit()
        except (OSError, ftplib.Error, EOFError):
            ftp.close()


# ---------------------------------------------------------------------------
# S3-compatible object storage (AWS Signature Version 4)
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    """Lower-case hex SHA-256 of some bytes (used throughout SigV4)."""
    return hashlib.sha256(data).hexdigest()


def sigv4_authorization(method: str, canonical_uri: str, headers: dict[str, str], payload_hash: str,
                        access_key: str, secret_key: str, region: str, when: dt.datetime,
                        service: str = "s3", query: str = "") -> str:
    """
    Build the AWS Signature Version 4 "Authorization" header value.

    SigV4 proves the request came from the holder of the secret key without
    sending the key: we hash a canonical description of the request (method,
    path, headers, payload hash), then sign that with a key derived from the
    secret + date + region + service using HMAC-SHA256. The server repeats the
    same calculation; any change to the signed parts in transit breaks it.

      headers      - every header to sign, lower-case names (must include host,
                     x-amz-date and x-amz-content-sha256)
      payload_hash - SHA-256 hex of the body (so the body can't be swapped)
      when         - request time in UTC (must match x-amz-date; servers reject
                     clock skew over ~15 minutes)
    Returns e.g. "AWS4-HMAC-SHA256 Credential=AKIA.../20260101/us-east-1/s3/aws4_request,
    SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=<64 hex>".
    """
    amz_date = when.strftime("%Y%m%dT%H%M%SZ")
    day = when.strftime("%Y%m%d")
    names = sorted(headers)
    canonical_headers = "".join(f"{n}:{' '.join(headers[n].split())}\n" for n in names)
    signed = ";".join(names)
    canonical_request = "\n".join([method, canonical_uri, query, canonical_headers, signed, payload_hash])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, _sha256_hex(canonical_request.encode("utf-8"))])
    key = ("AWS4" + secret_key).encode("utf-8")
    for part in (day, region, service, "aws4_request"):  # derive the signing key step by step
        key = hmac.new(key, part.encode("utf-8"), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"


def _s3_credentials(settings) -> tuple[str, str, str]:
    """(access key, secret key, session token) from NETHELPER_S3_* settings, else the standard AWS_* variables."""
    access = (settings.get("NETHELPER_S3_ACCESS_KEY") if settings else "") or os.environ.get("AWS_ACCESS_KEY_ID", "")
    secret = (settings.get("NETHELPER_S3_SECRET_KEY") if settings else "") or os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    token = os.environ.get("AWS_SESSION_TOKEN", "") if not (settings and settings.get("NETHELPER_S3_SECRET_KEY")) else ""
    if not access or not secret:
        raise DestinationError("S3 needs an access key and secret key: set NETHELPER_S3_ACCESS_KEY and "
                               "NETHELPER_S3_SECRET_KEY (or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)")
    return access, secret, token


def _s3_endpoint(dest: Destination, settings) -> tuple[str, str, str]:
    """
    Work out (scheme, host[:port], path prefix before the key) for a bucket.

    Empty NETHELPER_S3_ENDPOINT means AWS itself (https://s3.<region>.amazonaws.com).
    "Virtual-hosted" addressing puts the bucket in the host name
    (my-bucket.s3.amazonaws.com) - AWS's preferred form; "path" addressing puts it
    in the path (minio.local:9000/my-bucket) - what MinIO/Ceph/most self-hosted
    stores expect. "auto" = virtual for AWS (unless the bucket has dots, which
    break AWS's TLS certificate), path for everything else.
    """
    region = settings.get("NETHELPER_S3_REGION") if settings else "us-east-1"
    endpoint = (settings.get("NETHELPER_S3_ENDPOINT") if settings else "") or f"https://s3.{region}.amazonaws.com"
    parts = urllib.parse.urlsplit(endpoint)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise DestinationError(f"NETHELPER_S3_ENDPOINT {endpoint!r} must be an https:// URL")
    if parts.scheme == "http" and not (settings and settings.get("NETHELPER_DEST_ALLOW_INSECURE")):
        raise DestinationError("the S3 endpoint is plain http:// (unencrypted keys and data); use https:// or set "
                               "NETHELPER_DEST_ALLOW_INSECURE=true")
    style = settings.get("NETHELPER_S3_ADDRESSING") if settings else "auto"
    if style == "auto":
        style = "virtual" if parts.hostname.endswith("amazonaws.com") and "." not in dest.host else "path"
    netloc = parts.netloc.lower()
    if style == "virtual":
        return parts.scheme, f"{dest.host}.{netloc}", ""
    return parts.scheme, netloc, "/" + dest.host


def _s3_error(status: int, body: bytes) -> str:
    """Turn an S3 error response (XML with <Code> and <Message>) into a readable message with a hint."""
    text = body.decode("utf-8", "replace")
    code = (re.search(r"<Code>([^<]{1,100})</Code>", text) or [None, ""])[1]
    message = (re.search(r"<Message>([^<]{1,300})</Message>", text) or [None, ""])[1]
    hint = {
        "SignatureDoesNotMatch": "the secret key is wrong (or a proxy changed the request)",
        "InvalidAccessKeyId": "the access key is wrong or disabled",
        "AccessDenied": "the key isn't allowed to write to this bucket/prefix (needs s3:PutObject)",
        "NoSuchBucket": "the bucket doesn't exist at this endpoint/region",
        "RequestTimeTooSkewed": "this computer's clock is more than 15 minutes off - fix the time first",
        "PermanentRedirect": "the bucket is in another region - set NETHELPER_S3_REGION",
        "AuthorizationHeaderMalformed": "wrong region - set NETHELPER_S3_REGION to the bucket's region",
    }.get(code, "")
    out = f"S3 PUT returned HTTP {status}" + (f" {code}" if code else "") + (f": {message}" if message else "")
    return out + (f" - {hint}" if hint else "")


def _s3(dest: Destination, files: list[Path], subdir: str, settings) -> list[UploadResult]:
    """Upload each file with a SigV4-signed PUT to <prefix>/<subdir>/<name> (overwrites an object of the same key)."""
    access, secret, token = _s3_credentials(settings)
    region = settings.get("NETHELPER_S3_REGION") if settings else "us-east-1"
    scheme, host, base_path = _s3_endpoint(dest, settings)
    out = []
    for f in files:
        key = "/".join(p for p in [dest.path, subdir, _safe_name(f.name)] if p)
        # S3 canonical URI: each path segment percent-encoded once; '/' kept.
        uri = base_path + "/" + urllib.parse.quote(key, safe="/-_.~")
        body = f.read_bytes()
        payload_hash = _sha256_hex(body)
        now = dt.datetime.now(dt.timezone.utc)
        signed = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": now.strftime("%Y%m%dT%H%M%SZ")}
        if token:
            signed["x-amz-security-token"] = token
        auth = sigv4_authorization("PUT", uri, signed, payload_hash, access, secret, region, now)
        headers = {"Host": host, "X-Amz-Content-Sha256": payload_hash, "X-Amz-Date": signed["x-amz-date"],
                   "Authorization": auth, "Content-Type": mimetypes.guess_type(f.name)[0] or "application/octet-stream"}
        if token:
            headers["X-Amz-Security-Token"] = token
        status, resp = _request_full(f"{scheme}://{host}{uri}", "PUT", headers, body, timeout=600, settings=settings)
        if status not in (200, 201, 204):
            raise DestinationError(_s3_error(status, resp))
        out.append(UploadResult(str(f), dest.raw, True, f"s3://{dest.host}/{key}"))
    return out


# ---------------------------------------------------------------------------
# Email (SMTP)
# ---------------------------------------------------------------------------

def _clean_line(text: object, limit: int = 300) -> str:
    """
    One-line, printable version of possibly hostile text (an SSID, a banner):
    control characters and line breaks become spaces and the length is capped,
    so it can't add email headers or forge extra syslog lines.
    """
    flat = "".join(" " if (ord(c) < 32 or ord(c) == 127) else c for c in str(text))
    flat = " ".join(flat.split())
    return flat[:limit]


def _nethelper_doc(path: Path) -> dict | None:
    """The parsed results JSON if `path` is a NetHelper results/report JSON file, else None."""
    if path.suffix.lower() != ".json" or path.stat().st_size > 50_000_000:
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(doc, dict) and doc.get("tool") == "NetHelper" and isinstance(doc.get("results"), list):
        return doc
    return None


def _smtp_server(settings) -> tuple[str, int, str]:
    """(host, port, security) from NETHELPER_SMTP_SERVER / NETHELPER_SMTP_SECURITY, with the standard port per mode."""
    raw = (settings.get("NETHELPER_SMTP_SERVER") if settings else "") or ""
    if not raw:
        raise DestinationError("email destinations need an SMTP server: nethelper config set NETHELPER_SMTP_SERVER "
                               "smtp.example.com (and NETHELPER_SMTP_USER / NETHELPER_SMTP_PASSWORD if it needs login)")
    security = settings.get("NETHELPER_SMTP_SECURITY")
    host, _, port_text = raw.partition(":")
    port = int(port_text) if port_text else {"starttls": 587, "ssl": 465, "none": 25}[security]
    if security == "none" and not settings.get("NETHELPER_DEST_ALLOW_INSECURE"):
        raise DestinationError("NETHELPER_SMTP_SECURITY=none sends mail (and any password) unencrypted; use "
                               "starttls or ssl, or set NETHELPER_DEST_ALLOW_INSECURE=true")
    return host, port, security


def build_email(to: str, files: list[Path], settings) -> tuple[EmailMessage, list[str]]:
    """
    Compose the run email: a short plain-text summary (the diagnosis headline
    when a results JSON is attached) with each file attached, skipping files
    that would push the message over NETHELPER_EMAIL_MAX_MB. Returns the
    message and the names of files that were too big to attach.
    """
    host = _clean_line(socket.gethostname(), 100)
    sender = (settings.get("NETHELPER_SMTP_FROM") if settings else "") or ""
    user = (settings.get("NETHELPER_SMTP_USER") if settings else "") or ""
    if not sender:  # default: the login if it is an address, else nethelper@<this computer>
        sender = user if _EMAIL.fullmatch(user) else f"nethelper@{re.sub(r'[^A-Za-z0-9.-]', '-', host) or 'localhost'}"
    limit = int((settings.get("NETHELPER_EMAIL_MAX_MB") if settings else 20) * 1024 * 1024)
    headline, lines = "", []
    for f in files:
        doc = _nethelper_doc(f)
        if doc and doc.get("verdict") and not headline:
            first = doc["verdict"][0]
            headline = _clean_line(first.get("title", ""), 120)
            lines.append(f"Diagnosis: {headline}")
            lines += [f"  - {_clean_line(v.get('severity', ''))}: {_clean_line(v.get('title', ''), 200)}"
                      for v in doc["verdict"][:10]]
            lines.append("")
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = f"NetHelper results from {host}" + (f": {headline}" if headline else "")
    msg["X-Mailer"] = f"NetHelper {__version__}"
    total, skipped, attached = 0, [], []
    for f in files:
        size = f.stat().st_size
        if total + size > limit:
            skipped.append(f.name)
            continue
        total += size
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        attached.append((f, maintype, subtype))
    body = [f"NetHelper {__version__} on {host} at {time.strftime('%Y-%m-%d %H:%M:%S')}.", ""] + lines
    body += ["Attached:"] + [f"  {f.name} ({f.stat().st_size:,} bytes)" for f, _, _ in attached]
    if skipped:
        body += ["", f"Not attached (over the {limit // (1024 * 1024)} MB email limit; still on {host}):"]
        body += [f"  {n}" for n in skipped]
    msg.set_content("\n".join(body) + "\n")
    for f, maintype, subtype in attached:
        msg.add_attachment(f.read_bytes(), maintype=maintype, subtype=subtype, filename=_safe_name(f.name))
    return msg, skipped


def _email(dest: Destination, files: list[Path], subdir: str, settings) -> list[UploadResult]:
    """Send one email to the mailto: address with the files attached (STARTTLS/SSL, certificate verified)."""
    host, port, security = _smtp_server(settings)
    msg, skipped = build_email(dest.path, files, settings)
    user = settings.get("NETHELPER_SMTP_USER") if settings else ""
    password = settings.get("NETHELPER_SMTP_PASSWORD") if settings else ""
    context = _tls_context(settings)
    try:
        if security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=30, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=30)
        with server:
            server.ehlo()
            if security == "starttls":
                server.starttls(context=context)  # upgrade to TLS before any login or data
                server.ehlo()
            if user:
                server.login(user, password)
            server.send_message(msg)
    except smtplib.SMTPNotSupportedError as exc:
        raise DestinationError(f"{host}:{port} doesn't offer STARTTLS - use NETHELPER_SMTP_SECURITY=ssl (port 465) "
                               "or check the server/port") from exc
    except smtplib.SMTPAuthenticationError as exc:
        raise DestinationError(f"SMTP login refused for {user!r} (code {exc.smtp_code}) - check NETHELPER_SMTP_USER / "
                               "NETHELPER_SMTP_PASSWORD (Microsoft 365/Gmail: use an app password or an SMTP relay)") from exc
    except smtplib.SMTPRecipientsRefused as exc:
        raise DestinationError(f"the SMTP server refused the recipient {dest.path} (relaying not allowed? log in with "
                               "NETHELPER_SMTP_USER)") from exc
    except smtplib.SMTPResponseException as exc:
        reply = exc.smtp_error.decode("utf-8", "replace") if isinstance(exc.smtp_error, bytes) else exc.smtp_error
        raise DestinationError(f"SMTP error {exc.smtp_code}: {_clean_line(reply)}") from exc
    return [UploadResult(str(f), dest.raw, f.name not in skipped, f"email to {dest.path}",
                         None if f.name not in skipped else "too large to attach")
            for f in files]


# ---------------------------------------------------------------------------
# Syslog / SIEM (RFC 5424 messages over UDP, TCP or TLS)
# ---------------------------------------------------------------------------

FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, "local0": 16, "local1": 17, "local2": 18,
              "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23}
# Syslog severities: 3 = error, 4 = warning, 5 = notice, 6 = informational.
_STATUS_SEVERITY = {Status.FAIL.value: 3, Status.ERROR.value: 3, Status.WARN.value: 4, Status.PASS.value: 6,
                    Status.INFO.value: 6, Status.SKIP.value: 6}
_FINDING_SEVERITY = {"critical": 3, "warning": 4, "info": 5}
_LOG_SEVERITY = {"CRITICAL": 2, "ERROR": 3, "WARNING": 4}
# Regex: one line of a NetHelper run log - "2026-11-19 10:15:02,123 WARNING nethelper.dest: message".
_LOG_LINE = re.compile(r"^(\S+ \S+) (CRITICAL|ERROR|WARNING) (\S+): (.*)$")
# 32473 is the private enterprise number reserved for documentation/examples (RFC 5612), used as
# the structured-data ID suffix since NetHelper has no registered number of its own.
_SD_ID = "nethelper@32473"


def _sd_value(text: object) -> str:
    """Escape a structured-data parameter value: RFC 5424 requires \\ before '"', '\\' and ']'."""
    return re.sub(r'(["\\\]])', r"\\\1", _clean_line(text, 200))


def syslog_events(files: list[Path]) -> list[tuple[int, str, dict, str]]:
    """
    Turn the files into syslog events: (severity, msgid, fields, message).
      results JSON -> one "finding" event per diagnosis + one "check" event per check
      .log file    -> one "log" event per WARNING/ERROR/CRITICAL line
      anything else (and the destination test file) -> one "file" / "test" event
    """
    events: list[tuple[int, str, dict, str]] = []
    for f in files:
        doc = _nethelper_doc(f)
        if doc:
            for v in doc.get("verdict", []):
                events.append((_FINDING_SEVERITY.get(v.get("severity"), 5), "finding",
                               {"severity": v.get("severity", ""), "evidence": ",".join(v.get("evidence", []))},
                               _clean_line(v.get("title", ""), 300)))
            for r in doc.get("results", []):
                status = str(r.get("status", "INFO"))
                events.append((_STATUS_SEVERITY.get(status, 6), "check",
                               {"check": r.get("check_id", ""), "status": status, "section": r.get("section", "")},
                               _clean_line(f"{r.get('title', '')}: {r.get('summary', '')}", 400)))
            continue
        if f.suffix.lower() == ".log":
            with f.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = _LOG_LINE.match(line.rstrip("\n"))
                    if m:
                        events.append((_LOG_SEVERITY[m.group(2)], "log", {"logger": m.group(3), "run": f.stem},
                                       _clean_line(m.group(4), 600)))
            continue
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        msgid = "test" if f.name.startswith("nethelper-test-") else "file"
        text = "destination test - safe to ignore" if msgid == "test" else f"produced {f.name}"
        events.append((6, msgid, {"file": f.name, "size": f.stat().st_size, "sha256": digest}, text))
    return events


def format_syslog(severity: int, msgid: str, fields: dict, message: str, facility: int,
                  fmt: str = "rfc5424", when: dt.datetime | None = None) -> bytes:
    """
    One RFC 5424 syslog line:
      <PRI>1 TIMESTAMP HOST NetHelper PID MSGID [nethelper@32473 k="v" ...] MESSAGE
    PRI = facility*8 + severity. With fmt="json" the structured data is "-" and
    the message is a JSON object instead (easier for Splunk/Graylog/ELK to parse).
    """
    when = when or dt.datetime.now().astimezone()
    host = re.sub(r"[^!-~]", "-", socket.gethostname())[:255] or "-"  # printable ASCII, no spaces
    head = f"<{facility * 8 + severity}>1 {when.isoformat(timespec='milliseconds')} {host} NetHelper {os.getpid()} {msgid}"
    if fmt == "json":
        body = json.dumps({"msg": message, "type": msgid, **{k: _clean_line(v, 200) for k, v in fields.items()}},
                          ensure_ascii=False)
        return f"{head} - {body}".encode("utf-8")
    sd = "[" + _SD_ID + "".join(f' {k}="{_sd_value(v)}"' for k, v in fields.items()) + "]"
    return f"{head} {sd} {message}".encode("utf-8")


def _syslog(dest: Destination, files: list[Path], subdir: str, settings) -> list[UploadResult]:
    """Send the files' events to a syslog server: UDP datagrams, or octet-counted frames over TCP/TLS (RFC 6587/5425)."""
    facility = FACILITIES[settings.get("NETHELPER_SYSLOG_FACILITY") if settings else "local0"]
    fmt = settings.get("NETHELPER_SYSLOG_FORMAT") if settings else "rfc5424"
    events = syslog_events(files)
    lines = [format_syslog(sev, mid, flds, msg, facility, fmt) for sev, mid, flds, msg in events]
    port = dest.port or SYSLOG_PORTS[dest.scheme]
    transport = "udp" if dest.scheme in ("syslog", "syslog+udp") else dest.scheme.split("+")[1]
    where = f"{transport} {dest.host}:{port}"
    if not lines:  # e.g. a run log with no warnings: nothing to report, so don't open a connection
        return [UploadResult(str(f), dest.raw, True, f"syslog {where} (0 events)") for f in files]
    if transport == "udp":
        # getaddrinfo picks IPv4 or IPv6 to suit the server name.
        family, _, _, _, addr = socket.getaddrinfo(dest.host, port, type=socket.SOCK_DGRAM)[0]
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(10)
            udp.connect(addr)
            for line in lines:
                udp.send(line[:2048])  # keep under common UDP syslog size limits
    else:
        sock: socket.socket = socket.create_connection((dest.host, port), timeout=15)
        try:
            if transport == "tls":
                sock = _tls_context(settings).wrap_socket(sock, server_hostname=dest.host)
            for line in lines:
                sock.sendall(str(len(line)).encode("ascii") + b" " + line)  # octet counting: "<length> <message>"
            if isinstance(sock, ssl.SSLSocket):
                try:
                    sock = sock.unwrap()  # clean TLS close so the server knows nothing was cut off
                except (OSError, ssl.SSLError):
                    pass
        finally:
            sock.close()
    return [UploadResult(str(f), dest.raw, True, f"syslog {where} ({len(lines)} events)") for f in files]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send(dest: Destination, files: list[Path], subdir: str = "", settings=None, retries: int = 1) -> list[UploadResult]:
    """
    Copy `files` to `dest` under `subdir` (for email: send them in one message;
    for syslog: send their events). Never raises: failures come back as
    UploadResult(ok=False, error=...). Transient failures are retried once.
    """
    files = [Path(f) for f in files if f and Path(f).is_file()]
    if not files:
        return []
    attempt = 0
    while True:
        attempt += 1
        try:
            if dest.kind == "local" or (dest.kind == "smb" and sys.platform == "win32"):
                results = _to_local(dest, files, subdir)
            elif dest.kind == "smb":
                results = _smbclient(dest, files, subdir, settings)
            elif dest.kind == "sftp":
                results = _sftp(dest, files, subdir, settings)
            elif dest.kind == "webdav":
                results = _webdav(dest, files, subdir, settings)
            elif dest.kind == "https":
                results = _https(dest, files, subdir, settings)
            elif dest.kind == "s3":
                results = _s3(dest, files, subdir, settings)
            elif dest.kind == "email":
                results = _email(dest, files, subdir, settings)
            elif dest.kind == "syslog":
                results = _syslog(dest, files, subdir, settings)
            else:
                results = _ftps(dest, files, subdir, settings)
            for r in results:
                if r.ok:
                    log.info("uploaded %s -> %s", r.file, r.remote)
                else:
                    log.warning("not uploaded %s -> %s: %s", r.file, r.remote, r.error)
            return results
        except (OSError, ValueError, ftplib.Error, EOFError) as exc:  # ValueError covers DestinationError + email header errors
            msg = str(exc) or type(exc).__name__
            if "CERTIFICATE_VERIFY_FAILED" in msg:
                # The server's certificate isn't trusted (self-signed / internal CA / wrong name) - say how to fix it.
                msg += (" - the server's TLS certificate isn't trusted; if it comes from an internal/company CA, set "
                        "NETHELPER_DEST_CA_FILE to that CA's certificate (PEM)")
            transient = isinstance(exc, (TimeoutError, ConnectionError, socket.timeout)) or "timed out" in msg.lower()
            if attempt <= retries and transient:
                log.warning("upload to %s failed (%s); retrying", dest.raw, msg)
                time.sleep(2)
                continue
            log.warning("upload to %s failed: %s", dest.raw, msg)
            return [UploadResult(str(f), dest.raw, False, error=msg) for f in files]


def test(dest: Destination, settings=None, subdir: str = "") -> UploadResult:
    """Prove a destination works by uploading a small, clearly named probe file."""
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / f"nethelper-test-{socket.gethostname()}-{time.strftime('%Y%m%d-%H%M%S')}.txt"
        probe.write_text(f"NetHelper {__version__} destination test from {socket.gethostname()} "
                         f"at {time.strftime('%Y-%m-%d %H:%M:%S')}. Safe to delete.\n", encoding="utf-8")
        results = send(dest, [probe], subdir, settings, retries=0)
    return results[0] if results else UploadResult("", dest.raw, False, error="nothing sent")


def configured(settings) -> list[str]:
    """Destinations listed in NETHELPER_OUTPUT_DESTINATIONS (comma or semicolon separated)."""
    raw = settings.get("NETHELPER_OUTPUT_DESTINATIONS") if settings else ""
    return [d.strip() for d in re.split(r"\s*[;,]\s*", raw or "") if d.strip()]


# ---------------------------------------------------------------------------
# Per-run output registry
# ---------------------------------------------------------------------------

CATEGORIES = ("reports", "captures", "logs", "results")
_outputs: list[tuple[str, Path]] = []


def register(category: str, path: Path | str) -> None:
    """Record a file this run produced, for upload at the end of the run."""
    if category not in CATEGORIES:
        raise ValueError(f"unknown output category {category}")
    p = Path(path)
    if (category, p) not in _outputs:
        _outputs.append((category, p))


def produced(categories: set[str] | None = None) -> list[Path]:
    """Files produced so far in this run, optionally limited to some categories."""
    return [p for c, p in _outputs if categories is None or c in categories]


def reset() -> None:
    """Forget registered outputs (between menu actions / tests)."""
    _outputs.clear()
