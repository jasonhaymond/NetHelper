"""
Tests for the S3, email (SMTP) and syslog output destinations.

Each transport is exercised against a small in-process fake server (S3 PUT
endpoint, SMTP server, UDP and TCP syslog receivers) so the real network code
runs end to end without any outside service. The S3 request signing is checked
against AWS's own published Signature Version 4 example.
"""

from __future__ import annotations

import datetime as dt
import email
import http.server
import json
import socket
import socketserver
import threading
from email import policy
from pathlib import Path

import pytest

from nethelper.core import destinations as dst
from nethelper.core import settings as st


def _settings(tmp_path, **values):
    """Load settings from a throwaway .env containing just `values`."""
    env = tmp_path / "t.env"
    env.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")
    return st.load(str(env))


def _results_file(tmp_path, summary="12 ms", title="Gateway unreachable"):
    """Write a minimal NetHelper results JSON (the format report/export.py produces)."""
    doc = {"tool": "NetHelper", "version": "0.1.0",
           "verdict": [{"severity": "critical", "title": title, "explanation": "", "next_steps": [],
                        "evidence": ["conn.gateway_ping"]}],
           "results": [{"check_id": "conn.gateway_ping", "title": "Gateway ping", "section": "connectivity",
                        "status": "FAIL", "summary": summary},
                       {"check_id": "dns.os_resolver", "title": "DNS", "section": "dns", "status": "PASS",
                        "summary": "ok"}]}
    f = tmp_path / "results.json"
    f.write_text(json.dumps(doc), encoding="utf-8")
    return f


# ---------------------------------------------------------------- parsing

@pytest.mark.parametrize("raw,kind,host,path,port", [
    ("s3://acme-netlogs/nethelper/site1", "s3", "acme-netlogs", "nethelper/site1", None),
    ("s3://acme-netlogs", "s3", "acme-netlogs", "", None),
    ("mailto:helpdesk@example.com", "email", "", "helpdesk@example.com", None),
    ("MAILTO:j.smith+net@it.example.co.uk", "email", "", "j.smith+net@it.example.co.uk", None),
    ("syslog+tls://siem.example.com", "syslog", "siem.example.com", "/", 6514),
    ("syslog+tls://siem.example.com:10514", "syslog", "siem.example.com", "/", 10514),
])
def test_new_destination_forms_parse(raw, kind, host, path, port):
    """S3, mailto and TLS syslog destinations are recognised, with default ports filled in."""
    d = dst.parse(raw)
    assert (d.kind, d.host, d.path, d.port) == (kind, host, path, port)


@pytest.mark.parametrize("raw,why", [
    ("mailto:a@example.com,b@example.com", "one recipient"),     # several recipients in one entry
    ("mailto:a@example.com?bcc=x@evil.example", "one recipient"),  # mailto query can't add hidden recipients
    ("mailto:not-an-address", "one recipient"),
    ("s3://Bad_Bucket/x", "bucket"),                              # invalid bucket name
    ("s3://key:secret@bucket/x", "password"),                     # credentials in the URL
    ("s3://bucket/../x", "prefix"),                               # path traversal in the key prefix
    ("syslog://siem.example.com", "unencrypted"),                 # UDP syslog refused by default
    ("syslog+tcp://siem.example.com", "unencrypted"),
    ("syslog+tls://siem.example.com/some/path", "just a server"),
    ("syslog+tls://-oProxy=x", "host"),                           # option-like host name
])
def test_new_destination_rejections(raw, why):
    """Header/recipient smuggling, credentials in URLs, traversal and unencrypted syslog are refused."""
    with pytest.raises(Exception) as exc:
        dst.parse(raw)
    assert why in str(exc.value).lower()


def test_plain_syslog_allowed_only_when_insecure_enabled():
    """syslog:// (UDP) works once NETHELPER_DEST_ALLOW_INSECURE is set, on port 514 by default."""
    d = dst.parse("syslog://siem.example.com", allow_insecure=True)
    assert d.kind == "syslog" and d.port == 514


def test_new_settings_are_validated(tmp_path):
    """Bad S3/SMTP settings are rejected (and reported) instead of being used."""
    s = _settings(tmp_path, NETHELPER_S3_ENDPOINT="ftp://x", NETHELPER_SMTP_SERVER="smtp.example.com:99999",
                  NETHELPER_SMTP_FROM="Evil <a@b.com>\r\nBcc: x@y.com", NETHELPER_S3_REGION="us east")
    bad = " ".join(s.problems)
    for key in ("NETHELPER_S3_ENDPOINT", "NETHELPER_SMTP_SERVER", "NETHELPER_SMTP_FROM", "NETHELPER_S3_REGION"):
        assert key in bad
    assert s.get("NETHELPER_SMTP_FROM") == ""


# ---------------------------------------------------------------- S3

def test_sigv4_matches_aws_published_example():
    """
    Proves the signing code is correct: AWS's documented S3 example ("GET Object",
    examplebucket/test.txt with a Range header, 2013-05-24) must give exactly
    AWS's published signature.
    """
    when = dt.datetime(2013, 5, 24, tzinfo=dt.timezone.utc)
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    headers = {"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
               "x-amz-content-sha256": empty, "x-amz-date": "20130524T000000Z"}
    auth = dst.sigv4_authorization("GET", "/test.txt", headers, empty, "AKIAIOSFODNN7EXAMPLE",
                                   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", when)
    assert auth.endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
    assert "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date" in auth


class _S3Handler(http.server.BaseHTTPRequestHandler):
    """Fake S3: stores PUT bodies by path; answers 403 SignatureDoesNotMatch when the access key is wrong."""

    store: dict = {}
    headers_seen: list = []

    def do_PUT(self):  # noqa: N802 - name required by http.server
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).headers_seen.append(dict(self.headers))
        if "Credential=GOODKEY/" not in self.headers.get("Authorization", ""):
            msg = b"<Error><Code>SignatureDoesNotMatch</Code><Message>bad sig</Message></Error>"
            self.send_response(403)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return
        self.store[self.path] = body
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def s3_server():
    _S3Handler.store, _S3Handler.headers_seen = {}, []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _S3Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_s3_upload_path_style_signed(s3_server, tmp_path):
    """S3: path-style PUT to /bucket/prefix/subdir/name with a SigV4 header and payload hash."""
    f = tmp_path / "site.html"
    f.write_text("<p>report</p>", encoding="utf-8")
    s = _settings(tmp_path, NETHELPER_S3_ENDPOINT=f"http://127.0.0.1:{s3_server}", NETHELPER_DEST_ALLOW_INSECURE="true",
                  NETHELPER_S3_ACCESS_KEY="GOODKEY", NETHELPER_S3_SECRET_KEY="sekrit")
    res = dst.send(dst.parse("s3://netlogs/nh"), [f], "pc1/2026-01-01", s)
    assert res[0].ok, res[0].error
    assert _S3Handler.store["/netlogs/nh/pc1/2026-01-01/site.html"] == b"<p>report</p>"
    h = _S3Handler.headers_seen[-1]
    assert h["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=GOODKEY/") and "sekrit" not in h["Authorization"]
    assert h["X-Amz-Content-Sha256"] == __import__("hashlib").sha256(b"<p>report</p>").hexdigest()
    assert res[0].remote == "s3://netlogs/nh/pc1/2026-01-01/site.html"


def test_s3_errors_are_explained(s3_server, tmp_path):
    """S3 error XML becomes a readable message with a hint; missing keys and plain-http endpoints are refused."""
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    base = {"NETHELPER_S3_ENDPOINT": f"http://127.0.0.1:{s3_server}", "NETHELPER_DEST_ALLOW_INSECURE": "true"}
    bad = dst.send(dst.parse("s3://netlogs"), [f], "", _settings(tmp_path, NETHELPER_S3_ACCESS_KEY="WRONG",
                                                                    NETHELPER_S3_SECRET_KEY="x", **base))
    assert not bad[0].ok and "SignatureDoesNotMatch" in bad[0].error and "secret key" in bad[0].error
    nokey = dst.send(dst.parse("s3://netlogs"), [f], "", _settings(tmp_path, **base))
    assert not nokey[0].ok and "access key" in nokey[0].error
    plain = dst.send(dst.parse("s3://netlogs"), [f], "", _settings(
        tmp_path, NETHELPER_S3_ENDPOINT=f"http://127.0.0.1:{s3_server}", NETHELPER_S3_ACCESS_KEY="GOODKEY",
        NETHELPER_S3_SECRET_KEY="x"))
    assert not plain[0].ok and "unencrypted" in plain[0].error


def test_s3_addressing_auto(tmp_path):
    """AWS endpoints use virtual-host style (bucket in the host name) unless the bucket has dots; others use path style."""
    aws = _settings(tmp_path, NETHELPER_S3_REGION="eu-west-1")
    assert dst._s3_endpoint(dst.parse("s3://netlogs"), aws) == ("https", "netlogs.s3.eu-west-1.amazonaws.com", "")
    assert dst._s3_endpoint(dst.parse("s3://net.logs"), aws) == ("https", "s3.eu-west-1.amazonaws.com", "/net.logs")
    minio = _settings(tmp_path, NETHELPER_S3_ENDPOINT="https://minio.example.com:9000")
    assert dst._s3_endpoint(dst.parse("s3://netlogs"), minio) == ("https", "minio.example.com:9000", "/netlogs")


# ---------------------------------------------------------------- email

class _SMTPHandler(socketserver.StreamRequestHandler):
    """Just enough SMTP (EHLO/MAIL/RCPT/DATA/QUIT, no TLS) to receive one message."""

    messages: list = []

    def _say(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        self._say("220 fake ESMTP")
        rcpt, data = [], None
        while True:
            line = self.rfile.readline().decode(errors="replace").strip()
            if not line:
                return
            verb = line.split(" ")[0].upper()
            if verb in ("EHLO", "HELO"):
                self._say("250 fake")
            elif verb == "MAIL":
                self._say("250 ok")
            elif verb == "RCPT":
                rcpt.append(line)
                self._say("250 ok")
            elif verb == "DATA":
                self._say("354 go")
                chunks = []
                while (chunk := self.rfile.readline()) not in (b".\r\n", b""):
                    chunks.append(chunk)
                data = b"".join(chunks)
                type(self).messages.append((rcpt, data))
                self._say("250 queued")
            elif verb == "QUIT":
                self._say("221 bye")
                return
            else:
                self._say("502 no")


@pytest.fixture
def smtp_server():
    _SMTPHandler.messages = []
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _SMTPHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_email_sends_one_message_with_attachments(smtp_server, tmp_path):
    """Email: one message, diagnosis in the subject, files attached; a hostile title can't add headers."""
    results = _results_file(tmp_path, title="Bad\r\nBcc: victim@example.com")
    report = tmp_path / "site.html"
    report.write_text("<p>r</p>", encoding="utf-8")
    s = _settings(tmp_path, NETHELPER_SMTP_SERVER=f"127.0.0.1:{smtp_server}", NETHELPER_SMTP_SECURITY="none",
                  NETHELPER_DEST_ALLOW_INSECURE="true", NETHELPER_SMTP_FROM="nethelper@example.com")
    res = dst.send(dst.parse("mailto:helpdesk@example.com"), [results, report], "", s)
    assert all(r.ok for r in res), res
    assert len(_SMTPHandler.messages) == 1
    rcpt, raw = _SMTPHandler.messages[0]
    assert [r.lower() for r in rcpt] == ["rcpt to:<helpdesk@example.com>"]  # no smuggled Bcc recipient
    msg = email.message_from_bytes(raw, policy=policy.default)
    assert msg["Subject"].startswith("NetHelper results from ") and "Bad Bcc: victim" in msg["Subject"]
    assert msg["Bcc"] is None
    names = sorted(p.get_filename() for p in msg.iter_attachments())
    assert names == ["results.json", "site.html"]


def test_email_size_limit_and_insecure_refusal(smtp_server, tmp_path):
    """Files over NETHELPER_EMAIL_MAX_MB are listed, not attached; SMTP without TLS needs the insecure opt-in."""
    big = tmp_path / "capture.pcapng"
    big.write_bytes(b"\0" * (1024 * 1024 + 10))
    small = tmp_path / "site.html"
    small.write_text("x", encoding="utf-8")
    s = _settings(tmp_path, NETHELPER_SMTP_SERVER=f"127.0.0.1:{smtp_server}", NETHELPER_SMTP_SECURITY="none",
                  NETHELPER_DEST_ALLOW_INSECURE="true", NETHELPER_EMAIL_MAX_MB="1")
    res = {Path(r.file).name: r for r in dst.send(dst.parse("mailto:a@example.com"), [small, big], "", s)}
    assert res["site.html"].ok and not res["capture.pcapng"].ok and "too large" in res["capture.pcapng"].error
    body = email.message_from_bytes(_SMTPHandler.messages[-1][1], policy=policy.default).get_body().get_content()
    assert "capture.pcapng" in body and "Not attached" in body
    refused = dst.send(dst.parse("mailto:a@example.com"), [small], "", _settings(
        tmp_path, NETHELPER_SMTP_SERVER=f"127.0.0.1:{smtp_server}", NETHELPER_SMTP_SECURITY="none"))
    assert not refused[0].ok and "unencrypted" in refused[0].error


def test_email_starttls_required_by_default(smtp_server, tmp_path):
    """With the default (starttls), a server that can't do TLS is refused - nothing is sent in clear text."""
    f = tmp_path / "site.html"
    f.write_text("x", encoding="utf-8")
    res = dst.send(dst.parse("mailto:a@example.com"), [f], "",
                   _settings(tmp_path, NETHELPER_SMTP_SERVER=f"127.0.0.1:{smtp_server}"))
    assert not res[0].ok and "STARTTLS" in res[0].error
    assert _SMTPHandler.messages == []


def test_automatic_upload_skips_email_for_log_only(tmp_path, monkeypatch):
    """End-of-run log copies don't email (one email per command would be spam); explicit uploads still do."""
    from nethelper import cli

    sent = []
    monkeypatch.setattr(cli.destinations, "send", lambda d, files, sub, s: sent.append(d.kind) or [])
    monkeypatch.setattr(cli, "SETTINGS", _settings(tmp_path))
    log = tmp_path / "run.log"
    log.write_text("x", encoding="utf-8")
    cli.upload_files([log], ["mailto:a@example.com"], quiet=True, auto=True)
    assert sent == []
    cli.upload_files([log], ["mailto:a@example.com"], quiet=True)
    assert sent == ["email"]


# ---------------------------------------------------------------- syslog

def test_syslog_events_and_injection(tmp_path):
    """Results become one event per finding/check; log WARNING lines are forwarded; newlines can't forge lines."""
    results = _results_file(tmp_path, summary="ok\n<13>1 2026-01-01T00:00:00Z fake - - - forged")
    log = tmp_path / "run-x.log"
    log.write_text("2026-11-19 10:00:00,001 DEBUG nethelper.cmd: noise\n"
                   "2026-11-19 10:00:01,002 WARNING nethelper.dest: upload failed\n", encoding="utf-8")
    events = dst.syslog_events([results, log])
    kinds = [e[1] for e in events]
    assert kinds == ["finding", "check", "check", "log"]
    assert events[0][0] == 3 and events[3][0] == 4          # critical finding -> error; WARNING -> warning
    line = dst.format_syslog(*events[1], facility=16)
    assert b"\n" not in line and line.startswith(b"<131>1 ")  # PRI = local0 (16) * 8 + error (3)
    assert b'[nethelper@32473 check="conn.gateway_ping" status="FAIL" section="connectivity"]' in line
    assert dst._sd_value('a"b]c\\') == 'a\\"b\\]c\\\\'       # RFC 5424 escaping inside [ ... ]
    js = dst.format_syslog(*events[1], facility=16, fmt="json")
    assert json.loads(js.split(b" - ", 1)[1])["check"] == "conn.gateway_ping"


def test_syslog_udp_and_tcp_delivery(tmp_path):
    """UDP sends one datagram per event; TCP frames each event as '<length> <message>' (RFC 6587 octet counting)."""
    results = _results_file(tmp_path)
    s = _settings(tmp_path, NETHELPER_DEST_ALLOW_INSECURE="true")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(5)
    res = dst.send(dst.parse(f"syslog://127.0.0.1:{udp.getsockname()[1]}", allow_insecure=True), [results], "", s)
    assert res[0].ok and "3 events" in res[0].remote
    got = [udp.recv(4096) for _ in range(3)]
    udp.close()
    assert all(g.startswith(b"<") and b" NetHelper " in g for g in got)

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    received = bytearray()

    def accept():
        conn, _ = srv.accept()
        with conn:
            while chunk := conn.recv(65536):
                received.extend(chunk)

    t = threading.Thread(target=accept)
    t.start()
    res = dst.send(dst.parse(f"syslog+tcp://127.0.0.1:{srv.getsockname()[1]}", allow_insecure=True), [results], "", s)
    t.join(5)
    srv.close()
    assert res[0].ok
    frames, buf = [], bytes(received)
    while buf:
        length, _, rest = buf.partition(b" ")
        frames.append(rest[:int(length)])
        buf = rest[int(length):]
    assert len(frames) == 3 and all(f.startswith(b"<") for f in frames)


def test_secrets_for_new_destinations_are_masked(tmp_path):
    """The S3 secret key and SMTP password are secrets: masked on display and passed to the log masker."""
    s = _settings(tmp_path, NETHELPER_S3_SECRET_KEY="s3-sekrit-value", NETHELPER_SMTP_PASSWORD="smtp-pw-value")
    assert s.display("NETHELPER_S3_SECRET_KEY") == st.MASK and s.display("NETHELPER_SMTP_PASSWORD") == st.MASK
    assert {"s3-sekrit-value", "smtp-pw-value"} <= set(s.secrets())


# ---------------------------------------------------------------- hardening

def test_upload_does_not_follow_redirects_with_credentials(tmp_path):
    """
    Blocks credential leaks via redirect: an upload server answering 307 to
    another host must NOT cause the bearer token to be sent there.
    """
    leaked = []

    class Thief(http.server.BaseHTTPRequestHandler):
        def do_PUT(self):  # noqa: N802
            leaked.append(self.headers.get("Authorization"))
            self.send_response(201)
            self.end_headers()

        def log_message(self, *a):
            pass

    thief = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Thief)
    threading.Thread(target=thief.serve_forever, daemon=True).start()

    class Redirector(http.server.BaseHTTPRequestHandler):
        def do_PUT(self):  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{thief.server_address[1]}/stolen")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    redir = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=redir.serve_forever, daemon=True).start()
    try:
        f = tmp_path / "a.txt"
        f.write_text("x", encoding="utf-8")
        s = _settings(tmp_path, NETHELPER_DEST_TOKEN="tok-secret")
        res = dst.send(dst.parse(f"http://127.0.0.1:{redir.server_address[1]}/in", allow_insecure=True), [f], "", s)
        assert not res[0].ok and "307" in res[0].error
        assert leaked == []
    finally:
        thief.shutdown()
        redir.shutdown()


@pytest.mark.parametrize("raw", [
    "sftp://host/srv/out%0A",          # URL-encoded trailing newline in a remote path
    "s3://bucket/prefix%0A",
    "mailto:a@example.com%0A%0D",
])
def test_encoded_trailing_newlines_are_rejected(raw):
    """A %0A at the end can't slip past the path/address checks ('$' alone would allow a final newline)."""
    if raw.startswith("mailto:"):
        # The address is trimmed, so the newline is dropped rather than kept - either way none survives.
        assert "\n" not in dst.parse(raw).path and "\r" not in dst.parse(raw).path
        return
    with pytest.raises(dst.DestinationError):
        dst.parse(raw)
