"""
Tests for the throughput server/client (including its security limits), the
Wi-Fi parsers and channel analysis, output destinations, and source-address
binding for per-interface tests. Network tests use real sockets on 127.0.0.1.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
from pathlib import Path

import pytest

from nethelper.core import destinations as dst
from nethelper.core import settings as st
from nethelper.net import icmp, tcp, throughput, wifi

# ---------------------------------------------------------------- throughput


@pytest.fixture
def tp_server():
    srv = throughput.Server(bind="127.0.0.1", port=0, key="k3y")
    port = srv.start()
    yield port
    srv.stop()


def test_tcp_upload_download_parallel(tp_server):
    """Real TCP upload/download through the protocol, incl. parallel streams, with the correct key."""
    up = throughput.tcp_test("127.0.0.1", tp_server, "upload", 1, key="k3y")
    down = throughput.tcp_test("127.0.0.1", tp_server, "download", 1, streams=2, key="k3y")
    assert up.error is None and up.mbps and up.mbps > 10
    assert down.error is None and len(down.per_stream_mbps) == 2


def test_udp_reports_loss_and_jitter(tp_server):
    """The UDP test counts packets and computes loss/jitter on the server."""
    r = throughput.udp_test("127.0.0.1", tp_server, rate_mbps=5, seconds=1, size=500, key="k3y")
    assert r.error is None and r.udp["received"] > 0 and r.udp["loss_pct"] < 5
    assert "jitter_ms" in r.udp


def test_wrong_or_missing_key_is_rejected(tp_server):
    """Blocks use of a key-protected server without the key (HMAC challenge-response)."""
    assert "authentication failed" in throughput.tcp_test("127.0.0.1", tp_server, "upload", 1, key="wrong").error
    assert "requires a key" in throughput.tcp_test("127.0.0.1", tp_server, "upload", 1).error


def _raw_session(port: int, request: bytes) -> dict:
    """Talk to the server by hand: read the challenge, send `request`, return the reply."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.recv(4096)
        s.sendall(request)
        return json.loads(s.makefile().readline())


def test_server_limits_reject_abusive_requests():
    """Blocks resource abuse: oversized handshakes, out-of-range test lengths and bogus modes are refused."""
    srv = throughput.Server(bind="127.0.0.1", port=0)
    port = srv.start()
    try:
        assert "too long" in _raw_session(port, b"x" * 5000 + b"\n")["error"]
        assert "seconds" in _raw_session(port, b'{"mode":"upload","seconds":3600}\n')["error"]
        assert "mode" in _raw_session(port, b'{"mode":"shell","seconds":1}\n')["error"]
        assert "rate_bps" in _raw_session(port, b'{"mode":"udp","seconds":1,"rate_bps":99999999999999,"size":500}\n')["error"]
    finally:
        srv.stop()


def test_server_available_and_fallback_to_icmp():
    """A port without a NetHelper server is detected; auto_test falls back to an (approximate) ICMP load test."""
    assert not throughput.server_available("127.0.0.1", 1, timeout=1)
    res = throughput.auto_test("127.0.0.1", port=1, seconds=1, directions=("upload",), iperf_port=1)
    assert res["method"] == "icmp-load" and res["results"]["icmp"]["replies"] > 0


# ---------------------------------------------------------------- wifi

NETSH_NETWORKS = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : Office
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 84:78:48:c2:8f:3f
         Signal             : 96%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 44
         Bss Load:
             Connected Stations:         5
             Channel Utilization:        12 (4 %)
    BSSID 2                 : 84:78:48:c2:8f:3e
         Signal             : 80%
         Radio type         : 802.11ax
         Channel            : 6

SSID 2 : Office
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : aa:bb:cc:00:11:22
         Signal             : 70%
         Channel            : 6
"""


def test_netsh_networks_parser_and_evil_twin():
    """netsh scan output -> BSSIDs with signal/channel/band/load; same SSID with Open + WPA2 is flagged."""
    nets = wifi.parse_netsh_networks(NETSH_NETWORKS)
    assert len(nets) == 3
    first = nets[0]
    assert (first.ssid, first.channel, first.band, first.signal_pct, first.stations, first.utilization_pct) == \
        ("Office", 44, "5 GHz", 96, 5, 4)
    assert nets[1].band == "2.4 GHz"  # inferred from the channel when the Band line is missing
    assert wifi.evil_twin_suspects(nets) == [{"ssid": "Office", "security_types": ["OPEN", "PSK"]}]


def test_channel_analysis_excludes_own_radio_and_recommends():
    """Our own AP's extra SSIDs aren't counted as interference; a clean channel is recommended."""
    nets = [wifi.Network("Office", "84:78:48:c2:8f:3f", 44, "5 GHz", 96, -52),
            wifi.Network("Guest", "86:78:48:92:8f:3f", 44, "5 GHz", 95, -52),  # same radio, other SSID
            wifi.Network("Neighbour", "00:11:22:33:44:55", 44, "5 GHz", 70, -65),
            wifi.Network("N2", "00:11:22:33:44:66", 6, "2.4 GHz", 80, -60)]
    a = wifi.analyze_channels(nets, 44, own_bssid="84:78:48:c2:8f:3f")
    assert a["own_radio_bssids_excluded"] == 2
    assert a["strong_aps_on_or_overlapping_current"] == 1
    assert a["recommended_5ghz"] != 44 and a["recommended_24ghz"] in (1, 11)


def test_other_wifi_parsers():
    """nmcli list, iw scan, saved profiles and driver capabilities parse correctly."""
    nm = wifi.parse_nmcli_list("Office:84\\:78\\:48\\:C2\\:8F\\:3F:44:96:WPA2:5220 MHz\n:00\\:11\\:22\\:33\\:44\\:55:1:40::2412 MHz\n")
    assert nm[0].band == "5 GHz" and nm[0].bssid == "84:78:48:c2:8f:3f" and nm[1].ssid == "(hidden)"
    iw = wifi.parse_iw_scan("BSS 00:11:22:33:44:55(on wlan0)\n\tfreq: 2437\n\tsignal: -61.00 dBm\n\tSSID: Cafe\n\tRSN:\t * Version: 1\n")
    assert iw[0].ssid == "Cafe" and iw[0].channel == 6 and iw[0].security == "WPA2/WPA3"
    profiles = "User profiles\n-------------\n    All User Profile     : Home\n    All User Profile     : Work\n"
    assert wifi.parse_netsh_profiles(profiles) == ["Home", "Work"]
    drivers = ("    Radio types supported     : 802.11n 802.11ac\n"
               "    802.11w Management Frame Protection supported : Yes\n   WPA3-Personal CCMP\n")
    caps = wifi.parse_netsh_drivers(drivers)
    assert caps["radio_types"] == ["802.11n", "802.11ac"] and caps["pmf_supported"] and caps["wpa3_supported"]


# ---------------------------------------------------------------- destinations

@pytest.mark.parametrize("raw,kind", [
    ("D:\\NetHelper", "local"), ("Z:", "local"), ("\\\\fs01\\it\\out", "local"), ("/mnt/usb", "local"),
    ("~/reports", "local"), ("file:///srv/out", "local"), ("smb://fs01/it/out", "smb"),
    ("sftp://tech@backup01/srv/out", "sftp"), ("scp://tech@backup01:2222/~/out", "sftp"),
    ("webdavs://jason@cloud.example.com/remote.php/dav/files/jason/x", "webdav"),
    ("https://intake.example.com/upload", "https"), ("ftps://tech@ftp.example.com/out", "ftps"),
])
def test_destination_parsing(raw, kind):
    """Every supported destination form is recognised."""
    assert dst.parse(raw).kind == kind


@pytest.mark.parametrize("raw,why", [
    ("sftp://tech:hunter2@host/x", "passwords"),        # credential in URL
    ("http://host/x", "unencrypted"), ("ftp://host/x", "unencrypted"), ("webdav://host/x", "unencrypted"),
    ("sftp://host/x;rm -rf /", "remote path"),          # command smuggling via remote path
    ("sftp://host/$(id)", "remote path"),
    ("gopher://host/x", "unsupported"),
    ("sftp://-oProxyCommand=calc/x", "hostname"),       # option injection via host
])
def test_destination_rejections(raw, why):
    """Blocks credentials in URLs, unencrypted transports (by default), and injection via host/path."""
    with pytest.raises(Exception) as exc:
        dst.parse(raw)
    text = str(exc.value).lower()
    assert why in text or (why == "hostname" and "host" in text)


def test_insecure_allowed_only_when_enabled():
    """Plain http:// is accepted only with NETHELPER_DEST_ALLOW_INSECURE."""
    assert dst.parse("http://host/x", allow_insecure=True).kind == "https"


def test_subdir_template_is_sanitised():
    """{host}/{date} expands, and path traversal / odd characters are removed."""
    sub = dst.expand_subdir("{host}/../{date}/a:b")
    assert ".." not in sub.split("/") and ":" not in sub and socket.gethostname()[:3] in sub


def test_local_copy_never_overwrites(tmp_path):
    """Copies go into the sub-folder; a second upload of the same name gets a numeric suffix."""
    f = tmp_path / "report.html"
    f.write_text("hi", encoding="utf-8")
    d = dst.parse(str(tmp_path / "out"))
    r1 = dst.send(d, [f], "host1/2026-01-01")
    r2 = dst.send(d, [f], "host1/2026-01-01")
    assert r1[0].ok and r2[0].ok and r1[0].remote != r2[0].remote
    assert Path(r2[0].remote).name == "report-1.html"


class _DavHandler(http.server.BaseHTTPRequestHandler):
    """Minimal WebDAV/HTTP upload server: MKCOL creates folders, PUT/POST stores bodies; requires a token."""

    store: dict = {}

    def _auth(self) -> bool:
        if self.headers.get("Authorization") not in ("Bearer tok", "Basic dTpwdw=="):  # u:pw
            self.send_response(401)
            self.end_headers()
            return False
        return True

    def do_MKCOL(self):  # noqa: N802
        if self._auth():
            code = 405 if self.path in self.store else 201
            self.store[self.path] = b""
            self.send_response(code)
            self.end_headers()

    def do_PUT(self):  # noqa: N802
        if self._auth():
            self.store[self.path] = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(201)
            self.end_headers()

    do_POST = do_PUT

    def log_message(self, *a):
        pass


@pytest.fixture
def dav_server():
    _DavHandler.store = {}
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _DavHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], _DavHandler.store
    srv.shutdown()


def _settings(tmp_path, **values):
    env = tmp_path / "t.env"
    env.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")
    return st.load(str(env))


def test_webdav_upload_creates_folders_and_authenticates(dav_server, tmp_path):
    """WebDAV: folders created level by level (MKCOL), file PUT with Basic auth from NETHELPER_DEST_PASSWORD."""
    port, store = dav_server
    f = tmp_path / "r.html"
    f.write_text("<p>ok</p>", encoding="utf-8")
    s = _settings(tmp_path, NETHELPER_DEST_PASSWORD="pw")
    d = dst.parse(f"webdav://u@127.0.0.1:{port}/dav", allow_insecure=True)
    res = dst.send(d, [f], "pc1/2026-01-01", s)
    assert res[0].ok, res[0].error
    assert store["/dav/pc1"] == b"" and store["/dav/pc1/2026-01-01/r.html"] == b"<p>ok</p>"
    bad = dst.send(d, [f], "x", _settings(tmp_path, NETHELPER_DEST_PASSWORD="wrong"))
    assert not bad[0].ok and "auth" in bad[0].error.lower()


def test_https_put_with_bearer_token(dav_server, tmp_path):
    """HTTPS-style upload: PUT to <url>/<subdir>/<file> with the bearer token."""
    port, store = dav_server
    f = tmp_path / "cap.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1")
    s = _settings(tmp_path, NETHELPER_DEST_TOKEN="tok")
    res = dst.send(dst.parse(f"http://127.0.0.1:{port}/in", allow_insecure=True), [f], "pc1", s)
    assert res[0].ok and store["/in/pc1/cap.pcap"] == b"\xd4\xc3\xb2\xa1"


def test_sftp_uses_batch_mode_without_shell(monkeypatch, tmp_path):
    """SFTP builds a batch script (mkdir/put) and runs sftp with BatchMode and strict host keys - no remote shell."""
    captured = {}

    def fake_run(argv, timeout=0, input_text=None, **_):
        captured["argv"], captured["script"] = argv, input_text
        from nethelper.core.cmd import CmdResult
        return CmdResult(argv=argv, returncode=0)

    monkeypatch.setattr(dst.cmd, "run", fake_run)
    monkeypatch.setattr(dst.cmd, "which", lambda name: "/usr/bin/" + name)
    f = tmp_path / "r.html"
    f.write_text("x", encoding="utf-8")
    res = dst.send(dst.parse("sftp://tech@backup01:2222/srv/out"), [f], "pc1/2026-01-01")
    assert res[0].ok
    assert "BatchMode=yes" in captured["argv"] and "StrictHostKeyChecking=yes" in captured["argv"]
    assert captured["argv"][-1] == "tech@backup01" and "-P" in captured["argv"]
    assert '-mkdir "/srv/out/pc1/2026-01-01"' in captured["script"]
    assert 'put "' in captured["script"] and '"/srv/out/pc1/2026-01-01/r.html"' in captured["script"]


def test_smbclient_keeps_password_off_the_command_line(monkeypatch, tmp_path):
    """smbclient credentials go in a temporary auth file (deleted afterwards), never in argv."""
    seen = {}

    def fake_run(argv, timeout=0, **_):
        seen["argv"] = argv
        auth = argv[argv.index("-A") + 1]
        seen["auth"] = Path(auth).read_text(encoding="utf-8")
        seen["auth_path"] = auth
        from nethelper.core.cmd import CmdResult
        return CmdResult(argv=argv, returncode=0, stdout="")

    monkeypatch.setattr(dst.cmd, "run", fake_run)
    monkeypatch.setattr(dst.cmd, "which", lambda name: "/usr/bin/" + name)
    f = tmp_path / "r.html"
    f.write_text("x", encoding="utf-8")
    s = _settings(tmp_path, NETHELPER_DEST_PASSWORD="S3cretPw")
    res = dst._smbclient(dst.parse("smb://tech@fs01/it/out"), [f], "pc1", s)
    assert res[0].ok and "S3cretPw" not in " ".join(seen["argv"]) and "S3cretPw" in seen["auth"]
    assert not Path(seen["auth_path"]).exists()


def test_cli_upload_and_dest_commands(tmp_path, capsys):
    """`dest add/test/list` and `upload --to` work end to end with a local folder destination."""
    from nethelper import cli

    env = tmp_path / ".env"
    out = tmp_path / "dest"
    assert cli.main(["dest", "add", str(out), "--env", str(env), "--no-color"]) == 0
    assert cli.main(["dest", "test", "--env", str(env), "--no-color"]) == 0
    f = tmp_path / "a.txt"
    f.write_text("x", encoding="utf-8")
    assert cli.main(["upload", str(f), "--env", str(env), "--no-color", "--subdir", "s1"]) == 0
    assert (out / "s1" / "a.txt").exists()
    assert cli.main(["dest", "add", "sftp://u:p@h/x", "--env", str(env), "--no-color"]) == 3


# ---------------------------------------------------------------- source binding

def test_tcp_and_icmp_source_binding():
    """Per-interface tests bind to a local address: TCP connect and ping from 127.0.0.1 succeed."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        assert tcp.connect("127.0.0.1", srv.getsockname()[1], timeout=3, source="127.0.0.1").state == "open"
    finally:
        srv.close()
    assert icmp.echo("127.0.0.1", timeout=2, source="127.0.0.1").status == icmp.OK
    assert "-S" in icmp.system_ping_argv("1.1.1.1", False, 1, 32, None, False, "10.0.0.5") or \
        "-I" in icmp.system_ping_argv("1.1.1.1", False, 1, 32, None, False, "10.0.0.5")


def test_unknown_interface_is_a_clear_usage_error(ctx):
    """Asking for an interface that doesn't exist lists the real ones instead of silently testing nothing."""
    from nethelper import cli

    with pytest.raises(cli.UsageError) as exc:
        cli.check_interfaces(["Nope"], ctx.facts)
    assert "eth0" in str(exc.value)
