"""
Shared pytest fixtures for the NetHelper test suite.

pytest automatically loads this file. "Fixtures" are reusable setup helpers
that a test asks for by naming them as a parameter (e.g. `def test_x(ctx):`).

Isolation: every test runs with NETHELPER_HOME pointed at a fresh temporary
folder, so logs, baselines and captures never touch the real user data folder.
"""

from __future__ import annotations

import shutil
import socket
import ssl
# Security note (B404): tests generate a throwaway certificate with openssl
import subprocess  # nosec B404
import threading
from pathlib import Path

import pytest

from nethelper.core.config import Profile
from nethelper.core.context import Context, Options
from nethelper.core.privileges import Capabilities
from nethelper.system.model import Address, Interface, Neighbor, Route, Snapshot


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Point NetHelper's data folder at a temp dir for every test."""
    monkeypatch.setenv("NETHELPER_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("NETHELPER_PROFILE", raising=False)
    return tmp_path / "home"


def make_caps(elevated: bool = False, os_name: str = "linux", tools: dict | None = None) -> Capabilities:
    """A fake Capabilities object so tests control privilege level and OS."""
    return Capabilities(os=os_name, elevated=elevated, tools=tools or {}, os_detail="test", python="3")


def sample_snapshot() -> Snapshot:
    """A small, realistic system snapshot used by check/verdict tests."""
    eth = Interface(name="eth0", index=2, mac="aa:bb:cc:00:00:01", up=True, mtu=1500, speed_mbps=1000,
                    duplex="full", kind="ethernet",
                    addresses=[Address("192.168.1.50", 24, 4, "dhcp", "preferred")], dhcp=True)
    snap = Snapshot(hostname="testhost", interfaces=[eth],
                    routes=[Route("0.0.0.0/0", "192.168.1.1", "eth0", 100, 4)],
                    dns_servers=["192.168.1.1"],
                    neighbors=[Neighbor("192.168.1.1", "aa:bb:cc:00:00:fe", "eth0", "reachable")])
    return snap


@pytest.fixture
def ctx():
    """A Context with fake caps and a pre-filled snapshot (no real system calls)."""
    c = Context(make_caps(), Profile(), Options(timeout=1.0))
    c._memo["facts"] = ("ok", sample_snapshot())
    return c


def find_openssl() -> str | None:
    """Locate an openssl binary (Git for Windows ships one)."""
    return shutil.which("openssl") or next(
        (p for p in (r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\Program Files\Git\mingw64\bin\openssl.exe")
         if Path(p).exists()), None)


@pytest.fixture(scope="session")
def self_signed_cert(tmp_path_factory):
    """
    Generate a throwaway self-signed certificate for "localhost" (valid 2
    days) with openssl. Skips the dependent tests if openssl isn't available.
    """
    exe = find_openssl()
    if not exe:
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("cert")
    key, crt = d / "key.pem", d / "cert.pem"
    subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),  # nosec B603
                    "-days", "2", "-subj", "/CN=localhost/O=NetHelper Test",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True, timeout=60)
    return key, crt


@pytest.fixture
def tls_server(self_signed_cert):
    """A local TLS server on 127.0.0.1 presenting the self-signed cert. Yields its port."""
    key, crt = self_signed_cert
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(10)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(2)
                    try:
                        tls.recv(1024)
                    except OSError:
                        pass
            except (ssl.SSLError, OSError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()
