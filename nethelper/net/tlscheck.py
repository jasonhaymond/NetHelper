"""
TLS (HTTPS) handshake inspection.

Connects to host:port, performs a TLS handshake with full certificate
verification against the OS/Python trust store, and reports:
  - whether the certificate is trusted, and if not, why
  - subject, issuer, validity dates, days left, names (SANs) covered
  - negotiated TLS version and cipher suite
  - the certificate chain (Python 3.13+), and
  - signs of TLS interception ("SSL inspection") by a firewall or antivirus,
    which re-signs every site with its own CA - a frequent cause of failures
    in apps that pin certificates or don't trust that CA.

If verification fails we reconnect without verification *only to read* the
certificate for diagnosis; no data is ever sent over that unverified session.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field

from nethelper.net import x509

# Issuer names (organisation/common-name fragments) used by common TLS
# interception products. Seeing one of these as the issuer of a public site's
# certificate means traffic is being decrypted and re-encrypted in transit.
INTERCEPTION_MARKERS = [
    "fortinet", "fortigate", "palo alto", "zscaler", "netskope", "sophos", "cisco umbrella",
    "barracuda", "watchguard", "sonicwall", "untangle", "kaspersky", "avast", "avg ",
    "eset", "bitdefender", "mcafee", "symantec web", "bluecoat", "blue coat", "forcepoint",
    "websense", "checkpoint", "check point", "smoothwall", "lightspeed", "securly", "goguardian",
    "mitmproxy", "charles proxy", "fiddler", "burp", "iboss", "contentkeeper", "cyberoam",
]


@dataclass
class TlsResult:
    """Everything learned from one TLS handshake (see module docstring)."""

    host: str
    port: int
    connected: bool = False
    trusted: bool = False
    verify_error: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    cert: dict = field(default_factory=dict)
    chain: list[dict] = field(default_factory=list)
    name_ok: bool | None = None
    interception: str | None = None
    handshake_ms: float | None = None
    error: str | None = None


def _detect_interception(cert: dict) -> str | None:
    """Return the matching product marker if the issuer looks like a TLS-inspection CA."""
    issuer = " ".join(cert.get("issuer", {}).values()).lower()
    for marker in INTERCEPTION_MARKERS:
        if marker in issuer:
            return marker.strip()
    return None


def inspect(host: str, port: int = 443, timeout: float = 5.0, sni: str | None = None) -> TlsResult:
    """
    Perform the handshake and return a TlsResult. Never raises for network or
    certificate problems; those are reported in the result.
    """
    result = TlsResult(host=host, port=port)
    server_name = sni or host
    ctx = ssl.create_default_context()  # verifies certificate + hostname, TLS 1.2+
    der = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        result.error = f"TCP connect failed: {exc}"
        return result
    result.connected = True
    try:
        started = time.perf_counter()
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            result.handshake_ms = round((time.perf_counter() - started) * 1000, 1)
            result.trusted = True
            result.name_ok = True
            result.tls_version = tls.version()
            result.cipher = (tls.cipher() or (None,))[0]
            der = tls.getpeercert(binary_form=True)
            # Python 3.13+ can return the whole verified chain (leaf -> root).
            chain_fn = getattr(tls, "get_verified_chain", None)
            if chain_fn:
                for item in chain_fn():
                    if not isinstance(item, bytes):  # each entry is DER bytes
                        continue
                    try:
                        c = x509.parse_certificate(item)
                        result.chain.append({"subject": c["subject"], "issuer": c["issuer"],
                                             "not_after": c["not_after"]})
                    except (ValueError, IndexError):
                        pass
    except ssl.SSLCertVerificationError as exc:
        result.verify_error = exc.verify_message or str(exc)
    except (ssl.SSLError, OSError) as exc:
        result.error = f"TLS handshake failed: {exc}"
        return result
    finally:
        raw.close()

    if der is None:
        # Verification failed - reconnect WITHOUT verification purely to read
        # the certificate and explain what's wrong. Nothing is sent over it.
        diag = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        diag.check_hostname = False
        # Security note (B501): diagnostic read of an already-rejected cert; no data sent
        diag.verify_mode = ssl.CERT_NONE  # nosec B501
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw2:
                with diag.wrap_socket(raw2, server_hostname=server_name) as tls:
                    result.tls_version = tls.version()
                    result.cipher = (tls.cipher() or (None,))[0]
                    der = tls.getpeercert(binary_form=True)
        except (ssl.SSLError, OSError) as exc:
            result.error = f"could not read certificate: {exc}"
            return result

    if der:
        try:
            result.cert = x509.parse_certificate(der)
        except (ValueError, IndexError) as exc:
            result.error = f"could not parse certificate: {exc}"
            return result
        names = result.cert.get("san") or [result.cert.get("subject", {}).get("CN", "")]
        result.name_ok = x509.name_matches(server_name, names)
        result.interception = _detect_interception(result.cert)
    return result
