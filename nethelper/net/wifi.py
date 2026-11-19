"""
Wi-Fi tools: current connection, nearby-network scan, channel congestion
analysis, signal/roaming monitor, saved profiles and adapter capabilities.

Per OS (all work without elevation unless noted):
  Windows  netsh wlan show interfaces / networks mode=bssid / profiles / drivers.
           Windows caches scan results, so a fresh scan is first requested
           through the Native Wi-Fi API (WlanScan in wlanapi.dll via ctypes).
           Windows 11 requires Location permission for SSID/BSSID details.
  Linux    nmcli (NetworkManager) - `dev wifi list --rescan yes`; falls back
           to `iw dev <if> scan` (root) where NetworkManager isn't used.
  macOS    system_profiler SPAirPortDataType (current + nearby networks).
           SSIDs may be hidden unless Location Services are allowed.

Wi-Fi names and other broadcast fields are chosen by whoever runs the access
point - untrusted text - so everything is sanitised before display.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from nethelper.core import cmd, validate
from nethelper.system import linux as linux_sys
from nethelper.system import macos as macos_sys
from nethelper.system import windows as windows_sys
from nethelper.system.model import WifiInfo, normalize_mac

log = logging.getLogger("nethelper.wifi")

# Non-overlapping 2.4 GHz channels and the 5 GHz channels usable without DFS radar checks.
CHANNELS_24_CLEAN = (1, 6, 11)
CHANNELS_5_NON_DFS = (36, 40, 44, 48, 149, 153, 157, 161, 165)


@dataclass
class Network:
    """One access point (BSSID) seen in a scan."""

    ssid: str
    bssid: str | None = None
    channel: int | None = None
    band: str | None = None
    signal_pct: int | None = None
    rssi_dbm: int | None = None
    security: str | None = None
    radio: str | None = None
    utilization_pct: int | None = None  # channel busy-ness reported by the AP (BSS Load), if any
    stations: int | None = None         # clients connected to that AP (BSS Load), if any


def band_for(channel: int | None) -> str | None:
    """Infer the band from a channel number (1-14 = 2.4 GHz; higher = 5 GHz; 6 GHz needs the OS to say so)."""
    if channel is None:
        return None
    return "2.4 GHz" if channel <= 14 else "5 GHz"


def pct_to_dbm(pct: int) -> int:
    """Approximate dBm from a 0-100% quality figure (Windows/nmcli scale: 0% = -100 dBm, 100% = -50 dBm)."""
    return int(pct / 2 - 100)


# ---------------------------------------------------------------------------
# Parsers (pure functions, unit-tested with captured output)
# ---------------------------------------------------------------------------

# Regex: "SSID 3 : Office Guest" (network header) and "BSSID 2   : aa:bb:..." (access point header).
_SSID = re.compile(r"^SSID \d+\s*:\s?(.*)$")
_BSSID = re.compile(r"^\s+BSSID \d+\s*:\s*([0-9a-fA-F:]{17})")
# Regex: "Key : Value" pairs with the key indented (leading spaces), e.g. "   Signal   : 96%".
_KV = re.compile(r"^\s+([^:]+?)\s*:\s*(.*?)\s*$")


def parse_netsh_networks(text: str) -> list[Network]:
    """Parse `netsh wlan show networks mode=bssid` (English labels)."""
    out: list[Network] = []
    ssid, security, current = "", None, None
    for line in text.splitlines():
        m = _SSID.match(line)
        if m:
            ssid, security, current = validate.safe_text(m.group(1).strip(), 64), None, None
            continue
        m = _BSSID.match(line)
        if m:
            current = Network(ssid=ssid or "(hidden)", bssid=normalize_mac(m.group(1)), security=security)
            out.append(current)
            continue
        m = _KV.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if key == "authentication":
            security = value
            if current:
                current.security = value
        elif current is None:
            continue
        elif key == "signal" and value.rstrip("%").isdigit():
            current.signal_pct = int(value.rstrip("%"))
            current.rssi_dbm = pct_to_dbm(current.signal_pct)
        elif key == "radio type":
            current.radio = value
        elif key == "band":
            current.band = value
        elif key == "channel" and value.isdigit():
            current.channel = int(value)
        elif key == "channel utilization":
            m2 = re.search(r"\((\d+)\s*%\)", value)  # e.g. "12 (4 %)" -> 4
            if m2:
                current.utilization_pct = int(m2.group(1))
        elif key == "connected stations" and value.isdigit():
            current.stations = int(value)
    for n in out:
        n.band = n.band or band_for(n.channel)
    return out


def parse_nmcli_list(text: str) -> list[Network]:
    """
    Parse `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY,FREQ dev wifi list`.
    Terse mode separates fields with ':' and escapes literal colons as '\\:'.
    """
    out = []
    for line in text.splitlines():
        fields = [f.replace("\\:", ":") for f in re.split(r"(?<!\\):", line)]
        if len(fields) < 6:
            continue
        n = Network(ssid=validate.safe_text(fields[0], 64) or "(hidden)", bssid=normalize_mac(fields[1]),
                    security=fields[4] or "Open")
        try:
            n.channel = int(fields[2])
            n.signal_pct = int(fields[3])
            n.rssi_dbm = pct_to_dbm(n.signal_pct)
            freq = int(fields[5].split()[0])
            n.band = "2.4 GHz" if freq < 3000 else ("5 GHz" if freq < 5925 else "6 GHz")
        except (ValueError, IndexError):
            n.band = band_for(n.channel)
        out.append(n)
    return out


def parse_iw_scan(text: str) -> list[Network]:
    """Parse `iw dev <if> scan` (root): BSS blocks with SSID, freq, signal, security."""
    out: list[Network] = []
    cur: Network | None = None
    for line in text.splitlines():
        m = re.match(r"^BSS ([0-9a-f:]{17})", line)  # e.g. "BSS aa:bb:cc:dd:ee:ff(on wlan0)"
        if m:
            cur = Network(ssid="(hidden)", bssid=normalize_mac(m.group(1)), security="Open")
            out.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("SSID:"):
            cur.ssid = validate.safe_text(s[5:].strip(), 64) or "(hidden)"
        elif s.startswith("freq:"):
            freq = float(s.split()[1])
            cur.band = "2.4 GHz" if freq < 3000 else ("5 GHz" if freq < 5925 else "6 GHz")
            cur.channel = linux_sys._freq_to_channel(freq)
        elif s.startswith("signal:"):
            cur.rssi_dbm = int(float(s.split()[1]))
            cur.signal_pct = max(0, min(100, 2 * (cur.rssi_dbm + 100)))
        elif s.startswith("RSN:"):
            cur.security = "WPA2/WPA3"
        elif s.startswith("WPA:") and cur.security == "Open":
            cur.security = "WPA"
    return out


def parse_airport_networks(text: str) -> list[Network]:
    """Parse nearby networks from `system_profiler -json SPAirPortDataType` (macOS)."""
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for entry in data.get("SPAirPortDataType", []):
        for iface in entry.get("spairport_airport_interfaces", []):
            nets = list(iface.get("spairport_airport_other_local_wireless_networks", []))
            if iface.get("spairport_current_network_information"):
                nets.append(iface["spairport_current_network_information"])
            for n in nets:
                net = Network(ssid=validate.safe_text(str(n.get("_name", "(hidden)")), 64),
                              security=n.get("spairport_security_mode"), radio=n.get("spairport_network_phymode"))
                m = re.match(r"(\d+)\s*\(([\d.]+)GHz", str(n.get("spairport_network_channel", "")))
                if m:
                    net.channel, net.band = int(m.group(1)), m.group(2) + " GHz"
                sig = re.match(r"(-?\d+)\s*dBm", str(n.get("spairport_signal_noise", "")))
                if sig:
                    net.rssi_dbm = int(sig.group(1))
                    net.signal_pct = max(0, min(100, 2 * (net.rssi_dbm + 100)))
                out.append(net)
    return out


def parse_netsh_profiles(text: str) -> list[str]:
    """Saved Wi-Fi profile names from `netsh wlan show profiles` (no keys are ever read)."""
    names = []
    for line in text.splitlines():
        if ":" in line and "profile" in line.lower().split(":")[0]:
            name = line.split(":", 1)[1].strip()
            if name and name != "<None>":
                names.append(validate.safe_text(name, 64))
    return names


def parse_netsh_drivers(text: str) -> dict:
    """Key adapter capabilities from `netsh wlan show drivers`."""
    info: dict = {}
    for line in text.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if key in ("driver", "vendor", "version", "date"):
            info[key] = value
        elif key == "radio types supported":
            info["radio_types"] = value.split()
        elif key.startswith("802.11w"):
            info["pmf_supported"] = value.lower() == "yes"
    if "WPA3" in text:
        info["wpa3_supported"] = True
    return info


# ---------------------------------------------------------------------------
# Windows: request a fresh scan via the Native Wi-Fi API
# ---------------------------------------------------------------------------

def _windows_trigger_scan(wait: float = 4.0) -> bool:
    """
    Ask every Wi-Fi adapter to rescan (WlanScan), then wait for results.
    Best effort: returns False if the WLAN service/API isn't available.
    """
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("d1", ctypes.c_ulong), ("d2", ctypes.c_ushort), ("d3", ctypes.c_ushort), ("d4", ctypes.c_ubyte * 8)]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [("guid", GUID), ("desc", ctypes.c_wchar * 256), ("state", ctypes.c_uint)]

        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [("count", wintypes.DWORD), ("index", wintypes.DWORD), ("items", WLAN_INTERFACE_INFO * 64)]

        api = ctypes.WinDLL("wlanapi.dll")
        handle, version = wintypes.HANDLE(), wintypes.DWORD()
        if api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
            return False
        try:
            plist = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
            if api.WlanEnumInterfaces(handle, None, ctypes.byref(plist)) != 0:
                return False
            try:
                count = min(plist.contents.count, 64)
                for i in range(count):
                    api.WlanScan(handle, ctypes.byref(plist.contents.items[i].guid), None, None, None)
            finally:
                api.WlanFreeMemory(plist)
        finally:
            api.WlanCloseHandle(handle, None)
        time.sleep(wait)  # scans take ~2-4 s; results then appear in netsh output
        return True
    except (OSError, AttributeError) as exc:
        log.debug("WlanScan unavailable: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Networks seen, how the scan was done, and any note (e.g. permissions)."""

    networks: list[Network] = field(default_factory=list)
    method: str = ""
    note: str | None = None
    raw: str = ""


def current() -> list[WifiInfo]:
    """Current Wi-Fi association(s), using the same parsers as the system collectors."""
    if sys.platform == "win32":
        res = cmd.run(["netsh", "wlan", "show", "interfaces"], timeout=15)
        return windows_sys.parse_netsh_wlan(res.stdout)
    if sys.platform == "darwin":
        res = cmd.run(["system_profiler", "-json", "SPAirPortDataType"], timeout=30)
        return macos_sys.parse_airport_json(res.stdout)
    infos = []
    if cmd.which("nmcli"):
        res = cmd.run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY,DEVICE", "dev", "wifi"], timeout=15)
        infos = linux_sys.parse_nmcli_wifi(res.stdout)
    if not infos and cmd.which("iw"):
        dev = cmd.run(["iw", "dev"], timeout=10)
        for name in re.findall(r"Interface (\S+)", dev.stdout):
            info = linux_sys.parse_iw_link(cmd.run(["iw", "dev", name, "link"], timeout=10).stdout, name)
            if info:
                infos.append(info)
    return infos


def scan(rescan: bool = True) -> ScanResult:
    """Scan for nearby networks with the best method for this OS."""
    res = ScanResult()
    if sys.platform == "win32":
        if rescan:
            _windows_trigger_scan()
        out = cmd.run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=20)
        res.method, res.raw = "netsh", out.transcript()
        res.networks = parse_netsh_networks(out.stdout)
        text = (out.stdout + out.stderr).lower()
        if not res.networks and "location" in text:
            res.note = "Windows needs Location permission for Wi-Fi scans (Settings > Privacy & security > Location)"
        elif not res.networks and ("not running" in text or "no wireless" in text or out.error):
            res.note = "no Wi-Fi adapter or WLAN service (WlanSvc) not running"
    elif sys.platform == "darwin":
        out = cmd.run(["system_profiler", "-json", "SPAirPortDataType"], timeout=40)
        res.method, res.raw = "system_profiler", out.transcript()
        res.networks = parse_airport_networks(out.stdout)
        if any(n.ssid in ("<redacted>", "") for n in res.networks):
            res.note = "macOS hides SSIDs unless Location Services are allowed for your terminal app"
    else:
        if cmd.which("nmcli"):
            out = cmd.run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY,FREQ", "dev", "wifi", "list",
                           "--rescan", "yes" if rescan else "no"], timeout=30)
            res.method, res.raw = "nmcli", out.transcript()
            res.networks = parse_nmcli_list(out.stdout)
        if not res.networks and cmd.which("iw"):
            dev = cmd.run(["iw", "dev"], timeout=10)
            for name in re.findall(r"Interface (\S+)", dev.stdout):
                out = cmd.run(["iw", "dev", validate.interface(name), "scan"], timeout=30)
                res.method, res.raw = "iw", out.transcript()
                res.networks += parse_iw_scan(out.stdout)
                if "Operation not permitted" in out.stderr:
                    res.note = "iw scan needs root - run with sudo (or install NetworkManager/nmcli)"
        if not res.method:
            res.note = "no Wi-Fi scanning tool found (install NetworkManager or iw)"
    res.networks.sort(key=lambda n: -(n.signal_pct or 0))
    log.info("wifi scan via %s: %d BSSIDs%s", res.method, len(res.networks), f" ({res.note})" if res.note else "")
    return res


def profiles() -> tuple[list[str], str]:
    """Saved Wi-Fi network names (never passwords). Returns (names, method)."""
    if sys.platform == "win32":
        return parse_netsh_profiles(cmd.run(["netsh", "wlan", "show", "profiles"], timeout=15).stdout), "netsh"
    if sys.platform == "darwin":
        names = []
        for dev in ("en0", "en1"):
            out = cmd.run(["networksetup", "-listpreferredwirelessnetworks", dev], timeout=10)
            names += [validate.safe_text(ln.strip(), 64) for ln in out.stdout.splitlines()[1:] if ln.strip()]
        return names, "networksetup"
    if cmd.which("nmcli"):
        out = cmd.run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], timeout=10)
        return [validate.safe_text(ln.rsplit(":", 1)[0].replace("\\:", ":"), 64)
                for ln in out.stdout.splitlines() if ln.endswith(":802-11-wireless")], "nmcli"
    return [], "unsupported"


def adapter_capabilities() -> dict:
    """Wi-Fi adapter driver/capabilities (Windows only; empty elsewhere)."""
    if sys.platform != "win32":
        return {}
    return parse_netsh_drivers(cmd.run(["netsh", "wlan", "show", "drivers"], timeout=15).stdout)


def same_radio(a: str | None, b: str | None) -> bool:
    """
    Heuristic: do two BSSIDs belong to the same physical access point radio?
    APs broadcasting several SSIDs (Internal/Guest/IoT) derive extra BSSIDs
    from one base MAC, typically changing only the first octet (locally
    administered bit) and/or the 4th octet, keeping octets 2-3 and 5-6.
    Those extra SSIDs share the radio, so they are not interference.
    """
    if not a or not b:
        return False
    pa, pb = a.split(":"), b.split(":")
    return len(pa) == len(pb) == 6 and pa[1:3] == pb[1:3] and pa[4:] == pb[4:]


def analyze_channels(networks: list[Network], current_channel: int | None = None,
                     strong_dbm: int = -75, own_bssid: str | None = None) -> dict:
    """
    Channel congestion analysis.

    For each band, counts access points per channel, weighting stronger ones
    more (a neighbour at -50 dBm interferes far more than one at -85).
    2.4 GHz channels overlap: an AP on channel 3 interferes with 1-5 (±4 channels),
    which is why only 1, 6 and 11 are recommended. BSSIDs that are the same
    radio as the connected one (own_bssid; see same_radio) are excluded, as
    they are this AP's own extra SSIDs. Returns per-channel scores, how
    crowded the current channel is, and a recommendation.
    """
    own = [n for n in networks if own_bssid and same_radio(n.bssid, own_bssid)]
    networks = [n for n in networks if n not in own]
    def weight(n: Network) -> float:
        rssi = n.rssi_dbm if n.rssi_dbm is not None else -80
        return max(0.1, (rssi + 100) / 50)  # -50 dBm -> 1.0, -90 dBm -> 0.2

    score24: dict[int, float] = defaultdict(float)
    score5: dict[int, float] = defaultdict(float)
    count: dict[int, int] = defaultdict(int)
    for n in networks:
        if n.channel is None:
            continue
        count[n.channel] += 1
        if (n.band or "").startswith("2.4"):
            for ch in range(1, 14):
                if abs(ch - n.channel) <= 4:  # overlapping 20 MHz channels
                    score24[ch] += weight(n) * (1 - abs(ch - n.channel) / 5)
        elif (n.band or "").startswith("5"):
            score5[n.channel] += weight(n)
    rec24 = min(CHANNELS_24_CLEAN, key=lambda c: score24.get(c, 0.0))
    rec5 = min(CHANNELS_5_NON_DFS, key=lambda c: score5.get(c, 0.0))
    strong_same = [n for n in networks if current_channel and n.channel is not None
                   and (abs(n.channel - current_channel) <= 4 if current_channel <= 14 else n.channel == current_channel)
                   and (n.rssi_dbm or -100) >= strong_dbm]
    return {
        "aps_per_channel": dict(sorted(count.items())),
        "score_24ghz": {c: round(score24.get(c, 0.0), 2) for c in CHANNELS_24_CLEAN},
        "score_5ghz": {c: round(score5.get(c, 0.0), 2) for c in CHANNELS_5_NON_DFS},
        "recommended_24ghz": rec24,
        "recommended_5ghz": rec5,
        "current_channel": current_channel,
        "strong_aps_on_or_overlapping_current": len(strong_same),
        "own_radio_bssids_excluded": len(own),
    }


def evil_twin_suspects(networks: list[Network]) -> list[dict]:
    """
    SSIDs broadcast with DIFFERENT security types (e.g. 'Office' as WPA2 and
    as Open) - a classic sign of a rogue 'evil twin' access point, or of a
    misconfigured AP. Legitimate mixed WPA2/WPA3 transition setups are ignored.
    """
    by_ssid: dict[str, set[str]] = defaultdict(set)
    for n in networks:
        if n.ssid and n.ssid != "(hidden)":
            sec = (n.security or "?").upper()
            family = "OPEN" if "OPEN" in sec or sec in ("", "--") else ("ENT" if "ENTERPRISE" in sec or "802.1X" in sec else "PSK")
            by_ssid[n.ssid].add(family)
    return [{"ssid": s, "security_types": sorted(t)} for s, t in by_ssid.items() if len(t) > 1]


def to_dicts(networks: list[Network]) -> list[dict]:
    """Plain dicts for reports/JSON."""
    return [asdict(n) for n in networks]
