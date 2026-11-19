"""
OS-independent descriptions of the local network configuration.

Each OS collector (windows.py / linux.py / macos.py) fills in these same
classes, so checks never need to know which OS they're on. Every field is
optional-friendly: when an OS can't provide a value it's left as None/empty
rather than guessed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field

# Name/description fragments identifying VPN or tunnel adapters.
VPN_MARKERS = [
    "tun", "tap", "utun", "wg", "ppp", "ipsec", "wireguard", "openvpn", "tap-windows", "wintun",
    "anyconnect", "cisco", "globalprotect", "pangp", "fortinet", "forticlient", "juniper", "pulse",
    "tailscale", "zerotier", "nordlynx", "hamachi", "vpn", "openconnect", "sstp", "l2tp", "ikev2",
]
# Name/description fragments for virtual adapters that aren't real networks.
VIRTUAL_MARKERS = [
    "vethernet", "hyper-v", "virtualbox", "vmware", "vmnet", "docker", "veth", "br-", "virbr",
    "loopback", "bluetooth", "wsl", "npcap", "teredo", "isatap", "6to4", "pseudo", "lxc", "lxd",
]


@dataclass
class Address:
    """One IP address on an interface: address, prefix length, and state flags."""

    ip: str
    prefix: int
    family: int  # 4 or 6
    origin: str | None = None       # dhcp / manual / link-local / slaac / ...
    state: str | None = None        # preferred / duplicate / tentative / deprecated

    @property
    def network(self) -> str:
        """The subnet this address is in, e.g. 192.168.1.0/24."""
        return str(ipaddress.ip_interface(f"{self.ip.split('%')[0]}/{self.prefix}").network)

    @property
    def is_apipa(self) -> bool:
        """169.254.x.x - Windows/macOS self-assign this when DHCP fails."""
        return self.family == 4 and self.ip.startswith("169.254.")

    @property
    def is_link_local(self) -> bool:
        try:
            return ipaddress.ip_address(self.ip.split("%")[0]).is_link_local
        except ValueError:
            return False

    @property
    def is_global(self) -> bool:
        """Usable beyond the local link (private RFC1918 ranges count as usable here)."""
        try:
            ip = ipaddress.ip_address(self.ip.split("%")[0])
        except ValueError:
            return False
        return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast)


@dataclass
class Interface:
    """
    A network adapter. `kind` is a best guess: ethernet / wifi / vpn /
    virtual / loopback / other.
    """

    name: str
    index: int | None = None
    description: str = ""
    mac: str | None = None
    up: bool = False
    mtu: int | None = None
    speed_mbps: float | None = None
    duplex: str | None = None       # full / half / None (unknown)
    kind: str = "other"
    addresses: list[Address] = field(default_factory=list)
    dhcp: bool | None = None
    vlan_id: int | None = None      # 802.1Q tag configured on this interface itself
    vlan_parent: str | None = None  # for VLAN sub-interfaces (eth0.20 -> eth0)
    metric: int | None = None

    @property
    def ipv4(self) -> list[Address]:
        return [a for a in self.addresses if a.family == 4]

    @property
    def ipv6(self) -> list[Address]:
        return [a for a in self.addresses if a.family == 6]

    @property
    def usable(self) -> bool:
        """Up and holding at least one real (non-link-local) address."""
        return self.up and any(a.is_global for a in self.addresses)


@dataclass
class Route:
    """A routing-table entry. destination '0.0.0.0/0' or '::/0' = default route."""

    destination: str
    gateway: str | None
    interface: str | None
    metric: int | None = None
    family: int = 4

    @property
    def is_default(self) -> bool:
        return self.destination in ("0.0.0.0/0", "::/0", "default")


@dataclass
class Neighbor:
    """An ARP (IPv4) or NDP (IPv6) table entry: IP -> MAC on an interface."""

    ip: str
    mac: str | None
    interface: str | None = None
    state: str | None = None


@dataclass
class Connection:
    """A TCP/UDP socket: listening or connected, with owning process if known."""

    proto: str
    local: str
    local_port: int
    remote: str | None = None
    remote_port: int | None = None
    state: str | None = None
    pid: int | None = None
    process: str | None = None


@dataclass
class WifiInfo:
    """Current Wi-Fi association details (any field may be unknown)."""

    interface: str
    ssid: str | None = None
    bssid: str | None = None
    signal_pct: int | None = None
    rssi_dbm: int | None = None
    channel: int | None = None
    band: str | None = None
    radio: str | None = None       # 802.11ax etc.
    rx_mbps: float | None = None
    tx_mbps: float | None = None
    security: str | None = None
    note: str | None = None        # e.g. "location permission required"


@dataclass
class DhcpLease:
    """DHCP lease info for one interface."""

    interface: str
    server: str | None = None
    obtained: str | None = None
    expires: str | None = None


@dataclass
class Snapshot:
    """
    Everything collected about the local machine's networking.
    `raw` keeps the verbatim command outputs for report bundles; `errors`
    lists collectors that failed (shown as notes, never fatal).
    """

    hostname: str = ""
    uptime_s: float | None = None
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    dns_by_interface: dict[str, list[str]] = field(default_factory=dict)
    dns_search: list[str] = field(default_factory=list)
    dhcp: list[DhcpLease] = field(default_factory=list)
    proxy: dict = field(default_factory=dict)
    firewall: dict = field(default_factory=dict)
    wifi: list[WifiInfo] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    hosts_entries: list[tuple[str, str]] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def default_routes(self, family: int = 4) -> list[Route]:
        """Default routes for one address family, lowest metric first."""
        routes = [r for r in self.routes if r.is_default and r.family == family and r.gateway
                  and not is_unspecified(r.gateway)]
        return sorted(routes, key=lambda r: r.metric if r.metric is not None else 9999)

    def default_gateway(self, family: int = 4) -> str | None:
        """IP of the preferred default gateway, or None."""
        routes = self.default_routes(family)
        return routes[0].gateway if routes else None

    def interface(self, name: str | None) -> Interface | None:
        """Look an interface up by name (case-insensitive) or index string."""
        if not name:
            return None
        for iface in self.interfaces:
            if iface.name.lower() == name.lower() or str(iface.index) == name:
                return iface
        return None

    def primary_interface(self) -> Interface | None:
        """The interface carrying the preferred IPv4 default route."""
        routes = self.default_routes(4)
        if routes:
            iface = self.interface(routes[0].interface)
            if iface:
                return iface
        usable = [i for i in self.interfaces if i.usable and i.kind not in ("loopback", "virtual")]
        return usable[0] if usable else None

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("raw", None)
        return data


def classify(name: str, description: str = "", wireless: bool = False) -> str:
    """
    Guess an interface's kind from its name/description (e.g. "Wi-Fi",
    "wlan0", "TAP-Windows Adapter V9", "vEthernet (WSL)").
    """
    text = f"{name} {description}".lower()
    if name.lower() in ("lo", "lo0") or "loopback" in text:
        return "loopback"
    if wireless or any(m in text for m in ("wi-fi", "wifi", "wlan", "wireless", "802.11", "airport")):
        return "wifi"
    # Check VPN before virtual: some VPN adapters also look "virtual".
    words = text.replace("(", " ").replace(")", " ").replace("-", " ").split()
    if any(text.startswith(m) or m in words or (len(m) > 3 and m in text) for m in VPN_MARKERS):
        return "vpn"
    if any(m in text for m in VIRTUAL_MARKERS):
        return "virtual"
    if any(m in text for m in ("ethernet", "eth", "enp", "eno", "ens", "en0", "en1", "gigabit", "realtek", "intel")):
        return "ethernet"
    if name.lower().startswith("en"):
        return "ethernet"
    return "other"


def is_unspecified(ip: str | None) -> bool:
    """
    True for the "unspecified" address (0.0.0.0 or ::), which tools print to
    mean "no gateway / any address / no remote end" rather than a real host.
    """
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_unspecified
    except ValueError:
        return False


def normalize_mac(mac: str | None) -> str | None:
    """Return a MAC as lowercase aa:bb:cc:dd:ee:ff, or None if not a real MAC."""
    if not mac:
        return None
    hexes = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(hexes) != 12 or hexes == "0" * 12:
        return None
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))
