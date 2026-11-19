"""
The catalogue of every diagnostic check NetHelper knows about.

Each check is an ordinary Python function in nethelper/checks/*.py, tagged with
the @check(...) *decorator* defined here. (A decorator is a line starting with
"@" above a function; it runs once when the module loads and, here, records the
function in the REGISTRY dictionary along with its metadata.)

The metadata is what makes privilege handling automatic. A check declares:
  - admin:      whether it needs Administrator/root (NO / PARTIAL / YES)
  - platforms:  which OSes it supports
  - modes:      whether it runs in "quick" and/or "full" runs
  - intrusive:  whether it generates noticeable traffic (LAN sweep) and so
                must be explicitly allowed
  - external:   whether it contacts a third-party internet service
                (public IP lookup, speed test) and can be disabled for privacy
The runner reads these and decides, per check, to run / skip / note limits.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:  # imported only for type hints, avoids a circular import
    from nethelper.core.context import Context
    from nethelper.core.result import Outcome


class Admin(str, Enum):
    """How much a check depends on elevated (Administrator/root) rights."""

    NO = "no"            # works fully without elevation
    PARTIAL = "partial"  # runs either way; elevated gives more detail
    YES = "yes"          # cannot run without elevation; skipped otherwise


# Display order and titles of the report sections.
SECTIONS: list[tuple[str, str]] = [
    ("local", "Local host"),
    ("connectivity", "Connectivity"),
    ("dns", "DNS"),
    ("app", "Applications & services"),
    ("lan", "Local network (LAN)"),
    ("layer2", "Switchport & VLAN"),
]
SECTION_TITLES = dict(SECTIONS)


@dataclass(frozen=True)
class CheckSpec:
    """
    Everything NetHelper knows about one check (frozen = read-only once made).

      id          - stable identifier, e.g. "dns.resolvers"
      title       - short human name
      section     - one of the SECTIONS keys
      func        - the function to call: func(ctx) -> Outcome
      modes       - subset of {"quick", "full"}; empty = only run on demand
      admin       - Admin.NO / PARTIAL / YES
      platforms   - OS keys it supports (windows/linux/macos); None = all
      intrusive   - sends scan-like traffic; requires --allow-intrusive
      external    - contacts a third-party internet service
      description - one sentence explaining the check (shown by `nethelper list`)
      timeout     - seconds before the runner gives up on it
      exclusive   - uses a lot of bandwidth (speed test, throughput, sweep):
                    run alone AFTER the parallel checks, so it can't distort
                    their latency/loss measurements (and they can't slow it)
    """

    id: str
    title: str
    section: str
    func: Callable[["Context"], "Outcome"]
    modes: frozenset[str]
    admin: Admin
    platforms: frozenset[str] | None
    intrusive: bool
    external: bool
    description: str
    timeout: float
    exclusive: bool = False


# id -> CheckSpec. Filled in as each nethelper/checks/*.py module is imported.
REGISTRY: dict[str, CheckSpec] = {}


def check(
    id: str,
    title: str,
    section: str,
    modes: tuple[str, ...] = ("full",),
    admin: Admin = Admin.NO,
    platforms: tuple[str, ...] | None = None,
    intrusive: bool = False,
    external: bool = False,
    timeout: float = 60.0,
    exclusive: bool = False,
):
    """
    Decorator that registers a check function. Usage:

        @check("conn.gateway_ping", "Gateway ping", "connectivity", modes=("quick", "full"))
        def gateway_ping(ctx): ...

    The function's own docstring becomes the check's description.
    Registering two checks with the same id is a programming error.
    """
    if section not in SECTION_TITLES:
        raise ValueError(f"unknown section {section!r} for check {id}")

    def wrap(func):
        if id in REGISTRY:
            raise ValueError(f"duplicate check id {id}")
        doc = (func.__doc__ or "").strip().split("\n\n")[0].replace("\n", " ")
        REGISTRY[id] = CheckSpec(
            id=id, title=title, section=section, func=func,
            modes=frozenset(modes), admin=admin,
            platforms=frozenset(platforms) if platforms else None,
            intrusive=intrusive, external=external,
            description=" ".join(doc.split()), timeout=timeout, exclusive=exclusive,
        )
        return func

    return wrap


def load_all() -> dict[str, CheckSpec]:
    """
    Import every checks module so their @check decorators run, then return
    the filled REGISTRY. Safe to call repeatedly (Python imports once).
    """
    # Import order = display order within a section (interfaces last so the
    # Wi-Fi environment scan lists after the basic Wi-Fi check).
    from nethelper.checks import local, connectivity, dns_checks, app, lan, layer2, interfaces  # noqa: F401, I001

    return REGISTRY


def select(mode: str | None = None, ids: list[str] | None = None,
           sections: list[str] | None = None) -> list[CheckSpec]:
    """
    Choose which checks to run.
      mode     - "quick" or "full": every check tagged with that mode
      ids      - explicit check ids (or id prefixes like "dns." / "layer2")
      sections - whole sections, e.g. ["layer2"]
    Result is sorted by section order then registration order.
    """
    load_all()
    chosen: list[CheckSpec] = []
    for spec in REGISTRY.values():
        if mode and mode in spec.modes:
            chosen.append(spec)
        elif ids and any(spec.id == i or spec.id.startswith(i.rstrip(".") + ".") for i in ids):
            chosen.append(spec)
        elif sections and spec.section in sections:
            chosen.append(spec)
    order = {key: n for n, (key, _) in enumerate(SECTIONS)}
    ids_in_order = list(REGISTRY)
    chosen.sort(key=lambda s: (order[s.section], ids_in_order.index(s.id)))
    return chosen
