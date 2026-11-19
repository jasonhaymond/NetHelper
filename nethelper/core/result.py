"""
The standard result record that every NetHelper check produces.

Every diagnostic (ping the gateway, inspect a TLS certificate, read LLDP from
the switch...) returns the same shape of data, so the console printer, the
report writers (JSON/HTML/Markdown), the baseline comparer and the "verdict"
engine can all treat results uniformly without knowing what each check does.

Nothing here touches the network or the disk; it's pure data definitions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    """
    Outcome of a single check.

    Inheriting from `str` means each value is also a plain string ("PASS"),
    which makes JSON output and comparisons straightforward.
    """

    # Security note (B105): "PASS" is a test outcome label, not a password.
    PASS = "PASS"    # nosec B105
    WARN = "WARN"    # works, but something looks wrong or degraded
    FAIL = "FAIL"    # broken - very likely part of the user's problem
    INFO = "INFO"    # informational only; nothing to judge
    SKIP = "SKIP"    # deliberately not run (needs admin, wrong OS, not configured)
    ERROR = "ERROR"  # the check itself crashed - a NetHelper bug or odd environment


# Severity ordering used to pick the "worst" status in a group, and for sorting.
# Higher number = more serious.
SEVERITY = {
    Status.SKIP: 0,
    Status.INFO: 1,
    Status.PASS: 2,
    Status.WARN: 3,
    Status.ERROR: 4,
    Status.FAIL: 5,
}


@dataclass
class Outcome:
    """
    What a check function returns: the judgement plus supporting evidence.

    The runner (core/runner.py) wraps this into a full CheckResult by adding
    the check's id, title, section and how long it took, so individual checks
    only have to describe *what they found*.

    Fields:
      status   - one of the Status values above
      summary  - one human-readable line for the console ("3 ms, 0% loss")
      details  - structured data (dicts/lists/numbers/strings) for reports & JSON
      advice   - plain-English next steps shown when something is wrong
      raw      - raw text output of any external commands run, keyed by a label,
                 kept so a report bundle can include the evidence verbatim
    """

    status: Status
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    advice: list[str] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class CheckResult:
    """
    A finished check, ready to print, save or compare.

    Fields beyond Outcome's:
      check_id     - stable machine id, e.g. "conn.gateway_ping"; used by the
                     verdict rules and baselines, so never rename casually
      title        - human title, e.g. "Gateway ping"
      section      - grouping key, e.g. "connectivity"
      duration_ms  - wall-clock time the check took
      limited      - True when the check was skipped (or ran with reduced
                     detail) purely because we're not elevated; the CLI uses
                     this to note or hide privilege-limited checks
    """

    check_id: str
    title: str
    section: str
    status: Status
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    advice: list[str] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)
    duration_ms: float = 0.0
    limited: bool = False

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to a plain dictionary suitable for json.dumps().

        `asdict` recursively copies dataclass fields; the Status enum is
        replaced by its string value so the JSON stays human-readable.
        """
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CheckResult":
        """
        Rebuild a CheckResult from a dictionary previously produced by
        to_dict() - used when loading a saved baseline or JSON report.
        Unknown keys are ignored so older/newer report files still load.
        """
        known = {f for f in cls.__dataclass_fields__}  # names of our fields
        clean = {k: v for k, v in data.items() if k in known}
        clean["status"] = Status(clean.get("status", "INFO"))
        return cls(**clean)


def worst(statuses: list[Status]) -> Status:
    """
    Return the most serious status from a list (FAIL beats WARN beats PASS...).
    An empty list counts as INFO - "nothing to judge".
    """
    if not statuses:
        return Status.INFO
    return max(statuses, key=lambda s: SEVERITY[s])
