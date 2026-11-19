"""
Regenerate .env.example from the settings definitions (nethelper/core/settings.py).

Every setting, its description, default and group come from SPECS, so the
example file can't drift out of date; a test fails if it does. Run from the
project root after adding or changing a setting:

    python scripts/gen_env_example.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nethelper.core import settings  # noqa: E402 - path set up above

HEADER = "NetHelper settings - EXAMPLE (copy to your .env; see 'nethelper help settings')"


def main() -> int:
    """Write .env.example with every setting at its default (no secrets)."""
    target = ROOT / ".env.example"
    target.write_text(settings.render({}, header=HEADER), encoding="utf-8", newline="\n")
    print(f"wrote {target} ({len(settings.SPECS)} settings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
