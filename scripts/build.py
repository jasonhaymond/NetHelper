"""
Build a single-file, double-clickable-ish NetHelper: dist/nethelper.pyz

A ".pyz" is a Python *zip application* (stdlib `zipapp`): the whole nethelper
package zipped into one file that any machine with Python 3.11+ runs directly:

    python nethelper.pyz quick

Because NetHelper has no third-party dependencies, the .pyz is the complete
program - copy it to a USB stick or a client PC and run it.

Usage (from the project root):
    python scripts/build.py

Writes only inside dist/. Cached bytecode (__pycache__) is excluded so the
archive is small and contains source only.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    """Copy the package to a temp dir, zip it with an entry point, report the result."""
    version = re.search(r'__version__ = "([^"]+)"', (ROOT / "nethelper" / "__init__.py").read_text()).group(1)
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    target = dist / "nethelper.pyz"
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / "app"
        shutil.copytree(ROOT / "nethelper", staging / "nethelper",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        # "nethelper.cli:main" = call main() in nethelper/cli.py when the archive runs.
        zipapp.create_archive(staging, target, interpreter="/usr/bin/env python3",
                              main="nethelper.cli:main", compressed=True)
    print(f"built {target} ({target.stat().st_size // 1024} KB) - NetHelper {version}")
    print(f"run it with: {Path(sys.executable).name} {target.relative_to(ROOT)} quick")
    return 0


if __name__ == "__main__":
    sys.exit(main())
