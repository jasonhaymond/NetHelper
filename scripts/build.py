"""
Build the single-file NetHelper: dist/nethelper.pyz

A ".pyz" is a Python *zip application*: the whole nethelper package in one
zip file, with a first line telling Unix-like systems to run it with Python.
Any machine with Python 3.11+ runs it directly:

    python nethelper.pyz quick

NetHelper has no third-party dependencies, so the .pyz is the complete
program. Copy it to a USB stick or a client PC and run it.

Repeatable ("reproducible") build: the same source always produces a
byte-for-byte identical .pyz, on Windows, Linux or macOS, with any Python
3.11+. Anyone can check out a release tag, run this script, and confirm their
SHA-256 matches the published nethelper.pyz.sha256. That proves the download
was built from the public source and nothing else. Everything that would
normally vary between machines is fixed:
  - Timestamps: every entry is dated 1980-01-01 00:00, the earliest date a
    zip can hold, instead of each file's modification time.
  - Order: entries are written in sorted path order, not the order the disk
    lists them.
  - Permissions/OS markers: every entry is marked as a Unix file with mode
    0644 (read/write for owner, read for others), whichever OS builds it.
  - Line endings: text files are written with LF line endings. Git on
    Windows usually checks files out with CRLF, which would change the
    bytes.
  - Compression: entries are *stored* (not compressed). Different Pythons
    ship different compression libraries (Windows Python 3.14 uses zlib-ng,
    Linux distributions use classic zlib), and they produce different
    compressed bytes for the same input. Storing costs size (about 725 KB
    instead of about 250 KB), which is still small enough for any USB stick
    or email.

The archive's start-up file (__main__.py) passes NetHelper's exit code back to
the operating system (0 = all good, 1 = warnings, 2 = failures, 3 = usage
error...). That way scripts and schedulers that run the .pyz see the same exit
codes as `python -m nethelper`.

Usage (from the project root):
    python scripts/build.py

Writes only inside dist/. Cached bytecode (__pycache__, *.pyc) is left out,
so the archive contains source only.
"""

from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# First line of the file: lets `./nethelper.pyz` run directly on Linux/macOS
# (a "shebang" line). Python's zip reader ignores anything before the zip data.
SHEBANG = b"#!/usr/bin/env python3\n"

# The archive's entry point. It mirrors nethelper/__main__.py: run the CLI and
# hand its return value to sys.exit so the process exit code is correct.
MAIN_PY = b"""\
# Start-up file of nethelper.pyz: run the NetHelper command line and pass its
# exit code (0 ok, 1 warnings, 2 failures, 3 usage, 4 internal) to the OS.
import sys

from nethelper.cli import main

sys.exit(main())
"""

# Fixed timestamp for every entry: 1980-01-01 00:00:00, the zip format's
# minimum. Using real file times would change the hash on every checkout.
FIXED_DATE = (1980, 1, 1, 0, 0, 0)

# File types written with their line endings normalised to LF.
TEXT_SUFFIXES = {".py", ".txt", ".toml", ".json", ".md", ".html", ".css", ".js"}


def _entry(name: str) -> zipfile.ZipInfo:
    """
    Make the header for one archive entry with every machine-dependent field fixed.

    Input: the path inside the archive, with forward slashes
    (e.g. "nethelper/cli.py"). Output: a ZipInfo with a fixed date, "Unix"
    as the creating system, mode 0644, and no compression.
    """
    info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
    info.create_system = 3  # 3 = Unix. Python's default is 0 on Windows, 3 elsewhere.
    info.external_attr = 0o100644 << 16  # regular file, rw-r--r--, in the Unix-mode bits
    info.compress_type = zipfile.ZIP_STORED
    return info


def _package_files() -> list[tuple[str, Path]]:
    """
    List the files that go into the archive, in a fixed (sorted) order.

    Output: (path inside the archive, path on disk) pairs for everything under
    nethelper/, minus bytecode caches.
    """
    files = []
    for path in (ROOT / "nethelper").rglob("*"):
        # Skip folders (zip import doesn't need folder entries) and bytecode caches.
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        files.append((path.relative_to(ROOT).as_posix(), path))
    return sorted(files)


def build(target: Path) -> None:
    """
    Write the repeatable .pyz to `target`, replacing any existing file there.

    Side effect: creates or overwrites that one file.
    """
    with target.open("wb") as out:
        out.write(SHEBANG)
        with zipfile.ZipFile(out, "w") as zf:
            zf.writestr(_entry("__main__.py"), MAIN_PY)
            for name, path in _package_files():
                data = path.read_bytes()
                if path.suffix in TEXT_SUFFIXES:
                    data = data.replace(b"\r\n", b"\n")  # CRLF -> LF, see module docstring
                zf.writestr(_entry(name), data)


def main() -> int:
    """Build dist/nethelper.pyz and print its size and version. Returns exit code 0."""
    # Read the version from the line `__version__ = "X.Y.Z"` in nethelper/__init__.py.
    version = re.search(r'__version__ = "([^"]+)"', (ROOT / "nethelper" / "__init__.py").read_text()).group(1)
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    target = dist / "nethelper.pyz"
    build(target)
    print(f"built {target} ({target.stat().st_size // 1024} KB) - NetHelper {version}")
    print(f"run it with: {Path(sys.executable).name} {target.relative_to(ROOT)} quick")
    return 0


if __name__ == "__main__":
    sys.exit(main())
