"""
Tests for scripts/build.py, which builds the single-file dist/nethelper.pyz.

They prove:
  - The build is repeatable: the same source gives a byte-identical .pyz. A
    published SHA-256 can therefore be checked by anyone rebuilding from the
    release tag, which is how users confirm a download wasn't tampered with.
  - Machine-dependent details (file times, Windows CRLF line endings) don't
    leak into the archive.
  - The .pyz passes NetHelper's exit code to the operating system. Otherwise
    a script or scheduler running the .pyz would see "success" (0) even when
    a check failed or the command was wrong.

The builds write only to pytest's temporary folder (tmp_path), never to dist/.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess  # nosec B404 - tests run our own built file with a fixed argv
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_build():
    """Import scripts/build.py as a module (scripts/ isn't a package)."""
    spec = importlib.util.spec_from_file_location("nethelper_build", ROOT / "scripts" / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = _load_build()


@pytest.fixture(scope="module")
def pyz(tmp_path_factory) -> Path:
    """One .pyz built into a temporary folder, shared by the tests below."""
    target = tmp_path_factory.mktemp("build") / "nethelper.pyz"
    build.build(target)
    return target


def _sha256(path: Path) -> str:
    """Hex SHA-256 of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_build_is_byte_for_byte_repeatable(pyz, tmp_path):
    """Two builds of the same source are identical, even after the source files' times change."""
    first = _sha256(pyz)
    # Touch a source file's modification time. A non-repeatable build (like
    # zipapp's default) stores file times, so its hash would change here.
    source = ROOT / "nethelper" / "__init__.py"
    stat = source.stat()
    try:
        os.utime(source, (stat.st_atime, stat.st_mtime + 3600))
        again = tmp_path / "again.pyz"
        build.build(again)
    finally:
        os.utime(source, (stat.st_atime, stat.st_mtime))  # put the original time back
    assert _sha256(again) == first


def test_archive_entries_have_fixed_metadata(pyz):
    """Every entry has the fixed date, Unix mode 0644, no compression, sorted order, and no bytecode."""
    with zipfile.ZipFile(pyz) as zf:
        infos = zf.infolist()
        names = [i.filename for i in infos]
    assert names[0] == "__main__.py"
    assert names[1:] == sorted(names[1:])
    assert "nethelper/cli.py" in names
    assert not [n for n in names if "__pycache__" in n or n.endswith(".pyc")]
    for info in infos:
        assert info.date_time == build.FIXED_DATE
        assert info.create_system == 3
        assert info.external_attr == 0o100644 << 16
        assert info.compress_type == zipfile.ZIP_STORED


def test_text_files_are_stored_with_lf_line_endings(pyz):
    """CRLF line endings (Git's usual Windows checkout) are normalised, so Windows and Linux builds match."""
    with zipfile.ZipFile(pyz) as zf:
        for name in zf.namelist():
            if name.endswith(".py"):
                assert b"\r\n" not in zf.read(name), name


def test_pyz_passes_exit_codes_to_the_os(pyz):
    """`--version` exits 0 and an unknown command exits 3 (usage error), the same as `python -m nethelper`."""
    ok = subprocess.run([sys.executable, "-I", str(pyz), "--version"],  # nosec B603 - fixed argv, our own file
                        capture_output=True, text=True, timeout=60, check=False)
    assert ok.returncode == 0
    assert ok.stdout.strip().startswith("NetHelper ")
    bad = subprocess.run([sys.executable, "-I", str(pyz), "nosuchcommand"],  # nosec B603 - fixed argv, our own file
                         capture_output=True, text=True, timeout=60, check=False)
    assert bad.returncode == 3
