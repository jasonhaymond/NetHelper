"""
Where NetHelper keeps its own files on disk.

  Windows:      %LOCALAPPDATA%\\NetHelper\\
  Linux/macOS:  $XDG_DATA_HOME/nethelper/  (normally ~/.local/share/nethelper/)

Inside that folder:
  logs/        rotating log files (see logsetup.py)
  baselines/   saved "known good" runs for `nethelper baseline`
  captures/    packet capture files when no output path is given
  oui.csv      optional MAC-vendor database downloaded by `nethelper oui update`
  profile.toml optional default site profile (used when --profile isn't given)

Note: under sudo, "home" is root's home, so elevated runs keep separate files.
The NETHELPER_HOME environment variable overrides the location (useful for
tests and portable USB-stick use).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    """Return (and create if needed) NetHelper's data folder."""
    override = os.environ.get("NETHELPER_HOME")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "NetHelper"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "nethelper"
    base.mkdir(parents=True, exist_ok=True)
    return base


def sub_dir(name: str) -> Path:
    """Return (and create) a named sub-folder such as 'logs' or 'baselines'."""
    path = data_dir() / name
    path.mkdir(parents=True, exist_ok=True)
    return path
