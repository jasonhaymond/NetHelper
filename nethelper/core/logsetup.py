"""
Per-run logging: every NetHelper run writes its own detailed log file.

  <log dir>/run-20261118-140211-512-p4321-quick.log
              date     time   ms   process  command

Each file records, in consistently formatted lines
    2026-11-18 14:02:11,512 DEBUG nethelper.cmd: ran ['ping', ...] -> exit 0 in 41 ms
  - a header: version, OS, Python, elevated?, command line, settings in use
  - every check starting/finishing with status, summary and duration, and its
    details at DEBUG level
  - every external command run (arguments, exit code, duration, truncated output)
  - warnings and full error tracebacks
  - a footer with the exit code and total time

Rotation: after each new log is created, only the newest NETHELPER_LOG_KEEP
run logs (default 40) are kept; older ones are deleted. Retention is counted
in RUNS, not size, so "the last 40 runs" are always available for review via
`nethelper logs` or the Logs menu. Each file is also capped (10 MB) so a
runaway monitor session can't fill the disk.

SECURITY: a filter masks known secret values (e.g. the throughput key) in
every message before it's written; command output is truncated, and no
passwords are handled by NetHelper at all.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import sys
import time
from pathlib import Path

from nethelper import __version__
from nethelper.core.paths import sub_dir

LOG_PREFIX = "run-"
MAX_FILE_BYTES = 10_000_000
_state: dict = {"handler": None, "path": None, "started": None, "stream": None}

# Regex: characters allowed in the command part of a log file name.
_SAFE = re.compile(r"[^A-Za-z0-9_-]+")


class SecretMask(logging.Filter):
    """Replace any registered secret string in a log message with ********."""

    def __init__(self, secrets: list[str]):
        super().__init__()
        self.secrets = [s for s in secrets if s and len(s) >= 3]

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secrets:
            msg = record.getMessage()
            for s in self.secrets:
                msg = msg.replace(s, "********")
            record.msg, record.args = msg, None
        return True


class CappedFileHandler(logging.FileHandler):
    """A file handler that stops writing (with a note) once the file passes MAX_FILE_BYTES."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if self.stream and self.stream.tell() > MAX_FILE_BYTES:
                if not getattr(self, "_capped", False):
                    self._capped = True
                    self.stream.write("... log size limit reached; further lines omitted ...\n")
                return
        except (OSError, ValueError):
            pass
        super().emit(record)


def log_dir(configured: str = "") -> Path:
    """The folder run logs go to (configured NETHELPER_LOG_DIR, else <data dir>/logs)."""
    if configured:
        path = Path(configured).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        return path
    return sub_dir("logs")


def prune(folder: Path, keep: int) -> list[Path]:
    """Delete all but the newest `keep` run logs. Returns the deleted paths."""
    logs = sorted(folder.glob(f"{LOG_PREFIX}*.log"), key=lambda p: p.name, reverse=True)
    deleted = []
    for old in logs[max(keep, 1):]:
        try:
            old.unlink()
            deleted.append(old)
        except OSError:
            continue  # in use by a concurrent run, or permissions - try next time
    return deleted


def start_run(command: str, argv: list[str], settings=None, verbose: bool = False) -> Path | None:
    """
    Open this run's log file, write the header, apply retention, and return
    the file path (None if the log folder isn't writable - NetHelper still runs).
    """
    logger = logging.getLogger("nethelper")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for h in list(logger.handlers):  # a second start_run in one process (tests) replaces the first
        logger.removeHandler(h)
        h.close()
    level_name = settings.get("NETHELPER_LOG_LEVEL") if settings else "debug"
    keep = settings.get("NETHELPER_LOG_KEEP") if settings else 40
    secrets = settings.secrets() if settings else []
    mask = SecretMask(secrets)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    path = None
    try:
        folder = log_dir(settings.get("NETHELPER_LOG_DIR") if settings else "")
        stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}"
        name = _SAFE.sub("_", command or "menu")[:30]
        path = folder / f"{LOG_PREFIX}{stamp}-p{os.getpid()}-{name}.log"
        handler = CappedFileHandler(path, encoding="utf-8")
        handler.setFormatter(fmt)
        handler.setLevel(getattr(logging, level_name.upper(), logging.DEBUG))
        handler.addFilter(mask)
        logger.addHandler(handler)
        _state["handler"] = handler
        prune(folder, keep)
    except OSError as exc:
        print(f"warning: run log unavailable ({exc})", file=sys.stderr)
    if verbose:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(fmt)
        stream.setLevel(logging.DEBUG)
        stream.addFilter(mask)
        logger.addHandler(stream)
        _state["stream"] = stream
    _state["path"], _state["started"] = path, time.monotonic()

    from nethelper.core.privileges import is_elevated

    logger.info("=== NetHelper %s run started: %s ===", __version__, command or "menu")
    logger.info("command line: %s", " ".join(["nethelper", *argv]))
    logger.info("os: %s %s (%s) | python %s | elevated: %s | pid %s", platform.system(), platform.release(),
                platform.version(), platform.python_version(), is_elevated(), os.getpid())
    if settings is not None:
        logger.info("settings file: %s (%s)", settings.path, "found" if settings.path.exists() else "not present")
        for key in sorted(settings.values):
            logger.debug("setting %s=%s [%s]", key, settings.display(key), settings.source[key])
        for problem in settings.problems:
            logger.warning("settings: %s", problem)
    return path


def end_run(exit_code: int) -> None:
    """Write the footer and close the log file."""
    logger = logging.getLogger("nethelper")
    took = time.monotonic() - (_state["started"] or time.monotonic())
    logger.info("=== run finished: exit code %s after %.1f s ===", exit_code, took)
    for key in ("handler", "stream"):
        h = _state.get(key)
        if h:
            h.flush()
            if key == "handler":
                h.close()
            logger.removeHandler(h)
            _state[key] = None


def current_log() -> Path | None:
    """Path of this run's log file (shown to the user on errors)."""
    return _state["path"]


def list_runs(folder: Path) -> list[dict]:
    """Describe saved run logs, newest first: file, command, start time, exit code, size."""
    out = []
    for p in sorted(folder.glob(f"{LOG_PREFIX}*.log"), key=lambda x: x.name, reverse=True):
        parts = p.stem.split("-")  # run, date, time, ms, pPID, command...
        command = "-".join(parts[5:]) if len(parts) > 5 else "?"
        started = f"{parts[1][:4]}-{parts[1][4:6]}-{parts[1][6:]} {parts[2][:2]}:{parts[2][2:4]}:{parts[2][4:]}" if len(parts) > 2 else "?"
        exit_code = "running/aborted"
        try:
            with p.open("rb") as fh:
                fh.seek(max(0, p.stat().st_size - 400))
                tail = fh.read().decode("utf-8", errors="replace")
            m = re.search(r"exit code (\d+)", tail)
            if m:
                exit_code = m.group(1)
        except OSError:
            pass
        out.append({"path": p, "command": command, "started": started, "exit": exit_code, "size": p.stat().st_size})
    return out


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Backwards-compatible helper: start a run log for library/test use."""
    if _state["handler"] is None:
        start_run("library", [], None, verbose)
    return logging.getLogger("nethelper")
