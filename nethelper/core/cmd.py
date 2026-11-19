"""
The single, central place where NetHelper launches external programs
(ping, traceroute, ipconfig, ip, tcpdump, pktmon, PowerShell, ...).

SECURITY - why this file exists:
  Running external commands is the most dangerous thing a diagnostics tool
  does, because a hostname typed by a user could be crafted to smuggle in an
  extra command (e.g. "example.com & del C:\\*"). That attack, *command
  injection*, only works when a command line is handed to a shell (cmd.exe,
  /bin/sh) to interpret. This module therefore:
    1. Never uses a shell. Commands are passed as a list of separate arguments
       (["ping", "-n", "4", host]); the OS receives each argument verbatim and
       nothing in them is interpreted as shell syntax.
    2. Resolves the program to its full path with shutil.which() first, so we
       never accidentally run a look-alike program from the current folder.
    3. Always applies a timeout, so a hung tool can't freeze NetHelper.
  Callers still validate user input (see validate.py) as a second layer.

Other modules must call run()/powershell() here rather than importing
`subprocess` themselves; that keeps the security review surface to one file.

Every command is also written to the run log (arguments, exit code, time,
truncated output), and long-running background programs (Background) are
tracked so stop_all() can shut them down if the user presses Ctrl+C - an
interrupted capture never leaves tcpdump or pktmon running.
"""

from __future__ import annotations

import base64
import locale
import logging
import os
import shutil
import signal
# Security note (B404): deliberate: this module is the audited wrapper around subprocess
import subprocess  # nosec B404
import sys
import tempfile
import time
from dataclasses import dataclass, field

IS_WINDOWS = sys.platform == "win32"

# On Windows, stop each launched console program from flashing up its own
# window (matters when NetHelper itself runs without a console, e.g. as a .pyz).
_CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


@dataclass
class CmdResult:
    """
    Outcome of running one external command.

    Fields:
      argv        - the exact argument list that was run (for reports/logs)
      returncode  - program's exit code; None if it never started or timed out
      stdout      - its normal output, decoded to text
      stderr      - its error output, decoded to text
      duration_ms - how long it ran
      error       - why it couldn't run at all ("not found", "timed out"),
                    or None when it ran to completion (even with a non-zero code)
    """

    argv: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    error: str | None = None
    meta: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True when the program ran and reported success (exit code 0)."""
        return self.error is None and self.returncode == 0

    def transcript(self) -> str:
        """
        A readable record of the command and its output, used as "raw
        evidence" in report bundles so an engineer can see exactly what ran.
        """
        head = "$ " + " ".join(self.argv)
        parts = [head]
        if self.error:
            parts.append(f"[could not run: {self.error}]")
        if self.stdout:
            parts.append(self.stdout.rstrip())
        if self.stderr:
            parts.append("[stderr]\n" + self.stderr.rstrip())
        if self.returncode not in (None, 0):
            parts.append(f"[exit code {self.returncode}]")
        return "\n".join(parts)


def _console_encoding() -> str:
    """
    Work out which text encoding command-line programs use for their output.

    Windows console tools (ipconfig, ping, netsh) write in the legacy "OEM"
    code page (e.g. cp437 in the US), not UTF-8, so decoding them as UTF-8
    would garble accented characters in adapter names. We ask Windows which
    code page that is via its kernel32 API (ctypes = Python's built-in way to
    call functions inside Windows DLLs). Elsewhere the locale's encoding
    (almost always UTF-8) is correct.
    """
    if IS_WINDOWS:
        try:
            import ctypes

            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except (AttributeError, OSError):
            return "cp437"
    return locale.getpreferredencoding(False) or "utf-8"


def which(program: str) -> str | None:
    """
    Return the full path of an installed program, or None if it isn't found.

    On Windows a few tools (pktmon, netsh...) live in System32 and are always
    present; shutil.which searches the PATH the same way a terminal would.
    """
    return shutil.which(program)


log = logging.getLogger("nethelper.cmd")
LOG_OUTPUT_CHARS = 2000  # command output kept in the run log (DEBUG level), per stream


def run(
    argv: list[str],
    timeout: float = 20.0,
    encoding: str | None = None,
    input_text: str | None = None,
) -> CmdResult:
    """
    Run an external program safely, log what happened, and return the result.
    See _run() for the parameters; this wrapper only adds run-log entries
    (arguments, exit code, duration, truncated output).
    """
    result = _run(argv, timeout, encoding, input_text)
    # Don't fill the log with PowerShell's Base64-encoded script blob.
    shown = ["powershell", "-EncodedCommand", "<nethelper script>"] if "-EncodedCommand" in argv else argv
    if result.error:
        log.warning("command %s could not complete: %s (%.0f ms)", shown, result.error, result.duration_ms)
    else:
        log.debug("ran %s -> exit %s in %.0f ms", shown, result.returncode, result.duration_ms)
    if result.stdout and log.isEnabledFor(logging.DEBUG):
        log.debug("stdout of %s:\n%s", shown[0], result.stdout[:LOG_OUTPUT_CHARS])
    if result.stderr and log.isEnabledFor(logging.DEBUG):
        log.debug("stderr of %s:\n%s", shown[0], result.stderr[:LOG_OUTPUT_CHARS])
    return result


def _run(
    argv: list[str],
    timeout: float = 20.0,
    encoding: str | None = None,
    input_text: str | None = None,
) -> CmdResult:
    """
    Run an external program safely and capture its output.

    Parameters:
      argv       - program name followed by its arguments, each a separate
                   list item. NEVER a single string with spaces.
      timeout    - seconds before the program is killed
      encoding   - override output decoding (PowerShell output is UTF-8)
      input_text - optional text sent to the program's standard input

    Returns a CmdResult. Never raises for "program missing" or "timed out";
    those come back as CmdResult.error so checks can report them cleanly.
    """
    if not argv or not isinstance(argv, list):
        raise ValueError("argv must be a non-empty list of arguments")
    # Defence in depth: refuse anything that isn't a plain string argument.
    if not all(isinstance(a, str) for a in argv):
        raise TypeError("every argument must be a string")

    exe = which(argv[0])
    if exe is None:
        return CmdResult(argv=argv, returncode=None, error=f"'{argv[0]}' not found on this system")

    started = time.perf_counter()
    try:
        # shell=False (the default) is what prevents command injection: the
        # arguments go straight to the program, never through cmd.exe or sh.
        # Security note (B603): list argv, no shell, program resolved via which()
        proc = subprocess.run(  # nosec B603
            [exe, *argv[1:]],
            capture_output=True,
            timeout=timeout,
            input=input_text.encode("utf-8") if input_text is not None else None,
            stdin=None if input_text is not None else subprocess.DEVNULL,
            creationflags=_CREATE_NO_WINDOW,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        enc = encoding or _console_encoding()
        partial = (exc.stdout or b"").decode(enc, errors="replace")
        return CmdResult(
            argv=argv,
            returncode=None,
            stdout=partial,
            duration_ms=(time.perf_counter() - started) * 1000,
            error=f"timed out after {timeout:.0f}s",
        )
    except OSError as exc:  # e.g. permission denied executing the binary
        return CmdResult(argv=argv, returncode=None, error=str(exc))

    enc = encoding or _console_encoding()
    return CmdResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=proc.stdout.decode(enc, errors="replace"),
        stderr=proc.stderr.decode(enc, errors="replace"),
        duration_ms=(time.perf_counter() - started) * 1000,
    )


def powershell(script: str, timeout: float = 45.0) -> CmdResult:
    """
    Run a block of PowerShell on Windows and return its output (as UTF-8).

    The script is passed with -EncodedCommand (Base64 of UTF-16LE text), which
    is PowerShell's own mechanism for receiving a script verbatim. It avoids
    every quoting problem and means nothing in the script is re-parsed by a
    shell. Scripts passed here are fixed text written in this codebase; any
    user-supplied value must be validated before being placed in a script.

    -NoProfile skips the user's profile scripts (faster, predictable);
    -NonInteractive makes any prompt fail instead of hanging.
    """
    # Force PowerShell to emit UTF-8 so adapter names with accents decode right.
    full = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n$ProgressPreference='SilentlyContinue'\n" + script
    encoded = base64.b64encode(full.encode("utf-16-le")).decode("ascii")
    result = run(
        ["powershell", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", encoded],
        timeout=timeout,
        encoding="utf-8",
    )
    # Replace the unreadable Base64 blob in the transcript with a short label.
    result.argv = ["powershell", "-Command", "<nethelper script>"]
    return result


class Background:
    """
    A long-running external program (e.g. tcpdump during a packet capture)
    that we start, leave running for a while, then stop gracefully.

    Same safety rules as run(): list arguments, no shell, resolved path.
    """

    def __init__(self, argv: list[str]):
        """Start the program immediately. Raises FileNotFoundError if missing."""
        exe = which(argv[0])
        if exe is None:
            raise FileNotFoundError(f"'{argv[0]}' not found on this system")
        self.argv = argv
        # Output goes to temp files, not pipes: a chatty tool could otherwise
        # fill a pipe buffer and freeze while nobody is reading it.
        self._out = tempfile.TemporaryFile()
        self._err = tempfile.TemporaryFile()
        # Security note (B603): list argv, no shell, program resolved via which()
        self._proc = subprocess.Popen(  # nosec B603
            [exe, *argv[1:]],
            stdout=self._out,
            stderr=self._err,
            stdin=subprocess.DEVNULL,
            creationflags=_CREATE_NO_WINDOW,
        )
        _LIVE.add(self)
        log.info("started background %s (pid %s)", argv, self._proc.pid)

    def running(self) -> bool:
        """True while the program hasn't exited yet."""
        return self._proc.poll() is None

    def wait(self, timeout: float) -> bool:
        """Wait up to `timeout` seconds for it to exit; True if it exited."""
        try:
            self._proc.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def stop(self, grace: float = 5.0) -> CmdResult:
        """
        Ask the program to finish (Ctrl+C equivalent on Linux/macOS so capture
        tools flush their files), then force-kill it if it ignores us.
        """
        if self.running():
            if not IS_WINDOWS:
                self._proc.send_signal(signal.SIGINT)
            else:
                self._proc.terminate()
            try:
                self._proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=grace)
        _LIVE.discard(self)
        enc = _console_encoding()
        texts = []
        for fh in (self._out, self._err):
            try:
                fh.seek(0)
                texts.append(fh.read(1_000_000).decode(enc, errors="replace"))
                fh.close()
            except (OSError, ValueError):
                texts.append("")
        log.info("stopped background %s -> exit %s", self.argv[0], self._proc.returncode)
        return CmdResult(argv=self.argv, returncode=self._proc.returncode, stdout=texts[0], stderr=texts[1])


# Background programs still running - stopped by stop_all() on Ctrl+C/exit.
_LIVE: set[Background] = set()
# Extra cleanup callbacks (e.g. "pktmon stop") registered by modules.
_CLEANUPS: list = []


def register_cleanup(func) -> None:
    """Register a function to run on emergency shutdown (Ctrl+C / crash)."""
    if func not in _CLEANUPS:
        _CLEANUPS.append(func)


def unregister_cleanup(func) -> None:
    """Remove a previously registered cleanup once it's no longer needed."""
    if func in _CLEANUPS:
        _CLEANUPS.remove(func)


def stop_all() -> None:
    """
    Emergency cleanup: stop every background program and run registered
    cleanups, so an interrupted capture never leaves tcpdump or a pktmon
    session running after NetHelper exits.
    """
    for proc in list(_LIVE):
        try:
            proc.stop(grace=2.0)
        except Exception as exc:  # noqa: BLE001 - best effort during shutdown
            log.warning("could not stop background %s: %s", proc.argv[0], exc)
    for func in list(_CLEANUPS):
        try:
            func()
        except Exception:  # noqa: BLE001 - best effort during shutdown
            log.exception("cleanup %s failed", getattr(func, "__name__", func))
    _CLEANUPS.clear()


def in_remote_session() -> bool:
    """
    Best-effort detection of whether NetHelper is running over a remote
    connection (SSH or Remote Desktop). Used to warn before actions like
    restarting a network adapter, which would cut the user off.
    """
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT"):
        return True
    # Windows sets SESSIONNAME to e.g. "RDP-Tcp#3" for Remote Desktop sessions.
    return os.environ.get("SESSIONNAME", "").upper().startswith("RDP-")
