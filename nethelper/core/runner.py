"""
Runs a list of checks and returns their results.

Responsibilities:
  1. Gatekeeping - before running each check, compare its declared needs
     (registry.CheckSpec) against reality (privileges.Capabilities, options):
       wrong OS                  -> SKIP "not supported on <os>"
       needs admin, not elevated -> SKIP "requires Administrator/root" (limited=True)
       intrusive, not allowed    -> SKIP "add --allow-intrusive"
       external, --offline       -> SKIP "external lookups disabled"
  2. Parallelism - checks run concurrently in a thread pool (a set of worker
     threads), so a 35-second LLDP listen, a 30-second traceroute and a speed
     test overlap instead of adding up.
  3. Safety net - a check that raises an exception becomes an ERROR result
     (with the error text) instead of crashing the whole run; a check that runs
     past its timeout becomes ERROR "timed out".
  4. Logging - one log line per check with status and duration.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Callable

from nethelper.core.context import Context
from nethelper.core.privileges import elevation_hint
from nethelper.core.registry import Admin, CheckSpec
from nethelper.core.result import CheckResult, Outcome, Status

log = logging.getLogger("nethelper.runner")

# Key a check may put in Outcome.details to say "I ran, but without elevation
# some detail is missing" (e.g. process names for other users' connections).
PRIVILEGE_NOTE = "privilege_note"


def gate(spec: CheckSpec, ctx: Context) -> CheckResult | None:
    """
    Decide whether `spec` may run. Returns a SKIP CheckResult explaining why
    not, or None if it should run.
    """
    def skip(reason: str, limited: bool = False) -> CheckResult:
        return CheckResult(spec.id, spec.title, spec.section, Status.SKIP, reason, limited=limited)

    if spec.platforms and ctx.caps.os not in spec.platforms:
        return skip(f"not supported on {ctx.caps.os}")
    if spec.admin is Admin.YES and not ctx.caps.elevated:
        word = "Administrator" if ctx.caps.os == "windows" else "root"
        return skip(f"requires {word} - {elevation_hint()}", limited=True)
    if spec.intrusive and not ctx.options.allow_intrusive:
        return skip("generates scan traffic; re-run with --allow-intrusive to enable")
    if spec.external and not (ctx.options.external and ctx.profile.external_lookups):
        return skip("external internet lookups are disabled (--offline or profile)")
    return None


def run_one(spec: CheckSpec, ctx: Context) -> CheckResult:
    """
    Run a single check (after gating) and wrap its Outcome in a CheckResult.
    Any exception from the check becomes an ERROR result.
    """
    skipped = gate(spec, ctx)
    if skipped:
        log.info("check %s SKIP (%s)", spec.id, skipped.summary)
        return skipped
    started = time.perf_counter()
    try:
        outcome = spec.func(ctx)
        if not isinstance(outcome, Outcome):
            raise TypeError(f"check {spec.id} returned {type(outcome).__name__}, expected Outcome")
    except Exception as exc:  # noqa: BLE001 - deliberately broad: one bad check must not kill the run
        log.exception("check %s crashed", spec.id)
        outcome = Outcome(Status.ERROR, f"check failed: {type(exc).__name__}: {exc}")
    elapsed = (time.perf_counter() - started) * 1000
    # "Limited" only when the check itself says elevation would have helped
    # (a SKIP for "no wired interface" is not a privilege problem).
    limited = bool(outcome.details.get(PRIVILEGE_NOTE)) and not ctx.caps.elevated
    log.info("check %s %s in %.0f ms", spec.id, outcome.status.value, elapsed)
    return CheckResult(
        check_id=spec.id, title=spec.title, section=spec.section,
        status=outcome.status, summary=outcome.summary, details=outcome.details,
        advice=outcome.advice, raw=outcome.raw, duration_ms=round(elapsed, 1), limited=limited,
    )


def run_checks(
    specs: list[CheckSpec],
    ctx: Context,
    workers: int = 12,
    progress: Callable[[int, int, CheckResult], None] | None = None,
) -> list[CheckResult]:
    """
    Run all `specs` concurrently and return results in the same order as
    `specs` (so output is grouped and stable regardless of finish order).

    `progress(done, total, result)` is called as each check finishes, letting
    the CLI show a live counter.
    """
    if not specs:
        return []
    # Bandwidth-heavy checks run alone afterwards so they don't distort the
    # latency/loss measurements of everything else (see CheckSpec.exclusive).
    parallel = [s for s in specs if not s.exclusive]
    exclusive = [s for s in specs if s.exclusive]
    if exclusive and parallel:
        done: dict[str, CheckResult] = {}
        total = len(specs)

        def relay(n: int, _t: int, result: CheckResult) -> None:
            done[result.check_id] = result
            if progress:
                progress(len(done), total, result)

        first = run_checks(parallel, ctx, workers, relay)
        second = run_checks(exclusive, ctx, 1, relay)
        by_id = {r.check_id: r for r in first + second}
        return [by_id[s.id] for s in specs]
    results: dict[str, CheckResult] = {}
    started_at: dict[str, float] = {}  # check id -> moment a worker actually began it

    def timed(spec: CheckSpec) -> CheckResult:
        """Record the real start time (queued checks start later), then run."""
        started_at[spec.id] = time.monotonic()
        return run_one(spec, ctx)

    # Not a `with` block on purpose: leaving a `with` waits for every thread,
    # which would hang on a check that has blown its timeout.
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="check")
    try:
        futures = {pool.submit(timed, spec): spec for spec in specs}
        pending = set(futures)
        while pending:
            done, pending = wait(pending, timeout=1.0, return_when=FIRST_COMPLETED)
            for fut in done:
                spec = futures[fut]
                results[spec.id] = fut.result()
                if progress:
                    progress(len(results), len(specs), results[spec.id])
            # Give up on (but can't forcibly stop) checks past their timeout;
            # Python threads can't be killed, so the thread finishes in the
            # background and its late result is simply discarded.
            now = time.monotonic()
            for fut in list(pending):
                spec = futures[fut]
                began = started_at.get(spec.id)
                if began is not None and now - began > spec.timeout + 5:
                    pending.discard(fut)
                    results[spec.id] = CheckResult(spec.id, spec.title, spec.section, Status.ERROR,
                                                   f"timed out after {spec.timeout:.0f}s")
                    if progress:
                        progress(len(results), len(specs), results[spec.id])
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return [results[s.id] for s in specs]
