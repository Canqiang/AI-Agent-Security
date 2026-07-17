"""Transition-aware wait for a freshly pushed kernel version's commit-run.

Pure: all time + status access is injected, so it is fully unit-testable and
carries no Kaggle/sleep dependency. This is the fix for the 2026-06-23 bug where
a version-blind kernels_status returned a STALE "complete" and the submit fired
before the pushed version had run.
"""

from __future__ import annotations

from typing import Callable

_FAIL_STATES = {"error", "failed", "cancelled"}


def wait_for_fresh_complete(
    *,
    poll_status: Callable[[], str],
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    min_floor_s: float,
    timeout_s: float,
    poll_seconds: float,
    poll_error_grace_s: float = 0.0,
) -> dict:
    start = monotonic()
    saw_noncomplete = False
    error_streak_start: float | None = None
    while True:
        try:
            raw = str(poll_status() or "").strip().lower()
        except Exception as exc:
            # A brand-new kernel's session can 403/404 for a short window right
            # after creation (a half-created-state race on Kaggle's side, not a
            # real failure) -- tolerate up to poll_error_grace_s of CONTIGUOUS
            # errors before giving up; the default (0.0) fails on the very
            # first error, same practical outcome as before this existed, just
            # caught gracefully instead of crashing the caller.
            if error_streak_start is None:
                error_streak_start = monotonic()
            elapsed = monotonic() - start
            if monotonic() - error_streak_start >= poll_error_grace_s or elapsed > timeout_s:
                return {"ok": False, "status": None, "waited_s": round(elapsed, 3),
                        "saw_noncomplete": saw_noncomplete, "reason": "poll_error",
                        "error": str(exc)}
            sleep(poll_seconds)
            continue
        error_streak_start = None
        # kaggle client >=1.8 returns the enum repr, e.g.
        # "KernelWorkerStatus.COMPLETE"; keep only the token after the dot so the
        # comparisons below match (mirrors kaggle_status.py's rsplit normalization).
        status = raw.rsplit(".", 1)[-1]
        elapsed = monotonic() - start
        if status in _FAIL_STATES:
            return {"ok": False, "status": status, "waited_s": round(elapsed, 3),
                    "saw_noncomplete": saw_noncomplete, "reason": "kernel_failed"}
        if status != "complete":
            saw_noncomplete = True
        if status == "complete" and (saw_noncomplete or elapsed >= min_floor_s):
            return {"ok": True, "status": status, "waited_s": round(elapsed, 3),
                    "saw_noncomplete": saw_noncomplete, "reason": None}
        if elapsed > timeout_s:
            return {"ok": False, "status": status, "waited_s": round(elapsed, 3),
                    "saw_noncomplete": saw_noncomplete, "reason": "timeout"}
        sleep(poll_seconds)
