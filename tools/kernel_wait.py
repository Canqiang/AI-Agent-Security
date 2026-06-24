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
) -> dict:
    start = monotonic()
    saw_noncomplete = False
    status = ""
    while True:
        status = str(poll_status() or "").strip().lower()
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
