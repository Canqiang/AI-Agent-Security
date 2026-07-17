from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import kernel_wait as kw  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _poller(seq):
    it = iter(seq)
    last = {"v": seq[-1]}

    def poll():
        try:
            last["v"] = next(it)
        except StopIteration:
            pass
        return last["v"]

    return poll


def _run(seq, *, min_floor_s=240, timeout_s=5400, poll_seconds=30, poll_error_grace_s=0.0):
    clock = Clock()
    return kw.wait_for_fresh_complete(
        poll_status=_poller(seq),
        sleep=clock.advance,
        monotonic=clock.now,
        min_floor_s=min_floor_s,
        timeout_s=timeout_s,
        poll_seconds=poll_seconds,
        poll_error_grace_s=poll_error_grace_s,
    )


class _Boom(RuntimeError):
    pass


def _flaky_poller(*, raise_first_n, then_seq):
    """A poll_status fake that raises _Boom on each of its first `raise_first_n`
    calls, then delegates to a normal `_poller(then_seq)` for every call after."""
    calls = {"n": 0}
    delegate = _poller(then_seq)

    def poll():
        calls["n"] += 1
        if calls["n"] <= raise_first_n:
            raise _Boom(f"transient 403 on call {calls['n']}")
        return delegate()

    return poll


def _run_flaky(poll_status, *, min_floor_s=240, timeout_s=5400, poll_seconds=30,
               poll_error_grace_s=0.0):
    clock = Clock()
    return kw.wait_for_fresh_complete(
        poll_status=poll_status,
        sleep=clock.advance,
        monotonic=clock.now,
        min_floor_s=min_floor_s,
        timeout_s=timeout_s,
        poll_seconds=poll_seconds,
        poll_error_grace_s=poll_error_grace_s,
    )


def test_stale_complete_not_accepted_before_floor():
    # always "complete" with no transition -> only accepted at the floor
    res = _run(["complete"] * 100, min_floor_s=240, poll_seconds=30)
    assert res["ok"] is True
    assert res["saw_noncomplete"] is False
    assert res["waited_s"] >= 240


def test_fresh_complete_accepted_on_transition_below_floor():
    res = _run(["running", "running", "complete"], min_floor_s=240, poll_seconds=30)
    assert res["ok"] is True
    assert res["saw_noncomplete"] is True
    assert res["waited_s"] < 240


def test_kernel_error_fails_fast():
    res = _run(["running", "error"], min_floor_s=240, poll_seconds=30)
    assert res["ok"] is False
    assert res["reason"] == "kernel_failed"
    assert res["status"] == "error"


def test_timeout_when_never_completes():
    res = _run(["running"] * 100, min_floor_s=240, timeout_s=120, poll_seconds=30)
    assert res["ok"] is False
    assert res["reason"] == "timeout"


def test_dotted_enum_complete_accepted():
    # kaggle client 1.8.2 returns str(KernelWorkerStatus.COMPLETE) == "KernelWorkerStatus.COMPLETE";
    # the wait must normalize the enum-prefixed token, not loop to timeout.
    res = _run(
        ["KernelWorkerStatus.RUNNING", "KernelWorkerStatus.COMPLETE"],
        min_floor_s=240,
        poll_seconds=30,
    )
    assert res["ok"] is True
    assert res["status"] == "complete"
    assert res["saw_noncomplete"] is True


def test_dotted_enum_error_fails_fast():
    res = _run(["KernelWorkerStatus.RUNNING", "KernelWorkerStatus.ERROR"], min_floor_s=240, poll_seconds=30)
    assert res["ok"] is False
    assert res["reason"] == "kernel_failed"
    assert res["status"] == "error"


# --- poll_status transient-error tolerance (2026-07-17) ----------------------
# A brand-new kernel's session can 403 on GetKernelSessionStatus for a short
# window right after creation (a known half-created-state race -- see memory
# scored-submission-ledger's 2026-07-09 "INFRA INCIDENT" entry). Before this,
# any poll_status() exception propagated uncaught, crashing the whole
# push_submit_variants.py script with a raw traceback instead of a graceful
# {"ok": False} result.

def test_poll_error_fails_gracefully_on_first_call_when_grace_is_zero():
    # Default (grace=0.0): a raised exception fails immediately -- same
    # practical outcome as before (one error kills it), but caught gracefully
    # instead of crashing the caller.
    poll = _flaky_poller(raise_first_n=1, then_seq=["complete"])
    res = _run_flaky(poll, poll_error_grace_s=0.0)
    assert res["ok"] is False
    assert res["reason"] == "poll_error"
    assert res["status"] is None


def test_poll_error_tolerated_within_grace_window_then_recovers():
    # Two transient errors (6s apart at poll_seconds=3), well inside a 30s
    # grace window -- must retry through them and accept the eventual
    # transition to complete, exactly like a normal fresh-kernel run.
    poll = _flaky_poller(raise_first_n=2, then_seq=["running", "complete"])
    res = _run_flaky(poll, min_floor_s=1, poll_seconds=3, poll_error_grace_s=30.0)
    assert res["ok"] is True
    assert res["status"] == "complete"


def test_poll_error_past_grace_window_still_fails():
    # Errors persist well beyond the grace window -- must give up, not retry
    # forever (bounded, not infinite tolerance).
    poll = _flaky_poller(raise_first_n=1000, then_seq=["complete"])
    res = _run_flaky(poll, poll_seconds=10, poll_error_grace_s=25.0)
    assert res["ok"] is False
    assert res["reason"] == "poll_error"
    assert res["waited_s"] >= 25.0


def test_poll_error_streak_resets_after_a_successful_call():
    # error, success (still running), error again -- the SECOND error gets its
    # own fresh grace window rather than inheriting elapsed time from the
    # first (unrelated) blip.
    calls = {"n": 0}

    def poll():
        calls["n"] += 1
        if calls["n"] in (1, 3):
            raise _Boom(f"blip {calls['n']}")
        return "running"

    clock = Clock()
    res = kw.wait_for_fresh_complete(
        poll_status=poll, sleep=clock.advance, monotonic=clock.now,
        min_floor_s=240, timeout_s=5400, poll_seconds=5,
        poll_error_grace_s=8.0,
    )
    # Never reaches "complete" in this script -> times out, but must NOT have
    # given up early as "poll_error" (each streak is only ever one blip long,
    # well inside the 8s grace).
    assert res["reason"] == "timeout"
