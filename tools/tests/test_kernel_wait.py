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


def _run(seq, *, min_floor_s=240, timeout_s=5400, poll_seconds=30):
    clock = Clock()
    return kw.wait_for_fresh_complete(
        poll_status=_poller(seq),
        sleep=clock.advance,
        monotonic=clock.now,
        min_floor_s=min_floor_s,
        timeout_s=timeout_s,
        poll_seconds=poll_seconds,
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
