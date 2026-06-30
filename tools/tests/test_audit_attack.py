from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import audit_attack as aa  # noqa: E402


def test_safe_n_max_matches_v312_calibration():
    # Default calibration: PER_CANDIDATE_SECONDS_DEFAULT=22.5 against the cap
    # 9000*0.8=7200 -> int(7200/22.5)=320 safe candidates. Bracket = the two VALID
    # empirical points: N=200 SCORED/completed (=> per_candidate <= 7200/200=36) and
    # URAD single450 ~3h REAL timeout (=> per_candidate > 7200/450=16), i.e. (16, 36]s.
    # The old 42s/171 came from the DISPROVEN claim that the "incorrect format" runs
    # (a gateway abort, NOT a timeout) were timeouts; 171 wrongly sat below the
    # proven-completing N=200. Even 0.09*320~=29 < our best 55.8, so single-hop
    # N-tuning is still a dead end -- only the number 171 was wrong.
    n = aa.safe_n_max(
        budget_seconds=aa.RUNTIME_BUDGET_SECONDS_DEFAULT,
        safety_margin=aa.RUNTIME_SAFETY_MARGIN_DEFAULT,
        per_candidate_seconds=aa.PER_CANDIDATE_SECONDS_DEFAULT,
    )
    assert n == 320


def test_default_calibration_brackets_proven_anchors():
    # Pin the requirement (against the DEFAULT constants, not hardcoded numbers):
    # must NOT block the proven-completing N=200, MUST trip on single450-scale N.
    assert (
        aa.runtime_budget_blocker(
            n=200,
            per_candidate_seconds=aa.PER_CANDIDATE_SECONDS_DEFAULT,
            budget_seconds=aa.RUNTIME_BUDGET_SECONDS_DEFAULT,
            safety_margin=aa.RUNTIME_SAFETY_MARGIN_DEFAULT,
            allow_high_n=False,
        )
        is None
    )
    assert (
        aa.runtime_budget_blocker(
            n=450,
            per_candidate_seconds=aa.PER_CANDIDATE_SECONDS_DEFAULT,
            budget_seconds=aa.RUNTIME_BUDGET_SECONDS_DEFAULT,
            safety_margin=aa.RUNTIME_SAFETY_MARGIN_DEFAULT,
            allow_high_n=False,
        )
        is not None
    )


def test_runtime_blocker_passes_under_budget():
    # N=300 single-hop is just inside the wall (6750 of the 7200 cap) -> no blocker.
    assert (
        aa.runtime_budget_blocker(
            n=300,
            per_candidate_seconds=22.5,
            budget_seconds=9000.0,
            safety_margin=0.8,
            allow_high_n=False,
        )
        is None
    )


def test_runtime_blocker_trips_over_wall():
    # N=600 single-hop is over the v3.1.2 wall -> blocker (our N=600 failures).
    blocker = aa.runtime_budget_blocker(
        n=600,
        per_candidate_seconds=22.5,
        budget_seconds=9000.0,
        safety_margin=0.8,
        allow_high_n=False,
    )
    assert blocker is not None
    assert "safe N" in blocker


def test_runtime_blocker_overridable():
    # --allow-high-n is the explicit "I accept the runtime risk" escape hatch.
    assert (
        aa.runtime_budget_blocker(
            n=600,
            per_candidate_seconds=22.5,
            budget_seconds=9000.0,
            safety_margin=0.8,
            allow_high_n=True,
        )
        is None
    )


def test_runtime_blocker_expensive_candidate_lowers_cap():
    # read->post->delete (~3x cost) makes even N=200 risky.
    blocker = aa.runtime_budget_blocker(
        n=200,
        per_candidate_seconds=67.5,
        budget_seconds=9000.0,
        safety_margin=0.8,
        allow_high_n=False,
    )
    assert blocker is not None


def test_safe_n_max_zero_cost_guarded():
    # Defensive: never divide by zero.
    assert aa.safe_n_max(9000.0, 0.8, 0.0) == 0
