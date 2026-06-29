from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import audit_attack as aa  # noqa: E402


def test_safe_n_max_matches_v312_calibration():
    # Default calibration (42s/candidate, bracketed by aiagsec N=200 SCORED <=45s
    # and URAD single240 TIMED OUT >37.5s): 9000s * 0.8 / 42 = 171 safe candidates.
    # This is below the single-hop 0.09*N ceiling, so single-hop N-tuning cannot
    # beat our existing best (55.8) -- the real gains need a higher-raw/candidate route.
    n = aa.safe_n_max(
        budget_seconds=aa.RUNTIME_BUDGET_SECONDS_DEFAULT,
        safety_margin=aa.RUNTIME_SAFETY_MARGIN_DEFAULT,
        per_candidate_seconds=aa.PER_CANDIDATE_SECONDS_DEFAULT,
    )
    assert n == 171


def test_runtime_blocker_passes_under_budget():
    # N=300 single-hop is comfortably inside the wall -> no blocker.
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
