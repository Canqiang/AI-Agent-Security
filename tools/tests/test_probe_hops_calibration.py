from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import probe_hops_calibration as ph  # noqa: E402


def _rec(index: int, *, fired: bool = False, elapsed: float = 0.0) -> dict:
    return {"candidate_index": index, "exact_payload": fired, "elapsed_s": elapsed}


# ---- hit_rate_invariance ------------------------------------------------

def test_hit_rate_invariance_all_agree():
    """Every candidate that fires at the baseline hop cap also fires at the
    probe hop cap (and vice versa) -> invariant, zero mismatches."""
    baseline = [_rec(0, fired=True), _rec(1, fired=True), _rec(2, fired=False)]
    probe = [_rec(0, fired=True), _rec(1, fired=True), _rec(2, fired=False)]

    result = ph.hit_rate_invariance(baseline, probe)

    assert result["n"] == 3
    assert result["fired_baseline"] == 2
    assert result["fired_probe"] == 2
    assert result["agreements"] == 3
    assert result["mismatches"] == []
    assert result["invariant"] is True


def test_hit_rate_invariance_flags_probe_dropout():
    """The real risk: a candidate fires at hops=8 (baseline) but the tighter
    probe cap cuts it off before http.post -> flagged as a mismatch, not
    invariant. This is the signal that would forbid the hops=1 lever."""
    baseline = [_rec(0, fired=True), _rec(1, fired=True)]
    probe = [_rec(0, fired=True), _rec(1, fired=False)]

    result = ph.hit_rate_invariance(baseline, probe)

    assert result["fired_baseline"] == 2
    assert result["fired_probe"] == 1
    assert result["agreements"] == 1
    assert result["mismatches"] == [
        {"candidate_index": 1, "baseline": True, "probe": False}
    ]
    assert result["invariant"] is False


# ---- calibration_coefficient --------------------------------------------

def test_calibration_coefficient_basic_ratio():
    """coef = baseline_elapsed / probe_elapsed per candidate, skipping the
    first (warm-up) candidate. Uniform 2x ratio -> coef 2.0."""
    baseline = [_rec(0, elapsed=99.0), _rec(1, elapsed=4.0), _rec(2, elapsed=6.0)]
    probe = [_rec(0, elapsed=50.0), _rec(1, elapsed=2.0), _rec(2, elapsed=3.0)]

    result = ph.calibration_coefficient(baseline, probe, warmup_skip=1)

    assert result["samples"] == 2  # candidate 0 skipped as warm-up
    assert result["coef_p50"] == 2.0
    assert result["coef_mean"] == 2.0
    assert result["baseline_warm_mean"] == 5.0
    assert result["probe_warm_mean"] == 2.5


def test_calibration_coefficient_skips_zero_probe_elapsed():
    """A zero probe elapsed can't yield a ratio -> that candidate is skipped,
    no ZeroDivisionError, remaining candidates still counted."""
    baseline = [_rec(0, elapsed=99.0), _rec(1, elapsed=4.0), _rec(2, elapsed=6.0)]
    probe = [_rec(0, elapsed=50.0), _rec(1, elapsed=0.0), _rec(2, elapsed=3.0)]

    result = ph.calibration_coefficient(baseline, probe, warmup_skip=1)

    assert result["samples"] == 1  # candidate 1 skipped (zero probe), 0 is warm-up
    assert result["coef_p50"] == 2.0
    assert result["coef_mean"] == 2.0
