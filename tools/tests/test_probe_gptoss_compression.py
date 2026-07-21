from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import probe_gptoss_compression as pc  # noqa: E402


def _m(hit_rate: float, warm: float) -> dict:
    return {"hit_rate": hit_rate, "warm_seconds_per_candidate_mean": warm}


def test_faster_still_firing_variant_beats_current():
    """A variant that stays above the fire floor AND is cheaper than `current`
    is the win signal -- exit-worthy headroom."""
    per = {
        "current": _m(1.0, 10.0),
        "empty_analysis": _m(1.0, 7.0),   # fires, 1.43x faster -> should win
        "plain": _m(1.0, 20.0),
    }
    r = pc.rank_templates(per, min_fire_rate=0.99)

    assert r["a_variant_beats_current"] is True
    assert r["best_qualifying"]["template"] == "empty_analysis"
    assert r["best_qualifying"]["speedup_vs_current"] == 1.4286


def test_current_already_minimal_means_no_win():
    """When `current` is the cheapest firing template, the lever is tapped."""
    per = {
        "current": _m(1.0, 7.0),
        "empty_analysis": _m(1.0, 9.0),
        "plain": _m(1.0, 20.0),
    }
    r = pc.rank_templates(per, min_fire_rate=0.99)

    assert r["a_variant_beats_current"] is False
    assert r["best_qualifying"]["template"] == "current"


def test_a_fast_variant_below_the_fire_floor_is_disqualified():
    """The real trap: a template that generates almost nothing is fast but stops
    firing the exact-payload http.post. It must be disqualified, not crowned."""
    per = {
        "current": _m(1.0, 10.0),
        "over_collapsed": _m(0.4, 2.0),   # blazing fast but drops the tool call
    }
    r = pc.rank_templates(per, min_fire_rate=0.99)

    assert "over_collapsed" in r["disqualified"]
    assert r["a_variant_beats_current"] is False
    assert r["best_qualifying"]["template"] == "current"
