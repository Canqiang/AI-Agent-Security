from __future__ import annotations
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))

import analyze_gguf_sweep as ag  # noqa: E402


def _summary(cell):
    return {"results": {"gpt_oss": {"by_cell": cell}, "gemma": {"by_cell": cell}}}


def test_read_blocked_when_read_post_exfil_always_blocked_at_read():
    cell = {"read_post_exfil|imperative": {
        "attempted": 6, "follow_through_rate": 0.0, "real_raw_per_candidate": 0.0,
        "blocked_hops": {"fs.read": 6}}}
    d = ag.decide(_summary(cell))
    assert d["read_blocked"] is True and d["verdict"] == "read_blocked"


def test_viable_when_a_framing_lands_exfil():
    cell = {"read_post_exfil|persona": {
        "attempted": 6, "follow_through_rate": 0.83, "real_raw_per_candidate": 18.0,
        "blocked_hops": {}}}
    d = ag.decide(_summary(cell))
    assert d["verdict"] == "read_post_viable"
    assert d["best_read_post_cell"] == "read_post_exfil|persona"
