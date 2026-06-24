from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import submission_taxonomy as st  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "submissions_11refs.json"


def _records():
    return json.loads(FIXTURE.read_text())


def test_classify_each_of_the_11_refs():
    expected = {
        53996558: "pending",
        53964193: "system_error",
        53964173: "system_error",
        53964154: "system_error",
        53964131: "system_error",
        53964109: "system_error",
        53942563: "complete_scored",
        53800639: "runtime_exceeded",
        53793274: "runtime_exceeded",
        53771967: "runtime_exceeded",
        53765988: "complete_scored",
    }
    for rec in _records():
        assert st.classify(rec) == expected[rec["ref"]], rec["ref"]


def test_runtime_error_beats_complete_status():
    # status COMPLETE but a runtime error_description -> runtime_exceeded
    rec = {"status": "COMPLETE", "error_description": "exceeded the allowed runtime", "public_score": ""}
    assert st.classify(rec) == "runtime_exceeded"


def test_complete_zero_when_no_score_no_error():
    rec = {"status": "COMPLETE", "error_description": "", "public_score": ""}
    assert st.classify(rec) == "complete_zero"


def test_other_error_keeps_unknown_terminal_errors():
    rec = {"status": "ERROR", "error_description": "Quota exceeded for kernels", "public_score": ""}
    assert st.classify(rec) == "other_error"


def test_summarize_counts_and_best_score():
    manifests = [{"ref": r["ref"], "taxonomy": st.classify(r),
                  "public_score": st.score_value(r.get("public_score"))}
                 for r in _records()]
    summary = st.summarize(manifests)
    assert summary["counts_by_taxonomy"] == {
        "complete_scored": 2, "runtime_exceeded": 3, "system_error": 5, "pending": 1,
    }
    assert summary["best_public_score"] == 55.8
    assert summary["best_scored_ref"] == 53765988
    assert summary["unresolved_pending_refs"] == ["53996558"]
