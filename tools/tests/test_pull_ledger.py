from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import pull_submission_ledger as pl  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "submissions_11refs.json"


def _records():
    return json.loads(FIXTURE.read_text())


def test_build_ledger_classifies_and_rolls_up():
    manifests, ledger = pl.build_ledger(_records(), existing={}, now="2026-06-24T00:00:00+00:00")
    assert ledger["schema_version"] == pl.LEDGER_SCHEMA
    assert ledger["counts_by_taxonomy"]["system_error"] == 5
    assert ledger["best_public_score"] == 55.8
    assert ledger["unresolved_pending_refs"] == ["53996558"]
    m = manifests["53942563"]
    assert m["schema_version"] == pl.REF_SCHEMA
    assert m["taxonomy"] == "complete_scored"
    assert m["public_score"] == 18.0
    assert m["first_seen_at"] == "2026-06-24T00:00:00+00:00"


def test_build_ledger_is_idempotent_and_preserves_first_seen():
    first, _ = pl.build_ledger(_records(), existing={}, now="2026-06-24T00:00:00+00:00")
    # a later run: the pending ref has now resolved to a score
    recs = _records()
    for r in recs:
        if r["ref"] == 53996558:
            r["status"] = "COMPLETE"
            r["public_score"] = "9.000"
    second, ledger2 = pl.build_ledger(recs, existing=first, now="2026-06-25T00:00:00+00:00")
    resolved = second["53996558"]
    assert resolved["taxonomy"] == "complete_scored"
    assert resolved["first_seen_at"] == "2026-06-24T00:00:00+00:00"  # preserved
    assert resolved["resolved_at"] == "2026-06-25T00:00:00+00:00"    # newly set
    assert ledger2["unresolved_pending_refs"] == []


def test_write_ledger_emits_files(tmp_path):
    manifests, ledger = pl.build_ledger(_records(), existing={}, now="2026-06-24T00:00:00+00:00")
    pl.write_ledger(tmp_path, manifests, ledger)
    assert (tmp_path / "ledger.json").exists()
    assert (tmp_path / "ref-53964193.json").exists()
    written = json.loads((tmp_path / "ref-53964193.json").read_text())
    assert written["taxonomy"] == "system_error"


def test_current_baseline_ref_is_most_recent_complete_scored_not_dict_order():
    # Two complete_scored records:
    #   53765988 submitted 2026-06-15 (score 55.8) — older
    #   53942563 submitted 2026-06-22 (score 18.0) — more recent
    # We want current_baseline_ref to be the most-recently submitted (53942563),
    # regardless of dict iteration order.
    # To stress-test dict-order reliance, the RECORDS list puts the older one first
    # (opposite of what the real API returns), and we also pass existing with the
    # older one first in dict order.
    records = [
        {
            "ref": 53765988,
            "date": "2026-06-15T10:00:00+00:00",
            "status": "COMPLETE",
            "error_description": "",
            "public_score": "55.800",
            "description": "replay-dense-exfiltration",
        },
        {
            "ref": 53942563,
            "date": "2026-06-22T10:00:00+00:00",
            "status": "COMPLETE",
            "error_description": "",
            "public_score": "18.000",
            "description": "suppress_once_n200",
        },
    ]

    # First build — existing={}, records in "wrong" order (older first)
    first_manifests, first_ledger = pl.build_ledger(
        records, existing={}, now="2026-06-24T00:00:00+00:00"
    )
    # Even in first build, baseline must be 53942563 (more recent date)
    assert first_ledger["current_baseline_ref"] == 53942563

    # Second build: pass existing with 53765988 first in dict order (stress test)
    reordered_existing = {
        "53765988": first_manifests["53765988"],
        "53942563": first_manifests["53942563"],
    }
    _, ledger2 = pl.build_ledger(
        records, existing=reordered_existing, now="2026-06-25T00:00:00+00:00"
    )
    # Must still pick 53942563 (most-recently submitted), NOT 53765988 (first in dict)
    assert ledger2["current_baseline_ref"] == 53942563
