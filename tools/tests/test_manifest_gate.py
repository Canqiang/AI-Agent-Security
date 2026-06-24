from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import build_submission_manifest as bm  # noqa: E402


def _write_ledger(tmp_path, unresolved):
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps({"unresolved_pending_refs": unresolved}))
    return p


def test_gate_blocks_when_pending_unresolved(tmp_path):
    p = _write_ledger(tmp_path, ["53996558"])
    res = bm.unresolved_scored_refs(p, allow_pending=False)
    assert res["ok"] is False
    assert res["unresolved"] == ["53996558"]
    assert res["message"]


def test_gate_passes_when_clean(tmp_path):
    p = _write_ledger(tmp_path, [])
    res = bm.unresolved_scored_refs(p, allow_pending=False)
    assert res["ok"] is True


def test_gate_passes_when_allow_pending(tmp_path):
    p = _write_ledger(tmp_path, ["53996558"])
    res = bm.unresolved_scored_refs(p, allow_pending=True)
    assert res["ok"] is True


def test_gate_passes_when_ledger_missing(tmp_path):
    res = bm.unresolved_scored_refs(tmp_path / "nope.json", allow_pending=False)
    assert res["ok"] is True  # absent ledger is not a blocker by itself
