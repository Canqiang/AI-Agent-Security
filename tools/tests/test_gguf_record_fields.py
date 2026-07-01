from __future__ import annotations
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "competition_files"))
pytest.importorskip("aicomp_sdk", exc_type=ImportError)

import run_gguf_validation as rgv  # noqa: E402


def test_compact_tool_events_keeps_ok_and_error():
    trace = {"tool_events": [
        {"name": "fs.read", "ok": False, "error": "denied:Blocked", "side_effect": "READ"},
        {"name": "http.post", "ok": True, "error": "", "side_effect": "EGRESS"},
    ]}
    out = rgv.compact_tool_events(trace)
    assert out[0]["name"] == "fs.read" and out[0]["ok"] is False
    assert out[0]["error"].startswith("denied:")
    assert out[1]["ok"] is True
