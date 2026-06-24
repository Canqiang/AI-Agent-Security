from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import safe_submit as ss  # noqa: E402


def _deps(**over):
    base = dict(
        audit_fn=lambda: {"ok": True, "blockers": []},
        pending_fn=lambda: [],                    # no unresolved refs
        push_fn=lambda: {"ok": True, "version_number": 7, "machine_shape": "NvidiaTeslaT4"},
        wait_fn=lambda version: {"ok": True, "reason": None},
        verify_fn=lambda: {"ok": True, "blockers": []},
        submit_calls=[],
        record_fn=lambda: 99001,
    )
    base.update(over)
    submit_calls = base.pop("submit_calls")

    def submit_fn(version):
        submit_calls.append(version)
        return {"ref": 99001}

    deps = ss.SubmitDeps(
        audit_fn=base["audit_fn"], pending_fn=base["pending_fn"], push_fn=base["push_fn"],
        wait_fn=base["wait_fn"], verify_fn=base["verify_fn"], submit_fn=submit_fn,
        record_fn=base["record_fn"],
    )
    return deps, submit_calls


def _plan(**over):
    fields = dict(allow_high_n=False, allow_stacking=False, allow_pending=False,
                  dry_run=False, reason="")
    fields.update(over)
    return ss.SubmitPlan(**fields)


def test_audit_failure_blocks_before_push():
    deps, submit_calls = _deps(audit_fn=lambda: {"ok": False, "blockers": ["stacking without --allow-stacking"]})
    res = ss.run_safe_submit(_plan(), deps)
    assert res["ok"] is False
    assert res["stage"] == "audit"
    assert submit_calls == []


def test_pending_ref_blocks_before_push():
    deps, submit_calls = _deps(pending_fn=lambda: ["53996558"])
    res = ss.run_safe_submit(_plan(), deps)
    assert res["ok"] is False
    assert res["stage"] == "no_pending"
    assert submit_calls == []


def test_dry_run_stops_before_submit():
    deps, submit_calls = _deps()
    res = ss.run_safe_submit(_plan(dry_run=True), deps)
    assert res["ok"] is True
    assert res["stage"] == "dry_run"
    assert submit_calls == []


def test_wait_failure_blocks_submit():
    deps, submit_calls = _deps(wait_fn=lambda version: {"ok": False, "reason": "timeout"})
    res = ss.run_safe_submit(_plan(), deps)
    assert res["ok"] is False
    assert res["stage"] == "wait"
    assert submit_calls == []


def test_happy_path_submits_and_records():
    record_calls = []
    deps, submit_calls = _deps(record_fn=lambda: record_calls.append(1))
    res = ss.run_safe_submit(_plan(), deps)
    assert res["ok"] is True
    assert res["stage"] == "submitted"
    assert res["ref"] == 99001
    assert submit_calls == [7]
    assert len(record_calls) == 1  # record_fn was invoked exactly once


# --- FIX #1 tests: resolve_kernel_source and sources_match ---

def _make_kernel_folder(tmp_path: Path, source_text: str) -> Path:
    """Create a minimal kernel folder fixture with one %%writefile attack.py cell."""
    folder = tmp_path / "test_variant"
    folder.mkdir()
    nb = {
        "cells": [
            {
                "cell_type": "code",
                "source": [
                    "%%writefile /kaggle/working/attack.py\n",
                    source_text,
                ],
            }
        ]
    }
    (folder / "submission.ipynb").write_text(json.dumps(nb), encoding="utf-8")
    (folder / "kernel-metadata.json").write_text(
        json.dumps({"code_file": "submission.ipynb", "id": "canqiang/test"}),
        encoding="utf-8",
    )
    return folder


def test_resolve_kernel_source_extracts_embedded_source(tmp_path):
    source_text = "# chain attack\nn = 205\n"
    folder = _make_kernel_folder(tmp_path, source_text)
    result_path = ss.resolve_kernel_source(folder)
    assert result_path.exists()
    assert result_path.read_text(encoding="utf-8") == source_text


def test_sources_match_identical_after_normalize():
    assert ss.sources_match("hello\n", "hello\n") is True


def test_sources_match_different_returns_false():
    assert ss.sources_match("hello\n", "world\n") is False


def test_sources_match_normalize_whitespace():
    # trailing spaces / CRLF — normalize_source strips them, should still match
    assert ss.sources_match("hello  \r\n", "hello\n") is True
