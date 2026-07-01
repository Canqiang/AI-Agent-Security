from __future__ import annotations
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "competition_files"))
pytest.importorskip("aicomp_sdk", exc_type=ImportError)

import run_gguf_validation as rgv  # noqa: E402
from aicomp_sdk.core.cells import cell_signature  # noqa: E402


def test_compact_tool_events_keeps_ok_and_error():
    trace = {"tool_events": [
        {"name": "fs.read", "ok": False, "error": "denied:Blocked", "side_effect": "READ"},
        {"name": "http.post", "ok": True, "error": "", "side_effect": "EGRESS"},
    ]}
    out = rgv.compact_tool_events(trace)
    assert out[0]["name"] == "fs.read" and out[0]["ok"] is False
    assert out[0]["error"].startswith("denied:")
    assert out[1]["ok"] is True


def test_cell_signature_empty_tool_events_returns_valid_signature():
    """
    Unit test: cell_signature([]) returns a well-formed CellSignature dict (not None).
    This verifies that the removed None-guard on score_cell_signature was unnecessary
    and that the unconditional form is safe even on the exception path where trace={}.
    """
    sig = cell_signature([])
    assert sig is not None
    assert isinstance(sig, dict)
    # Verify all required fields are present
    assert "n_tools" in sig
    assert "hash" in sig
    assert "tool_seq_ngram" in sig
    assert sig["n_tools"] == 0
    assert isinstance(sig["hash"], str)
    assert len(sig["hash"]) > 0
    # Verify the hash is deterministic for empty input
    sig2 = cell_signature([])
    assert sig["hash"] == sig2["hash"]


def test_score_cell_signature_exception_path_unconditional():
    """
    Integration test: when _replay_candidate_trace raises inside run_model's loop
    (the error path where trace stays {}), the resulting record's score_cell_signature
    is a real signature computed from empty tool_events (NOT None), and this does not raise.
    """
    from aicomp_sdk.attacks.contracts import AttackCandidate

    # Create a minimal mock candidate
    mock_candidate = mock.MagicMock(spec=AttackCandidate)
    mock_candidate.user_messages = []

    # Mock the dependencies: fail _replay_candidate_trace to trigger the exception path
    # Patch at the source location where it's imported inside run_model
    with mock.patch("aicomp_sdk.evaluation.ops._replay_candidate_trace") as mock_replay:
        mock_replay.side_effect = RuntimeError("simulated replay failure")

        # Mock other required functions/imports to prevent external calls
        with mock.patch("aicomp_sdk.core.predicates.eval_predicates") as mock_eval:
            mock_eval.return_value = []

            with mock.patch("run_gguf_validation.importlib.import_module") as mock_import:
                mock_model_module = mock.MagicMock()
                mock_model_module._unload_model = None
                mock_import.return_value = mock_model_module

                with mock.patch("aicomp_sdk.evaluation.ops.resolve_fixtures_dir") as mock_fixtures:
                    mock_fixtures.return_value = "/fake/fixtures"

                    # Call run_model with fail_fast=False (default) so exception is caught
                    try:
                        result, records = rgv.run_model(
                            model_name="gpt_oss",
                            candidates=[mock_candidate],
                            budget_per_model_s=10.0,
                            max_tool_hops=4,
                            env_selection="gym",
                            payload="test_payload",
                            fail_fast=False,  # Exception path: catch and continue
                        )
                    except Exception:
                        # If run_model itself raises, the test fails (exception path should NOT raise)
                        pytest.fail("run_model should not raise when fail_fast=False and _replay_candidate_trace fails")

    # Verify the record was created even though trace is empty
    assert len(records) == 1
    record = records[0]

    # Verify error was recorded
    assert record["error"] is not None
    assert "RuntimeError" in record["error"]

    # Verify score_cell_signature is now a dict (valid signature), not None
    sig = record["score_cell_signature"]
    assert sig is not None, "score_cell_signature should not be None on exception path"
    assert isinstance(sig, dict), "score_cell_signature should be a CellSignature dict"
    assert "n_tools" in sig
    assert sig["n_tools"] == 0, "empty tool_events should give n_tools=0"
    assert "hash" in sig
    assert isinstance(sig["hash"], str)
    assert len(sig["hash"]) > 0
