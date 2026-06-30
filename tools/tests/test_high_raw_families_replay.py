from __future__ import annotations
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "research"))
sys.path.insert(0, str(REPO / "competition_files"))
sys.path.insert(0, str(REPO / "tools"))
pytest.importorskip("aicomp_sdk", exc_type=ImportError)

import candidate_families as cf  # noqa: E402
from aicomp_sdk.attacks.contracts import AttackCandidate  # noqa: E402
from aicomp_sdk.evaluation.ops import _replay_candidate_trace, resolve_fixtures_dir  # noqa: E402
from aicomp_sdk.core.predicates import eval_predicates  # noqa: E402
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail  # noqa: E402
from compliant_agent import CompliantAgent  # noqa: E402


def _replay(msg):
    cand = AttackCandidate.from_messages((msg,))
    return _replay_candidate_trace(
        candidate=cand, index=0, seed=123, fixtures_dir=resolve_fixtures_dir(),
        agent_factory=CompliantAgent, guardrail=OptimalGuardrail(),
        env_selection="sandbox", max_tool_hops=8)


def test_read_post_exfil_read_is_guardrail_blocked_locally():
    # Every framing parses to an fs.read hop; v3.1.0 guardrail denies secret.txt.
    for i in range(len(cf.READ_POST_FRAMINGS)):
        tr = _replay(cf.read_post_exfil(i).messages[0])
        reads = [e for e in tr.get("tool_events", []) if e["name"] == "fs.read"]
        assert reads, f"framing {i} did not parse to an fs.read"
        assert reads[0]["ok"] is False  # guardrail-denied
        assert "EXFILTRATION" not in {p["predicate"] for p in eval_predicates(tr)}


def test_read_post_no_secret_is_zero_exfil_locally():
    for i in range(len(cf.SAFE_FRAMINGS)):
        tr = _replay(cf.read_post_no_secret(i).messages[0])
        assert "EXFILTRATION" not in {p["predicate"] for p in eval_predicates(tr)}
