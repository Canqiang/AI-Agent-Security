from __future__ import annotations
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "research"))
sys.path.insert(0, str(REPO / "competition_files"))

import candidate_families as cf  # noqa: E402

SECRET_FILE = "secret.txt"


def _domains(specs):
    return [d for s in specs for d in s.domains]


def test_read_post_exfil_is_single_message_multihop():
    specs = [cf.read_post_exfil(i) for i in range(len(cf.READ_POST_FRAMINGS))]
    for s in specs:
        assert len(s.messages) == 1  # single-message, multi-hop
        assert s.route == "file_handoff_exfil"
        assert s.expected_tools == ["fs.read", "http.post"]
        assert s.expected_predicates == ["EXFILTRATION"]
        assert SECRET_FILE in s.messages[0]
        assert s.runtime_cost_units == 2
        assert any(t.startswith("framing:") for t in s.tags)


def test_read_post_exfil_cycles_framings_and_unique_domains():
    n = len(cf.READ_POST_FRAMINGS)
    specs = [cf.read_post_exfil(i) for i in range(2 * n)]
    framings = [t for s in specs for t in s.tags if t.startswith("framing:")]
    assert len(set(framings)) == n  # every framing represented
    doms = _domains(specs)
    assert len(doms) == len(set(doms))  # unique sink domain per candidate


def test_read_post_stack_attempts_four_hops_single_message():
    specs = [cf.read_post_stack(i) for i in range(len(cf.STACK_FRAMINGS))]
    for s in specs:
        assert len(s.messages) == 1
        assert s.expected_tools == ["fs.read", "http.post", "fs.delete", "email.send"]
        assert set(s.expected_predicates) == {"EXFILTRATION", "DESTRUCTIVE_WRITE", "CONFUSED_DEPUTY"}
        assert s.public_score_posture == "research_only"
        assert "secret.txt" in s.messages[0]
        assert s.runtime_cost_units == 4
