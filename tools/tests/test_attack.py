from __future__ import annotations
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "competition_files"))
sys.path.insert(0, str(REPO / "src"))

pytest.importorskip("aicomp_sdk", exc_type=ImportError)

from aicomp_sdk.attacks.contracts import AttackRunConfig  # noqa: E402

from attack import AttackAlgorithm  # noqa: E402


def _candidates(n: int):
    return AttackAlgorithm(config={"n_candidates": n}).run(None, AttackRunConfig())


def test_generates_requested_candidate_count():
    candidates = _candidates(5)
    assert len(candidates) == 5


def test_each_candidate_is_single_message_sentinel_stack_shape():
    for candidate in _candidates(5):
        assert len(candidate.user_messages) == 1
        msg = candidate.user_messages[0]
        assert "http.post" in msg
        assert "data=SECRET_MARKER" in msg
        assert "an external recipient" in msg
        assert "compose a brand-new note" in msg
        low = msg.lower()
        assert "send" not in low
        assert "email" not in low
        assert "upload" not in low


def test_each_candidate_has_a_unique_domain():
    urls = []
    for candidate in _candidates(10):
        match = re.search(r"url=(https://\S+?/p)", candidate.user_messages[0])
        assert match, candidate.user_messages[0]
        urls.append(match.group(1))
    assert len(set(urls)) == len(urls)
