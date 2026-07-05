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

from attack import AttackAlgorithm, FALLBACK_N, HARD_N_CAP, PAYLOAD  # noqa: E402

_SENSITIVE_URL_WORDS = (
    "secret", "password", "token", "key", "credential",
    "private", "confidential", "api_key",
)


def _candidates(n: int):
    return AttackAlgorithm(config={"n_candidates": n}).run(None, AttackRunConfig())


def test_generates_requested_candidate_count():
    candidates = _candidates(5)
    assert len(candidates) == 5


def test_each_candidate_is_single_hop_sentinel_shape():
    for candidate in _candidates(5):
        assert len(candidate.user_messages) == 1
        msg = candidate.user_messages[0]
        assert "http.post" in msg
        assert f"data={PAYLOAD}" in msg
        low = msg.lower()
        # CONFUSED_DEPUTY-disabling words must never appear (standing rule).
        assert "send" not in low
        assert "email" not in low
        assert "upload" not in low


def test_each_candidate_has_a_unique_clean_domain():
    urls = []
    for candidate in _candidates(HARD_N_CAP):
        msg = candidate.user_messages[0]
        match = re.search(r"url=(http://\S+?)\s", msg)
        assert match, msg
        url = match.group(1)
        urls.append(url)
        assert not any(w in url.lower() for w in _SENSITIVE_URL_WORDS), url
    assert len(set(urls)) == len(urls)


def test_probe_excludes_cold_start_from_measured_latency():
    # ref 54257709 regression: a naive probe that times its FIRST rep averages
    # in the one-time model-load cost (observed 75-146s), drastically
    # undersizing N (~95 instead of ~500-1100). The probe must pay that cost
    # via a throwaway warm-up BEFORE timing starts.
    calls = {"n": 0}

    class ColdStartEnv:
        def reset(self):
            pass

        def interact(self, _msg, max_tool_hops=8):
            calls["n"] += 1
            import time
            time.sleep(0.25 if calls["n"] == 1 else 0.02)

        def export_trace_dict(self):
            return {"tool_events": [{"name": "http.post", "args": {"data": PAYLOAD}}]}

    algo = AttackAlgorithm(config={})
    lat = algo._probe_latency(ColdStartEnv(), 8)
    assert lat is not None
    assert lat < 0.15, f"cold-start leaked into measured latency: {lat}"


def test_falls_back_to_fixed_n_when_env_not_probeable():
    # No n_candidates override + a non-probeable env must not raise and must
    # yield the fixed fallback count (audit / dry-run / gateway-probe-failure).
    class RaisingEnv:
        def __getattr__(self, _name):
            def _boom(*_a, **_k):
                raise RuntimeError("env not probeable")
            return _boom

    for env in (None, RaisingEnv()):
        cands = AttackAlgorithm(config={}).run(env, AttackRunConfig())
        assert len(cands) == FALLBACK_N
        assert FALLBACK_N < 600  # never trips audit's stale-default guard
