"""Pure classification of Kaggle submission records into an outcome taxonomy.

No network, no I/O. Consumed by tools/pull_submission_ledger.py and tests.
"""

from __future__ import annotations

import re
from typing import Any

TAXONOMY = (
    "complete_scored",
    "complete_zero",
    "runtime_exceeded",
    "system_error",
    "other_error",
    "pending",
)

_PENDING_TOKENS = ("pending", "queued", "running", "submitted")
_RUNTIME_RE = re.compile(r"exceeded the allowed runtime", re.IGNORECASE)
_SYSTEM_RE = re.compile(r"a system error", re.IGNORECASE)


def _is_terminal(status: str) -> bool:
    s = status.lower()
    return not any(tok in s for tok in _PENDING_TOKENS)


def score_value(raw: Any) -> float | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def classify(record: dict) -> str:
    status = str(record.get("status") or "")
    err = str(record.get("error_description") or "")
    if not _is_terminal(status):
        return "pending"
    if _RUNTIME_RE.search(err):
        return "runtime_exceeded"
    if _SYSTEM_RE.search(err):
        return "system_error"
    if err.strip():
        return "other_error"
    score = score_value(record.get("public_score"))
    if score is not None and score > 0:
        return "complete_scored"
    return "complete_zero"


def summarize(manifests: list[dict]) -> dict:
    counts: dict[str, int] = {}
    best_score: float | None = None
    best_ref = None
    unresolved: list[str] = []
    for m in manifests:
        tax = m.get("taxonomy")
        counts[tax] = counts.get(tax, 0) + 1
        if tax == "pending":
            unresolved.append(str(m.get("ref")))
        score = m.get("public_score")
        if isinstance(score, (int, float)) and (best_score is None or score > best_score):
            best_score = float(score)
            best_ref = m.get("ref")
    return {
        "counts_by_taxonomy": counts,
        "best_public_score": best_score,
        "best_scored_ref": best_ref,
        "unresolved_pending_refs": unresolved,
    }
