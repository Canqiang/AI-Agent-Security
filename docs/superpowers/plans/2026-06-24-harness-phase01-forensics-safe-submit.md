# Harness Phase 0+1 (Submission Forensics & Safe-Submit) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make it impossible to spend a scored Kaggle slot without recording its
outcome (Phase 0), and impossible to repeat the 2026-06-23 burst of submit-before-
commit-run-finished failures (Phase 1).

**Architecture:** Two pure-logic modules — `submission_taxonomy` (classify a
submission record) and `kernel_wait` (a transition-aware wait state machine) —
are unit-tested in isolation. Two CLIs wrap them: `pull_submission_ledger`
(fetch → classify → write durable per-ref/rollup manifests) and `safe_submit`
(the single gated path: audit → no-pending → push → fresh-complete wait → output
verify → submit → record). The two existing unsafe submit paths are retired
behind `safe_submit`.

**Tech Stack:** Python 3.11, stdlib + argparse, pytest 9.x, the Kaggle Python
API (`kaggle.api.kaggle_api_extended.KaggleApi`). Reuses existing
`tools/kaggle_status.py`, `tools/audit_attack.py`, `tools/push_kaggle_kernel.py`,
`tools/write_submission_csv.py`.

## Global Constraints

- Every tool: `from __future__ import annotations`, argparse CLI, prints JSON,
  exit `0` on ok / `2` on blocked — matching existing `tools/*.py` style.
- Reuse `kaggle_status.py` helpers (`to_jsonable`, `now_iso`, `object_get`,
  `normalize_submission`, `fetch_submissions`) — do not re-implement them.
- Taxonomy enum is exactly: `complete_scored`, `complete_zero`,
  `runtime_exceeded`, `system_error`, `other_error`, `pending`.
- `safe_submit.py` is the ONLY module that calls `competition_submit_code`
  (except behind an explicit `--unsafe` flag).
- Wait defaults: `min_floor_seconds=240`, `poll_seconds=30`, `timeout_seconds=5400`.
- Pure-logic modules (`submission_taxonomy`, `kernel_wait`) take NO Kaggle /
  network / sleep dependency; CLIs inject real adapters. ALL Kaggle calls are
  mocked in tests. `make ci` stays SDK-free and Kaggle-free.
- Tracked evidence: `submissions/manifests/ref-<ref>.json` and `ledger.json`.
  Raw pulled logs go to `/tmp` or `research/results/` (already git-ignored).
- All work lands on branch `harness-phase01-forensics-safe-submit` (already
  checked out; the design spec commit `83f4125` is its first commit).

---

## File Structure

```
tools/submission_taxonomy.py        # new — pure classifier + ledger rollup logic
tools/pull_submission_ledger.py     # new — Phase 0 CLI: fetch, classify, write manifests
tools/kernel_wait.py                # new — pure wait state machine
tools/safe_submit.py                # new — Phase 1 CLI: single gated submit path
tools/build_submission_manifest.py  # modify — add unresolved_scored_refs gate
tools/push_submit_variants.py       # modify — route each variant via safe_submit
tools/submit_code_kernel.py         # modify — thin safe_submit wrapper
Makefile                            # modify — ledger, safe-submit, test targets; ci runs tests
tools/tests/test_submission_taxonomy.py   # new
tools/tests/test_pull_ledger.py           # new
tools/tests/test_manifest_gate.py         # new
tools/tests/test_kernel_wait.py           # new
tools/tests/test_safe_submit.py           # new
tools/tests/fixtures/submissions_11refs.json  # new — golden corpus from the real incident
submissions/manifests/ref-<ref>.json # generated (tracked)
submissions/manifests/ledger.json    # generated (tracked)
```

---

## Task 1: Submission outcome taxonomy (pure classifier)

**Files:**
- Create: `tools/submission_taxonomy.py`
- Create: `tools/tests/fixtures/submissions_11refs.json`
- Test: `tools/tests/test_submission_taxonomy.py`

**Interfaces:**
- Produces: `classify(record: dict) -> str` (one of the 6 enum values);
  `TAXONOMY: tuple[str, ...]`; `score_value(raw) -> float | None`;
  `summarize(manifests: list[dict]) -> dict` (counts + best score + unresolved).

- [ ] **Step 1: Create the golden fixture from the real incident**

Create `tools/tests/fixtures/submissions_11refs.json`:

```json
[
  {"ref": 53996558, "status": "SubmissionStatus.PENDING", "error_description": "", "public_score": "", "description": ""},
  {"ref": 53964193, "status": "ERROR", "error_description": "A system error. Please try resubmitting to resolve the error and contact Kaggle Support if it persists.", "public_score": "", "description": "chain_k6_n205"},
  {"ref": 53964173, "status": "ERROR", "error_description": "A system error. Please try resubmitting to resolve the error and contact Kaggle Support if it persists.", "public_score": "", "description": "chain_k4_n180"},
  {"ref": 53964154, "status": "ERROR", "error_description": "A system error. Please try resubmitting to resolve the error and contact Kaggle Support if it persists.", "public_score": "", "description": "chain_k3_n220"},
  {"ref": 53964131, "status": "ERROR", "error_description": "A system error. Please try resubmitting to resolve the error and contact Kaggle Support if it persists.", "public_score": "", "description": "chain_k2_n250"},
  {"ref": 53964109, "status": "ERROR", "error_description": "A system error. Please try resubmitting to resolve the error and contact Kaggle Support if it persists.", "public_score": "", "description": "linear_n400"},
  {"ref": 53942563, "status": "COMPLETE", "error_description": "", "public_score": "18.000", "description": "suppress_once_n200"},
  {"ref": 53800639, "status": "COMPLETE", "error_description": "Your submission notebook exceeded the allowed runtime. Review the competition's Code Requirements page for the time limits.", "public_score": "", "description": "static_c1_n600"},
  {"ref": 53793274, "status": "COMPLETE", "error_description": "Your submission notebook exceeded the allowed runtime. Review the competition's Code Requirements page for the time limits.", "public_score": "", "description": ""},
  {"ref": 53771967, "status": "COMPLETE", "error_description": "Your submission notebook exceeded the allowed runtime. Review the competition's Code Requirements page for the time limits.", "public_score": "", "description": ""},
  {"ref": 53765988, "status": "COMPLETE", "error_description": "", "public_score": "55.800", "description": "replay-dense-exfiltration"}
]
```

- [ ] **Step 2: Write the failing test**

Create `tools/tests/test_submission_taxonomy.py`:

```python
from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import submission_taxonomy as st  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "submissions_11refs.json"


def _records():
    return json.loads(FIXTURE.read_text())


def test_classify_each_of_the_11_refs():
    expected = {
        53996558: "pending",
        53964193: "system_error",
        53964173: "system_error",
        53964154: "system_error",
        53964131: "system_error",
        53964109: "system_error",
        53942563: "complete_scored",
        53800639: "runtime_exceeded",
        53793274: "runtime_exceeded",
        53771967: "runtime_exceeded",
        53765988: "complete_scored",
    }
    for rec in _records():
        assert st.classify(rec) == expected[rec["ref"]], rec["ref"]


def test_runtime_error_beats_complete_status():
    # status COMPLETE but a runtime error_description -> runtime_exceeded
    rec = {"status": "COMPLETE", "error_description": "exceeded the allowed runtime", "public_score": ""}
    assert st.classify(rec) == "runtime_exceeded"


def test_complete_zero_when_no_score_no_error():
    rec = {"status": "COMPLETE", "error_description": "", "public_score": ""}
    assert st.classify(rec) == "complete_zero"


def test_other_error_keeps_unknown_terminal_errors():
    rec = {"status": "ERROR", "error_description": "Quota exceeded for kernels", "public_score": ""}
    assert st.classify(rec) == "other_error"


def test_summarize_counts_and_best_score():
    manifests = [{"ref": r["ref"], "taxonomy": st.classify(r),
                  "public_score": st.score_value(r.get("public_score"))}
                 for r in _records()]
    summary = st.summarize(manifests)
    assert summary["counts_by_taxonomy"] == {
        "complete_scored": 2, "runtime_exceeded": 3, "system_error": 5, "pending": 1,
    }
    assert summary["best_public_score"] == 55.8
    assert summary["best_scored_ref"] == 53765988
    assert summary["unresolved_pending_refs"] == ["53996558"]
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `python -m pytest tools/tests/test_submission_taxonomy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'submission_taxonomy'`.

- [ ] **Step 4: Write the implementation**

Create `tools/submission_taxonomy.py`:

```python
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
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `python -m pytest tools/tests/test_submission_taxonomy.py -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add tools/submission_taxonomy.py tools/tests/test_submission_taxonomy.py tools/tests/fixtures/submissions_11refs.json
git commit -m "feat: submission outcome taxonomy classifier with incident golden fixture"
```

---

## Task 2: `pull_submission_ledger.py` (Phase 0 recorder)

**Files:**
- Create: `tools/pull_submission_ledger.py`
- Test: `tools/tests/test_pull_ledger.py`

**Interfaces:**
- Consumes: `submission_taxonomy.classify`, `.score_value`, `.summarize`.
- Produces: `build_ledger(records: list[dict], existing: dict[str, dict], now: str) -> tuple[dict[str, dict], dict]`
  returning `(ref_manifests_by_ref, ledger_rollup)`; `write_ledger(out_dir, manifests, ledger)`;
  `REF_SCHEMA = "2026-06-24.submission-ref.v1"`, `LEDGER_SCHEMA = "2026-06-24.submission-ledger.v1"`.

- [ ] **Step 1: Write the failing test**

Create `tools/tests/test_pull_ledger.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tools/tests/test_pull_ledger.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pull_submission_ledger'`.

- [ ] **Step 3: Write the implementation**

Create `tools/pull_submission_ledger.py`:

```python
"""Phase 0 forensics: pull Kaggle submissions, classify outcomes, write durable
per-ref manifests and a rollup ledger.

Network-free core: build_ledger() takes already-fetched records so it is fully
unit-testable. main() fetches via the Kaggle API and writes files.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import submission_taxonomy as st
from kaggle_status import (
    DEFAULT_COMPETITION,
    fetch_submissions,
    normalize_submission,
    now_iso,
)

REF_SCHEMA = "2026-06-24.submission-ref.v1"
LEDGER_SCHEMA = "2026-06-24.submission-ledger.v1"
DEFAULT_OUT_DIR = TOOLS.parent / "submissions" / "manifests"
_TERMINAL_TAX = {"complete_scored", "complete_zero", "runtime_exceeded",
                 "system_error", "other_error"}


def _ref_key(record: dict) -> str:
    return str(record.get("ref"))


def build_ref_manifest(
    record: dict, *, taxonomy: str, now: str, existing: dict | None, log_excerpt: str | None
) -> dict:
    first_seen = (existing or {}).get("first_seen_at", now)
    resolved_at = (existing or {}).get("resolved_at")
    if taxonomy in _TERMINAL_TAX and resolved_at is None:
        resolved_at = now
    return {
        "schema_version": REF_SCHEMA,
        "ref": record.get("ref"),
        "competition": record.get("competition") or DEFAULT_COMPETITION,
        "kernel": record.get("kernel"),
        "kernel_version_url": record.get("url"),
        "submitted_at": record.get("date"),
        "description": record.get("description") or "",
        "status": record.get("status"),
        "taxonomy": taxonomy,
        "public_score": st.score_value(record.get("public_score")),
        "private_score": st.score_value(record.get("private_score")),
        "error_description": record.get("error_description") or "",
        "log_excerpt": log_excerpt if log_excerpt is not None
        else (existing or {}).get("log_excerpt"),
        "first_seen_at": first_seen,
        "resolved_at": resolved_at,
        "notes": (existing or {}).get("notes", ""),
    }


def build_ledger(
    records: list[dict],
    *,
    existing: dict[str, dict],
    now: str,
    log_fetcher: Callable[[dict, str], str | None] | None = None,
) -> tuple[dict[str, dict], dict]:
    manifests: dict[str, dict] = dict(existing)
    for record in records:
        key = _ref_key(record)
        taxonomy = st.classify(record)
        prior = existing.get(key)
        log_excerpt = None
        if log_fetcher is not None and taxonomy in {
            "runtime_exceeded", "system_error", "other_error", "complete_zero"
        } and (prior is None or prior.get("log_excerpt") is None):
            log_excerpt = log_fetcher(record, taxonomy)
        manifests[key] = build_ref_manifest(
            record, taxonomy=taxonomy, now=now, existing=prior, log_excerpt=log_excerpt
        )
    summary = st.summarize(list(manifests.values()))
    baseline_ref = None
    for m in manifests.values():
        if m["taxonomy"] == "complete_scored":
            baseline_ref = m["ref"]  # last (most recent if records date-desc)
            break
    ledger = {
        "schema_version": LEDGER_SCHEMA,
        "competition": DEFAULT_COMPETITION,
        "updated_at": now,
        "counts_by_taxonomy": summary["counts_by_taxonomy"],
        "best_public_score": summary["best_public_score"],
        "best_scored_ref": summary["best_scored_ref"],
        "current_baseline_ref": baseline_ref,
        "unresolved_pending_refs": summary["unresolved_pending_refs"],
        "refs": sorted(
            (
                {
                    "ref": m["ref"], "submitted_at": m["submitted_at"],
                    "taxonomy": m["taxonomy"], "public_score": m["public_score"],
                    "description": m["description"],
                }
                for m in manifests.values()
            ),
            key=lambda r: str(r["submitted_at"] or ""),
            reverse=True,
        ),
    }
    return manifests, ledger


def load_existing(out_dir: Path) -> dict[str, dict]:
    existing: dict[str, dict] = {}
    if not out_dir.exists():
        return existing
    for path in out_dir.glob("ref-*.json"):
        try:
            data = json.loads(path.read_text())
            existing[str(data.get("ref"))] = data
        except Exception:
            continue
    return existing


def write_ledger(out_dir: Path, manifests: dict[str, dict], ledger: dict) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, manifest in manifests.items():
        (out_dir / f"ref-{key}.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    (out_dir / "ledger.json").write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def fetch_records(api: Any, competition: str, page_size: int) -> list[dict]:
    raw = fetch_submissions(api, competition, page_size)
    return [normalize_submission(item) for item in raw]


def make_log_fetcher(api: Any, kernel: str | None, mode: str) -> Callable[[dict, str], str | None] | None:
    if mode == "never" or not kernel:
        return None

    def fetch(record: dict, taxonomy: str) -> str | None:
        import tempfile
        try:
            with tempfile.TemporaryDirectory() as tmp:
                api.kernels_output(kernel, path=tmp, quiet=True)
                logs = list(Path(tmp).glob("*.log"))
                if not logs:
                    return None
                text = logs[0].read_text(errors="replace")
                return text[-4000:]
        except Exception as exc:  # best-effort diagnostic only
            return f"<log fetch failed: {exc}>"

    return fetch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--kernel", default="canqiang/aiagsec-submission")
    parser.add_argument("--page-size", type=int, default=25)
    parser.add_argument("--pull-logs", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--print", action="store_true")
    args = parser.parse_args()

    from kaggle.api.kaggle_api_extended import KaggleApi

    api = KaggleApi()
    api.authenticate()
    records = fetch_records(api, args.competition, args.page_size)
    log_mode = "never" if args.pull_logs == "never" else args.pull_logs
    log_fetcher = make_log_fetcher(api, args.kernel, log_mode)
    existing = load_existing(args.out_dir)
    manifests, ledger = build_ledger(
        records, existing=existing, now=now_iso(), log_fetcher=log_fetcher
    )
    write_ledger(args.out_dir, manifests, ledger)
    if args.print:
        print(json.dumps(ledger, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tools/tests/test_pull_ledger.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Backfill the real ledger and inspect**

Run: `python tools/pull_submission_ledger.py --print`
Expected: writes `submissions/manifests/ref-*.json` + `ledger.json`; printed rollup
shows `system_error: 5`, `runtime_exceeded: 3`, `best_public_score: 55.8`,
`unresolved_pending_refs: ["53996558"]` (or `[]` once it resolves).

- [ ] **Step 6: Commit**

```bash
git add tools/pull_submission_ledger.py tools/tests/test_pull_ledger.py submissions/manifests/
git commit -m "feat: pull_submission_ledger writes durable per-ref + rollup manifests"
```

---

## Task 3: `unresolved_scored_refs` gate in the manifest

**Files:**
- Modify: `tools/build_submission_manifest.py` (add helper + wire into both blocker lists)
- Test: `tools/tests/test_manifest_gate.py`

**Interfaces:**
- Produces: `unresolved_scored_refs(ledger_path: Path, allow_pending: bool) -> dict`
  returning `{"ok": bool, "unresolved": list[str], "message": str | None}`.

- [ ] **Step 1: Write the failing test**

Create `tools/tests/test_manifest_gate.py`:

```python
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tools/tests/test_manifest_gate.py -v`
Expected: FAIL — `AttributeError: module 'build_submission_manifest' has no attribute 'unresolved_scored_refs'`.

- [ ] **Step 3: Add the helper**

In `tools/build_submission_manifest.py`, add this function near `pending_status`
(around line 169):

```python
def unresolved_scored_refs(ledger_path: Path, allow_pending: bool) -> dict[str, Any]:
    if not Path(ledger_path).exists():
        return {"ok": True, "unresolved": [], "message": None}
    try:
        ledger = json.loads(Path(ledger_path).read_text())
    except Exception:
        return {"ok": True, "unresolved": [], "message": None}
    unresolved = [str(r) for r in (ledger.get("unresolved_pending_refs") or [])]
    ok = allow_pending or not unresolved
    return {
        "ok": ok,
        "unresolved": unresolved,
        "message": None if ok else "unresolved pending scored ref(s) in ledger without --allow-pending",
    }
```

- [ ] **Step 4: Wire it into `build_manifest` and both blocker lists**

In `build_manifest` (around line 431, where the `kaggle` block is assembled),
add a `ledger` block to the manifest:

```python
    manifest["ledger"] = unresolved_scored_refs(
        DEFAULT_OUT_DIR / "ledger.json", args.allow_pending
    )
```

(define `DEFAULT_OUT_DIR = REPO / "submissions" / "manifests"` near the top if
not already present; `REPO` already exists in this file).

In `collect_blockers` (before `return blockers`, ~line 337) and in
`strict_submit_blockers` (before `return blockers`, ~line 361), add:

```python
    if not manifest.get("ledger", {}).get("ok", True):
        blockers.append(manifest["ledger"].get("message") or "unresolved pending scored ref(s) in ledger")
```

- [ ] **Step 5: Run the test + a manifest smoke to verify**

Run: `python -m pytest tools/tests/test_manifest_gate.py -v`
Expected: PASS (4 tests).

Run: `make manifest-smoke` (requires SDK)
Expected: still builds a `/tmp` manifest; now includes a `ledger` block.

- [ ] **Step 6: Commit**

```bash
git add tools/build_submission_manifest.py tools/tests/test_manifest_gate.py
git commit -m "feat: unresolved_scored_refs gate blocks submit while a ref is pending"
```

---

## Task 4: `kernel_wait.py` — transition-aware wait state machine

**Files:**
- Create: `tools/kernel_wait.py`
- Test: `tools/tests/test_kernel_wait.py`

**Interfaces:**
- Produces: `wait_for_fresh_complete(*, poll_status, sleep, monotonic, min_floor_s, timeout_s, poll_seconds) -> dict`
  returning `{"ok": bool, "status": str, "waited_s": float, "saw_noncomplete": bool, "reason": str | None}`.

- [ ] **Step 1: Write the failing test**

Create `tools/tests/test_kernel_wait.py`:

```python
from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import kernel_wait as kw  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def _poller(seq):
    it = iter(seq)
    last = {"v": seq[-1]}

    def poll():
        try:
            last["v"] = next(it)
        except StopIteration:
            pass
        return last["v"]

    return poll


def _run(seq, *, min_floor_s=240, timeout_s=5400, poll_seconds=30):
    clock = Clock()
    return kw.wait_for_fresh_complete(
        poll_status=_poller(seq),
        sleep=clock.advance,
        monotonic=clock.now,
        min_floor_s=min_floor_s,
        timeout_s=timeout_s,
        poll_seconds=poll_seconds,
    )


def test_stale_complete_not_accepted_before_floor():
    # always "complete" with no transition -> only accepted at the floor
    res = _run(["complete"] * 100, min_floor_s=240, poll_seconds=30)
    assert res["ok"] is True
    assert res["saw_noncomplete"] is False
    assert res["waited_s"] >= 240


def test_fresh_complete_accepted_on_transition_below_floor():
    res = _run(["running", "running", "complete"], min_floor_s=240, poll_seconds=30)
    assert res["ok"] is True
    assert res["saw_noncomplete"] is True
    assert res["waited_s"] < 240


def test_kernel_error_fails_fast():
    res = _run(["running", "error"], min_floor_s=240, poll_seconds=30)
    assert res["ok"] is False
    assert res["reason"] == "kernel_failed"
    assert res["status"] == "error"


def test_timeout_when_never_completes():
    res = _run(["running"] * 100, min_floor_s=240, timeout_s=120, poll_seconds=30)
    assert res["ok"] is False
    assert res["reason"] == "timeout"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tools/tests/test_kernel_wait.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'kernel_wait'`.

- [ ] **Step 3: Write the implementation**

Create `tools/kernel_wait.py`:

```python
"""Transition-aware wait for a freshly pushed kernel version's commit-run.

Pure: all time + status access is injected, so it is fully unit-testable and
carries no Kaggle/sleep dependency. This is the fix for the 2026-06-23 bug where
a version-blind kernels_status returned a STALE "complete" and the submit fired
before the pushed version had run.
"""

from __future__ import annotations

from typing import Callable

_FAIL_STATES = {"error", "failed", "cancelled"}


def wait_for_fresh_complete(
    *,
    poll_status: Callable[[], str],
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    min_floor_s: float,
    timeout_s: float,
    poll_seconds: float,
) -> dict:
    start = monotonic()
    saw_noncomplete = False
    status = ""
    while True:
        status = str(poll_status() or "").strip().lower()
        elapsed = monotonic() - start
        if status in _FAIL_STATES:
            return {"ok": False, "status": status, "waited_s": round(elapsed, 3),
                    "saw_noncomplete": saw_noncomplete, "reason": "kernel_failed"}
        if status != "complete":
            saw_noncomplete = True
        if status == "complete" and (saw_noncomplete or elapsed >= min_floor_s):
            return {"ok": True, "status": status, "waited_s": round(elapsed, 3),
                    "saw_noncomplete": saw_noncomplete, "reason": None}
        if elapsed > timeout_s:
            return {"ok": False, "status": status, "waited_s": round(elapsed, 3),
                    "saw_noncomplete": saw_noncomplete, "reason": "timeout"}
        sleep(poll_seconds)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tools/tests/test_kernel_wait.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add tools/kernel_wait.py tools/tests/test_kernel_wait.py
git commit -m "feat: transition-aware kernel wait that rejects stale complete"
```

---

## Task 5: `safe_submit.py` — the single gated submit path

**Files:**
- Create: `tools/safe_submit.py`
- Test: `tools/tests/test_safe_submit.py`

**Interfaces:**
- Consumes: `kernel_wait.wait_for_fresh_complete`, `audit_attack.audit`,
  `pull_submission_ledger.build_ledger`/`fetch_records`,
  `push_kaggle_kernel.push_kernel`.
- Produces: `run_safe_submit(plan: SubmitPlan, deps: SubmitDeps) -> dict`
  returning `{"ok": bool, "stage": str, "blockers": list[str], "ref": int | None}`.
  `SubmitPlan` and `SubmitDeps` are simple dataclasses (fields below).

- [ ] **Step 1: Write the failing test**

Create `tools/tests/test_safe_submit.py`:

```python
from __future__ import annotations

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
    deps, submit_calls = _deps()
    res = ss.run_safe_submit(_plan(), deps)
    assert res["ok"] is True
    assert res["stage"] == "submitted"
    assert res["ref"] == 99001
    assert submit_calls == [7]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tools/tests/test_safe_submit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'safe_submit'`.

- [ ] **Step 3: Write the implementation**

Create `tools/safe_submit.py`:

```python
"""The single gated Kaggle submit path.

run_safe_submit() is pure orchestration over injected dependencies, so the gate
ordering is unit-tested without touching Kaggle. main() wires the real adapters:
audit_attack.audit, pull_submission_ledger, push_kaggle_kernel.push_kernel,
kernel_wait.wait_for_fresh_complete, kernels_output verification, and
competition_submit_code.

This is the ONLY module that calls competition_submit_code (except --unsafe).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

REPO = TOOLS.parent
DEFAULT_COMPETITION = "ai-agent-security-multi-step-tool-attacks"
DEFAULT_KERNEL = "canqiang/aiagsec-submission"
MIN_FLOOR_SECONDS = 240.0
POLL_SECONDS = 30.0
TIMEOUT_SECONDS = 5400.0


@dataclass
class SubmitPlan:
    allow_high_n: bool = False
    allow_stacking: bool = False
    allow_pending: bool = False
    dry_run: bool = False
    reason: str = ""


@dataclass
class SubmitDeps:
    audit_fn: Callable[[], dict]
    pending_fn: Callable[[], list]
    push_fn: Callable[[], dict]
    wait_fn: Callable[[int], dict]
    verify_fn: Callable[[], dict]
    submit_fn: Callable[[int], dict]
    record_fn: Callable[[], Any]


def run_safe_submit(plan: SubmitPlan, deps: SubmitDeps) -> dict:
    # 1. Audit
    audit = deps.audit_fn()
    if not audit.get("ok"):
        return {"ok": False, "stage": "audit", "blockers": audit.get("blockers", []), "ref": None}
    # 2. No-pending
    pending = deps.pending_fn()
    if pending and not plan.allow_pending:
        return {"ok": False, "stage": "no_pending",
                "blockers": [f"unresolved pending refs: {pending}"], "ref": None}
    # 3. Push
    push = deps.push_fn()
    if not push.get("ok") or push.get("version_number") is None:
        return {"ok": False, "stage": "push", "blockers": ["push failed"], "ref": None}
    if push.get("machine_shape") != "NvidiaTeslaT4":
        return {"ok": False, "stage": "push",
                "blockers": [f"machine_shape != NvidiaTeslaT4: {push.get('machine_shape')}"], "ref": None}
    version = int(push["version_number"])
    # 4. Wait for a fresh complete
    wait = deps.wait_fn(version)
    if not wait.get("ok"):
        return {"ok": False, "stage": "wait", "blockers": [wait.get("reason") or "wait failed"], "ref": None}
    # 5. Verify output
    verify = deps.verify_fn()
    if not verify.get("ok"):
        return {"ok": False, "stage": "verify", "blockers": verify.get("blockers", []), "ref": None}
    # dry-run stops here
    if plan.dry_run:
        return {"ok": True, "stage": "dry_run", "blockers": [], "ref": None}
    # 6. Submit
    response = deps.submit_fn(version)
    ref = response.get("ref") if isinstance(response, dict) else None
    # 7. Record
    deps.record_fn()
    return {"ok": True, "stage": "submitted", "blockers": [], "ref": ref}


# ---- real adapters ---------------------------------------------------------

def _real_audit(source: Path, n: int, plan: SubmitPlan) -> Callable[[], dict]:
    import audit_attack

    def run() -> dict:
        result = audit_attack.audit(
            n=n, source=source,
            allow_high_n=plan.allow_high_n, allow_stacking=plan.allow_stacking,
        )
        return {"ok": result["ok"], "blockers": result.get("blockers", [])}

    return run


def _real_pending(api: Any, competition: str) -> Callable[[], list]:
    import pull_submission_ledger as pl

    def run() -> list:
        records = pl.fetch_records(api, competition, 25)
        _, ledger = pl.build_ledger(records, existing={}, now=pl.now_iso())
        return ledger["unresolved_pending_refs"]

    return run


def _status_text(api: Any, kernel: str) -> str:
    from kaggle_status import object_get
    status = api.kernels_status(kernel)
    return str(object_get(status, "status") or "")


def _real_verify(api: Any, kernel: str) -> Callable[[], dict]:
    import tempfile
    from write_submission_csv import OFFICIAL_IDS  # four-row contract

    def run() -> dict:
        blockers: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            api.kernels_output(kernel, path=tmp, quiet=True)
            csvs = list(Path(tmp).glob("submission.csv"))
            if not csvs:
                return {"ok": False, "blockers": ["no submission.csv in kernel output"]}
            text = csvs[0].read_text()
            for needed in OFFICIAL_IDS:
                if needed not in text:
                    blockers.append(f"submission.csv missing row {needed}")
            for log in Path(tmp).glob("*.log"):
                body = log.read_text(errors="replace")
                if "Traceback" in body or "exceeded the allowed runtime" in body:
                    blockers.append("kernel log shows an error/runtime overflow")
                    break
        return {"ok": not blockers, "blockers": blockers}

    return run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", default=DEFAULT_KERNEL)
    parser.add_argument("--kernel-folder", type=Path, required=True,
                        help="prepared kernel folder with kernel-metadata.json")
    parser.add_argument("--source", type=Path, default=REPO / "src" / "attack.py")
    parser.add_argument("--n", type=int, default=200)
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--message", required=True)
    parser.add_argument("--allow-high-n", action="store_true")
    parser.add_argument("--allow-stacking", action="store_true")
    parser.add_argument("--allow-pending", action="store_true")
    parser.add_argument("--reason", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--unsafe", action="store_true",
                        help="skip wait+verify (explicit, logged escape hatch)")
    parser.add_argument("--min-floor-seconds", type=float, default=MIN_FLOOR_SECONDS)
    parser.add_argument("--timeout-seconds", type=float, default=TIMEOUT_SECONDS)
    parser.add_argument("--poll-seconds", type=float, default=POLL_SECONDS)
    args = parser.parse_args()

    if (args.allow_stacking or args.allow_high_n or args.allow_pending) and not args.reason:
        print(json.dumps({"ok": False, "stage": "args",
                          "blockers": ["override flags require --reason"]}, indent=2))
        return 2

    from kaggle.api.kaggle_api_extended import KaggleApi
    import kernel_wait
    import pull_submission_ledger as pl
    from push_kaggle_kernel import push_kernel

    api = KaggleApi()
    api.authenticate()
    plan = SubmitPlan(
        allow_high_n=args.allow_high_n, allow_stacking=args.allow_stacking,
        allow_pending=args.allow_pending, dry_run=args.dry_run, reason=args.reason,
    )

    def wait_fn(version: int) -> dict:
        if args.unsafe:
            return {"ok": True, "reason": "unsafe-skip"}
        return kernel_wait.wait_for_fresh_complete(
            poll_status=lambda: _status_text(api, args.kernel),
            sleep=time.sleep, monotonic=time.monotonic,
            min_floor_s=args.min_floor_seconds, timeout_s=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )

    def verify_fn() -> dict:
        if args.unsafe:
            return {"ok": True, "blockers": []}
        return _real_verify(api, args.kernel)()

    def record_fn():
        records = pl.fetch_records(api, args.competition, 25)
        existing = pl.load_existing(pl.DEFAULT_OUT_DIR)
        manifests, ledger = pl.build_ledger(records, existing=existing, now=pl.now_iso())
        pl.write_ledger(pl.DEFAULT_OUT_DIR, manifests, ledger)

    deps = SubmitDeps(
        audit_fn=_real_audit(args.source, args.n, plan),
        pending_fn=_real_pending(api, args.competition),
        push_fn=lambda: push_kernel(args.kernel_folder),
        wait_fn=wait_fn,
        verify_fn=verify_fn,
        submit_fn=lambda version: _to_jsonable_submit(api, args, version),
        record_fn=record_fn,
    )
    result = run_safe_submit(plan, deps)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


def _to_jsonable_submit(api: Any, args: argparse.Namespace, version: int) -> dict:
    from kaggle_status import object_get
    response = api.competition_submit_code(
        file_name="submission.csv", message=args.message,
        competition=args.competition, kernel=args.kernel, kernel_version=version, quiet=True,
    )
    return {"ref": object_get(response, "ref", "id")}


if __name__ == "__main__":
    raise SystemExit(main())
```

> NOTE for the implementer: `push_kaggle_kernel.push_kernel` must return a dict
> containing `version_number` and `machine_shape`. Inspect it; if it does not
> yet return `version_number`, add it (it already sets `machine_shape`). Confirm
> `write_submission_csv` exposes the four official IDs as `OFFICIAL_IDS`; if it
> uses a different name, import that name instead (do not duplicate the list).

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tools/tests/test_safe_submit.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Verify the real audit adapter blocks a stacking source (no network)**

Run: `python tools/safe_submit.py --kernel-folder kaggle_push/submission_variants/chain_k6_n205 --source src/archive/attack_v3_stacking.py --message "should not submit" --dry-run`
Expected: exits `2`, `stage: "audit"`, blockers mention stacking. (Audit runs
locally before any Kaggle call; if `KaggleApi().authenticate()` runs first and
needs creds, that's fine on this machine — creds are present — but no submit
happens.)

- [ ] **Step 6: Commit**

```bash
git add tools/safe_submit.py tools/tests/test_safe_submit.py
git commit -m "feat: safe_submit single gated path (audit/pending/push/wait/verify/submit/record)"
```

---

## Task 6: Retire unsafe paths + Makefile wiring + CI

**Files:**
- Modify: `tools/push_submit_variants.py` (route each variant through `safe_submit`)
- Modify: `tools/submit_code_kernel.py` (thin `safe_submit` wrapper)
- Modify: `Makefile` (add `ledger`, `safe-submit`, `test`; run tests in `ci`)

**Interfaces:**
- Consumes: `safe_submit.run_safe_submit`, `safe_submit.main`.

- [ ] **Step 1: Replace the buggy wait in `push_submit_variants.py`**

Delete `wait_for_kernel_complete` (lines 86-114) and rewrite `submit_variant`
(lines 117-169) so it delegates to `safe_submit`. Replace the body of
`submit_variant` with:

```python
def submit_variant(api, *, folder, competition, kernel, poll_seconds, timeout_seconds):
    import safe_submit as ss
    from push_kaggle_kernel import push_kernel

    manifest = load_json(folder / "variant-manifest.json")
    message = (
        f"{manifest['name']} k{manifest['chain_k']} n{manifest['n_candidates']} "
        f"exp{manifest['expected_public_score']} {manifest['description']}"
    )
    # Variants are stacking/high-N: they MUST be explicitly allowed with a reason,
    # and they go through the same gated path. By default the audit gate refuses
    # them — which is the correct, safe behavior after the 2026-06-23 incident.
    plan = ss.SubmitPlan(
        allow_high_n=True, allow_stacking=True, allow_pending=False,
        dry_run=False, reason=f"variant batch: {manifest['name']}",
    )
    source = folder / "attack.py" if (folder / "attack.py").exists() else REPO / "src" / "attack.py"
    deps = ss.SubmitDeps(
        audit_fn=ss._real_audit(source, int(manifest["n_candidates"]), plan),
        pending_fn=ss._real_pending(api, competition),
        push_fn=lambda: push_kernel(folder),
        wait_fn=lambda version: __import__("kernel_wait").wait_for_fresh_complete(
            poll_status=lambda: ss._status_text(api, kernel),
            sleep=__import__("time").sleep, monotonic=__import__("time").monotonic,
            min_floor_s=ss.MIN_FLOOR_SECONDS, timeout_s=timeout_seconds, poll_seconds=poll_seconds,
        ),
        verify_fn=ss._real_verify(api, kernel),
        submit_fn=lambda version: ss._to_jsonable_submit_from(api, competition, kernel, message, version),
        record_fn=lambda: None,
    )
    result = ss.run_safe_submit(plan, deps)
    return {"created_at": now_iso(), "variant": manifest, "message": message,
            "folder": str(folder), "result": result, "ok": result["ok"]}
```

Add a small reusable helper to `safe_submit.py` (so both callers share it):

```python
def _to_jsonable_submit_from(api, competition, kernel, message, version):
    from kaggle_status import object_get
    response = api.competition_submit_code(
        file_name="submission.csv", message=message, competition=competition,
        kernel=kernel, kernel_version=int(version), quiet=True,
    )
    return {"ref": object_get(response, "ref", "id")}
```

Add `REPO = Path(__file__).resolve().parent.parent` import usage at the top of
`push_submit_variants.py` if not already present (it is, line 13).

- [ ] **Step 2: Make `submit_code_kernel.py` a thin wrapper**

Replace `submit_code_kernel.py`'s `submit()` raw `competition_submit_code` call
with a deprecation that routes through `safe_submit`. Replace its `main()` body so
the only `competition_submit_code` in the repo lives in `safe_submit.py`:

```python
def main() -> int:
    import safe_submit
    print(json.dumps({"ok": False,
        "message": "submit_code_kernel is retired; use tools/safe_submit.py "
                   "(or `make safe-submit`). Raw kernel-version submit is unsafe."},
        indent=2))
    return 2
```

- [ ] **Step 3: Add Makefile targets and run tests in CI**

In `Makefile`, add:

```makefile
.PHONY: test
test:
	$(PYTHON) -m pytest tools/tests -q

.PHONY: ledger
ledger:
	$(PYTHON) tools/pull_submission_ledger.py --print

.PHONY: safe-submit
safe-submit:
	$(PYTHON) tools/safe_submit.py --kernel-folder $(KERNEL_FOLDER) --message "$(MESSAGE)"
```

Then add `test` to the `ci` target's prerequisite list (the `ci:` line, ~line in
the Makefile where `ci: compile parity ...` is defined) so `make ci` runs the
new pytest suite. The suite is Kaggle-free and SDK-free (all network mocked).

- [ ] **Step 4: Run the full gate**

Run: `python -m pytest tools/tests -q`
Expected: PASS (all tests from Tasks 1-5).

Run: `make ci`
Expected: PASS — compile, parity, lint, AND the new pytest suite.

- [ ] **Step 5: Verify no raw submit path remains**

Run: `grep -rn "competition_submit_code" tools/`
Expected: matches ONLY in `tools/safe_submit.py`.

- [ ] **Step 6: Commit**

```bash
git add tools/push_submit_variants.py tools/submit_code_kernel.py tools/safe_submit.py Makefile
git commit -m "refactor: route all scored submits through safe_submit; retire unsafe paths"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** Phase 0 taxonomy (§3.1)→Task 1; ledger tool + manifests
  (§3.2-3.3)→Task 2; unresolved_scored_refs gate (§3.4)→Task 3; safe_submit gate
  order + wait state machine (§4.1-4.2)→Tasks 4-5; retire unsafe paths
  (§4.3)→Task 6; Makefile (§5)→Task 6; tests (§6)→every task. Operational note
  (§8) is covered by `make ledger` backfilling 53996558. Phase 2/3 (§9)
  intentionally excluded.
- **Placeholder scan:** none — every code step has complete code; the two
  implementer NOTEs (push_kernel `version_number`, `OFFICIAL_IDS` name) are
  explicit verification instructions, not deferred work.
- **Type consistency:** `classify`/`score_value`/`summarize` signatures match
  between Tasks 1-2; `wait_for_fresh_complete` keyword args match between Task 4
  impl and Task 5 adapter; `SubmitPlan`/`SubmitDeps` fields match between the
  Task 5 test and impl; `_real_audit`/`_real_pending`/`_real_verify`/
  `_status_text`/`_to_jsonable_submit_from` reused by Task 6 are all defined in
  Task 5.
```
