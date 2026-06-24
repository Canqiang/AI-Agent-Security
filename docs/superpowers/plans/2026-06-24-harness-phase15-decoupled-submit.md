# Harness Phase 1.5 (Decoupled push/confirm submit) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `safe_submit`'s single blocking wait with a decoupled two-phase flow — `push` records the pushed version + a pre-push `.log` fingerprint and returns immediately; `confirm` detects that version's completion (without a per-version status API) and submits only with `--submit`.

**Architecture:** A pure state/fingerprint module (`submit_state.py`) and a controlled signal experiment (`probe_kernel_signals.py`) come first. Then `safe_submit`'s pure orchestration is split into `run_push_and_record` and `run_confirm_submit`, each unit-tested with injected dependencies (same DI style as Phase 1). Real Kaggle adapters and a `push`/`confirm` CLI wire it together; the superseded blocking `kernel_wait` is deleted.

**Tech Stack:** Python 3.11, stdlib + argparse, pytest 9.x, the Kaggle Python API. Reuses Phase 0/1: `tools/safe_submit.py` (`resolve_kernel_source`, `_real_audit`, `_real_pending`, `_real_verify`, `_to_jsonable_submit_from`), `tools/pull_submission_ledger.py`, `tools/push_kaggle_kernel.py`, `tools/check_submission_notebook.py`.

## Global Constraints

- Every tool: `from __future__ import annotations`, argparse CLI, prints JSON, exit `0`/`2`, matching existing `tools/*.py` style.
- `safe_submit.py` is the ONLY module that calls `competition_submit_code`.
- **Submission requires the explicit `--submit` flag.** Bare `confirm` is a non-mutating readiness check (no submit). `--unsafe` skips verify only.
- Completion of pushed version `N` requires ALL three: `get_kernel().metadata.current_version_number == N`; `kernels_status` is `COMPLETE` with empty `failureMessage`; the current `kernels_output` `.log` fingerprint differs from the recorded `pre_push_log_fingerprint`.
- Pending-submit state lives at `submissions/tmp/pending-submit.json` (gitignored); schema `2026-06-24.pending-submit.v1`. Single in-flight submission at a time.
- Pure modules (`submit_state`, the orchestration functions) take NO Kaggle/network dependency; CLIs inject real adapters. ALL Kaggle calls are mocked in tests. `make ci` stays SDK-free/Kaggle-free.
- The controlled experiment (`probe_kernel_signals.py`) requires Kaggle credentials; it is NOT part of `make ci`.
- All work lands on branch `harness-phase15-decoupled-submit` (already checked out; spec commit `947f768` is its first commit).

---

## File Structure

```
tools/submit_state.py                # new — pending-submit state I/O + log_fingerprint (pure)
tools/probe_kernel_signals.py        # new — controlled signal experiment (manual, real Kaggle)
tools/safe_submit.py                 # modify — split orchestration into push/confirm; add adapters; subcommand CLI
tools/kernel_wait.py                 # DELETE — superseded by confirm's one-shot detection
tools/tests/test_kernel_wait.py      # DELETE
tools/tests/test_submit_state.py     # new
tools/tests/test_probe_signals.py    # new (pure helper only)
tools/tests/test_safe_submit.py      # modify — replace old run_safe_submit tests with push/confirm tests
Makefile                             # modify — probe-signals, submit-push, submit-confirm targets
docs/superpowers/results/2026-06-24-phase15-signal-experiment.md  # new (Task 3 findings)
submissions/tmp/pending-submit.json  # generated at runtime (gitignored)
```

---

## Task 1: `submit_state.py` — pending-submit state + `.log` fingerprint (pure)

**Files:**
- Create: `tools/submit_state.py`
- Test: `tools/tests/test_submit_state.py`

**Interfaces:**
- Produces: `PENDING_SCHEMA: str`; `write_pending_state(path: Path, state: dict) -> None`;
  `load_pending_state(path: Path) -> dict | None`; `clear_pending_state(path: Path) -> None`;
  `log_fingerprint(output_dir: Path) -> str | None`.

- [ ] **Step 1: Write the failing test**

Create `tools/tests/test_submit_state.py`:

```python
from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import submit_state as ss  # noqa: E402


def test_state_round_trip(tmp_path):
    p = tmp_path / "pending-submit.json"
    ss.write_pending_state(p, {"kernel": "u/k", "version_number": 8})
    loaded = ss.load_pending_state(p)
    assert loaded["kernel"] == "u/k"
    assert loaded["version_number"] == 8
    assert loaded["schema_version"] == ss.PENDING_SCHEMA


def test_load_absent_returns_none(tmp_path):
    assert ss.load_pending_state(tmp_path / "nope.json") is None


def test_load_malformed_returns_none(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json{")
    assert ss.load_pending_state(p) is None


def test_clear_state(tmp_path):
    p = tmp_path / "pending-submit.json"
    ss.write_pending_state(p, {"kernel": "u/k"})
    ss.clear_pending_state(p)
    assert not p.exists()
    ss.clear_pending_state(p)  # idempotent: no error when already absent


def test_log_fingerprint_changes_with_content(tmp_path):
    (tmp_path / "run.log").write_text("first run output\n")
    fp1 = ss.log_fingerprint(tmp_path)
    assert isinstance(fp1, str) and len(fp1) == 64
    (tmp_path / "run.log").write_text("second run output\n")
    fp2 = ss.log_fingerprint(tmp_path)
    assert fp1 != fp2


def test_log_fingerprint_none_without_logs(tmp_path):
    (tmp_path / "submission.csv").write_text("Id,Score\n")
    assert ss.log_fingerprint(tmp_path) is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tools/tests/test_submit_state.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'submit_state'`.

- [ ] **Step 3: Write the implementation**

Create `tools/submit_state.py`:

```python
"""Pending-submit state I/O and output-log fingerprinting for the decoupled
push/confirm submit flow. Pure: filesystem + hashing only, no Kaggle/network."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

PENDING_SCHEMA = "2026-06-24.pending-submit.v1"


def write_pending_state(path: Path, state: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(state)
    payload["schema_version"] = PENDING_SCHEMA
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_pending_state(path: Path) -> dict | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def clear_pending_state(path: Path) -> None:
    path = Path(path)
    if path.exists():
        path.unlink()


def log_fingerprint(output_dir: Path) -> str | None:
    """sha256 over the sorted *.log files (name + bytes) in output_dir.

    Returns None when no .log file is present. The commit always writes an
    identical placeholder submission.csv, so only the .log varies per run.
    """
    output_dir = Path(output_dir)
    logs = sorted(output_dir.glob("*.log"))
    if not logs:
        return None
    h = hashlib.sha256()
    for p in logs:
        h.update(p.name.encode("utf-8"))
        h.update(p.read_bytes())
    return h.hexdigest()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tools/tests/test_submit_state.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add tools/submit_state.py tools/tests/test_submit_state.py
git commit -m "feat: submit_state — pending-submit persistence + .log fingerprint"
```

---

## Task 2: `probe_kernel_signals.py` — controlled signal experiment tool

**Files:**
- Create: `tools/probe_kernel_signals.py`
- Test: `tools/tests/test_probe_signals.py`

**Interfaces:**
- Consumes: `submit_state.log_fingerprint`.
- Produces: `build_signal_row(elapsed_s, status, current_version_number, log_present, log_fingerprint, last_run_time) -> dict` (pure, testable); a CLI `main()` that pushes a trivial CPU probe kernel and polls.

This tool studies how the signals (`kernels_status`, `current_version_number`, `.log` fingerprint) transition over a real run, WITHOUT touching the real submission kernel. A trivial CPU kernel (no GPU quota, fast) is enough to study the signal mechanics; the separately-known GPU-queue latency is not what we study here.

- [ ] **Step 1: Write the failing test (pure helper only)**

Create `tools/tests/test_probe_signals.py`:

```python
from __future__ import annotations

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TOOLS))

import probe_kernel_signals as pk  # noqa: E402


def test_build_signal_row_shape():
    row = pk.build_signal_row(
        elapsed_s=30.0, status="running", current_version_number=8,
        log_present=False, log_fingerprint=None, last_run_time="2026-06-24T05:00:00",
    )
    assert row["elapsed_s"] == 30.0
    assert row["status"] == "running"
    assert row["current_version_number"] == 8
    assert row["log_present"] is False
    assert row["log_fingerprint"] is None
    assert row["last_run_time"] == "2026-06-24T05:00:00"


def test_build_signal_row_records_fingerprint():
    row = pk.build_signal_row(
        elapsed_s=90.0, status="complete", current_version_number=8,
        log_present=True, log_fingerprint="abc123", last_run_time=None,
    )
    assert row["status"] == "complete"
    assert row["log_fingerprint"] == "abc123"
    assert row["log_present"] is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tools/tests/test_probe_signals.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'probe_kernel_signals'`.

- [ ] **Step 3: Write the implementation**

Create `tools/probe_kernel_signals.py`:

```python
"""Controlled experiment: push a trivial throwaway kernel and poll the signals
the decoupled confirm step depends on, to learn how each transitions over a run.

Writes a timestamped JSONL of signal rows and prints a transition summary.
Requires Kaggle credentials; not part of make ci.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from submit_state import log_fingerprint

DEFAULT_SLUG = "canqiang/aiagsec-signal-probe"
PROBE_NOTEBOOK = {
    "cells": [
        {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
         "source": [
             "import time, datetime\n",
             "marker = datetime.datetime.utcnow().isoformat()\n",
             "print('probe-run-marker', marker)\n",
             "time.sleep(5)\n",
             "open('probe_output.txt','w').write(marker)\n",
         ]},
    ],
    "metadata": {"kernelspec": {"name": "python3", "language": "python", "display_name": "Python 3"}},
    "nbformat": 4, "nbformat_minor": 5,
}


def build_signal_row(
    *, elapsed_s: float, status: str, current_version_number: Any,
    log_present: bool, log_fingerprint: str | None, last_run_time: Any,
) -> dict:
    return {
        "elapsed_s": elapsed_s,
        "status": status,
        "current_version_number": current_version_number,
        "log_present": log_present,
        "log_fingerprint": log_fingerprint,
        "last_run_time": str(last_run_time) if last_run_time is not None else None,
    }


def write_probe_kernel(folder: Path, slug: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "probe.ipynb").write_text(json.dumps(PROBE_NOTEBOOK), encoding="utf-8")
    (folder / "kernel-metadata.json").write_text(json.dumps({
        "id": slug, "title": "AIAgSec Signal Probe", "code_file": "probe.ipynb",
        "language": "python", "kernel_type": "notebook", "is_private": True,
        "enable_gpu": False, "enable_tpu": False, "enable_internet": False,
        "dataset_sources": [], "competition_sources": [], "kernel_sources": [],
    }, indent=2), encoding="utf-8")


def current_version_number(api: Any, slug: str) -> Any:
    user, name = slug.split("/", 1)
    mod = __import__("kagglesdk.kernels.types.kernels_api_service",
                     fromlist=["ApiGetKernelRequest"])
    with api.build_kaggle_client() as client:
        req = mod.ApiGetKernelRequest()
        req.user_name, req.kernel_slug = user, name
        return getattr(client.kernels.kernels_api_client.get_kernel(req).metadata,
                       "current_version_number", None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", default=DEFAULT_SLUG)
    parser.add_argument("--poll-seconds", type=float, default=20.0)
    parser.add_argument("--max-seconds", type=float, default=1800.0)
    parser.add_argument("--out", type=Path, default=Path("/tmp/aiagsec-signal-probe.jsonl"))
    args = parser.parse_args()

    from kaggle.api.kaggle_api_extended import KaggleApi
    from kaggle_status import object_get
    from push_kaggle_kernel import push_kernel

    api = KaggleApi(); api.authenticate()
    with tempfile.TemporaryDirectory() as folder:
        write_probe_kernel(Path(folder), args.slug)
        push = push_kernel(Path(folder))
    print(json.dumps({"push": push}, indent=2))
    pushed_version = push.get("version_number")

    start = time.monotonic()
    rows: list[dict] = []
    while time.monotonic() - start <= args.max_seconds:
        elapsed = round(time.monotonic() - start, 1)
        status = str(object_get(api.kernels_status(args.slug), "status") or "")
        cvn = current_version_number(api, args.slug)
        with tempfile.TemporaryDirectory() as out:
            try:
                api.kernels_output(args.slug, path=out, quiet=True)
            except Exception:
                pass
            fp = log_fingerprint(Path(out))
            present = fp is not None
        row = build_signal_row(elapsed_s=elapsed, status=status, current_version_number=cvn,
                               log_present=present, log_fingerprint=fp, last_run_time=None)
        rows.append(row)
        with args.out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
        print(json.dumps(row))
        if status.lower() == "complete" and cvn == pushed_version and present:
            print(json.dumps({"observed_completion": True, "pushed_version": pushed_version}))
            break
        time.sleep(args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tools/tests/test_probe_signals.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add tools/probe_kernel_signals.py tools/tests/test_probe_signals.py
git commit -m "feat: probe_kernel_signals — controlled signal experiment tool"
```

---

## Task 3: Run the signal experiment and record findings (OPERATOR task)

**Files:**
- Create: `docs/superpowers/results/2026-06-24-phase15-signal-experiment.md`

This is an operational task run by the controller/operator (needs Kaggle credentials). It is NOT a code/subagent task and has no automated test. It validates the `.log` signal before `confirm` is trusted for a real submit.

- [ ] **Step 1: Run the experiment**

Run: `python3 tools/probe_kernel_signals.py`
Expected: pushes the probe kernel, then prints one JSON signal row per poll, ending with `observed_completion` when status is `complete`, `current_version_number == pushed_version`, and a `.log` is present.

- [ ] **Step 2: Record findings**

Create `docs/superpowers/results/2026-06-24-phase15-signal-experiment.md` documenting, from the JSONL:
- Whether `kernels_output` yields a `.log` and whether its fingerprint changed from absent/old to a new value exactly once, after completion.
- When `current_version_number` advanced to the pushed version (on save vs. on completion).
- Whether `kernels_status` ever showed a non-`complete` state during the run, or stayed stale `complete`.
- The verdict: is the three-condition completion check (version + status + log-change) sound? If the `.log` proved unretrievable or non-changing, note the fallback (notebook version-marker) is required and STOP to re-plan.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/results/2026-06-24-phase15-signal-experiment.md
git commit -m "docs: phase 1.5 signal experiment findings"
```

---

## Task 4: Split orchestration into `run_push_and_record` + `run_confirm_submit` (pure DI)

**Files:**
- Modify: `tools/safe_submit.py` (add the two pure functions + their context/deps dataclasses; keep existing adapters and `main` untouched for now)
- Modify: `tools/tests/test_safe_submit.py` (add tests for the two new functions)

**Interfaces:**
- Produces:
  - `@dataclass PushContext(kernel, competition, message, audited_source_sha256, reason, now, allow_pending, allow_high_n, allow_stacking)`
  - `@dataclass PushDeps(audit_fn, pending_fn, state_exists_fn, baseline_fp_fn, push_fn, write_state_fn)`
  - `run_push_and_record(ctx: PushContext, deps: PushDeps) -> dict` → `{"ok", "stage", "blockers", "version_number", "state"}`
  - `@dataclass ConfirmDeps(current_version_fn, status_fn, fingerprint_fn, verify_fn, submit_fn, record_fn, clear_state_fn)`
  - `run_confirm_submit(state: dict, deps: ConfirmDeps, *, do_submit: bool, unsafe: bool=False) -> dict` → `{"ok", "stage", "blockers", "ref"}`

- [ ] **Step 1: Write the failing tests**

Append to `tools/tests/test_safe_submit.py`:

```python
def _push_ctx(**over):
    fields = dict(kernel="u/k", competition="comp", message="m",
                  audited_source_sha256="sha", reason="", now="2026-06-24T00:00:00Z",
                  allow_pending=False, allow_high_n=False, allow_stacking=False)
    fields.update(over)
    return ss.PushContext(**fields)


def _push_deps(written, **over):
    base = dict(
        audit_fn=lambda: {"ok": True, "blockers": []},
        pending_fn=lambda: [],
        state_exists_fn=lambda: False,
        baseline_fp_fn=lambda: "OLDFP",
        push_fn=lambda: {"ok": True, "version_number": 8, "machine_shape": "NvidiaTeslaT4"},
        write_state_fn=lambda state: written.append(state),
    )
    base.update(over)
    return ss.PushDeps(**base)


def test_push_audit_failure_blocks_before_push():
    written = []
    deps = _push_deps(written, audit_fn=lambda: {"ok": False, "blockers": ["stacking"]})
    res = ss.run_push_and_record(_push_ctx(), deps)
    assert res["ok"] is False and res["stage"] == "audit"
    assert written == []


def test_push_existing_state_blocks():
    written = []
    deps = _push_deps(written, state_exists_fn=lambda: True)
    res = ss.run_push_and_record(_push_ctx(), deps)
    assert res["ok"] is False and res["stage"] == "state_exists"
    assert written == []


def test_push_pending_ref_blocks():
    written = []
    deps = _push_deps(written, pending_fn=lambda: ["53996558"])
    res = ss.run_push_and_record(_push_ctx(), deps)
    assert res["ok"] is False and res["stage"] == "no_pending"
    assert written == []


def test_push_happy_path_records_state():
    written = []
    res = ss.run_push_and_record(_push_ctx(), _push_deps(written))
    assert res["ok"] is True and res["stage"] == "pushed"
    assert res["version_number"] == 8
    assert len(written) == 1
    st = written[0]
    assert st["version_number"] == 8
    assert st["pre_push_log_fingerprint"] == "OLDFP"
    assert st["kernel"] == "u/k"
    assert st["audited_source_sha256"] == "sha"


def _confirm_deps(submit_calls, cleared, **over):
    base = dict(
        current_version_fn=lambda: 8,
        status_fn=lambda: {"status": "complete", "failure_message": ""},
        fingerprint_fn=lambda: "NEWFP",
        verify_fn=lambda: {"ok": True, "blockers": []},
        record_fn=lambda: None,
        clear_state_fn=lambda: cleared.append(True),
    )
    base.update(over)

    def submit_fn():
        submit_calls.append(True)
        return {"ref": 99}

    return ss.ConfirmDeps(submit_fn=submit_fn, **base)


_STATE = {"version_number": 8, "pre_push_log_fingerprint": "OLDFP"}


def test_confirm_version_mismatch_not_ready():
    subs, cleared = [], []
    deps = _confirm_deps(subs, cleared, current_version_fn=lambda: 7)
    res = ss.run_confirm_submit(_STATE, deps, do_submit=True)
    assert res["ok"] is False and res["stage"] == "version_mismatch"
    assert subs == []


def test_confirm_status_not_complete_not_ready():
    subs, cleared = [], []
    deps = _confirm_deps(subs, cleared, status_fn=lambda: {"status": "running", "failure_message": ""})
    res = ss.run_confirm_submit(_STATE, deps, do_submit=True)
    assert res["ok"] is False and res["stage"] == "status_not_complete"
    assert subs == []


def test_confirm_log_unchanged_not_ready():
    subs, cleared = [], []
    deps = _confirm_deps(subs, cleared, fingerprint_fn=lambda: "OLDFP")
    res = ss.run_confirm_submit(_STATE, deps, do_submit=True)
    assert res["ok"] is False and res["stage"] == "log_unchanged"
    assert subs == []


def test_confirm_ready_without_submit_does_not_submit():
    subs, cleared = [], []
    deps = _confirm_deps(subs, cleared)
    res = ss.run_confirm_submit(_STATE, deps, do_submit=False)
    assert res["ok"] is True and res["stage"] == "ready"
    assert subs == [] and cleared == []


def test_confirm_ready_with_submit_submits_and_clears():
    subs, cleared = [], []
    deps = _confirm_deps(subs, cleared)
    res = ss.run_confirm_submit(_STATE, deps, do_submit=True)
    assert res["ok"] is True and res["stage"] == "submitted" and res["ref"] == 99
    assert subs == [True] and cleared == [True]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tools/tests/test_safe_submit.py -k "push or confirm" -v`
Expected: FAIL — `AttributeError: module 'safe_submit' has no attribute 'PushContext'`.

- [ ] **Step 3: Add the dataclasses and orchestration functions to `safe_submit.py`**

Insert after the existing `SubmitDeps` dataclass (around line 82):

```python
@dataclass
class PushContext:
    kernel: str
    competition: str
    message: str
    audited_source_sha256: str
    reason: str
    now: str
    allow_pending: bool = False
    allow_high_n: bool = False
    allow_stacking: bool = False


@dataclass
class PushDeps:
    audit_fn: Callable[[], dict]
    pending_fn: Callable[[], list]
    state_exists_fn: Callable[[], bool]
    baseline_fp_fn: Callable[[], "str | None"]
    push_fn: Callable[[], dict]
    write_state_fn: Callable[[dict], None]


@dataclass
class ConfirmDeps:
    current_version_fn: Callable[[], int]
    status_fn: Callable[[], dict]
    fingerprint_fn: Callable[[], "str | None"]
    verify_fn: Callable[[], dict]
    submit_fn: Callable[[], dict]
    record_fn: Callable[[], Any]
    clear_state_fn: Callable[[], None]


def run_push_and_record(ctx: PushContext, deps: PushDeps) -> dict:
    audit = deps.audit_fn()
    if not audit.get("ok"):
        return {"ok": False, "stage": "audit", "blockers": audit.get("blockers", []),
                "version_number": None, "state": None}
    if deps.state_exists_fn() and not ctx.allow_pending:
        return {"ok": False, "stage": "state_exists",
                "blockers": ["an uncleared pending-submit exists; run confirm or clear it first"],
                "version_number": None, "state": None}
    pending = deps.pending_fn()
    if pending and not ctx.allow_pending:
        return {"ok": False, "stage": "no_pending",
                "blockers": [f"unresolved pending refs: {pending}"], "version_number": None, "state": None}
    baseline = deps.baseline_fp_fn()
    push = deps.push_fn()
    if not push.get("ok") or push.get("version_number") is None:
        return {"ok": False, "stage": "push", "blockers": ["push failed"],
                "version_number": None, "state": None}
    if push.get("machine_shape") != "NvidiaTeslaT4":
        return {"ok": False, "stage": "push",
                "blockers": [f"kernel metadata machine_shape != NvidiaTeslaT4 (requested value, not API-confirmed): {push.get('machine_shape')}"],
                "version_number": None, "state": None}
    version = int(push["version_number"])
    state = {
        "kernel": ctx.kernel, "competition": ctx.competition, "message": ctx.message,
        "version_number": version, "push_time": ctx.now,
        "pre_push_log_fingerprint": baseline,
        "audited_source_sha256": ctx.audited_source_sha256, "reason": ctx.reason,
        "created_at": ctx.now,
    }
    deps.write_state_fn(state)
    return {"ok": True, "stage": "pushed", "blockers": [], "version_number": version, "state": state}


def run_confirm_submit(state: dict, deps: ConfirmDeps, *, do_submit: bool, unsafe: bool = False) -> dict:
    n = int(state["version_number"])
    current = deps.current_version_fn()
    if current != n:
        return {"ok": False, "stage": "version_mismatch",
                "blockers": [f"current_version_number={current} != pushed {n}"], "ref": None}
    status = deps.status_fn()
    status_text = str(status.get("status") or "").strip().lower()
    if status_text != "complete" or (status.get("failure_message") or ""):
        return {"ok": False, "stage": "status_not_complete",
                "blockers": [f"status={status_text} failure={status.get('failure_message') or ''}"], "ref": None}
    current_fp = deps.fingerprint_fn()
    if current_fp == state.get("pre_push_log_fingerprint"):
        return {"ok": False, "stage": "log_unchanged",
                "blockers": ["kernel .log unchanged since push; run not finished"], "ref": None}
    if not unsafe:
        verify = deps.verify_fn()
        if not verify.get("ok"):
            return {"ok": False, "stage": "verify", "blockers": verify.get("blockers", []), "ref": None}
    if not do_submit:
        return {"ok": True, "stage": "ready", "blockers": [], "ref": None}
    response = deps.submit_fn()
    ref = response.get("ref") if isinstance(response, dict) else None
    deps.record_fn()
    deps.clear_state_fn()
    return {"ok": True, "stage": "submitted", "blockers": [], "ref": ref}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tools/tests/test_safe_submit.py -k "push or confirm" -v`
Expected: PASS (9 new tests).

- [ ] **Step 5: Commit**

```bash
git add tools/safe_submit.py tools/tests/test_safe_submit.py
git commit -m "feat: decoupled push/confirm orchestration (pure, DI-tested)"
```

---

## Task 5: Real Kaggle adapters for the confirm signals

**Files:**
- Modify: `tools/safe_submit.py` (add three adapters)
- Modify: `tools/tests/test_safe_submit.py` (mocked-api tests)

**Interfaces:**
- Produces: `_current_version_number(api, kernel: str) -> int`;
  `_session_status(api, kernel: str) -> dict` (`{"status", "failure_message"}`);
  `_fetch_log_fingerprint(api, kernel: str) -> str | None`.

- [ ] **Step 1: Write the failing tests (mocked api)**

Append to `tools/tests/test_safe_submit.py`:

```python
class _FakeMeta:
    current_version_number = 8


class _FakeGetKernelResp:
    metadata = _FakeMeta()


class _FakeKC:
    def get_kernel(self, req):
        return _FakeGetKernelResp()


class _FakeClientCtx:
    def __enter__(self):
        class _K:
            kernels_api_client = _FakeKC()
        class _C:
            kernels = _K()
        return _C()

    def __exit__(self, *a):
        return False


class _FakeApi:
    def build_kaggle_client(self):
        return _FakeClientCtx()

    def kernels_status(self, kernel):
        return {"status": "COMPLETE", "failureMessage": ""}

    def kernels_output(self, kernel, path, quiet=True):
        (Path(path) / "run.log").write_text("fresh log\n")


def test_current_version_number_adapter():
    assert ss._current_version_number(_FakeApi(), "u/k") == 8


def test_session_status_adapter():
    st = ss._session_status(_FakeApi(), "u/k")
    assert st["status"] == "COMPLETE"


def test_fetch_log_fingerprint_adapter():
    fp = ss._fetch_log_fingerprint(_FakeApi(), "u/k")
    assert isinstance(fp, str) and len(fp) == 64
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tools/tests/test_safe_submit.py -k "adapter" -v`
Expected: FAIL — `AttributeError: module 'safe_submit' has no attribute '_current_version_number'`.

- [ ] **Step 3: Add the adapters to `safe_submit.py`**

Insert near the other `_real_*` adapters (after `_status_text`, around line 152):

```python
def _current_version_number(api: Any, kernel: str) -> int:
    user, name = kernel.split("/", 1)
    mod = __import__("kagglesdk.kernels.types.kernels_api_service",
                     fromlist=["ApiGetKernelRequest"])
    with api.build_kaggle_client() as client:
        req = mod.ApiGetKernelRequest()
        req.user_name, req.kernel_slug = user, name
        resp = client.kernels.kernels_api_client.get_kernel(req)
        return int(getattr(resp.metadata, "current_version_number", -1))


def _session_status(api: Any, kernel: str) -> dict:
    from kaggle_status import object_get
    raw = api.kernels_status(kernel)
    return {
        "status": str(object_get(raw, "status") or ""),
        "failure_message": str(object_get(raw, "failureMessage", "failure_message") or ""),
    }


def _fetch_log_fingerprint(api: Any, kernel: str) -> "str | None":
    import tempfile
    from submit_state import log_fingerprint
    with tempfile.TemporaryDirectory() as out:
        try:
            api.kernels_output(kernel, path=out, quiet=True)
        except Exception:
            return None
        return log_fingerprint(Path(out))
```

> NOTE for the implementer: Task 3's experiment findings are authoritative. If they showed `current_version_number` is better sourced elsewhere, or that a non-`complete` status is never observed, keep the three-condition check as written (it stays correct) but adjust ONLY the field extraction here to match what the experiment proved reliable. Do not weaken `run_confirm_submit`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tools/tests/test_safe_submit.py -k "adapter" -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add tools/safe_submit.py tools/tests/test_safe_submit.py
git commit -m "feat: confirm-signal Kaggle adapters (version/status/log-fingerprint)"
```

---

## Task 6: `push`/`confirm` CLI, remove blocking wait + old orchestration, Makefile, integration

**Files:**
- Modify: `tools/safe_submit.py` (rewrite `main()` into subcommands; remove `run_safe_submit`, `SubmitDeps`, the `wait_fn`/`_real_verify`-via-wait path; keep `_real_audit`, `_real_pending`, `_real_verify`, `_to_jsonable_submit_from`, `resolve_kernel_source`, `sources_match`)
- Modify: `tools/tests/test_safe_submit.py` (delete tests of the removed `run_safe_submit`)
- Delete: `tools/kernel_wait.py`, `tools/tests/test_kernel_wait.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes: everything from Tasks 1–5.

- [ ] **Step 1: Delete the superseded blocking wait**

```bash
git rm tools/kernel_wait.py tools/tests/test_kernel_wait.py
```

- [ ] **Step 2: Remove the old monolithic orchestration and rewrite `main()` as subcommands**

In `tools/safe_submit.py`: delete the `SubmitDeps` dataclass, `run_safe_submit`, and the entire old `main()`. Also delete the now-unused tests in `tools/tests/test_safe_submit.py` that referenced `run_safe_submit`/`SubmitDeps` (the original Phase 1 `test_audit_failure_blocks_before_push` etc. that used `ss.SubmitDeps`). Replace `main()` with:

```python
def _push_cli(args) -> int:
    from kaggle.api.kaggle_api_extended import KaggleApi
    import pull_submission_ledger as pl
    from push_kaggle_kernel import push_kernel
    from check_submission_notebook import normalize_source, sha256_text
    from submit_state import write_pending_state, load_pending_state, log_fingerprint

    if (args.allow_stacking or args.allow_high_n or args.allow_pending) and not args.reason:
        print(json.dumps({"ok": False, "stage": "args", "blockers": ["override flags require --reason"]}, indent=2))
        return 2

    api = KaggleApi(); api.authenticate()
    try:
        audit_source = resolve_kernel_source(args.kernel_folder)
    except Exception as exc:
        print(json.dumps({"ok": False, "stage": "resolve_source", "blockers": [str(exc)]}, indent=2)); return 2
    if args.source is not None:
        if not sources_match(audit_source.read_text(encoding="utf-8"),
                             Path(args.source).read_text(encoding="utf-8")):
            print(json.dumps({"ok": False, "stage": "parity",
                              "blockers": ["kernel-folder embedded source does not match --source"]}, indent=2)); return 2
    src_sha = sha256_text(normalize_source(audit_source.read_text(encoding="utf-8")))

    ctx = PushContext(
        kernel=args.kernel, competition=args.competition, message=args.message,
        audited_source_sha256=src_sha, reason=args.reason, now=pl.now_iso(),
        allow_pending=args.allow_pending, allow_high_n=args.allow_high_n, allow_stacking=args.allow_stacking,
    )

    def baseline_fp():
        return _fetch_log_fingerprint(api, args.kernel)

    def pending_fn():
        records = pl.fetch_records(api, args.competition, 25)
        _, ledger = pl.build_ledger(records, existing={}, now=pl.now_iso())
        return ledger["unresolved_pending_refs"]

    deps = PushDeps(
        audit_fn=_real_audit(audit_source, args.n, SubmitPlan(
            allow_high_n=args.allow_high_n, allow_stacking=args.allow_stacking)),
        pending_fn=pending_fn,
        state_exists_fn=lambda: load_pending_state(STATE_PATH) is not None,
        baseline_fp_fn=baseline_fp,
        push_fn=lambda: push_kernel(args.kernel_folder),
        write_state_fn=lambda state: write_pending_state(STATE_PATH, state),
    )
    result = run_push_and_record(ctx, deps)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


def _confirm_cli(args) -> int:
    from kaggle.api.kaggle_api_extended import KaggleApi
    import pull_submission_ledger as pl
    from submit_state import load_pending_state, clear_pending_state

    state = load_pending_state(STATE_PATH)
    if state is None:
        print(json.dumps({"ok": True, "stage": "nothing_pending", "ref": None}, indent=2)); return 0
    api = KaggleApi(); api.authenticate()
    kernel = state["kernel"]

    def record_fn():
        records = pl.fetch_records(api, state["competition"], 25)
        existing = pl.load_existing(pl.DEFAULT_OUT_DIR)
        manifests, ledger = pl.build_ledger(records, existing=existing, now=pl.now_iso())
        pl.write_ledger(pl.DEFAULT_OUT_DIR, manifests, ledger)

    deps = ConfirmDeps(
        current_version_fn=lambda: _current_version_number(api, kernel),
        status_fn=lambda: _session_status(api, kernel),
        fingerprint_fn=lambda: _fetch_log_fingerprint(api, kernel),
        verify_fn=_real_verify(api, kernel),
        submit_fn=lambda: _to_jsonable_submit_from(api, state["competition"], kernel, state["message"], state["version_number"]),
        record_fn=record_fn,
        clear_state_fn=lambda: clear_pending_state(STATE_PATH),
    )
    result = run_confirm_submit(state, deps, do_submit=args.submit, unsafe=args.unsafe)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("push")
    p.add_argument("--kernel", default=DEFAULT_KERNEL)
    p.add_argument("--kernel-folder", type=Path, required=True)
    p.add_argument("--source", type=Path, default=None)
    p.add_argument("--n", type=int, default=200)
    p.add_argument("--competition", default=DEFAULT_COMPETITION)
    p.add_argument("--message", required=True)
    p.add_argument("--allow-high-n", action="store_true")
    p.add_argument("--allow-stacking", action="store_true")
    p.add_argument("--allow-pending", action="store_true")
    p.add_argument("--reason", default="")
    p.set_defaults(func=_push_cli)

    c = sub.add_parser("confirm")
    c.add_argument("--submit", action="store_true", help="actually submit when ready (burns a scored slot)")
    c.add_argument("--unsafe", action="store_true", help="skip output verify")
    c.set_defaults(func=_confirm_cli)

    args = parser.parse_args()
    return args.func(args)
```

Add the state-path constant near the top constants (after `_AUDIT_TMP`, ~line 30):

```python
STATE_PATH = REPO / "submissions" / "tmp" / "pending-submit.json"
```

`SubmitPlan` is retained (now only carries `allow_high_n`/`allow_stacking` for `_real_audit`). Update its use in `_real_audit` calls accordingly (it already accepts those fields).

- [ ] **Step 3: Add Makefile targets**

In `Makefile`, add:

```makefile
.PHONY: probe-signals
probe-signals:
	$(PYTHON) tools/probe_kernel_signals.py

.PHONY: submit-push
submit-push:
	$(PYTHON) tools/safe_submit.py push --kernel-folder $(KERNEL_FOLDER) --message "$(MESSAGE)"

.PHONY: submit-confirm
submit-confirm:
	$(PYTHON) tools/safe_submit.py confirm $(CONFIRM_ARGS)
```

(`make submit-confirm CONFIRM_ARGS=--submit` to actually submit.)

- [ ] **Step 4: Run the full suite + integration checks**

Run: `python3 -m pytest tools/tests -q`
Expected: PASS (all tests; the deleted `test_kernel_wait.py` and removed `run_safe_submit` tests are gone, the new push/confirm/adapter/state/probe tests pass).

Run: `make ci`
Expected: PASS (green, including pytest).

Run: `python3 -c "import ast,sys; ast.parse(open('tools/safe_submit.py').read()); print('safe_submit imports-clean')"` then `grep -rn "competition_submit_code" tools/`
Expected: `competition_submit_code` appears ONLY in `tools/safe_submit.py`; `grep -rn "kernel_wait" tools/` returns nothing.

- [ ] **Step 5: Commit**

```bash
git add tools/safe_submit.py tools/tests/test_safe_submit.py Makefile
git commit -m "feat: push/confirm CLI subcommands; remove blocking kernel_wait and old run_safe_submit"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** decoupled push/confirm (spec §4)→Tasks 4,6; state artifact (§4)→Task 1; completion detection three conditions (§5)→Task 4 `run_confirm_submit` + Task 5 adapters; controlled experiment (§6)→Tasks 2,3; refactor + kernel_wait removal + variant scope-out (§7)→Task 6; testing (§8)→every task; `--submit` safe default + version-mismatch (§9)→Task 4 tests. The `.log`-only-varies fact (§3)→Task 1 `log_fingerprint`.
- **Placeholder scan:** none — code steps carry complete code; the Task 3 operator task is explicitly manual with a concrete procedure + findings deliverable; the Task 5 NOTE is a precise "adjust field extraction per experiment, do not weaken the check" instruction tied to planned Task 3.
- **Type consistency:** `PushContext`/`PushDeps`/`ConfirmDeps` fields match between the Task 4 tests and impl; `run_push_and_record`/`run_confirm_submit` return shapes match the tests; `log_fingerprint`/state functions used in Tasks 2,5,6 match Task 1's signatures; adapters added in Task 5 (`_current_version_number`/`_session_status`/`_fetch_log_fingerprint`) are the exact names wired in Task 6.
