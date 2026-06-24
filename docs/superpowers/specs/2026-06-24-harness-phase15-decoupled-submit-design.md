# Harness Phase 1.5 — Decoupled push/confirm submit with .log-fingerprint completion detection

> Date: 2026-06-24
> Status: proposed design, pending user review.
> Scope: replace `safe_submit`'s single blocking wait with a decoupled two-phase
> flow (`push` then `confirm`) whose completion detection works against a Kaggle
> API that exposes no per-version status. Builds directly on the merged Phase
> 0/1 (`tools/safe_submit.py`, `pull_submission_ledger.py`, `audit_attack.py`).

---

## 1. Motivating finding (from the Phase 1 live dry-run)

A `safe_submit --dry-run` against `kaggle_push/submission` on 2026-06-24:

- **Validated the fail-closed safety**: it pushed, waited, and on not getting a
  verified fresh-complete within the 90-min timeout it failed at stage `wait`
  and did NOT submit — zero scored slots burned (the opposite of the 2026-06-23
  stale-complete bug).
- **But could not complete.** Two compounding causes:
  1. The submission notebook's commit-run is *not* heavy — cell 4's non-rerun
     branch only writes a 4-row placeholder `submission.csv` ("Avoids a slow
     local replay at commit"). So the >90-min latency is **Kaggle's GPU kernel
     queue + scheduling**, which is unpredictable (minutes to hours) and outside
     our control.
  2. The Kaggle API exposes **no per-version status**. `kernels_status` and the
     low-level `get_kernel_session_status` both take only `(user, slug)` and
     report the latest *session*, which can read a stale `COMPLETE` from the
     prior version while a freshly-pushed version is still queued/running.

A blocking wait is therefore the wrong model: the wait is dominated by an
unpredictable, possibly multi-hour queue, and the only status signal is
version-blind.

---

## 2. Goals & success criteria

- **Decouple** the submit so no step blocks on the GPU queue: push returns
  immediately; confirmation/submission happens later, on demand.
- **Version-aware completion detection** that does not rely on the version-blind
  status alone, so `confirm` never submits a version that has not actually run.
- Preserve every Phase 1 safety property: audit the *shipped* source, no
  parallel pending slot, verify a valid output before submit, record the ref.

Non-goals: faster commit-run (the commit is already light; queue is Kaggle's),
variant batch submission, any change to the attack itself.

---

## 3. API constraint and available signals (established by probing)

No endpoint reports a *specific version's* run status. Available signals:

| Signal | Source | What it tells us |
|---|---|---|
| `version_number = N` | `push_kernel` (`save_kernel`) response | the new version we just pushed |
| `current_version_number` | `get_kernel(user, slug).metadata` | the kernel's current version number |
| session status (`COMPLETE`/…) | `kernels_status(slug)` | latest session status — **version-blind**, may be stale during a new run |
| `.log` (+ other output files) | `kernels_output(slug, path)` | the latest version's output; the `.log` differs per run |
| `last_run_time` | `kernels_list` | run **start** time (≈ push time), not completion |

The commit always writes an identical 4-row placeholder `submission.csv`, so the
CSV content is constant across versions and useless for completion detection.
The `.log` is the per-run-varying artifact — the basis for detection.

---

## 4. Architecture — two phases

`safe_submit` becomes two subcommands over one shared pending-submit state file.

### `safe_submit push --kernel-folder … --message … [--source … --allow-* --reason …]`

1. **Audit** the *shipped* source via `resolve_kernel_source(kernel_folder)`
   (extract the `%%writefile attack.py` cell), run `audit_attack.audit`.
2. **No-pending**: refuse if any prior Kaggle scored ref is pending (via the
   ledger) OR an uncleared `pending-submit.json` already exists, unless
   `--allow-pending --reason`.
3. **Capture baseline**: `kernels_output(kernel)` → record the current `.log`
   fingerprint (sha256 of the `.log` bytes; `null` if the kernel has no prior
   output).
4. **Push** → capture `version_number = N`; assert `machine_shape` metadata is
   `NvidiaTeslaT4` (truthful "requested, not API-confirmed" message as in Phase 1).
5. **Record** `submissions/tmp/pending-submit.json` and **exit immediately**.

### `safe_submit confirm [--submit] [--unsafe]`

1. Read `pending-submit.json` (absent → "nothing pending", exit 0).
2. **Completion check** (all three required — §5).
3. If not complete → exit 2 with a precise reason (`version_mismatch` /
   `status_not_complete` / `log_unchanged`); re-runnable.
4. If complete → **verify** output (4-row official `submission.csv` + `.log`
   has no `Traceback` / `exceeded the allowed runtime`). `--unsafe` skips verify.
5. **Submission requires the explicit `--submit` flag** (it burns a scored slot).
   Bare `confirm` is a non-mutating readiness check: it reports the completion
   check + verify result and exits without submitting. With `--submit` and when
   ready: `competition_submit_code` → record the new ref into the ledger
   (`pull_submission_ledger`) → clear `pending-submit.json`.

### State artifact — `submissions/tmp/pending-submit.json` (gitignored)

```json
{
  "schema_version": "2026-06-24.pending-submit.v1",
  "kernel": "canqiang/aiagsec-submission",
  "competition": "ai-agent-security-multi-step-tool-attacks",
  "version_number": 0,
  "message": "...",
  "push_time": "2026-06-24T...Z",
  "pre_push_log_fingerprint": "sha256|null",
  "audited_source_sha256": "...",
  "reason": "",
  "created_at": "2026-06-24T...Z"
}
```

Gitignored operational state under `submissions/tmp/` (already ignored). It
persists across sessions on the same machine; single in-flight submission at a
time (a second `push` while one is uncleared is refused by step 2). Cross-machine
persistence is out of scope (single-operator workflow).

---

## 5. Completion detection (the core)

`confirm` declares version `N` complete only when ALL hold:

1. `get_kernel(user, slug).metadata.current_version_number == N`. If it is `≠ N`
   (typically greater — a newer version was pushed externally), the recorded `N`
   is no longer the current version → error `version_mismatch`; do not submit.
2. `kernels_status(slug)` session status is `COMPLETE` with empty
   `failureMessage`.
3. The current `kernels_output` `.log` fingerprint **differs** from
   `pre_push_log_fingerprint` — i.e., a new run produced a new `.log`. (If the
   baseline was `null`, any retrievable `.log` satisfies this.)

Condition 3 is the version-aware backstop the version-blind status cannot
provide. Conditions 1–2 are fast corroboration; condition 3 is authoritative.

---

## 6. First deliverable — controlled signal experiment

Before `confirm` is wired to depend on the `.log` fingerprint, validate the
signal empirically with `tools/probe_kernel_signals.py`:

- Push a throwaway trivial **GPU** kernel to a separate slug (e.g.
  `canqiang/aiagsec-signal-probe`) whose notebook only sleeps briefly, prints a
  unique line, and writes a tiny output file — exercising the same GPU
  queue + `.log` mechanics cheaply, without touching the real submission kernel.
- Poll on an interval and record, timestamped: `kernels_status`,
  `get_kernel().current_version_number`, whether `kernels_output` yields a `.log`
  and its fingerprint, and `last_run_time`.
- Produce a small report (a table of how each signal transitions over time).

Acceptance for the signal: the `.log` is retrievable via `kernels_output` and
its fingerprint changes once (and only once) per run, transitioning from the
pre-push baseline to a new value after the run completes. If the experiment
shows the `.log` is unreliable or unavailable, fall back to the lightweight
notebook version-marker approach (write a per-push nonce file in commit and
check it in `confirm`) — recorded as the contingency, not the default.

The experiment requires Kaggle credentials + GPU quota; it is **not** part of
`make ci`.

---

## 7. Changes to existing code

- `tools/safe_submit.py`: reshape the pure orchestration `run_safe_submit` into
  `run_push_and_record(plan, deps)` and `run_confirm_submit(state, deps)`, each
  unit-tested with injected dependencies (same DI style as the Phase 1 tests).
  Reuse `resolve_kernel_source`, `_real_audit`, `_real_pending`, `_real_verify`,
  `_to_jsonable_submit_from`; add a `.log`-fingerprint adapter over
  `kernels_output`. CLI gains `push` / `confirm` subcommands; keep
  `--allow-* + --reason`, `--dry-run`, `--unsafe`.
- `tools/kernel_wait.py`: the blocking `wait_for_fresh_complete` is superseded by
  `confirm`'s one-shot detection → remove it and its test (no dead code). Record
  in the plan that this deletion is intentional.
- `tools/push_submit_variants.py`: variant batch submission is **out of scope**
  for Phase 1.5 (the chain_k* variants are known-bad and stacking). Leave it
  routed through the Phase 1 gated path; do not extend it to two-phase here.
- `tools/pull_submission_ledger.py`: reused unchanged by `confirm`'s record step.

---

## 8. Testing

- **Offline unit tests** (injected fake deps, no Kaggle, in `make ci`):
  - `run_push_and_record`: writes a correct `pending-submit.json`; refuses on a
    pending Kaggle ref or an existing uncleared state (with override behavior).
  - `run_confirm_submit`: returns not-ready (no submit) for each of
    `version_mismatch`, `status_not_complete`, `log_unchanged`; when all three
    pass, bare `confirm` verifies and reports ready WITHOUT submitting, while
    `--submit` verifies → submits → records → clears state.
  - the `.log`-fingerprint change-detection helper (pure function).
- **Controlled experiment** (§6): real-signal validation, not in CI.

---

## 9. Known limitations / edge cases

- The `.log` fingerprint assumes `kernels_output` returns the latest *completed*
  version's output and that the `.log` is run-unique. §6 validates this before
  reliance; the contingency is a notebook version-marker.
- `current_version_number` greater than `N` at `confirm` time means an external
  push happened; `confirm` refuses rather than submitting a wrong version.
- A genuinely failed run (status `ERROR`/`CANCELLED`, or `failureMessage` set)
  is surfaced by `confirm` as not-ready with that reason, not submitted.
- Single in-flight submission only; `push` refuses while a prior
  `pending-submit.json` is uncleared (clear it via a successful/explicitly
  abandoned `confirm`).

---

## 10. Out of scope (future)

- Faster commit-run / GPU-queue avoidance (the commit is already light).
- Variant batch (`push_submit_variants`) two-phase support.
- An auto-retry loop/cron around `confirm` (the one-shot design enables it, but
  wiring it is separate).
- The actual attack improvement toward the 55.8 replay-dense approach (Phase 2/3).
