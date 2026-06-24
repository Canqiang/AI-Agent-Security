# Harness Engineering — Phase 0+1: Submission Forensics & Safe-Submit

> Date: 2026-06-24
> Status: proposed design, pending user review.
> Scope: the first two phases of the harness-engineering effort for Kaggle
> `ai-agent-security-multi-step-tool-attacks`. Phase 0 = forensics / oracle
> ingestion. Phase 1 = submission-mechanics correctness. Phases 2–3 (runtime
> fidelity台, A/B sweep, 55.8 reproduction) are out of scope here; see §9.

---

## 1. Motivating incident (evidence)

On 2026-06-23, five scored submissions were pushed in a ~4-minute burst and all
failed. Pulled from the Kaggle API on 2026-06-24, the real ledger is:

| Date | ref | shape | outcome |
|---|---|---|---|
| 06-17 | 53765988 | `replay-dense-exfiltration` | **public 55.800** (best ever; a different kernel) |
| 06-17/18 | 53771967 / 53793274 / 53800639 | static C1 **N=600** | `runtime_exceeded`, no score |
| 06-22 | 53942563 | `suppress_once` direct-EXFIL **N=200** | **public 18.000** (current `src/attack.py`) |
| 06-23 | 53964109–53964193 | linear_n400, chain_k2/k3/k4/k6 | **`system_error` ×5** |
| 06-24 | 53996558 | resubmit of chain_k6_n205 | **pending** (high runtime risk) |

Two root causes, both code-confirmed:

1. **Version-blind wait race.** `tools/push_submit_variants.py::wait_for_kernel_complete`
   polls `api.kernels_status(slug)`, which returns the *slug's* latest known
   status, not the just-pushed *version's*. The Kaggle client exposes no
   per-version status/output API (`kernels_status(kernel)` and
   `kernels_output(kernel, path)` both target the slug). All five variants push
   to the same slug `canqiang/aiagsec-submission`; the first 30 s poll returns
   the stale `complete` from the 06-22 version, so `competition_submit_code`
   fires before the new version's GPU commit-run (loading 20B+26B GGUF → minutes)
   finishes → Kaggle "A system error". Submissions were ~46 s apart.

2. **Audit-gate bypass.** The variant path pushes prebaked
   `kaggle_push/submission_variants/` kernels and never runs
   `tools/audit_attack.py`, which would have blocked the stacking (k≥2) and
   high-N shapes outright.

And one meta-failure: **five slots were spent and nothing was recorded.** The
repo's tracked status snapshot is stale from 06-22; the failures' taxonomy was
recoverable only by ad-hoc API calls. The docs' rule ("save a manifest per
failed ref with a runtime-failure taxonomy") was never enforceable, so it never
happened.

---

## 2. Goals & success criteria

- **Phase 0:** it is *impossible* to spend a scored slot and not know, durably,
  what happened to it. Every ref is pulled, classified, and recorded; a new
  submit is gated on prior refs being resolved.
- **Phase 1:** the 06-23 burst is *structurally* impossible to repeat. There is
  exactly one gated submit path; it audits the source, serializes against
  pending refs, waits correctly for the pushed version's commit-run, and
  verifies a fresh valid output before submitting.

Non-goals here: predicting scored runtime / safe-N (Phase 2), ranking attack
variants (Phase 3), changing the attack itself.

---

## 3. Phase 0 — Forensics / Oracle ingestion

### 3.1 Outcome taxonomy

A single classifier maps any submission record to one enum value (precedence
top-to-bottom):

| taxonomy | rule |
|---|---|
| `pending` | status is not terminal (`SubmissionStatus.PENDING`, queued, running) |
| `runtime_exceeded` | `error_description` matches `/exceeded the allowed runtime/i` |
| `system_error` | `error_description` matches `/A system error/i` |
| `other_error` | a terminal record with another non-empty `error_description` (kept verbatim) not matching the above |
| `complete_zero` | status `COMPLETE`, no error, `public_score` blank or `== 0` |
| `complete_scored` | status `COMPLETE`, `public_score` present and `> 0` |

`complete_zero` is the important "silent" failure: the run finished but scored
nothing (mechanics / encoding-aware-scorer / guardrail) — distinct from an
error.

### 3.2 New tool: `tools/pull_submission_ledger.py`

- Reuses `tools/kaggle_status.py`'s `fetch_submissions` / `normalize_submission`.
- Args: `--competition` (default the comp), `--kernel <slug>` (for kernel
  metadata / T4 assertion), `--pull-logs {auto,always,never}` (default `auto`),
  `--out-dir submissions/manifests`, `--print`.
- `--pull-logs auto` ⇒ fetch `kernels_output` logs only for refs that are
  `*_error`, `complete_zero`, or newly seen during backfill. Healthy
  `complete_scored` / still-`pending` refs cost one status call. (Per D1.)
  - Known limitation: `kernels_output` is version-blind (latest version only),
    so a historical error ref's pulled log may belong to a newer version; for
    error classification we rely on the per-submission `error_description`, which
    is reliable. The log is a best-effort diagnostic aid only, flagged as such.
- **Idempotent:** reads existing `ref-*.json`, updates only changed/`pending`
  refs, upgrades `pending`→terminal, never drops history.
- Exit 0 (it is a recorder); exit 2 only on auth/network failure.

### 3.3 Durable artifacts

`submissions/manifests/ref-<ref>.json` (immutable per-ref evidence):

```json
{
  "schema_version": "2026-06-24.submission-ref.v1",
  "ref": 53964193,
  "competition": "ai-agent-security-multi-step-tool-attacks",
  "kernel": "canqiang/aiagsec-submission",
  "kernel_version_url": "/code/canqiang/aiagsec-submission?scriptVersionId=329640745",
  "submitted_at": "2026-06-23T02:25:03Z",
  "description": "chain_k6_n205 ...",
  "status": "ERROR",
  "taxonomy": "system_error",
  "public_score": null,
  "private_score": null,
  "error_description": "A system error. Please try resubmitting...",
  "attack_shape": { "family": "chain_k6", "n_candidates": 205, "messages_per_candidate": 6, "source_sha256": null },
  "log_excerpt": null,
  "first_seen_at": "2026-06-24T...Z",
  "resolved_at": "2026-06-23T02:25:30Z",
  "notes": ""
}
```

`attack_shape` is best-effort (parsed from the `description`, or matched to a
local `kaggle_push/*` / `submission_variants/*` manifest by version url when
available). It is advisory, never a gate input.

`submissions/manifests/ledger.json` (rollup, regenerated each run):

```json
{
  "schema_version": "2026-06-24.submission-ledger.v1",
  "competition": "ai-agent-security-multi-step-tool-attacks",
  "updated_at": "2026-06-24T...Z",
  "counts_by_taxonomy": { "complete_scored": 2, "runtime_exceeded": 3, "system_error": 5, "pending": 1 },
  "best_public_score": 55.8,
  "best_scored_ref": 53765988,
  "current_baseline_ref": 53942563,
  "unresolved_pending_refs": ["53996558"],
  "refs": [ "...ref summaries, date desc..." ]
}
```

First run **backfills all existing refs** so the 11-ref history (incl. the five
06-23 failures and today's pending) becomes durable evidence immediately.

### 3.4 New gate: `unresolved_scored_refs`

`tools/build_submission_manifest.py` gains a check: load `ledger.json`; emit a
blocker `unresolved_scored_refs` if any ref is `pending`, unless
`--allow-pending` (deliberate parallel-slot risk). This makes "record before you
spend the next slot" enforceable and supersedes the ad-hoc pending check.

---

## 4. Phase 1 — Submission-mechanics correctness

### 4.1 New tool: `tools/safe_submit.py` — the single gated submit path

Every scored submission goes through this. Each numbered step is a hard gate;
failure exits 2 with the named blocker and **does not submit**.

1. **Audit.** Resolve the kernel's embedded `attack.py` (from the
   `--kernel-folder` notebook's `%%writefile` cell, or the live kernel source);
   run `tools/audit_attack.py` programmatically. Any audit blocker
   (N≥600, stacking, sensitive-URL, duplicate buckets, message length, env
   interaction) refuses the submit — unless the matching override is present
   *with a reason*: `--allow-stacking`/`--allow-high-n` each require
   `--reason "<text>"`, which is recorded into the ref manifest.
2. **No-pending.** Refresh via `pull_submission_ledger`; refuse if any prior ref
   is `pending` (serialize), unless `--allow-pending --reason`.
3. **Push.** Reuse `push_kaggle_kernel.push_kernel(folder)`; capture
   `version_number`; assert `machine_shape == NvidiaTeslaT4`.
4. **Wait for a fresh complete** (defeats the stale-complete race):
   poll `kernels_status(slug)` every `--poll-seconds` (30); record the initial
   status; **accept `complete` only after** either (a) observing a transition
   into a non-complete state (queued/running) since push, **or** (b) elapsed ≥
   `--min-floor-seconds` (default 240 — a 2-model GGUF commit-run cannot finish
   faster). `error`/`cancelled` → fail. `--timeout-seconds` (default 5400) → fail.
5. **Verify output.** `kernels_output(slug, path)`; assert a fresh
   `submission.csv` exists and is the exact four-row shape (reuse
   `write_submission_csv` validation); scan the `.log` for
   `/Traceback|exceeded the allowed runtime|Error:/` → fail on match.
6. **Submit.** Only now `competition_submit_code(file_name, message,
   competition, kernel, kernel_version)`.
7. **Record.** Re-run `pull_submission_ledger` → write the new ref's `pending`
   manifest, which then gates the next submit (step 2).

`--dry-run` runs steps 1–5 and stops before step 6. `--unsafe` skips steps 4–5
(explicit, logged escape hatch).

### 4.2 Wait state machine (the literal fix)

```
state = "pushed"; saw_noncomplete = False; t0 = now
loop every poll_seconds:
    s = kernels_status(slug).lower()
    if s in {error, failed, cancelled}: FAIL("kernel run failed")
    if s != "complete": saw_noncomplete = True
    if s == "complete" and (saw_noncomplete or elapsed >= min_floor): RETURN ok
    if elapsed > timeout: FAIL("timeout")
```

The 06-23 bug is exactly "accepted `complete` at the first poll without
`saw_noncomplete` and below the floor". Both backstops must hold.

### 4.3 Retiring the unsafe paths (per D2)

- `tools/push_submit_variants.py`: keep the batch driver, but each variant is
  submitted **through `safe_submit`** (serialized by the no-pending gate); the
  buggy `wait_for_kernel_complete` is deleted. The default chain/linear variant
  set remains **blocked by the audit gate** (stacking/high-N) unless overridden
  with a reason.
- `tools/submit_code_kernel.py`: reduced to a thin `safe_submit --kernel`
  wrapper (or removed). The raw `competition_submit_code` call no longer exists
  outside `safe_submit` except behind `--unsafe`.

---

## 5. Makefile integration

| target | action |
|---|---|
| `make ledger` | `pull_submission_ledger.py --pull-logs auto`; write manifests, print rollup |
| `make safe-submit KERNEL_FOLDER=... MESSAGE=...` | full-gated submit via `safe_submit.py` |
| `make submit-ready` | now also fails on the `unresolved_scored_refs` blocker |

`make ci` (SDK-free) gains the Phase 0/1 **unit tests** (all Kaggle calls mocked).

---

## 6. Testing strategy

- **Taxonomy classifier (Phase 0):** golden fixtures built from the real 11
  refs. Asserts: the five 06-23 → `system_error`; the three N=600 →
  `runtime_exceeded`; 53942563 → `complete_scored` (18.0); 53765988 →
  `complete_scored` (55.8); 53996558 → `pending`. This incident is the perfect
  regression corpus.
- **Wait state machine (Phase 1):** mocked `kernels_status` sequences —
  `[complete]` from t0 must be **rejected** until floor/transition;
  `[complete, complete]` stale must be rejected; `[queued, running, complete]`
  accepted; `[running, error]` → fail; never-complete → timeout.
- **Audit integration:** a stacking `submission_variants/chain_k6_n205` folder
  must be refused by `safe_submit` without an override.
- **End-to-end dry-run:** `safe_submit --dry-run` against a known-good folder
  passes steps 1–5 with a fully mocked Kaggle API; no real submit.

---

## 7. File inventory (new / changed)

```
tools/pull_submission_ledger.py     # new — Phase 0 recorder + taxonomy
tools/safe_submit.py                # new — Phase 1 single gated submit path
tools/build_submission_manifest.py  # changed — unresolved_scored_refs gate
tools/push_submit_variants.py       # changed — route each variant via safe_submit
tools/submit_code_kernel.py         # changed — thin safe_submit wrapper / retire
Makefile                            # changed — ledger, safe-submit targets
submissions/manifests/ref-<ref>.json   # generated evidence (tracked)
submissions/manifests/ledger.json      # generated rollup (tracked)
tests/ (or tools/tests/)            # new — classifier + wait-state-machine units
```

`ref-*.json` and `ledger.json` are intentionally tracked (small, durable
evidence). Pulled raw logs stay under `research/results/` or `/tmp` (ignored).

---

## 8. Operational note — the live pending ref

`53996558` (chain_k6_n205) is in the scoring queue now. Under `safe_submit` it
would have been refused twice: by the audit gate (stacking) and, if forced,
likely surfaced as `runtime_exceeded` afterward (~1230 user-messages vs the
N=600 that already exceeded). The first `make ledger` run will record its
outcome; no action needed beyond letting the ledger capture it.

---

## 9. Roadmap context (out of scope here)

- **Phase 2 — runtime-fidelity台:** make `run_gguf_validation` run the full
  `eval_attack` gateway path (not the bare `_replay_candidate_trace`) as a
  non-scored T4 shadow kernel; derive a safe-N projection; add a parity-assertion
  tool proving台 config == gateway constants (hops, backend, guardrail, seed).
- **Phase 3 — velocity & calibration:** A/B/sweep ranking engine feeding
  promotion; canary→recalibrate loop; reproduce/beat the 55.8 replay-dense
  approach (current baseline is ~1/3 of it).
```
