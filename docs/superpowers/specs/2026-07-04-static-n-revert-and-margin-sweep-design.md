# Static-N Revert + Adaptive Margin Sweep — Design & Decision Record

**Date:** 2026-07-04
**Status:** In progress. 2/5 rungs scored, 1/5 pending, 2/5 queued.
**Supersedes:** the 2026-07-03 static-N ladder (`src/attack.py` commit `66fbebf`) — retired as a measured failure.
**Related:** `2026-07-02-adaptive-per-model-fill-design.md` (the mechanism this reverts to), memory `scored-submission-ledger`, `scoring-gateway-and-adaptive-n`, `competitive-landscape-2026-07-01`.

---

## 1. Problem

2026-07-03 shipped a static-N ladder (fixed candidate count, same for both
models, no live probing) at three rungs: N=900, N=1150, N=670. **All three
failed identically** — Kaggle status `other_error`, `error_description`
"incorrect format", no score. N=670 was chosen to mirror a community-reported
"proven" static N=667 (`caoyupeng`, public ~60); it failed anyway.

Root-caused 2026-07-04 (see memory `scoring-gateway-and-adaptive-n` for the
full trace):

1. The notebook's own visible kernel log is a **decoy** — it is always the
   pre-submit commit-step placeholder branch (`IS_RERUN` falsy), never the real
   scored rerun. All three failures showed near-identical ~25s logs; this
   proved nothing about a shared root cause, since that log can't see the real
   replay at all.
2. `self.config.get("n_candidates")` cannot crash — `AttackAlgorithmBase.__init__`
   unconditionally sets `self.config` to a dict. Ruled out as an alternative
   explanation.
3. **New mechanism, confirmed by reading `jed_attack_gateway.py` end to end:**
   Phase-2 replay (`_replay_and_score`) runs once per entry in
   `build_guardrail_configs()` — `"public"` always, plus `"private"` whenever
   `AICOMP_ATTACK_GUARDRAIL_ID` is set, which the real graded rerun does. So
   **every candidate is replayed TWICE per model**, with **zero wall-clock
   check anywhere in that loop**, and any single exception raises an uncaught
   `GatewayRuntimeError` that aborts the whole submission before
   `write_submission()` ever runs. Real replay cost is roughly 2× a naive
   `N × per-candidate-latency` estimate — a concrete reason a "conservative"
   N=670 still blew the wall.
4. **Leaderboard cross-check (via `kaggle competitions leaderboard -s`, not
   JS-gated) reframed the whole picture:** multiple teams landed 70-100+ public
   the same day (07-03), including Victor Merckle's 100.49 at 08:49 — *before*
   our 900/1150 failures at 09:40/09:43 that same morning. **The wall is
   time-varying shared-resource contention, not a fixed ceiling.** 90-100 is
   genuinely reachable same-day via the same single-hop primitive; our specific
   attempt just had worse luck/timing, or a worse safety margin, than theirs.

Static-N also gave up a real lever for no benefit: pinning both models to one
shared N wastes gemma's speed advantage (non-reasoning, replays far faster
than gpt_oss). The adaptive per-model fill (`2026-07-02-adaptive-per-model-fill-design.md`)
already solves this and has a proven non-failing data point (ref `54283427`,
public 32.415, 2026-07-03).

## 2. Decision

Revert `src/attack.py` to the adaptive per-model fill, using the exact
(`BUDGET_MARGIN=0.55`, `HARD_N_CAP=1100`) config that scored 32.415 — the one
config proven not to fail. Then, rather than guess a single new static number
again (the mistake made 3 times on 07-03), **sweep the one safety knob that
controls aggressiveness** (`BUDGET_MARGIN` / `HARD_N_CAP`) across today's fresh
5-submission quota, monotonically from conservative to aggressive:

| rung | margin | cap  | role |
|---|---|---|---|
| canary_m030_cap600 | 0.30 | 600 | near-certain landing; confirms scorer + today's contention |
| adaptive_m055_cap1100 (main `src/attack.py`) | 0.55 | 1100 | exact repeat of the proven 07-03 config |
| step_m070_cap1400 | 0.70 | 1400 | moderate step up |
| step_m085_cap1700 | 0.85 | 1700 | aggressive step |
| moonshot_m095_cap1950 | 0.95 | 1950 | near max margin, cap near the SDK's 2000-candidate ceiling |

Every rung is byte-identical to `src/attack.py` except these two constants —
same `TEMPLATE`, `PAYLOAD`, probe mechanism, and cold-start fix. This isolates
"how aggressive can today's margin be" as the only variable under test.

Since Kaggle keeps the best-ever public score regardless of what any single
submission does, and the banked best (55.8, pre-v3.1.2 baseline) is unaffected
by any of these rungs failing, there is no downside to firing all 5 — only the
question of how to allocate them for maximum information + upside.

## 3. Implementation

- `src/attack.py`: reverted to the pre-pivot adaptive source (git history
  `66fbebf^`), docstring updated to record why (see §1), constants unchanged
  from the proven config.
- `tools/tests/test_attack.py`: restored the adaptive-era tests (cold-start
  probe test, env-not-probeable fallback test), dropped the two static-only
  tests.
- `notebooks/submission.ipynb` + `kaggle_push/submission/` (deploy copy):
  re-synced to the reverted source; `tools/check_submission_notebook.py`
  parity confirmed.
- New tool `tools/prepare_margin_sweep_variants.py`: generates a variant
  folder (`submission.ipynb` + `kernel-metadata.json` + `variant-manifest.json`
  + a plain `attack.py` copy for easy audit/diffing) per rung by regex-
  substituting the `BUDGET_MARGIN`/`HARD_N_CAP` assignment lines in the
  canonical source. Mirrors the existing `tools/prepare_submission_variant.py`
  pattern (used for the 06-23 chain/linear variants) but targets the adaptive
  mechanism instead of a from-scratch template generator.
- All 5 rungs (main + 4 variants) locally audited clean
  (`tools/audit_attack.py --allow-high-n --allow-env-probe`) and parity-checked
  before spending any real submission quota.

## 4. Bugs found and fixed in existing tooling

`tools/push_submit_variants.py` (last touched during the 2026-06-23 chain-
variant work, never updated alongside `safe_submit.py`'s subsequent evolution)
had two real staleness bugs, both hit on the first live use today:

1. Its `_real_audit()` call was missing the `per_candidate_seconds` positional
   argument that `safe_submit.py` added later — `TypeError` on first
   invocation.
2. Its hardcoded `SubmitPlan(...)` never set `allow_env_probe=True`. The old
   chain/linear variants never touched `env`, so this never mattered; the new
   adaptive variants DO call `env.interact()` to probe latency, so every one
   would have hard-failed the audit gate ("scored source contains env calls")
   without this fix.

Both fixed directly in `tools/push_submit_variants.py` (not routed around).

## 5. Operational constraint discovered: submissions are strictly sequential

`safe_submit.py`'s no-pending gate (`_real_pending`) queries the Kaggle API
LIVE on every call, not a cache — a second ref cannot be submitted while a
first is unresolved without `--allow-pending`. Chose NOT to override this:
firing multiple concurrently-pending scored reruns would risk contending with
ourselves on the same shared backend this whole investigation is about.
**Consequence: the 5-rung sweep is a multi-hour campaign**, not a batch fired
in one sitting — each rung is submitted only after the previous one fully
resolves (observed so far: 2h37m and re-checks up to ~4.5h).

## 6. Results so far (updated as rungs resolve)

- `canary_m030_cap600` → ref `54314894`, **public 16.76**, complete_scored.
  Confirms SECRET_MARKER still scores today (no silent evaluator-update
  deploy) and the reverted mechanism works cleanly.
- `adaptive_m055_cap1100` (main kernel, proven-repeat) → ref `54318747`,
  **public 30.57**, complete_scored. Closely matches yesterday's 32.415 on the
  identical config — today's contention is in the same ballpark as yesterday.
  Margin→score looks roughly linear in this range (0.30→16.76, 0.55→30.57;
  ratio ~1.83 tracks the margin ratio ~1.83).
- `step_m070_cap1400` → ref `54325761`, submitted, pending.
- `step_m085_cap1700`, `moonshot_m095_cap1950` → queued, not yet submitted.

## 7. Risks & open items

- If the roughly-linear margin→score relationship breaks down (rather than
  gracefully saturating) as margin approaches the real wall, a rung could
  repeat the 07-03 "incorrect format" failure instead of a graceful
  low/zero score. No downside either way (best score is preserved), but it
  would mean the wall is sharper/less forgiving than the canary/proven-repeat
  data suggests.
- The evaluator update (SECRET_MARKER → real-fixture replay traces) is still
  not confirmed deployed; each rung's success is also, incidentally, a fresh
  same-day check that it hasn't landed yet.
- `expected_public_score` in each variant manifest (`hard_n_cap * 0.09`) is an
  optimistic ceiling (assumes the cap binds for both models), not a mean-case
  prediction — real scores are governed by live-probed latency, not the cap.

## 8. Experience / process notes

- Trust the audit's own empirically-calibrated `safe_n_max` (320,
  `per_candidate_seconds=22.5`, bracketed by two real scored-outcome data
  points) over external/community N numbers — `caoyupeng`'s reported working
  N=667 did not transfer to our environment (N=670 failed 3 times over). This
  is now the second time this lesson has cost real submissions to relearn.
  the 22.5s/candidate empirical figure, in hindsight, already implicitly
  reflected the 2× guardrail-replay cost discovered in §1.3 — it was right for
  a reason we didn't understand yet when it was first calibrated.
- When a background/scaffolding tool hasn't been exercised in weeks, expect it
  to have drifted from the code it wraps — audit it against current call
  signatures before trusting it with real, quota-limited actions.
