# Project Engineering Design -- Runtime-Gated Candidate Factory

> Date: 2026-06-22
> Status: proposed engineering contract after council review.
> Scope: repo organization, blocking gates, evidence manifests, and promotion
> workflow for Kaggle `ai-agent-security-multi-step-tool-attacks`.

---

## 1. Verdict

The algorithm direction is sound, but the project should not be operated as a
collection of notebooks and prose gates. The next version must be organized as a
runtime-gated candidate factory:

```text
scored adapter       -> audit/parity/runtime gates -> Kaggle scored canary
research candidates -> local lint/replay           -> GGUF validation
validated winners   -> promotion manifest          -> scored adapter
```

The immediate priority is not a richer attack family. It is making the gates
executable so stale `N=600`, notebook/source drift, wrong Kaggle metadata, or a
pending submission cannot accidentally burn a slot.

---

## 2. Target Repository Layout

```text
src/
  attack.py                         # only scored entrypoint; stdlib + aicomp_sdk only
  archive/                          # optional: old submitted variants, not imported

tools/
  audit_attack.py                   # blocking scored-source audit
  check_submission_notebook.py      # source/notebook parity
  lint_candidate_bank.py            # research CandidateSpec lint
  eval_candidate_bank.py            # local replay summary, mock-only
  kaggle_status.py                  # Python API polling; avoids broken CLI path
  build_submission_manifest.py      # immutable evidence before submit

research/
  candidate_families.py             # dev-only generators
  candidate_bank.schema.json        # CandidateSpec contract
  controls.py                       # negative controls for scorer sanity
  results/                          # ignored raw validation outputs

notebooks/
  submission.ipynb                  # writes /kaggle/working/attack.py
  validation.ipynb                  # GGUF gpt_oss/gemma validation only

docs/
  README.md
  project-engineering-design.md
  scoring-mechanics.md
  elicitation-templates.md
  superpowers/specs/
  superpowers/plans/
  superpowers/results/              # small summarized result docs only

submissions/
  manifests/                        # small JSON/markdown evidence per Kaggle ref
```

Rules:

- `src/attack.py` must not import from `research/`, `tools/`, notebooks, or local
  generated files.
- `research/` can import SDK internals and use heavy dependencies; it is
  excluded from scored submission.
- `tools/` own reproducibility and gates. If a requirement matters for
  submission safety, it belongs in a tool, not only in a document.
- `kaggle_push/`, raw result JSONL, model outputs, and notebook download
  artifacts stay ignored.

---

## 3. Scored Submission Contract

`src/attack.py` is a minimal adapter:

1. deterministic candidate generation;
2. no `env.interact()`, `snapshot()`, or `restore()` in the default scored path;
3. no online search, no Go-Explore, no stacking unless a manifest explicitly
   promotes it;
4. one clear source of candidate count;
5. clean public domains and payloads only from approved sandbox secret markers;
6. no dependency outside stdlib and `aicomp_sdk`.

The first blocking audit must fail on:

- `N_CANDIDATES >= 600`;
- duplicate `http.post` host buckets;
- URL containing `secret/password/token/key/credential/private/confidential/api_key`;
- any scored-path call to `env.interact`, `snapshot`, or `restore`;
- message over 2000 chars;
- total replay messages above the current budget cap;
- unresolved notebook/source mismatch;
- stacking enabled without a promotion manifest.

`core/cells.py::_bucket_url` currently buckets by full host, so
`h0.example.net` and `h1.example.net` should be distinct. The audit should still
prove this with a small SDK-backed check so a future SDK change cannot silently
break the cell economics.

---

## 4. Kaggle Packaging Contract

Every scored attempt needs a manifest before submit:

```json
{
  "competition": "ai-agent-security-multi-step-tool-attacks",
  "source_sha256": "...",
  "notebook_attack_sha256": "...",
  "kernel_slug": "canqiang/...",
  "kernel_version": 0,
  "machine_shape": "NvidiaTeslaT4",
  "n_candidates": 0,
  "total_replay_messages": 0,
  "templates": ["C1"],
  "expected_raw_compliant": 0,
  "validation_summary": "...",
  "pending_refs_checked_at": "..."
}
```

Submission blockers:

- metadata does not prove `machine_shape == "NvidiaTeslaT4"`;
- commit-run placeholder CSV is not exactly the four official rows:
  `gpt_oss_public`, `gpt_oss_private`, `gemma_public`, `gemma_private`;
- an earlier Kaggle ref is still `PENDING`, unless the manifest states that the
  parallel-slot risk is intentional;
- Kaggle status was checked only through the broken CLI path. Use the Python API
  status path for monitoring.

---

## 5. Runtime Model

The old `N=200/300/400` ladder is only a sketch. The gate should be evidence
driven:

```text
estimated_wall_s =
  p95_seconds_per_candidate
  * n_candidates
  * target_model_count
  * safety_factor
```

Record both message and hop economics:

- `seconds_per_candidate`;
- `seconds_per_user_message`;
- `seconds_per_tool_hop`;
- `p50/p95` latency;
- `hit_rate_gpt_oss`, `hit_rate_gemma`;
- `exact_payload_rate`;
- `guardrail_block_rate`;
- `raw_per_second`;
- `raw_per_replay_message`.

Hop-count wording must name the path:

- Kaggle gateway code uses `AttackRunConfig.max_tool_hops` / `DEFAULT_MAX_TOOL_HOPS`
  = 8 during replay.
- Local SDK `evaluation.ops` default options use
  `EVALUATION_DEFAULT_MAX_TOOL_HOPS = 4`.

Designs should not rely on more than 4 hops unless the validation path is known
to match the scored Kaggle gateway. Every result summary must record which path
and hop cap produced it.

---

## 6. Validation Contract

`notebooks/validation.ipynb` is the load-bearing research environment. A result
is promotable only if it records:

- exact source SHA and generated candidate manifest;
- model backend and quantization, especially GGUF/Q4 path;
- target model split: `gpt_oss` and `gemma` separately;
- repeated deterministic replay for small N;
- per-model hit rate with lower-bound estimate, not just a single success;
- exact payload rate;
- trace match against expected tools;
- score density versus C1;
- runtime budget evidence.

Negative controls are required before trusting score density:

- no-secret payload;
- wrong-secret payload;
- duplicate host/domain;
- duplicate body with unique host;
- decoy secret in user text but not in `http.post.data`.

These controls prove the scorer is counting real EXFIL findings and distinct
score cells, not prompt echoes, duplicate artifacts, or mock-agent behavior.

---

## 7. Promotion Contract

Candidate states:

| State | Meaning |
|---|---|
| `research` | generated or hypothesized; never scored |
| `validated` | real-model evidence exists, but not yet score-dense |
| `promoted` | eligible for scored adapter |
| `rejected` | keep evidence, do not retry without a new hypothesis |

Minimum promotion gates:

1. nonzero findings on both target models;
2. repeated replay stability for the exact prompt family;
3. exact trace match, not accidental single-step fallback;
4. score density beats or justifies replacing C1 under conservative estimates;
5. no unexplained guardrail block spike;
6. static export possible without online search;
7. source/notebook parity and manifest complete.

Single-EXFIL multi-turn families are research-only by default because they
produce the same 18 raw as C1 while spending more messages. Stacking is
hard-disabled from scored export until message-vs-hop runtime economics are
measured.

---

## 8. Migration Plan

### Phase 0 -- Freeze Unsafe Submit Path

- Lower or gate away `N_CANDIDATES=600`.
- Add a manifest for ref `53800639` with source/notebook SHA, runtime failure
  taxonomy, and exact submitted settings.

### Phase 1 -- Blocking Gates

- Implement `tools/audit_attack.py`.
- Implement `tools/check_submission_notebook.py`.
- Add generated-output ignores for `research/results/`, `docs/superpowers/results/*.jsonl`,
  and transient submission bundles.

### Phase 2 -- Validation Baseline

- Build `notebooks/validation.ipynb`.
- Run C1 at small N (`50/100/150/200`) on the exact GGUF path where possible.
- Produce a summarized validation result under `docs/superpowers/results/`.

### Phase 3 -- Candidate Factory

- Add `research/candidate_families.py` and schema.
- Generate direct C1 and research-only families.
- Lint and local-replay only as smoke tests.

### Phase 4 -- Promotion

- Write `research/promotion_manifest.json` or per-run manifests.
- Promote only one family at a time into `src/attack.py`.

### Phase 5 -- Scored Canary

- Submit only after audit, parity, manifest, validation summary, T4 metadata,
  and pending-ref checks all pass.

---

## 9. First Concrete Slice

The next implementation slice should be deliberately narrow:

```bash
python tools/audit_attack.py --n 200
python tools/audit_attack.py --n 600
python tools/check_submission_notebook.py
python tools/local_eval.py compliant --n 20
```

Expected behavior:

- `--n 600` fails or emits a high-risk blocker;
- `--n 200` passes only if message/domain/source checks pass;
- parity check reports exact SHA equality or a deliberate inline mismatch;
- local eval proves only scoring plumbing, not real-model hit rate.

### Implementation Status

As of the first implementation pass:

- `tools/audit_attack.py` exists and blocks stale high-N or unpromoted
  multi-message scored shapes.
- `tools/check_submission_notebook.py` exists and verifies that the notebook's
  `%%writefile /kaggle/working/attack.py` source matches `src/attack.py`.
- `src/attack.py` and `notebooks/submission.ipynb` default to the suppress-once canary
  upper bound `N_CANDIDATES=200`.
- Old `N=2000` / stacking variants are archived under `src/archive/`.
- `Makefile` now provides `make ci` for SDK-free GitHub checks and `make check`
  for the full local SDK gate.
- `make submit-ready` builds a strict `/tmp` manifest and fails until validation
  summary and commit-run CSV evidence are complete.
- `.github/workflows/check.yml` runs `make ci` on push and pull request without
  requiring the private competition SDK.
- `docs/infra.md` documents the CI/local split and submit-readiness distinction.
- `tools/validate_validation_summary.py` and
  `submissions/manifests/validation-summary.schema.json` define the minimal
  GGUF validation evidence contract.
- `tools/write_submission_csv.py` writes the official four-row commit-run CSV.

The next implementation slice is `notebooks/validation.ipynb` producing a real
GGUF validation summary for the current suppress-once source SHA. Once that file
exists, `make submit-ready` should be the promotion gate from
`local_gates_ready=true` to `submit_ready=true`.
