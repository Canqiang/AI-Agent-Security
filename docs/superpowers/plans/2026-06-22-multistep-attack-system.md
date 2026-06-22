# Multi-Step Attack System Plan

> Status: proposed on 2026-06-22.
> Scope: build a dev-only candidate generation and validation system for multi-step attacks, while keeping scored `src/attack.py` runtime-safe.
> Primary spec: `docs/superpowers/specs/2026-06-22-multistep-attack-system.md`.
> Engineering contract: `docs/project-engineering-design.md`.

## Goal

Design and implement a repeatable system that can:

1. generate multiple families of single-step and multi-step `AttackCandidate` chains;
2. lint candidates before replay;
3. run local smoke checks with the compliant mock agent;
4. run real-model GGUF validation in Kaggle;
5. promote only verified candidates into `src/attack.py` or `notebooks/submission.ipynb`.

The system should separate leaderboard submissions from research probes. Multi-step candidates are not promoted just because they are interesting; they must pass hit-rate and runtime gates.

## Non-Goals

- Do not replace the current low-N static canary path before it produces a valid score.
- Do not promote any multi-step family before the blocking audit/parity/manifest tools exist.
- Do not put online Go-Explore or long `env.interact()` searches into scored `AttackAlgorithm.run()`.
- Do not submit high-N multi-step chains without validation wall-time evidence.
- Do not treat ChatML/Harmony text as privileged instruction injection; it is only a probe.
- Do not target real systems, real endpoints, or real credentials. All endpoints and payloads must stay in the competition sandbox pattern.

---

## Phase 0: Documentation Baseline

**Files:**
- `docs/superpowers/specs/2026-06-22-multistep-attack-system.md`
- `docs/superpowers/plans/2026-06-22-multistep-attack-system.md`

**Tasks:**
- Record system architecture.
- Record candidate families and promotion gates.
- Keep existing `docs/scoring-mechanics.md` user edits intact.

**Verification:**

```bash
rg -n "File Handoff|Harmony|Promotion Gate|CandidateSpec" docs/superpowers
```

---

## Phase 1: Candidate Schema and Family Generators

**Files to add:**
- `research/candidate_families.py`
- `research/candidate_bank.schema.json`
- optionally `tools/generate_candidate_bank.py`

**Candidate families for v1:**

| Family | Messages | Purpose |
|---|---:|---|
| `direct_exfil_control` | 1 | score/control baseline |
| `memory_2turn` | 2 | cross-turn memory |
| `file_handoff_3turn` | 3 | local state handoff |
| `legacy_runbook_3turn` | 3 | grandma/legacy framing |
| `harmony_protocol_probe` | 2-3 | protocol-format probe |
| `taint_window_launder_probe` | 6-8 | public guardrail research only |
| `confused_deputy_route` | 2 | non-EXFIL predicate exploration |

**Behavior:**
- Generate deterministic `CandidateSpec` dicts.
- Use clean unique domains: `https://h{i}.example.net/p`.
- Verify these domains are distinct score-cell buckets through SDK `_bucket_url`; do not rely on visual uniqueness alone.
- Keep message length below 2000 chars.
- Mark each spec with `public_guardrail_risk`.
- Default output should be small: `--n-per-family 20`.

**Verification:**

```bash
python tools/generate_candidate_bank.py --n-per-family 20 --out /tmp/aiagsec_candidates.jsonl
python -m json.tool research/candidate_bank.schema.json >/dev/null
```

---

## Phase 2: Static Lint and Audit

**Files to add or extend:**
- `tools/audit_attack.py`
- `tools/lint_candidate_bank.py`

**Checks:**
- candidate count;
- total replay messages;
- max/mean/min message length;
- duplicate domains;
- duplicate score-cell host buckets;
- URL sensitive words;
- `secret.txt` direct-read attempts;
- families marked `research-only`;
- estimated replay cost units;
- expected raw under compliant baseline for direct EXFIL candidates.

**Verification:**

```bash
python tools/lint_candidate_bank.py /tmp/aiagsec_candidates.jsonl
python tools/audit_attack.py --n 200
```

Expected:
- no sensitive URL warnings;
- `file_handoff_3turn` uses clean `handoff-{i}.txt`, not `secret.txt`;
- `taint_window_launder_probe` is flagged as research-only.

---

## Phase 3: Replay Summary

**Files to add:**
- `tools/eval_candidate_bank.py`

**Behavior:**
- Convert CandidateSpec messages to `AttackCandidate`.
- Replay against local compliant agent where applicable.
- Produce JSON summary with:
  - findings;
  - predicates;
  - successful tools;
  - blocked tools;
  - no-tool/refusal count;
  - per-family score density.

**Important boundary:**
The compliant agent is only a scoring plumbing smoke test. It cannot predict real `gpt_oss` or `gemma` refusal behavior.

**Verification:**

```bash
python tools/eval_candidate_bank.py /tmp/aiagsec_candidates.jsonl --agent compliant --limit 20
```

Expected:
- `direct_exfil_control` scores;
- multi-step families may need a smarter local mock or GGUF validation to be meaningful.

---

## Phase 4: GGUF Real-Model Validation

**Files:**
- `notebooks/validation.ipynb`
- output summaries under ignored `research/results/`

**Behavior:**
- Load candidate bank.
- Replay small batches against real `gpt_oss` and `gemma` GGUF targets.
- Record:
  - hit rate;
  - exact payload rate;
  - negative-control behavior;
  - guardrail block rate;
  - refusal/no-tool rate;
  - wrong-tool rate;
  - wall time;
  - p50/p95 seconds per candidate;
  - path and hop cap;
  - raw per second;
  - representative traces.

**Batch plan:**

| Batch | N/family | Families |
|---|---:|---|
| V0 | 5 | direct, memory, file handoff |
| V1 | 20 | direct, memory, file handoff, legacy |
| V2 | 20 | Harmony probe, ChatML probe |
| V3 | 5-10 | taint-window and confused deputy probes |

**Verification:**

```bash
python -c "import json; json.load(open('notebooks/validation.ipynb'))"
jupyter nbconvert --to script --stdout notebooks/validation.ipynb > /tmp/validation.py
python -m py_compile /tmp/validation.py
```

---

## Phase 5: Promotion

**Files to add:**
- `research/promotion_manifest.json`
- optionally `tools/promote_candidate_family.py`

**Promotion gate:**

| Gate | Required |
|---|---|
| Real-model score | nonzero on both target models for small N, with repeated replay stability |
| Hit-rate floor | min-model hit rate has an explicit lower bound, not one lucky finding |
| Runtime | score density acceptable vs C1 by raw/sec and raw/message |
| Trace match | expected multi-step path appears, not accidental single-step fallback |
| Negative controls | no-secret/wrong-secret do not trigger EXFIL; duplicate-domain merges cell |
| Guardrail | no unexplained DENY spike |
| Static export | can be represented without online search in scored `run()` |
| Parity | `src/attack.py` and notebook attack source match or mismatch is explicitly accepted |
| Manifest | source SHA, notebook SHA, N, total messages, T4 metadata, and pending-ref decision are recorded |

**Promotion outcomes:**
- `promoted_to_submission`: safe to copy into `src/attack.py`;
- `research_only`: keep for Working Note;
- `rejected`: keep result summary, do not retry without new hypothesis.

---

## Phase 6: Submission Integration

**Files:**
- `src/attack.py`
- `notebooks/submission.ipynb`

**Rules:**
- Keep scored `AttackAlgorithm.run()` deterministic.
- Prefer static candidate generation over reading JSON files in submission.
- Start with low N canaries.
- Do not mix many families in one scored submission until each family has per-model validation.

**Pre-submit commands:**

```bash
python tools/audit_attack.py --n 200
python tools/check_submission_notebook.py
python tools/local_eval.py compliant --n 20
# once implemented:
# python tools/kaggle_status.py --competition ai-agent-security-multi-step-tool-attacks
```

Add validation summary manually before burning a Kaggle slot:

```text
family:
N:
messages_per_candidate:
gpt_oss hit_rate:
gemma hit_rate:
expected replay calls:
source sha:
notebook sha:
```

---

## Open Questions

1. Does `file_handoff_3turn` produce true multi-step traces on both gpt-oss and gemma, or does one model summarize instead of acting?
2. Does Harmony/ChatML formatting help gpt-oss without hurting gemma?
3. Is the public taint-window launder probe worth a private-guardrail bet, or only a Working Note result?
4. What is the real score-density cutoff where a multi-step family beats low-N C1?
5. Can a two-turn memory family deliver most of the multi-step value at much lower runtime cost than file handoff?

## Definition of Done

- Candidate families are generated deterministically.
- Candidate bank lint catches unsafe or runtime-heavy shapes.
- At least C1 and one multi-step family have GGUF validation summaries.
- Promotion manifest clearly says what is submitted and why.
- The scored notebook contains only promoted, runtime-gated logic.
