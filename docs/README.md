# AI Agent Security Docs

> Status: reorganized on 2026-06-22 after runtime and council review.
> Current operating rule: do not spend another scored Kaggle slot until the
> blocking audit/parity/runtime gates in `project-engineering-design.md` exist.

## Current Decision

The project direction is runtime-first:

1. keep scored `src/attack.py` static, deterministic, and zero-interaction;
2. use the suppress-once direct EXFIL canary first, then recover a valid low-N
   score before larger sweeps;
3. keep real-model template search, multi-step families, stacking, and
   Harmony/ChatML probes in dev-only validation until promoted by evidence;
4. treat Kaggle packaging and pending-submission state as part of the algorithm,
   not as a last-mile detail.

The current repo is not submit-ready if `src/attack.py` or
`notebooks/submission.ipynb` still default to `N_CANDIDATES=600`; ref `53800639`
already showed that shape can runtime-exceed with no score.

## Read Order

1. `project-engineering-design.md` -- engineering architecture, target layout,
   blocking gates, and phased migration.
2. `infra.md` -- executable gate levels, Makefile targets, and CI/local split.
3. `competition-rules-and-overview.md` -- competition contract and operational
   constraints.
4. `scoring-mechanics.md` -- SDK scoring reverse engineering and runtime
   evidence.
5. `elicitation-templates.md` -- prompt/template hypotheses and what still needs
   GGUF validation.
6. `superpowers/specs/2026-06-22-agent-attack-research-design.md` --
   literature-backed predicate-route matrix and comprehensive attack/validation
   design.
7. `superpowers/specs/2026-06-22-attack-algorithm-design.md` -- scored attack
   strategy.
8. `superpowers/specs/2026-06-22-multistep-attack-system.md` -- research-only
   candidate factory and promotion rules.
9. `superpowers/plans/*.md` -- implementation work breakdowns.

## Gate Commands

- `make ci` -- SDK-free checks suitable for GitHub Actions.
- `make check` -- full local smoke gate; requires `competition_files/aicomp_sdk`.
- `make manifest-smoke` -- build a throwaway pre-submit manifest under `/tmp`.
- `make submit-ready` -- strict manifest gate; fails until validation/CSV
  evidence is complete.
- `make manifest-local` -- refresh the tracked latest local manifest and summary.
- `make submission-csv` -- generate the official four-row commit-run CSV.
- `make validation-summary` -- validate GGUF summary JSON against current source.
- `make validation-gguf` -- run real T4/GGUF validation and write that summary.
- `make kaggle-status` -- refresh Kaggle pending/status JSON.

## Current No-Go Conditions

Do not submit a new scored run when any of these are true:

- `N_CANDIDATES >= 600`;
- `tools/audit_attack.py` is missing or fails;
- `tools/check_submission_notebook.py` is missing or reports an unexplained
  mismatch;
- no validation record exists for the exact source/notebook SHA being submitted;
- a prior Kaggle ref is still `PENDING`, unless the slot-risk tradeoff is an
  explicit decision;
- Kaggle metadata does not prove `NvidiaTeslaT4`;
- the commit-run `submission.csv` does not contain exactly
  `gpt_oss_public`, `gpt_oss_private`, `gemma_public`, `gemma_private`.

## Generated Outputs

Keep large or volatile outputs out of docs. Summarize them into durable markdown
or small manifests instead:

- raw candidate banks: `research/results/` or `/tmp`;
- Kaggle push scaffolding: `kaggle_push/`;
- scored submission evidence: small manifest under `submissions/manifests/` or
  a summarized result under `docs/superpowers/results/`.
