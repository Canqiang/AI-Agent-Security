# Infrastructure

> Status: minimal executable infra added on 2026-06-22.

This repository has two gate levels because the competition SDK under
`competition_files/` is local-only and must not be redistributed.

## Gate Levels

| Command | Runs in GitHub CI | Requires `competition_files/aicomp_sdk` | Purpose |
|---|---:|---:|---|
| `make ci` | yes | no | Syntax, notebook/source parity, candidate-bank schema/lint |
| `make check` | no | yes | Full local gate: CI checks plus attack audit, compliant replay, manifest smoke |
| `make manifest-smoke` | no | yes | Build throwaway pre-submit manifest under `/tmp` |
| `make submit-ready` | no | yes | Strict manifest build; fails until validation and CSV evidence are complete |
| `make manifest-local` | no | yes | Refresh tracked latest local manifest and markdown summary |
| `make submission-csv` | no | no | Write the official four-row commit-run CSV |
| `make validation-summary` | no | no | Validate a GGUF summary JSON against the current source/notebook SHA |
| `make validation-gguf` | no | yes + GGUF models/GPU | Run real `gpt_oss`/`gemma` validation and write the summary JSON |
| `make validation-kernel` | no | no | Build ignored self-contained Kaggle validation kernel folder |
| `make kaggle-status` | no | Kaggle credentials | Refresh Kaggle pending/status snapshot |

`make ci` is intentionally SDK-free. It catches repository drift that can be
checked from a clean clone:

- Python syntax for all tracked `.py` files;
- `src/attack.py` and `notebooks/submission.ipynb` parity;
- `notebooks/validation.ipynb` JSON and Python syntax;
- normal candidate-bank lint for mixed research families;
- scored candidate-bank lint for `direct_exfil_suppress_once`.

`make check` is the local pre-submit smoke. It additionally proves:

- `src/attack.py` passes the blocking scored audit at `N=200`;
- the suppress-once candidate bank replays through the SDK scorer with the
  compliant mock agent;
- `tools/local_eval.py compliant --n 20` still produces the expected EXFIL
  score path;
- manifest generation works without mutating tracked manifest files.

## Submit Readiness

Passing `make check` is necessary but not sufficient for a scored Kaggle
submission. `submit_ready=true` still requires:

- a GGUF real-model validation summary for the exact source/notebook SHA;
- official four-row `submission.csv` evidence;
- fresh Kaggle status with no pending refs, unless parallel-slot risk is
  deliberate;
- kernel metadata proving `NvidiaTeslaT4`.

The tracked latest manifest currently remains the source of truth for this
distinction: local gates can pass while strict submit blockers remain.

## Strict Submit Gate

`make submit-ready` writes a strict manifest to `/tmp` and intentionally exits
non-zero until every submit blocker is resolved. It also generates the commit-run
CSV through `tools/write_submission_csv.py`, so the remaining blocker should be
the GGUF validation summary unless Kaggle status or metadata is stale.

The validation summary must use schema
`2026-06-22.validation-summary.v1` and pass:

```bash
python tools/validate_validation_summary.py research/results/validation-summary.latest.json
```

Required top-level fields:

- `source_sha256` and `notebook_attack_sha256` for the exact submitted source;
- `candidate_family`, `validation_n`, `total_messages`, `max_tool_hops`;
- `backend`, for example the GGUF/llama.cpp harness description;
- `results.gpt_oss` and `results.gemma`, each with attempted candidates,
  findings, hit rate, exact payload rate, guardrail block rate, p95 seconds per
  candidate, and total wall time.

Submit readiness requires both model results to have positive findings,
positive hit rate, and positive exact-payload rate. The backend string must
identify GGUF llama.cpp validation; mock or placeholder summaries are rejected.

The real-model producer is:

```bash
make validation-gguf \
  VALIDATION_N=20 \
  VALIDATION_MAX_TOOL_HOPS=8 \
  VALIDATION_BUDGET_PER_MODEL=3000
```

It writes:

- `research/results/validation-summary.latest.json`, consumed by
  `make submit-ready`;
- `research/results/validation-raw.latest.jsonl`, a per-candidate replay log
  for debugging failed or slow candidates.

Run it in a T4 environment with the competition SDK plus the GGUF model files
available. The repo notebook `notebooks/validation.ipynb` is a thin Kaggle entry
point for that command. For offline Kaggle runs, set `GPT_OSS_MODEL_PATH` and
`GEMMA_MODEL_PATH` to the attached `.gguf` files before running the notebook.

For Kaggle API push, build the ignored self-contained kernel folder first:

```bash
make validation-kernel
kaggle kernels push -p kaggle_push/validation
```

This matters because Kaggle kernel push uploads only the notebook named in
`kernel-metadata.json`; the generated notebook embeds the required `src/` and
`tools/` files before running validation.

Generated CSV evidence should stay outside git, for example:

```bash
make submission-csv SUBMISSION_CSV=/tmp/aiagsec-submission.csv
```

The strict gate refreshes Kaggle status before building the manifest and rejects
snapshots older than `MAX_KAGGLE_STATUS_AGE_MIN` minutes.
