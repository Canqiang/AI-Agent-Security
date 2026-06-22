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
| `make manifest-local` | no | yes | Refresh tracked latest local manifest and markdown summary |
| `make kaggle-status` | no | Kaggle credentials | Refresh Kaggle pending/status snapshot |

`make ci` is intentionally SDK-free. It catches repository drift that can be
checked from a clean clone:

- Python syntax for all tracked `.py` files;
- `src/attack.py` and `notebooks/submission.ipynb` parity;
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
