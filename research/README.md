# Research Workspace

This directory is for dev-only candidate generation, controls, validation
helpers, and raw experiment outputs. Nothing in `src/attack.py` may import from
this directory.

Files:

- `candidate_families.py` -- deterministic CandidateSpec generators;
- `candidate_bank.schema.json` -- schema for generated candidates;
- generated negative controls live in `candidate_families.py`;
- `results/` -- raw JSONL/JSON validation outputs, ignored unless summarized.

Promotion into scored submission must happen through a manifest and a minimal
edit to `src/attack.py` / `notebooks/submission.ipynb`.

Example:

```bash
python research/candidate_families.py --families all --n 20 \
  --out research/results/candidate_bank.sample.jsonl
python tools/lint_candidate_bank.py research/results/candidate_bank.sample.jsonl
python tools/lint_candidate_bank.py research/results/candidate_bank.sample.jsonl \
  --scored --max-total-messages 400
python tools/eval_candidate_bank.py research/results/candidate_bank.sample.jsonl \
  --max-tool-hops 4
```

The default `all` bank intentionally contains research-only and rejected
negative-control families, so it should pass normal lint but fail `--scored`.
Use `tools/eval_candidate_bank.py` to prove scorer plumbing and controls with
the local compliant mock agent before spending GGUF or Kaggle runtime.
