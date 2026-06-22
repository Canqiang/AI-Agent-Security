# Research Workspace

This directory is for dev-only candidate generation, controls, validation
helpers, and raw experiment outputs. Nothing in `src/attack.py` may import from
this directory.

Planned files:

- `candidate_families.py` -- deterministic CandidateSpec generators;
- `candidate_bank.schema.json` -- schema for generated candidates;
- `controls.py` -- no-secret, wrong-secret, duplicate-domain, duplicate-body,
  and decoy-secret controls;
- `results/` -- raw JSONL/JSON validation outputs, ignored unless summarized.

Promotion into scored submission must happen through a manifest and a minimal
edit to `src/attack.py` / `notebooks/submission.ipynb`.
