# Submission Manifests

Each scored Kaggle attempt should have a small manifest before submission.

The manifest should record:

- source SHA and notebook attack SHA;
- kernel slug/version and `machine_shape`;
- candidate count and total replay messages;
- template/family names;
- validation summary reference;
- pending-ref check result;
- Kaggle submission ref and final status once known.

Do not store large bundles or generated notebooks here. Store compact JSON
manifests and optional Markdown summaries only.

Build a local pre-submit manifest with:

```bash
python tools/build_submission_manifest.py \
  --n 200 \
  --machine-shape NvidiaTeslaT4 \
  --candidate-bank research/results/candidate_bank.suppress.jsonl \
  --candidate-bank-scored \
  --eval-candidate-bank \
  --allow-missing-validation \
  --summary-md docs/superpowers/results/pre-submit-local-summary.md
```

`--allow-missing-validation` is for a local evidence snapshot only. For a real
scored submission, omit that flag, add `--validation-summary ...`, and keep the
Kaggle metadata, commit-run `submission.csv`, and pending-ref fields current.
The generated Markdown summary is for review; the JSON manifest remains the
source of truth.

For the strict pre-submit path, use:

```bash
make submit-ready \
  VALIDATION_SUMMARY=research/results/validation-summary.latest.json \
  SUBMISSION_CSV=/tmp/aiagsec-submission.csv
```

`make submit-ready` is expected to fail until the GGUF validation summary exists
and passes `tools/validate_validation_summary.py`. It still writes the manifest
under `/tmp`, so the blockers remain inspectable.
The command refreshes Kaggle status first and rejects stale status snapshots.

Generate the official four-row commit-run CSV with:

```bash
make submission-csv SUBMISSION_CSV=/tmp/aiagsec-submission.csv
```

Refresh Kaggle status with:

```bash
python tools/kaggle_status.py \
  --competition ai-agent-security-multi-step-tool-attacks \
  --kernel canqiang/aiagsec-static-c1-n600 \
  --out submissions/manifests/kaggle-status.latest.json
```

If `submissions.pending_refs` is non-empty, pass each ref to
`tools/build_submission_manifest.py` as `--pending-ref <ref>` unless the
parallel-slot risk is intentional.
