# Submission Manifest Summary

- Manifest: `submissions/manifests/pre-submit-local.latest.json`
- Created: `2026-06-22T08:38:49+00:00`
- Competition: `ai-agent-security-multi-step-tool-attacks`
- Description: static C1 n200 local pre-submit evidence with live Kaggle status
- Local gates ready: `true`
- Submit ready: `false`

## Source

- Source: `src/attack.py`
- Source SHA256: `6e0123010ccc1ac4adaf4278c920f0ac175eafdce4e116d534f84e19d9f68ca9`
- Requested candidates: `200`
- Module default candidates: `200`
- Notebook source match: `true`

## Gates

| Gate | Result | Detail |
|---|---|---|
| attack audit | pass | 200 candidates, 200 messages, 200 unique host buckets |
| notebook parity | pass | attack SHA `6e0123010ccc1ac4adaf4278c920f0ac175eafdce4e116d534f84e19d9f68ca9` |
| candidate bank | pass | research/results/candidate_bank.c1.jsonl |
| validation summary | fail | no GGUF validation summary supplied |
| T4 metadata | pass | machine_shape=`NvidiaTeslaT4` |
| pending refs | pass | 0 pending |
| commit-run csv | fail | no commit-run submission.csv supplied |

## Candidate Bank

- Lint candidates: `5`
- Lint messages: `5`
- Scored mode: `true`
- Lint blockers: `0`
- Lint warnings: `0`
- Eval findings: `5`
- Eval raw score: `90.0`
- Eval raw per message: `18.0`
- Eval over budget: `false`

## Kaggle Status

- Status snapshot present: `true`
- Snapshot path: `submissions/manifests/kaggle-status.latest.json`
- Snapshot pending refs: `[]`
- Kernel slug: `canqiang/aiagsec-static-c1-n600`
- Kernel version: `None`

## Blockers

- none

## Strict Submit Blockers

- GGUF validation summary missing or invalid
- official four-row submission.csv evidence missing or invalid

## Notes

- Live Kaggle status shows no pending refs; GGUF validation summary and commit-run CSV not attached yet.
