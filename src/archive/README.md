# Archived Attack Variants

These files are historical scored-submission experiments. They are kept for
provenance only and must not be imported by `src/attack.py` or copied into
`notebooks/submission.ipynb` without a fresh audit and promotion manifest.

Current reasons they are archived:

- high candidate counts such as `N_CANDIDATES=2000` are incompatible with the
  current runtime-first plan;
- stacking is explicitly unresolved and disabled from scored export until
  message-vs-hop runtime economics are measured on the GGUF validation path;
- old templates may not match the current C1 baseline or current Kaggle runtime
  evidence.
