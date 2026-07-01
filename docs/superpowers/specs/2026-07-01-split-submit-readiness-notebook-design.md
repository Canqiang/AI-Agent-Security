# Design: split submit-readiness checking out of the GGUF validation notebook

> Date: 2026-07-01
> Status: design, pre-implementation (awaiting spec review)
> Related: `docs/superpowers/specs/2026-06-30-gguf-v312-viability-sweep-design.md`,
> `notebooks/validation.ipynb`, `tools/prepare_validation_kernel.py`,
> `tools/run_gguf_validation.py`, `tools/validate_validation_summary.py`,
> memory `gguf-v312-sweep-status`.

## 1. Problem & goal

`notebooks/validation.ipynb` currently does two unrelated things in one shared
Kaggle kernel:

1. **Cell 4**: our GGUF research sweep (`sentinel_stack` + `read_post_no_secret`,
   added this session) — pure research, never meant to fail loudly.
2. **Cell 5**: a submit-**readiness** check — runs
   `tools/run_gguf_validation.py --n 20 ...` against the CURRENT scored
   family (`direct_exfil_suppress_once`, driven by `src/attack.py`) and,
   critically, that script's own `main()` (`tools/run_gguf_validation.py:425`)
   returns exit code 2 if the result isn't submit-ready. The notebook cell
   calls it with `subprocess.run(cmd, check=True)`, so a "not ready" result
   raises `CalledProcessError`, which papermill turns into a fatal notebook
   error — even though cell 4 (which ran first and is what we actually care
   about) already completed successfully.

This is not a logic bug: `direct_exfil_suppress_once` genuinely produces 0
findings under live v3.1.2 (already independently confirmed by a real scored
submission, ref `54189970`, public 0.000 — see `scored-submission-ledger`
memory), so the readiness check is correctly reporting "not ready." But
because it's permanently unready now (not a transient blip), every future
research-only run of this shared notebook will keep showing kernel-level
`ERROR`, masking whether the research cells actually succeeded. Two live runs
this session hit exactly this.

**Goal:** separate "run a GGUF research sweep" from "check whether
`src/attack.py` is submit-ready" into two independent notebooks/kernels, so a
permanently-failing readiness check never again clobbers an unrelated
research run's status — without changing the readiness check's own logic,
which is correct and still needed for real pre-submission workflows.

## 2. What moves where

`notebooks/validation.ipynb` currently has 8 cells: markdown header (0), 3
setup cells (1-3: repo-root finder, GGUF model env defaults,
`ensure_llama_cpp()`), the research sweep (4), the readiness check (5), an
opt-in `suppress_ab` A/B experiment gated behind `RUN_SUPPRESS_AB_EXPERIMENT`
(6, also tests `src/attack.py`-family variants — same "testing the scored
path" concern as cell 5, not the research sweep's concern), and a
summary-display cell (7) that prints back cell 5's output.

- **`notebooks/validation.ipynb` (kept, narrowed):** cells 0 (markdown,
  reworded — see §5), 1-3 (setup, unchanged), 4 (our sweep, unchanged). Cells
  5, 6, 7 removed.
- **`notebooks/submit_readiness.ipynb` (new):** cells 0 (markdown, describing
  its actual purpose), 1-3 (setup, duplicated from `validation.ipynb` — Jupyter
  notebooks don't share code across files in this repo's existing pattern, and
  extracting a shared bootstrap module is out of scope here), then the
  readiness check (still `subprocess.run(cmd, check=True)` — that hard-fail
  behavior is now *correct*, since this kernel's only job is to answer
  "ready or not," and papermill marking the kernel ERROR on "not ready" is the
  intended signal for a human deciding whether to submit), the `suppress_ab`
  experiment cell, and the summary-display cell.

## 3. Kernel-push tooling

New `tools/prepare_submit_readiness_kernel.py`, a standalone script (not a
generalization of `tools/prepare_validation_kernel.py` — a deliberate choice:
these two kernels' embed lists and cell content are now independent concerns,
and keeping the scripts independent means changing one can't risk regressing
the other). It follows the exact same shape as `prepare_validation_kernel.py`
(same `bootstrap_cell()`/`metadata()`/`build_kernel()`/`main()` structure,
same bootstrap-cell-injection pattern into the notebook), with:

```
DEFAULT_OUT_DIR = REPO / "kaggle_push" / "submit_readiness"
DEFAULT_KERNEL_ID = "canqiang/aiagsec-submit-readiness"
DEFAULT_TITLE = "AIAgSec Submit Readiness"
EMBEDDED_FILES = (
    "src/attack.py",
    "tools/run_gguf_validation.py",
    "tools/run_gguf_bank_experiment.py",
    "tools/validate_validation_summary.py",
    "tools/check_submission_notebook.py",
    "tools/lint_candidate_bank.py",
    "research/candidate_families.py",
    "research/candidate_bank.schema.json",
    "notebooks/submission.ipynb",
)
```

(This is `prepare_validation_kernel.py`'s *current* `EMBEDDED_FILES` verbatim,
minus `tools/analyze_gguf_sweep.py` — that file is research-sweep-only, not
needed by cells 5/6/7.)

`tools/prepare_validation_kernel.py` is **left unchanged, deliberately**
(explicit trade-off, approved): a dependency trace shows `validation.ipynb`
post-split no longer strictly needs `src/attack.py`,
`tools/validate_validation_summary.py`, `tools/check_submission_notebook.py`,
or `notebooks/submission.ipynb` — but pruning risks breaking the research
sweep kernel we already spent real GPU time validating twice this session, for
a payload-size saving of a few KB. Not worth the risk. A future cleanup can
prune it once the split has proven stable.

`tools/push_kaggle_kernel.py` needs no changes — it already takes an
arbitrary folder argument (`kaggle_push/validation` today,
`kaggle_push/submit_readiness` for the new kernel).

## 4. Test coverage

`tools/tests/test_validation_kernel_embeds_notebook_deps.py` (added earlier
this session after the `analyze_gguf_sweep.py` embed-miss) currently hardcodes
one `(notebook, EMBEDDED_FILES)` pair. Generalize it to iterate a small list of
pairs — `(notebooks/validation.ipynb, prepare_validation_kernel.EMBEDDED_FILES)`
and `(notebooks/submit_readiness.ipynb, prepare_submit_readiness_kernel.EMBEDDED_FILES)`
— so the same regression guard covers both kernels without duplicating the
test file. Each pair gets its own test-function invocation (via
`pytest.mark.parametrize` or an explicit loop with per-pair assertions), not
a single test that silently only reports the first failure.

## 5. Notebook markdown headers

`notebooks/validation.ipynb` cell 0 currently reads: *"Run this on Kaggle with
T4 and the competition SDK/model datasets attached. It writes the strict
validation summary consumed by `make submit-ready`."* — the second sentence is
no longer true post-split. New text:

> # GGUF validation notebook
>
> Run this on Kaggle with T4 and the competition SDK/model datasets attached.
> Drives research-track GGUF candidate-bank sweeps (see `tools/run_gguf_bank_experiment.py`).
> For submit-readiness checking against the live scored family, use
> `notebooks/submit_readiness.ipynb` instead.

`notebooks/submit_readiness.ipynb` cell 0 (new):

> # Submit readiness notebook
>
> Run this on Kaggle with T4 and the competition SDK/model datasets attached.
> Checks whether the current `src/attack.py` family is submit-ready under the
> live SDK and writes `research/results/validation-summary.latest.json`,
> consumed by `make submit-ready`. This kernel is expected to fail (papermill
> error) when the current family is not submit-ready — that is the intended
> signal, not a bug.

## 6. Makefile

Mirror the existing `validation-kernel`/`push-validation-kernel` targets:

```make
.PHONY: submit-readiness-kernel
submit-readiness-kernel:
	$(PYTHON) tools/prepare_submit_readiness_kernel.py

.PHONY: push-submit-readiness-kernel
push-submit-readiness-kernel: submit-readiness-kernel
	$(PYTHON) tools/push_kaggle_kernel.py kaggle_push/submit_readiness
```

Add a notebook syntax-check target for the new notebook, and fold it into
`ci` alongside the existing one:

```make
.PHONY: submit-readiness-notebook-check
submit-readiness-notebook-check:
	$(PYTHON) tools/check_validation_notebook.py notebooks/submit_readiness.ipynb
```

`ci`'s dependency line changes from
`ci: compile parity validation-notebook-check bank-lint bank-scored-lint test`
to
`ci: compile parity validation-notebook-check submit-readiness-notebook-check bank-lint bank-scored-lint test`.

`make submit-ready` itself needs **no changes** — it reads
`research/results/validation-summary.latest.json` (a local path) regardless of
which kernel produced it; the human pulls that file from whichever kernel they
ran, same as today.

## 7. Testing

- `tools/check_validation_notebook.py` (existing, notebook-agnostic — takes a
  path argument) validates both notebooks are JSON-valid and Python-syntax
  clean, wired into `ci` per §6.
- The generalized `test_validation_kernel_embeds_notebook_deps.py` (§4) proves
  every script either notebook subprocess-invokes is embedded by its
  respective prepare script.
- No SDK-backed test is needed — this is pure notebook/tooling restructuring,
  no change to `src/attack.py`, `run_gguf_validation.py`, or
  `validate_validation_summary.py`'s logic.

## 8. Risks / explicit non-guarantees

- `notebooks/submit_readiness.ipynb`'s readiness check will still fail
  (expected papermill error) as long as `direct_exfil_suppress_once` scores 0
  under v3.1.2 — this design does not fix that underlying problem, it only
  stops it from clobbering unrelated research runs. Fixing the scored attack
  itself is a separate, later decision (already explicitly deferred once this
  session).
- `prepare_validation_kernel.py`'s over-embedding (§3) is a deliberate,
  bounded cost (a few KB of unused base64-encoded files per push), not a
  correctness risk.
- Both new/changed notebooks need one live Kaggle push each to fully confirm
  (mirroring how every other notebook change this session was verified) —
  out of scope for the code-only implementation plan; a human decides when to
  run that push, same pattern as every other Kaggle action this session.

## 9. Out of scope (YAGNI)

- No shared bootstrap module extracted for the duplicated setup cells (1-3) —
  two notebooks with ~30 duplicated lines each is not worth a new shared-code
  mechanism for this repo's notebook-based workflow.
- No pruning of `prepare_validation_kernel.py`'s `EMBEDDED_FILES` (§3,
  explicit trade-off).
- No change to `run_gguf_validation.py`, `validate_validation_summary.py`, or
  any scored-path logic — the readiness check's judgment is correct and
  untouched.
