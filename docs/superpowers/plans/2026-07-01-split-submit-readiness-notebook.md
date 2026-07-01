# Split submit-readiness out of validation.ipynb — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate the submit-readiness check (which correctly, permanently fails under live v3.1.2 for the current scored family) out of `notebooks/validation.ipynb` into its own notebook/kernel, so it stops clobbering unrelated GGUF research sweep runs with a kernel-level `ERROR`.

**Architecture:** Move cells 5 (readiness check), 6 (opt-in `suppress_ab` experiment), 7 (summary display) out of `notebooks/validation.ipynb` into a new `notebooks/submit_readiness.ipynb`, duplicating the 3 shared setup cells. Add a standalone `tools/prepare_submit_readiness_kernel.py` (not a generalization of the existing `prepare_validation_kernel.py`) with its own kernel id and embed list. Generalize the existing embed-regression test to cover both notebook/script pairs. Wire new Makefile targets.

**Tech Stack:** Python 3.11, pytest, Jupyter notebook JSON (`nbformat` 4.5).

## Global Constraints

- `tools/run_gguf_validation.py`, `tools/validate_validation_summary.py`, and any scored-path logic are **not touched** — the readiness check's judgment is correct; only its blast radius changes.
- `tools/prepare_validation_kernel.py`'s `EMBEDDED_FILES` is **left unchanged** (deliberate, approved trade-off — it will over-embed a few files `validation.ipynb` no longer strictly needs; this is intentional, not an oversight to "clean up").
- `notebooks/submit_readiness.ipynb`'s readiness-check cell **keeps `check=True`** — a hard papermill failure on "not ready" is the correct, intended behavior for this notebook now that it's dedicated to that one job.
- `make submit-ready` requires **no changes** — it reads `research/results/validation-summary.latest.json` from a local path regardless of which kernel produced it.
- `make ci` must stay green at every commit.

---

### Task 1: Extract `notebooks/submit_readiness.ipynb` from `notebooks/validation.ipynb`

**Files:**
- Modify: `notebooks/validation.ipynb` (remove cells 5-7, reword cell 0)
- Create: `notebooks/submit_readiness.ipynb`

**Interfaces:**
- Produces: `notebooks/validation.ipynb` with exactly 5 cells (markdown header, 3 setup cells, the sweep cell); `notebooks/submit_readiness.ipynb` with exactly 6 cells (markdown header, 3 setup cells, the readiness check, the `suppress_ab` experiment, the summary display).
- Consumes: nothing from other tasks — this is the first task.

- [ ] **Step 1: Write the one-off script that performs the split**

Create `_split_submit_readiness.py` at the repo root (deleted in Step 4, never committed — the commit step only `git add`s the two `.ipynb` files by name):

```python
# _split_submit_readiness.py (repo root, deleted in Step 4, never committed)
import json
from pathlib import Path

path = Path("notebooks/validation.ipynb")
nb = json.loads(path.read_text())
cells = nb["cells"]

assert len(cells) == 8, f"expected 8 cells in validation.ipynb, found {len(cells)}"

header, setup1, setup2, setup3, sweep, readiness, suppress_ab, display = cells

new_header = {
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "# GGUF validation notebook\n",
        "\n",
        "Run this on Kaggle with T4 and the competition SDK/model datasets attached.\n",
        "Drives research-track GGUF candidate-bank sweeps (see `tools/run_gguf_bank_experiment.py`).\n",
        "For submit-readiness checking against the live scored family, use\n",
        "`notebooks/submit_readiness.ipynb` instead.",
    ],
}

nb["cells"] = [new_header, setup1, setup2, setup3, sweep]
path.write_text(json.dumps(nb, indent=1) + "\n")
print("rewrote notebooks/validation.ipynb:", len(nb["cells"]), "cells")

readiness_header = {
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "# Submit readiness notebook\n",
        "\n",
        "Run this on Kaggle with T4 and the competition SDK/model datasets attached.\n",
        "Checks whether the current `src/attack.py` family is submit-ready under the\n",
        "live SDK and writes `research/results/validation-summary.latest.json`,\n",
        "consumed by `make submit-ready`. This kernel is expected to fail (papermill\n",
        "error) when the current family is not submit-ready — that is the intended\n",
        "signal, not a bug.",
    ],
}

readiness_nb = {
    "cells": [readiness_header, setup1, setup2, setup3, readiness, suppress_ab, display],
    "metadata": nb["metadata"],
    "nbformat": nb["nbformat"],
    "nbformat_minor": nb["nbformat_minor"],
}

readiness_path = Path("notebooks/submit_readiness.ipynb")
readiness_path.write_text(json.dumps(readiness_nb, indent=1) + "\n")
print("wrote notebooks/submit_readiness.ipynb:", len(readiness_nb["cells"]), "cells")
```

Run: `python3 _split_submit_readiness.py`
Expected: prints `rewrote notebooks/validation.ipynb: 5 cells` then `wrote notebooks/submit_readiness.ipynb: 7 cells`.

- [ ] **Step 2: Verify both notebooks are valid and contain the expected content**

Run:
```bash
python3 -c "
import json
v = json.load(open('notebooks/validation.ipynb'))
r = json.load(open('notebooks/submit_readiness.ipynb'))
assert len(v['cells']) == 5
assert len(r['cells']) == 7
v_src = ''.join(''.join(c.get('source', [])) for c in v['cells'])
r_src = ''.join(''.join(c.get('source', [])) for c in r['cells'])
assert 'sentinel_stack_sweep' in v_src
# NOTE: don't assert 'run_gguf_validation.py' not in v_src -- the shared
# setup cell (cell 1, kept in both notebooks) legitimately references that
# filename as a repo-root marker check, unrelated to subprocess invocation.
# VALIDATION_N / validation-summary.latest.json only ever appear in the
# readiness cell (moved out), so they're the reliable markers instead.
assert 'VALIDATION_N' not in v_src
assert 'validation-summary.latest.json' not in v_src
assert 'submit_readiness' in v_src  # the reworded header text
assert 'VALIDATION_N' in r_src
assert 'RUN_SUPPRESS_AB_EXPERIMENT' in r_src
assert 'validation-summary.latest.json' in r_src
assert 'sentinel_stack_sweep' not in r_src
print('both notebooks OK')
"
```
Expected: prints `both notebooks OK`.

- [ ] **Step 3: Run the notebook syntax check on both**

Run: `python3 tools/check_validation_notebook.py notebooks/validation.ipynb && python3 tools/check_validation_notebook.py notebooks/submit_readiness.ipynb`
Expected: both print `"ok": true` with no syntax errors (this script is notebook-agnostic already — it takes the path as a CLI argument, no changes needed to it).

- [ ] **Step 4: Clean up the one-off script**

```bash
rm _split_submit_readiness.py
```

- [ ] **Step 5: Commit**

```bash
git add notebooks/validation.ipynb notebooks/submit_readiness.ipynb
git commit -m "feat(research): split submit-readiness checking into its own notebook

Two consecutive Kaggle runs showed kernel-level ERROR because the
readiness check (correctly reporting direct_exfil_suppress_once is
dead under v3.1.2) was chained via check=True after our unrelated
GGUF research sweep cell in the same notebook. Move the readiness
check, its opt-in suppress_ab experiment, and its summary display
into notebooks/submit_readiness.ipynb, leaving validation.ipynb as a
pure research-sweep notebook."
```

---

### Task 2: Standalone kernel-push tooling for the readiness notebook

**Files:**
- Create: `tools/prepare_submit_readiness_kernel.py`
- Modify: `Makefile`

**Interfaces:**
- Produces: `build_kernel(out_dir, *, kernel_id, title) -> dict` (same shape as `tools/prepare_validation_kernel.py`'s function of the same name) and a module-level `EMBEDDED_FILES` tuple, importable by Task 3's test.
- Consumes: `notebooks/submit_readiness.ipynb` (from Task 1).

- [ ] **Step 1: Write the failing test**

Create `tools/tests/test_prepare_submit_readiness_kernel.py`:

Note: cross-notebook embed coverage (does every script `submit_readiness.ipynb`
subprocess-invokes appear in `EMBEDDED_FILES`) is Task 3's job, not this one —
Task 3 generalizes the existing embed-regression test to cover both notebooks,
so this test file only needs to check `prepare_submit_readiness_kernel.py`'s
own mechanics, not duplicate that scan.

```python
from __future__ import annotations
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))

import prepare_submit_readiness_kernel as psrk  # noqa: E402


def test_build_kernel_writes_notebook_and_metadata(tmp_path):
    result = psrk.build_kernel(tmp_path, kernel_id="canqiang/aiagsec-submit-readiness", title="Test Title")
    assert result["ok"] is True
    assert result["embedded_files"] == list(psrk.EMBEDDED_FILES)

    notebook_path = Path(result["notebook"])
    metadata_path = Path(result["metadata"])
    assert notebook_path.exists() and notebook_path.name == "submit_readiness.ipynb"
    assert metadata_path.exists()

    metadata = json.loads(metadata_path.read_text())
    assert metadata["id"] == "canqiang/aiagsec-submit-readiness"
    assert metadata["title"] == "Test Title"
    assert metadata["code_file"] == "submit_readiness.ipynb"
    assert metadata["machine_shape"] == "NvidiaTeslaT4"

    notebook = json.loads(notebook_path.read_text())
    cell_types = [c["cell_type"] for c in notebook["cells"]]
    assert cell_types.count("code") >= 2  # at least the bootstrap cell + original code cells
    bootstrap_source = "".join(notebook["cells"][2]["source"])
    assert "bootstrapped submit-readiness files" in bootstrap_source
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tools/tests/test_prepare_submit_readiness_kernel.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'prepare_submit_readiness_kernel'`.

- [ ] **Step 3: Write minimal implementation**

Create `tools/prepare_submit_readiness_kernel.py`:

```python
"""Build a self-contained Kaggle kernel folder for submit-readiness checking.

Kaggle `kernels_push` uploads only the notebook/script named by
`kernel-metadata.json`. This tool embeds the small repo files needed by
`notebooks/submit_readiness.ipynb` into a generated notebook under
`kaggle_push/`, so the remote kernel can recreate `src/` and `tools/` before
running.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
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


def load_notebook(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        notebook = json.load(fh)
    if not isinstance(notebook, dict) or not isinstance(notebook.get("cells"), list):
        raise ValueError(f"{path} is not a valid notebook object")
    return notebook


def bootstrap_cell() -> dict[str, Any]:
    encoded = {
        rel_path: base64.b64encode((REPO / rel_path).read_bytes()).decode("ascii")
        for rel_path in EMBEDDED_FILES
    }
    source = (
        "from pathlib import Path\n"
        "import base64\n"
        "\n"
        f"FILES = {json.dumps(encoded, indent=2, sort_keys=True)}\n"
        "for rel_path, payload in FILES.items():\n"
        "    path = Path(rel_path)\n"
        "    path.parent.mkdir(parents=True, exist_ok=True)\n"
        "    path.write_bytes(base64.b64decode(payload.encode('ascii')))\n"
        "print('bootstrapped submit-readiness files:', ', '.join(sorted(FILES)))\n"
    )
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [line + "\n" for line in source.splitlines()],
    }


def metadata(*, kernel_id: str, title: str) -> dict[str, Any]:
    return {
        "id": kernel_id,
        "title": title,
        "code_file": "submit_readiness.ipynb",
        "language": "python",
        "kernel_type": "notebook",
        "is_private": True,
        "enable_gpu": True,
        "enable_tpu": False,
        "enable_internet": True,
        "machine_shape": "NvidiaTeslaT4",
        "dataset_sources": [],
        "competition_sources": ["ai-agent-security-multi-step-tool-attacks"],
        "kernel_sources": [],
    }


def build_kernel(out_dir: Path, *, kernel_id: str, title: str) -> dict[str, Any]:
    notebook = load_notebook(REPO / "notebooks" / "submit_readiness.ipynb")
    cells = list(notebook["cells"])
    cells.insert(
        1,
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "## Bootstrap\n",
                "\n",
                "This generated cell recreates the repo files required by the readiness runner."
            ],
        },
    )
    cells.insert(2, bootstrap_cell())
    notebook["cells"] = cells

    out_dir.mkdir(parents=True, exist_ok=True)
    notebook_path = out_dir / "submit_readiness.ipynb"
    metadata_path = out_dir / "kernel-metadata.json"
    notebook_path.write_text(json.dumps(notebook, indent=1) + "\n", encoding="utf-8")
    metadata_path.write_text(
        json.dumps(metadata(kernel_id=kernel_id, title=title), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "ok": True,
        "out_dir": str(out_dir),
        "notebook": str(notebook_path),
        "metadata": str(metadata_path),
        "embedded_files": list(EMBEDDED_FILES),
        "kernel_id": kernel_id,
        "title": title,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--kernel-id", default=DEFAULT_KERNEL_ID)
    parser.add_argument("--title", default=DEFAULT_TITLE)
    args = parser.parse_args()
    print(json.dumps(build_kernel(args.out_dir, kernel_id=args.kernel_id, title=args.title),
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Add to `Makefile` (near the existing `validation-kernel`/`push-validation-kernel` targets):

```make
.PHONY: submit-readiness-kernel
submit-readiness-kernel:
	$(PYTHON) tools/prepare_submit_readiness_kernel.py

.PHONY: push-submit-readiness-kernel
push-submit-readiness-kernel: submit-readiness-kernel
	$(PYTHON) tools/push_kaggle_kernel.py kaggle_push/submit_readiness
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tools/tests/test_prepare_submit_readiness_kernel.py -q`
Expected: PASS (1 test).

- [ ] **Step 5: Manually verify the Makefile target works end to end**

Run: `make submit-readiness-kernel`
Expected: prints a JSON object with `"ok": true` and `"kernel_id": "canqiang/aiagsec-submit-readiness"`; `kaggle_push/submit_readiness/submit_readiness.ipynb` and `kaggle_push/submit_readiness/kernel-metadata.json` exist.

- [ ] **Step 6: Commit**

```bash
git add tools/prepare_submit_readiness_kernel.py tools/tests/test_prepare_submit_readiness_kernel.py Makefile
git commit -m "feat(research): standalone kernel-push tooling for submit-readiness notebook"
```

---

### Task 3: Generalize the embed-regression test and wire notebook-check into ci

**Files:**
- Modify: `tools/tests/test_validation_kernel_embeds_notebook_deps.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `prepare_validation_kernel.EMBEDDED_FILES` (existing), `prepare_submit_readiness_kernel.EMBEDDED_FILES` (Task 2), `notebooks/validation.ipynb` and `notebooks/submit_readiness.ipynb` (Task 1).

- [ ] **Step 1: Read the current test file**

The current `tools/tests/test_validation_kernel_embeds_notebook_deps.py` hardcodes one `(NOTEBOOK, EMBEDDED_FILES)` pair (`notebooks/validation.ipynb` / `prepare_validation_kernel.EMBEDDED_FILES`). Replace its single test with a parametrized version covering both notebooks.

- [ ] **Step 2: Write the failing test (replace the file's content)**

Replace the full contents of `tools/tests/test_validation_kernel_embeds_notebook_deps.py` with:

```python
"""Every local .py script a validation/readiness notebook subprocess-invokes
must be embedded by its matching prepare_*_kernel script, or it 404s on
Kaggle after the GPU work already ran (Kaggle only uploads the notebook
itself, per prepare_validation_kernel's own docstring)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))

import prepare_validation_kernel as pvk  # noqa: E402
import prepare_submit_readiness_kernel as psrk  # noqa: E402

# Matches both quote styles: validation.ipynb's sweep cell uses double
# quotes, submit_readiness.ipynb's older readiness/suppress_ab cells
# (moved verbatim in Task 1) use single quotes.
SCRIPT_ARG_RE = re.compile(r'["\']((?:src|tools|research)/[\w./]+\.py)["\']')

NOTEBOOK_EMBED_PAIRS = (
    ("notebooks/validation.ipynb", pvk.EMBEDDED_FILES),
    ("notebooks/submit_readiness.ipynb", psrk.EMBEDDED_FILES),
)


def cell_source(cell: dict) -> str:
    source = cell.get("source", [])
    if isinstance(source, str):
        return source
    return "".join(str(line) for line in source)


def referenced_scripts(notebook_rel_path: str) -> set[str]:
    notebook = json.loads((REPO / notebook_rel_path).read_text())
    scripts: set[str] = set()
    for cell in notebook.get("cells", []):
        if cell.get("cell_type") != "code":
            continue
        source = cell_source(cell)
        if "sys.executable" not in source:
            continue
        scripts.update(SCRIPT_ARG_RE.findall(source))
    return scripts


@pytest.mark.parametrize("notebook_rel_path,embedded_files", NOTEBOOK_EMBED_PAIRS)
def test_every_subprocess_invoked_script_is_embedded(notebook_rel_path, embedded_files):
    scripts = referenced_scripts(notebook_rel_path)
    assert scripts, f"expected at least one sys.executable-invoked script in {notebook_rel_path}"
    missing = scripts - set(embedded_files)
    assert not missing, f"{notebook_rel_path}: scripts invoked but not embedded: {missing}"
```

- [ ] **Step 3: Run test to verify it fails, then passes**

Run: `python3 -m pytest tools/tests/test_validation_kernel_embeds_notebook_deps.py -q`
Expected (before Task 1/2 are committed in the same working tree, this should already pass since Tasks 1-2 are prerequisites completed earlier in this same plan run — if run standalone before Task 1/2, it FAILS with `ModuleNotFoundError: No module named 'prepare_submit_readiness_kernel'`). Since Task 1 and 2 are already done by this point in the plan, expect: PASS, 2 tests (one per notebook).

- [ ] **Step 4: Wire the new notebook's syntax check into `ci`**

Add to `Makefile` (near the existing `validation-notebook-check` target):

```make
.PHONY: submit-readiness-notebook-check
submit-readiness-notebook-check:
	$(PYTHON) tools/check_validation_notebook.py notebooks/submit_readiness.ipynb
```

Find the `ci` target's dependency line:

```make
ci: compile parity validation-notebook-check bank-lint bank-scored-lint test
```

Replace it with:

```make
ci: compile parity validation-notebook-check submit-readiness-notebook-check bank-lint bank-scored-lint test
```

- [ ] **Step 5: Run the full suite and `make ci`**

Run: `python3 -m pytest tools/tests -q && make ci`
Expected: all pass, `make ci` green (now including the new `submit-readiness-notebook-check` step).

- [ ] **Step 6: Commit**

```bash
git add tools/tests/test_validation_kernel_embeds_notebook_deps.py Makefile
git commit -m "test(research): generalize embed-regression test to cover both kernels; wire submit_readiness.ipynb into ci"
```

---

## Self-Review

- **Spec coverage:** design §2 (cell moves) → Task 1. §3 (kernel-push tooling) → Task 2. §4 (test coverage) → Task 3 Steps 1-3. §5 (markdown headers) → Task 1 Step 1's new header text. §6 (Makefile) → Task 2 Step 3's targets + Task 3 Step 4's notebook-check target and `ci` wiring. §7 (testing) → Task 1 Step 3 (both notebooks syntax-checked) + Task 3 (embed regression). Covered.
- **Placeholders:** none — every code block is complete, copied verbatim from the existing `notebooks/validation.ipynb`'s actual cell content (read directly from the file before writing this plan) and from `tools/prepare_validation_kernel.py`'s actual current source.
- **Type consistency:** `prepare_submit_readiness_kernel.build_kernel`'s signature (`out_dir: Path, *, kernel_id: str, title: str`) matches `prepare_validation_kernel.build_kernel`'s exactly, which Task 2's test relies on being callable the same way. `EMBEDDED_FILES` in both `prepare_validation_kernel` and `prepare_submit_readiness_kernel` are both `tuple[str, ...]` module constants, matching how Task 3's generalized test imports and uses them identically.

## Execution Handoff

(See the offer that follows the plan.)
