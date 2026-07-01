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
