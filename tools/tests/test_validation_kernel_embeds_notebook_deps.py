"""Every local .py script the validation notebook subprocess-invokes must be
embedded by prepare_validation_kernel, or it 404s on Kaggle after the GPU
sweep already ran (Kaggle only uploads the notebook itself, per
prepare_validation_kernel's own docstring)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))

from prepare_validation_kernel import EMBEDDED_FILES  # noqa: E402

NOTEBOOK = REPO / "notebooks" / "validation.ipynb"
SCRIPT_ARG_RE = re.compile(r'"((?:src|tools|research)/[\w./]+\.py)"')


def cell_source(cell: dict) -> str:
    source = cell.get("source", [])
    if isinstance(source, str):
        return source
    return "".join(str(line) for line in source)


def referenced_scripts() -> set[str]:
    notebook = json.loads(NOTEBOOK.read_text())
    scripts: set[str] = set()
    for cell in notebook.get("cells", []):
        if cell.get("cell_type") != "code":
            continue
        source = cell_source(cell)
        if "sys.executable" not in source:
            continue
        scripts.update(SCRIPT_ARG_RE.findall(source))
    return scripts


def test_every_subprocess_invoked_script_is_embedded():
    scripts = referenced_scripts()
    assert scripts, "expected at least one sys.executable-invoked script in the notebook"
    missing = scripts - set(EMBEDDED_FILES)
    assert not missing, f"scripts invoked by the notebook but not embedded for Kaggle: {missing}"
