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
