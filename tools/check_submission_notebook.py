"""Check that the Kaggle submission notebook writes the same attack source.

The scored rerun imports `/kaggle/working/attack.py`, not the local
`src/attack.py`. This tool extracts the notebook's `%%writefile` cell and fails
on drift unless the caller explicitly accepts inline divergence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = REPO / "src" / "attack.py"
DEFAULT_NOTEBOOK = REPO / "notebooks" / "submission.ipynb"
WRITEFILE_PREFIX = "%%writefile"
ATTACK_BASENAME = "attack.py"


def normalize_source(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_writefile_source(notebook_path: Path) -> tuple[str, int]:
    with notebook_path.open("r", encoding="utf-8") as fh:
        notebook = json.load(fh)

    matches: list[tuple[str, int]] = []
    for idx, cell in enumerate(notebook.get("cells", [])):
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", [])
        if isinstance(source, str):
            lines = source.splitlines(keepends=True)
        else:
            lines = [str(line) for line in source]
        if not lines:
            continue
        first = lines[0].strip()
        if first.startswith(WRITEFILE_PREFIX) and ATTACK_BASENAME in first:
            matches.append(("".join(lines[1:]), idx))

    if not matches:
        raise RuntimeError(f"no {WRITEFILE_PREFIX} cell for {ATTACK_BASENAME} found")
    if len(matches) > 1:
        raise RuntimeError(f"multiple {ATTACK_BASENAME} writefile cells found: {len(matches)}")
    return matches[0]


def check(source_path: Path, notebook_path: Path, allow_inline: bool) -> dict[str, object]:
    source_text = normalize_source(source_path.read_text(encoding="utf-8"))
    notebook_text_raw, cell_index = extract_writefile_source(notebook_path)
    notebook_text = normalize_source(notebook_text_raw)

    source_sha = sha256_text(source_text)
    notebook_sha = sha256_text(notebook_text)
    match = source_sha == notebook_sha

    status = {
        "source": str(source_path.relative_to(REPO)),
        "notebook": str(notebook_path.relative_to(REPO)),
        "writefile_cell_index": cell_index,
        "source_sha256": source_sha,
        "notebook_attack_sha256": notebook_sha,
        "match": match,
        "allow_inline": allow_inline,
        "ok": match or allow_inline,
    }
    if not match:
        status["message"] = (
            "notebook writes an attack.py that differs from src/attack.py; "
            "use --allow-inline only with a submission manifest explaining why"
        )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--notebook", type=Path, default=DEFAULT_NOTEBOOK)
    parser.add_argument("--allow-inline", action="store_true")
    args = parser.parse_args()

    result = check(args.source, args.notebook, args.allow_inline)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
