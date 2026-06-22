"""Check that the GGUF validation notebook is JSON-valid and Python-syntax clean."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def cell_source(cell: dict[str, Any]) -> str:
    source = cell.get("source", [])
    if isinstance(source, str):
        return source
    return "".join(str(line) for line in source)


def check(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        notebook = json.load(fh)

    cells = notebook.get("cells", [])
    if not isinstance(cells, list):
        raise ValueError("notebook cells must be a list")

    code_cells = 0
    for index, cell in enumerate(cells):
        if not isinstance(cell, dict):
            raise ValueError(f"cell {index} must be an object")
        if cell.get("cell_type") != "code":
            continue
        code_cells += 1
        source = cell_source(cell)
        stripped = source.lstrip()
        if stripped.startswith(("%", "!")):
            raise SyntaxError(f"cell {index} uses notebook magic/shell syntax")
        compile(source, f"{path}:cell{index}", "exec")

    return {
        "ok": True,
        "path": str(path),
        "cells": len(cells),
        "code_cells": code_cells,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("notebook", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.notebook), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
