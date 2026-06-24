"""Submit a specific Kaggle kernel version to the code competition."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_COMPETITION = "ai-agent-security-multi-step-tool-attacks"


def to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if hasattr(value, "to_dict"):
        try:
            return to_jsonable(value.to_dict())
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        return {
            str(key): to_jsonable(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }
    return str(value)


def main() -> int:
    import safe_submit  # noqa: F401 — confirms the module exists on PYTHONPATH
    print(json.dumps({"ok": False,
        "message": "submit_code_kernel is retired; use tools/safe_submit.py "
                   "(or `make safe-submit`). Raw kernel-version submit is unsafe."},
        indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
