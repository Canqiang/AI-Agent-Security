"""Submit a specific Kaggle kernel version to the code competition."""

from __future__ import annotations

import json


DEFAULT_COMPETITION = "ai-agent-security-multi-step-tool-attacks"


def main() -> int:
    print(json.dumps({"ok": False,
        "message": "submit_code_kernel is retired; use tools/safe_submit.py "
                   "(or `make safe-submit`). Raw kernel-version submit is unsafe."},
        indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
