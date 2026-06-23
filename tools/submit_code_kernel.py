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


def submit(
    *,
    competition: str,
    kernel: str,
    kernel_version: int,
    message: str,
    file_name: str,
) -> dict[str, Any]:
    from kaggle.api.kaggle_api_extended import KaggleApi

    api = KaggleApi()
    api.authenticate()
    response = api.competition_submit_code(
        file_name=file_name,
        message=message,
        competition=competition,
        kernel=kernel,
        kernel_version=kernel_version,
        quiet=True,
    )
    return {
        "ok": True,
        "competition": competition,
        "kernel": kernel,
        "kernel_version": kernel_version,
        "message": message,
        "file_name": file_name,
        "response": to_jsonable(response),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--kernel-version", type=int, required=True)
    parser.add_argument("--message", required=True)
    parser.add_argument("--file-name", default="submission.csv")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    result = submit(
        competition=args.competition,
        kernel=args.kernel,
        kernel_version=args.kernel_version,
        message=args.message,
        file_name=args.file_name,
    )
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
