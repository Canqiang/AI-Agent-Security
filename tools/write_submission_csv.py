"""Write or validate the official four-row Kaggle commit-run CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
OFFICIAL_SUBMISSION_IDS = [
    "gpt_oss_public",
    "gpt_oss_private",
    "gemma_public",
    "gemma_private",
]


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]], list[str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    headers = list(reader.fieldnames or [])
    ids = [str(row.get("Id", "")) for row in rows]
    return headers, rows, ids


def write_csv(path: Path, prediction: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["Id", "Prediction"])
        writer.writeheader()
        for row_id in OFFICIAL_SUBMISSION_IDS:
            writer.writerow({"Id": row_id, "Prediction": prediction})


def status(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "present": False,
            "path": rel(path),
            "ok": False,
            "message": "submission.csv path does not exist",
        }
    headers, rows, ids = read_csv(path)
    headers_ok = headers == ["Id", "Prediction"]
    predictions = [row.get("Prediction") for row in rows]
    predictions_ok = all(isinstance(value, str) and bool(value) for value in predictions)
    ok = headers_ok and len(rows) == 4 and ids == OFFICIAL_SUBMISSION_IDS and predictions_ok
    messages: list[str] = []
    if not headers_ok:
        messages.append("submission.csv header must be exactly Id,Prediction")
    if len(rows) != 4:
        messages.append("submission.csv must contain exactly four data rows")
    if ids != OFFICIAL_SUBMISSION_IDS:
        messages.append("submission.csv Id rows do not match official four-row contract")
    if not predictions_ok:
        messages.append("submission.csv Prediction values must be non-empty")
    return {
        "present": True,
        "path": rel(path),
        "sha256": sha256_file(path),
        "headers": headers,
        "ids": ids,
        "expected_ids": OFFICIAL_SUBMISSION_IDS,
        "ok": ok,
        "message": None if ok else "; ".join(messages),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--prediction", default="placeholder")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    if not args.check_only:
        write_csv(args.out, args.prediction)

    result = status(args.out)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
