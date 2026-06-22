"""Validate a GGUF real-model validation summary for submit manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "2026-06-22.validation-summary.v1"
REQUIRED_MODELS = ("gpt_oss", "gemma")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_BACKEND_WORDS = ("gguf", "llama")


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


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("validation summary must be a JSON object")
    return data


def source_sha(path: Path) -> str:
    return sha256_file(path)


def notebook_attack_sha(path: Path, source_path: Path) -> str:
    from check_submission_notebook import check

    result = check(
        source_path=source_path,
        notebook_path=path,
        allow_inline=False,
    )
    return str(result["notebook_attack_sha256"])


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def check_rate(value: Any) -> bool:
    return is_number(value) and 0.0 <= float(value) <= 1.0


def check_positive_rate(value: Any) -> bool:
    return is_number(value) and 0.0 < float(value) <= 1.0


def check_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def check_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_model_result(
    name: str,
    value: Any,
    blockers: list[str],
    *,
    expected_attempted: int | None,
) -> None:
    if not isinstance(value, dict):
        blockers.append(f"results.{name} must be an object")
        return

    attempted = value.get("attempted_candidates")
    findings = value.get("findings")
    if not check_positive_int(attempted):
        blockers.append(f"results.{name}.attempted_candidates must be a positive integer")
    elif expected_attempted is not None and attempted != expected_attempted:
        blockers.append(
            f"results.{name}.attempted_candidates must equal validation_n={expected_attempted}"
        )
    if not check_nonnegative_int(findings):
        blockers.append(f"results.{name}.findings must be a non-negative integer")
    elif findings == 0:
        blockers.append(f"results.{name}.findings must be positive for submit readiness")
    if check_positive_int(attempted) and check_nonnegative_int(findings) and findings > attempted:
        blockers.append(f"results.{name}.findings cannot exceed attempted_candidates")

    for field in ("hit_rate", "exact_payload_rate"):
        if not check_positive_rate(value.get(field)):
            blockers.append(f"results.{name}.{field} must be a positive number in (0, 1]")

    for field in ("guardrail_block_rate",):
        if not check_rate(value.get(field)):
            blockers.append(f"results.{name}.{field} must be a number in [0, 1]")

    for field in ("seconds_per_candidate_p95", "time_taken_s"):
        if not is_number(value.get(field)) or float(value[field]) <= 0:
            blockers.append(f"results.{name}.{field} must be a positive number")


def validate_data(
    data: dict[str, Any],
    *,
    expected_source_sha: str | None,
    expected_notebook_sha: str | None,
) -> list[str]:
    blockers: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        blockers.append(f"schema_version must be {SCHEMA_VERSION}")

    source_sha_value = data.get("source_sha256")
    notebook_sha_value = data.get("notebook_attack_sha256")
    if not isinstance(source_sha_value, str) or not HEX64_RE.match(source_sha_value):
        blockers.append("source_sha256 must be a 64-char lowercase hex SHA256")
    if not isinstance(notebook_sha_value, str) or not HEX64_RE.match(notebook_sha_value):
        blockers.append("notebook_attack_sha256 must be a 64-char lowercase hex SHA256")
    if expected_source_sha and source_sha_value != expected_source_sha:
        blockers.append("source_sha256 does not match current src/attack.py")
    if expected_notebook_sha and notebook_sha_value != expected_notebook_sha:
        blockers.append("notebook_attack_sha256 does not match current submission notebook")

    for field in ("candidate_family", "backend"):
        if not is_nonempty_string(data.get(field)):
            blockers.append(f"{field} must be a non-empty string")
    backend = str(data.get("backend") or "").lower()
    missing_backend_words = [word for word in REQUIRED_BACKEND_WORDS if word not in backend]
    if missing_backend_words:
        blockers.append(
            "backend must identify GGUF llama.cpp validation; missing: "
            + ", ".join(missing_backend_words)
        )

    validation_n = data.get("validation_n")
    for field in ("validation_n", "total_messages", "max_tool_hops"):
        if not check_positive_int(data.get(field)):
            blockers.append(f"{field} must be a positive integer")
    expected_attempted = validation_n if check_positive_int(validation_n) else None

    results = data.get("results")
    if not isinstance(results, dict):
        blockers.append("results must be an object keyed by target model")
    else:
        for model in REQUIRED_MODELS:
            if model not in results:
                blockers.append(f"results.{model} is required")
            else:
                validate_model_result(
                    model,
                    results[model],
                    blockers,
                    expected_attempted=expected_attempted,
                )

    return blockers


def validate_file(
    path: Path | None,
    *,
    expected_source_sha: str | None = None,
    expected_notebook_sha: str | None = None,
) -> dict[str, Any]:
    if path is None:
        return {
            "present": False,
            "ok": False,
            "message": "no GGUF validation summary supplied",
        }
    if not path.exists():
        return {
            "present": False,
            "path": rel(path),
            "ok": False,
            "message": "validation summary path does not exist",
        }

    try:
        data = load_json(path)
    except Exception as exc:
        return {
            "present": True,
            "path": rel(path),
            "ok": False,
            "message": f"cannot read validation summary: {exc}",
        }

    blockers = validate_data(
        data,
        expected_source_sha=expected_source_sha,
        expected_notebook_sha=expected_notebook_sha,
    )
    return {
        "present": True,
        "path": rel(path),
        "sha256": sha256_file(path),
        "schema_version": data.get("schema_version"),
        "candidate_family": data.get("candidate_family"),
        "validation_n": data.get("validation_n"),
        "results_models": sorted((data.get("results") or {}).keys())
        if isinstance(data.get("results"), dict)
        else [],
        "blockers": blockers,
        "ok": not blockers,
        "message": None if not blockers else "validation summary failed schema/source checks",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    parser.add_argument("--source", type=Path, default=REPO / "src" / "attack.py")
    parser.add_argument("--notebook", type=Path, default=REPO / "notebooks" / "submission.ipynb")
    args = parser.parse_args()

    sys.path.insert(0, str(REPO / "tools"))
    result = validate_file(
        args.summary,
        expected_source_sha=source_sha(args.source),
        expected_notebook_sha=notebook_attack_sha(args.notebook, args.source),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
