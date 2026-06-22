"""Fetch Kaggle submission/kernel status as JSON.

Uses the Kaggle Python API rather than the CLI submission listing path. The
output is designed to feed `tools/build_submission_manifest.py` decisions:
`pending_refs` can be passed as repeated `--pending-ref` values, and kernel
metadata/status can justify the T4 runtime requirement.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_COMPETITION = "ai-agent-security-multi-step-tool-attacks"
PENDING_STATUSES = {"pending", "queued", "running", "submitted"}


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


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
    if hasattr(value, "to_json"):
        try:
            return json.loads(value.to_json())
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        return {
            str(key): to_jsonable(item)
            for key, item in vars(value).items()
            if not key.startswith("_")
        }
    return str(value)


def object_get(value: Any, *names: str) -> Any:
    if isinstance(value, dict):
        for name in names:
            if name in value:
                return value[name]
    for name in names:
        if hasattr(value, name):
            return getattr(value, name)
    return None


def normalize_submission(value: Any) -> dict[str, Any]:
    raw = to_jsonable(value)
    status = object_get(raw, "status") or object_get(value, "status")
    status_text = str(status or "").strip()
    return {
        "ref": object_get(raw, "ref", "id") or object_get(value, "ref", "id"),
        "date": object_get(raw, "date") or object_get(value, "date"),
        "description": object_get(raw, "description") or object_get(value, "description"),
        "file_name": object_get(raw, "fileName", "file_name")
        or object_get(value, "file_name"),
        "status": status_text,
        "public_score": object_get(raw, "publicScore", "public_score")
        or object_get(value, "public_score"),
        "private_score": object_get(raw, "privateScore", "private_score")
        or object_get(value, "private_score"),
        "error_description": object_get(raw, "errorDescription", "error_description")
        or object_get(value, "error_description"),
        "submitted_by": object_get(raw, "submittedBy", "submitted_by")
        or object_get(value, "submitted_by"),
        "team_name": object_get(raw, "teamName", "team_name") or object_get(value, "team_name"),
        "url": object_get(raw, "url") or object_get(value, "url"),
        "raw": raw,
    }


def is_pending(submission: dict[str, Any]) -> bool:
    status = str(submission.get("status") or "").strip().lower()
    if status in PENDING_STATUSES:
        return True
    public_score = submission.get("public_score")
    private_score = submission.get("private_score")
    error_description = submission.get("error_description")
    return not public_score and not private_score and not error_description and status in {"", "none"}


def authenticate_api():
    from kaggle.api.kaggle_api_extended import KaggleApi

    api = KaggleApi()
    api.authenticate()
    return api


def fetch_submissions(api: Any, competition: str, page_size: int) -> list[dict[str, Any]]:
    submissions = api.competition_submissions(
        competition=competition,
        page_size=page_size,
    )
    return [normalize_submission(item) for item in (submissions or []) if item is not None]


def fetch_kernel_status(api: Any, kernel: str | None) -> dict[str, Any]:
    if not kernel:
        return {"present": False, "ok": True}
    status = api.kernels_status(kernel)
    normalized = to_jsonable(status)
    return {
        "present": True,
        "kernel": kernel,
        "ok": True,
        "status": normalized,
    }


def fetch_kernel_metadata(api: Any, kernel: str | None) -> dict[str, Any]:
    if not kernel:
        return {"present": False, "ok": True}
    if "/" in kernel:
        user, slug = kernel.split("/", 1)
    else:
        user, slug = None, kernel
    kernels = api.kernels_list(search=slug, mine=user is None, user=user, page_size=20) or []
    normalized = [to_jsonable(item) for item in kernels if item is not None]
    exact = []
    for item in normalized:
        ref = object_get(item, "ref", "id")
        if ref == kernel or object_get(item, "slug") == slug:
            exact.append(item)
    return {
        "present": True,
        "kernel": kernel,
        "ok": bool(exact or normalized),
        "matches": exact or normalized,
    }


def build_status(args: argparse.Namespace) -> dict[str, Any]:
    api = authenticate_api()
    submissions = []
    if not args.no_submissions:
        submissions = fetch_submissions(api, args.competition, args.page_size)
    pending = [item for item in submissions if is_pending(item)]
    submissions_status = {
        "queried": not args.no_submissions,
        "page_size": args.page_size,
        "items": submissions,
        "pending_refs": [str(item.get("ref")) for item in pending if item.get("ref")],
        "pending_count": len(pending),
        "ok": len(pending) == 0 or args.allow_pending,
        "allow_pending": args.allow_pending,
    }
    kernel_status = fetch_kernel_status(api, args.kernel)
    kernel_metadata = fetch_kernel_metadata(api, args.kernel)
    return {
        "created_at": now_iso(),
        "competition": args.competition,
        "ok": bool(submissions_status["ok"])
        and bool(kernel_status.get("ok", True))
        and bool(kernel_metadata.get("ok", True)),
        "submissions": submissions_status,
        "kernel_status": kernel_status,
        "kernel_metadata": kernel_metadata,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--page-size", type=int, default=20)
    parser.add_argument("--kernel", help="kernel slug, e.g. canqiang/aiagsec-static-c1-n600")
    parser.add_argument("--no-submissions", action="store_true")
    parser.add_argument("--allow-pending", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    if args.page_size <= 0:
        parser.error("--page-size must be positive")

    try:
        result = build_status(args)
    except Exception as exc:
        payload = {
            "created_at": now_iso(),
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "hint": "Check Kaggle credentials and network access.",
        }
        print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stderr)
        return 2

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
