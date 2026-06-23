"""Push prepared Kaggle submission variants and submit each completed version."""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_ROOT = REPO / "kaggle_push" / "submission_variants"
DEFAULT_OUT = Path("/tmp/aiagsec-five-submissions.jsonl")
DEFAULT_COMPETITION = "ai-agent-security-multi-step-tool-attacks"
DEFAULT_KERNEL = "canqiang/aiagsec-submission"
DEFAULT_VARIANTS = (
    "linear_n400",
    "chain_k2_n250",
    "chain_k3_n220",
    "chain_k4_n180",
    "chain_k6_n205",
)


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


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def status_text(status: Any) -> str:
    data = to_jsonable(status)
    return str(object_get(data, "status") or object_get(status, "status") or "")


def wait_for_kernel_complete(
    api: Any,
    *,
    kernel: str,
    poll_seconds: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    started = time.monotonic()
    while True:
        status = api.kernels_status(kernel)
        normalized = to_jsonable(status)
        text = status_text(status).lower()
        if text == "complete":
            return {"ok": True, "status": normalized, "waited_s": round(time.monotonic() - started, 3)}
        if text in {"error", "failed", "cancelled"}:
            return {
                "ok": False,
                "status": normalized,
                "waited_s": round(time.monotonic() - started, 3),
                "message": f"kernel ended with status={text}",
            }
        if time.monotonic() - started > timeout_seconds:
            return {
                "ok": False,
                "status": normalized,
                "waited_s": round(time.monotonic() - started, 3),
                "message": f"timed out waiting for kernel completion; last status={text}",
            }
        time.sleep(poll_seconds)


def submit_variant(
    api: Any,
    *,
    folder: Path,
    competition: str,
    kernel: str,
    poll_seconds: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    from push_kaggle_kernel import push_kernel

    manifest = load_json(folder / "variant-manifest.json")
    message = (
        f"{manifest['name']} k{manifest['chain_k']} n{manifest['n_candidates']} "
        f"exp{manifest['expected_public_score']} {manifest['description']}"
    )
    row: dict[str, Any] = {
        "created_at": now_iso(),
        "variant": manifest,
        "message": message,
        "folder": str(folder),
    }
    push_result = push_kernel(folder)
    row["push"] = push_result
    version = push_result.get("version_number")
    if not push_result.get("ok") or version is None:
        row["ok"] = False
        row["error"] = "push failed or did not return version_number"
        return row

    wait_result = wait_for_kernel_complete(
        api,
        kernel=kernel,
        poll_seconds=poll_seconds,
        timeout_seconds=timeout_seconds,
    )
    row["kernel_wait"] = wait_result
    if not wait_result.get("ok"):
        row["ok"] = False
        row["error"] = "kernel did not complete before submit"
        return row

    response = api.competition_submit_code(
        file_name="submission.csv",
        message=message,
        competition=competition,
        kernel=kernel,
        kernel_version=int(version),
        quiet=True,
    )
    row["submit"] = to_jsonable(response)
    row["ok"] = True
    return row


def parse_variants(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS))
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--kernel", default=DEFAULT_KERNEL)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--poll-seconds", type=float, default=30.0)
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    args = parser.parse_args()

    from kaggle.api.kaggle_api_extended import KaggleApi

    api = KaggleApi()
    api.authenticate()
    rows: list[dict[str, Any]] = []
    for name in parse_variants(args.variants):
        folder = args.root / name
        row = submit_variant(
            api,
            folder=folder,
            competition=args.competition,
            kernel=args.kernel,
            poll_seconds=args.poll_seconds,
            timeout_seconds=args.timeout_seconds,
        )
        append_jsonl(args.out, row)
        rows.append(row)
        print(json.dumps(row, indent=2, sort_keys=True))
        if not row.get("ok"):
            return 2
    return 0 if all(row.get("ok") for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
