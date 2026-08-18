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


def submit_variant(
    api: Any,
    *,
    folder: Path,
    competition: str,
    kernel: str,
    poll_seconds: float,
    timeout_seconds: float,
    allow_pending: bool = False,
    poll_error_grace_seconds: float | None = None,
) -> dict[str, Any]:
    import kernel_wait
    import safe_submit as ss
    from push_kaggle_kernel import push_kernel

    manifest = load_json(folder / "variant-manifest.json")
    # The kernel this variant actually lives at: push_kernel uploads the folder's
    # notebook under kernel-metadata.json's `id`, so the wait/verify/submit steps
    # MUST target THAT kernel, not a shared default. Submitting from a shared
    # generic kernel submits its stale output (2026-08-18: burned a submission on
    # the generic kernel's placeholder zeros).
    variant_kernel = load_json(folder / "kernel-metadata.json").get("id") or kernel
    message = (
        f"{manifest['name']} k{manifest['chain_k']} n{manifest['n_candidates']} "
        f"exp{manifest['expected_public_score']} {manifest['description']}"
    )
    # Variants are stacking/high-N: they MUST be explicitly allowed with a reason,
    # and they go through the same gated path. By default the audit gate refuses
    # them — which is the correct, safe behavior after the 2026-06-23 incident.
    # allow_pending stacks concurrent scored reruns (needed to fire a full sweep
    # in one day) — opt-in only, since concurrent reruns can worsen our own
    # shared-backend contention.
    plan = ss.SubmitPlan(
        allow_high_n=True, allow_stacking=True, allow_pending=allow_pending,
        allow_env_probe=True, dry_run=False,
        reason=f"variant batch: {manifest['name']}",
    )
    source = ss.resolve_kernel_source(folder)

    grace_s = (
        ss.FRESH_KERNEL_POLL_ERROR_GRACE_S
        if poll_error_grace_seconds is None
        else poll_error_grace_seconds
    )

    def wait_fn(version: int) -> dict:
        return kernel_wait.wait_for_fresh_complete(
            poll_status=lambda: ss._status_text(api, variant_kernel),
            sleep=time.sleep, monotonic=time.monotonic,
            min_floor_s=ss.MIN_FLOOR_SECONDS, timeout_s=timeout_seconds,
            poll_seconds=poll_seconds,
            poll_error_grace_s=grace_s,
        )

    import audit_attack

    deps = ss.SubmitDeps(
        audit_fn=ss._real_audit(
            source, int(manifest["n_candidates"]), plan,
            audit_attack.PER_CANDIDATE_SECONDS_DEFAULT,
        ),
        pending_fn=ss._real_pending(api, competition),
        push_fn=lambda: push_kernel(folder),
        wait_fn=wait_fn,
        verify_fn=ss._real_verify(api, variant_kernel),
        submit_fn=lambda version: ss._to_jsonable_submit_from(api, competition, variant_kernel, message, version),
        record_fn=lambda: None,
    )
    result = ss.run_safe_submit(plan, deps)
    return {"created_at": now_iso(), "variant": manifest, "message": message,
            "folder": str(folder), "result": result, "ok": result["ok"]}


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
    parser.add_argument("--poll-error-grace-seconds", type=float, default=None,
                        help="tolerate this many contiguous seconds of "
                             "kernels_status errors before giving up (default: "
                             "safe_submit.FRESH_KERNEL_POLL_ERROR_GRACE_S) -- "
                             "covers a brand-new kernel slug's brief "
                             "half-created-state 403/404 window")
    parser.add_argument("--allow-pending", action="store_true",
                        help="stack concurrent scored reruns (fire a full sweep in one day)")
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
            allow_pending=args.allow_pending,
            poll_error_grace_seconds=args.poll_error_grace_seconds,
        )
        append_jsonl(args.out, row)
        rows.append(row)
        print(json.dumps(row, indent=2, sort_keys=True))
        if not row.get("ok"):
            return 2
    return 0 if all(row.get("ok") for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
