"""The single gated Kaggle submit path.

run_safe_submit() is pure orchestration over injected dependencies, so the gate
ordering is unit-tested without touching Kaggle. main() wires the real adapters:
audit_attack.audit, pull_submission_ledger, push_kaggle_kernel.push_kernel,
kernel_wait.wait_for_fresh_complete, kernels_output verification, and
competition_submit_code.

This is the ONLY module that calls competition_submit_code (except --unsafe).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

REPO = TOOLS.parent
DEFAULT_COMPETITION = "ai-agent-security-multi-step-tool-attacks"
DEFAULT_KERNEL = "canqiang/aiagsec-submission"
MIN_FLOOR_SECONDS = 240.0
POLL_SECONDS = 30.0
TIMEOUT_SECONDS = 5400.0


@dataclass
class SubmitPlan:
    allow_high_n: bool = False
    allow_stacking: bool = False
    allow_pending: bool = False
    dry_run: bool = False
    reason: str = ""


@dataclass
class SubmitDeps:
    audit_fn: Callable[[], dict]
    pending_fn: Callable[[], list]
    push_fn: Callable[[], dict]
    wait_fn: Callable[[int], dict]
    verify_fn: Callable[[], dict]
    submit_fn: Callable[[int], dict]
    record_fn: Callable[[], Any]


def run_safe_submit(plan: SubmitPlan, deps: SubmitDeps) -> dict:
    # 1. Audit
    audit = deps.audit_fn()
    if not audit.get("ok"):
        return {"ok": False, "stage": "audit", "blockers": audit.get("blockers", []), "ref": None}
    # 2. No-pending
    pending = deps.pending_fn()
    if pending and not plan.allow_pending:
        return {"ok": False, "stage": "no_pending",
                "blockers": [f"unresolved pending refs: {pending}"], "ref": None}
    # 3. Push
    push = deps.push_fn()
    if not push.get("ok") or push.get("version_number") is None:
        return {"ok": False, "stage": "push", "blockers": ["push failed"], "ref": None}
    if push.get("machine_shape") != "NvidiaTeslaT4":
        return {"ok": False, "stage": "push",
                "blockers": [f"machine_shape != NvidiaTeslaT4: {push.get('machine_shape')}"], "ref": None}
    version = int(push["version_number"])
    # 4. Wait for a fresh complete
    wait = deps.wait_fn(version)
    if not wait.get("ok"):
        return {"ok": False, "stage": "wait", "blockers": [wait.get("reason") or "wait failed"], "ref": None}
    # 5. Verify output
    verify = deps.verify_fn()
    if not verify.get("ok"):
        return {"ok": False, "stage": "verify", "blockers": verify.get("blockers", []), "ref": None}
    # dry-run stops here
    if plan.dry_run:
        return {"ok": True, "stage": "dry_run", "blockers": [], "ref": None}
    # 6. Submit
    response = deps.submit_fn(version)
    ref = response.get("ref") if isinstance(response, dict) else None
    # 7. Record
    deps.record_fn()
    return {"ok": True, "stage": "submitted", "blockers": [], "ref": ref}


# ---- real adapters ---------------------------------------------------------

def _real_audit(source: Path, n: int, plan: SubmitPlan) -> Callable[[], dict]:
    import audit_attack

    def run() -> dict:
        result = audit_attack.audit(
            n=n, source=source,
            allow_high_n=plan.allow_high_n, allow_stacking=plan.allow_stacking,
        )
        return {"ok": result["ok"], "blockers": result.get("blockers", [])}

    return run


def _real_pending(api: Any, competition: str) -> Callable[[], list]:
    import pull_submission_ledger as pl

    def run() -> list:
        records = pl.fetch_records(api, competition, 25)
        _, ledger = pl.build_ledger(records, existing={}, now=pl.now_iso())
        return ledger["unresolved_pending_refs"]

    return run


def _status_text(api: Any, kernel: str) -> str:
    from kaggle_status import object_get
    status = api.kernels_status(kernel)
    return str(object_get(status, "status") or "")


def _real_verify(api: Any, kernel: str) -> Callable[[], dict]:
    import tempfile
    from write_submission_csv import OFFICIAL_SUBMISSION_IDS  # four-row contract

    def run() -> dict:
        blockers: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            api.kernels_output(kernel, path=tmp, quiet=True)
            csvs = list(Path(tmp).glob("submission.csv"))
            if not csvs:
                return {"ok": False, "blockers": ["no submission.csv in kernel output"]}
            text = csvs[0].read_text()
            for needed in OFFICIAL_SUBMISSION_IDS:
                if needed not in text:
                    blockers.append(f"submission.csv missing row {needed}")
            for log in Path(tmp).glob("*.log"):
                body = log.read_text(errors="replace")
                if "Traceback" in body or "exceeded the allowed runtime" in body:
                    blockers.append("kernel log shows an error/runtime overflow")
                    break
        return {"ok": not blockers, "blockers": blockers}

    return run


def _to_jsonable_submit_from(
    api: Any, competition: str, kernel: str, message: str, version: int
) -> dict:
    from kaggle_status import object_get
    response = api.competition_submit_code(
        file_name="submission.csv", message=message, competition=competition,
        kernel=kernel, kernel_version=int(version), quiet=True,
    )
    return {"ref": object_get(response, "ref", "id")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", default=DEFAULT_KERNEL)
    parser.add_argument("--kernel-folder", type=Path, required=True,
                        help="prepared kernel folder with kernel-metadata.json")
    parser.add_argument("--source", type=Path, default=REPO / "src" / "attack.py")
    parser.add_argument("--n", type=int, default=200)
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--message", required=True)
    parser.add_argument("--allow-high-n", action="store_true")
    parser.add_argument("--allow-stacking", action="store_true")
    parser.add_argument("--allow-pending", action="store_true")
    parser.add_argument("--reason", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--unsafe", action="store_true",
                        help="skip wait+verify (explicit, logged escape hatch)")
    parser.add_argument("--min-floor-seconds", type=float, default=MIN_FLOOR_SECONDS)
    parser.add_argument("--timeout-seconds", type=float, default=TIMEOUT_SECONDS)
    parser.add_argument("--poll-seconds", type=float, default=POLL_SECONDS)
    args = parser.parse_args()

    if (args.allow_stacking or args.allow_high_n or args.allow_pending) and not args.reason:
        print(json.dumps({"ok": False, "stage": "args",
                          "blockers": ["override flags require --reason"]}, indent=2))
        return 2

    from kaggle.api.kaggle_api_extended import KaggleApi
    import kernel_wait
    import pull_submission_ledger as pl
    from push_kaggle_kernel import push_kernel

    api = KaggleApi()
    api.authenticate()
    plan = SubmitPlan(
        allow_high_n=args.allow_high_n, allow_stacking=args.allow_stacking,
        allow_pending=args.allow_pending, dry_run=args.dry_run, reason=args.reason,
    )
    source = Path(args.source).resolve()

    def wait_fn(version: int) -> dict:
        if args.unsafe:
            return {"ok": True, "reason": "unsafe-skip"}
        return kernel_wait.wait_for_fresh_complete(
            poll_status=lambda: _status_text(api, args.kernel),
            sleep=time.sleep, monotonic=time.monotonic,
            min_floor_s=args.min_floor_seconds, timeout_s=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )

    def verify_fn() -> dict:
        if args.unsafe:
            return {"ok": True, "blockers": []}
        return _real_verify(api, args.kernel)()

    def record_fn():
        records = pl.fetch_records(api, args.competition, 25)
        existing = pl.load_existing(pl.DEFAULT_OUT_DIR)
        manifests, ledger = pl.build_ledger(records, existing=existing, now=pl.now_iso())
        pl.write_ledger(pl.DEFAULT_OUT_DIR, manifests, ledger)

    deps = SubmitDeps(
        audit_fn=_real_audit(source, args.n, plan),
        pending_fn=_real_pending(api, args.competition),
        push_fn=lambda: push_kernel(args.kernel_folder),
        wait_fn=wait_fn,
        verify_fn=verify_fn,
        submit_fn=lambda version: _to_jsonable_submit_from(
            api, args.competition, args.kernel, args.message, version
        ),
        record_fn=record_fn,
    )
    result = run_safe_submit(plan, deps)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
