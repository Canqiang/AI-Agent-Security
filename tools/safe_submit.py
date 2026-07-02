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

# Under-REPO temp dir for extracted audit sources (gitignored via submissions/tmp/)
_AUDIT_TMP = REPO / "submissions" / "tmp"
DEFAULT_KERNEL = "canqiang/aiagsec-submission"
MIN_FLOOR_SECONDS = 240.0
POLL_SECONDS = 30.0
TIMEOUT_SECONDS = 5400.0


def resolve_kernel_source(kernel_folder: Path) -> Path:
    """Extract the %%writefile attack.py source from the kernel folder's notebook.

    Writes the embedded source to REPO/submissions/tmp/audit-src-<name>.py so the
    path satisfies audit_attack's source.relative_to(REPO) requirement. Returns the
    written Path. Raises RuntimeError (from extract_writefile_source) if the notebook
    has zero or multiple writefile cells.
    """
    import json as _json
    from check_submission_notebook import extract_writefile_source

    meta_path = kernel_folder / "kernel-metadata.json"
    meta = _json.loads(meta_path.read_text(encoding="utf-8"))
    code_file = meta["code_file"]
    text, _ = extract_writefile_source(kernel_folder / code_file)
    out_path = _AUDIT_TMP / f"audit-src-{kernel_folder.name}.py"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return out_path


def sources_match(text_a: str, text_b: str) -> bool:
    """Return True iff text_a and text_b are identical after normalisation."""
    from check_submission_notebook import normalize_source, sha256_text

    return sha256_text(normalize_source(text_a)) == sha256_text(normalize_source(text_b))


@dataclass
class SubmitPlan:
    allow_high_n: bool = False
    allow_stacking: bool = False
    allow_pending: bool = False
    allow_env_probe: bool = False
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
                "blockers": [f"kernel metadata machine_shape != NvidiaTeslaT4 (requested value, not API-confirmed): {push.get('machine_shape')}"], "ref": None}
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

def _real_audit(source: Path, n: int, plan: SubmitPlan, per_candidate_seconds: float) -> Callable[[], dict]:
    import audit_attack

    def run() -> dict:
        result = audit_attack.audit(
            n=n, source=source,
            allow_high_n=plan.allow_high_n, allow_stacking=plan.allow_stacking,
            per_candidate_seconds=per_candidate_seconds,
            allow_env_probe=plan.allow_env_probe,
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
    parser.add_argument("--source", type=Path, default=None,
                        help="optional parity reference: if given, must match the kernel folder's embedded source")
    parser.add_argument("--n", type=int, default=200)
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--message", required=True)
    parser.add_argument("--allow-high-n", action="store_true")
    parser.add_argument("--allow-stacking", action="store_true")
    parser.add_argument("--allow-env-probe", action="store_true",
                        help="permit env.interact/probe in the scored source (adaptive per-model fill)")
    parser.add_argument("--per-candidate-seconds", type=float, default=None,
                        help="grader seconds/candidate for the runtime-wall precheck "
                             "(default: audit_attack's v3.1.2 single-hop calibration; raise for multi-tool routes)")
    parser.add_argument("--allow-pending", action="store_true")
    parser.add_argument("--reason", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--unsafe", action="store_true",
                        help="skip wait+verify (explicit, logged escape hatch)")
    parser.add_argument("--min-floor-seconds", type=float, default=MIN_FLOOR_SECONDS)
    parser.add_argument("--timeout-seconds", type=float, default=TIMEOUT_SECONDS)
    parser.add_argument("--poll-seconds", type=float, default=POLL_SECONDS)
    args = parser.parse_args()

    if (args.allow_stacking or args.allow_high_n or args.allow_pending or args.allow_env_probe) and not args.reason:
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
        allow_pending=args.allow_pending, allow_env_probe=args.allow_env_probe,
        dry_run=args.dry_run, reason=args.reason,
    )

    # Resolve the audited source from the kernel folder (what actually ships)
    try:
        audit_source = resolve_kernel_source(args.kernel_folder)
    except Exception as exc:
        print(json.dumps({"ok": False, "stage": "resolve_source",
                          "blockers": [str(exc)]}, indent=2))
        return 2

    # If --source is provided, assert parity with the kernel folder's embedded source
    if args.source is not None:
        ref_text = Path(args.source).read_text(encoding="utf-8")
        if not sources_match(audit_source.read_text(encoding="utf-8"), ref_text):
            print(json.dumps({"ok": False, "stage": "parity",
                              "blockers": ["kernel-folder embedded source does not match --source"]},
                             indent=2))
            return 2

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

    import audit_attack
    per_candidate_seconds = (
        args.per_candidate_seconds if args.per_candidate_seconds is not None
        else audit_attack.PER_CANDIDATE_SECONDS_DEFAULT
    )
    deps = SubmitDeps(
        audit_fn=_real_audit(audit_source, args.n, plan, per_candidate_seconds),
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
