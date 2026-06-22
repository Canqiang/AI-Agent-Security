"""Build a pre-submit evidence manifest for Kaggle code submissions.

The manifest is intentionally local/offline: it runs repo-local gates and
records Kaggle metadata supplied by args or a local metadata JSON. Network status
polling belongs in a separate Kaggle status tool.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "attack.py"
NOTEBOOK = REPO / "notebooks" / "submission.ipynb"
DEFAULT_OUT_DIR = REPO / "submissions" / "manifests"
OFFICIAL_SUBMISSION_IDS = [
    "gpt_oss_public",
    "gpt_oss_private",
    "gemma_public",
    "gemma_private",
]

sys.path.insert(0, str(REPO / "tools"))

from audit_attack import audit as audit_attack  # noqa: E402
from check_submission_notebook import check as check_notebook  # noqa: E402
from eval_candidate_bank import evaluate_bank  # noqa: E402
from lint_candidate_bank import lint as lint_candidate_bank  # noqa: E402
from lint_candidate_bank import load_candidate_bank  # noqa: E402


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


def git_output(args: list[str]) -> str | None:
    try:
        return subprocess.check_output(
            ["git", *args],
            cwd=REPO,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return None


def git_info() -> dict[str, Any]:
    status = git_output(["status", "--short"])
    return {
        "commit": git_output(["rev-parse", "HEAD"]),
        "branch": git_output(["branch", "--show-current"]),
        "dirty": bool(status),
        "status_short": status.splitlines() if status else [],
    }


def load_json_file(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    with path.open("r", encoding="utf-8") as fh:
        value = json.load(fh)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def read_submission_csv(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {
            "present": False,
            "ok": False,
            "message": "no commit-run submission.csv supplied",
        }
    if not path.exists():
        return {
            "present": False,
            "ok": False,
            "path": rel(path),
            "message": "submission.csv path does not exist",
        }

    with path.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    ids = [row.get("Id", "") for row in rows]
    ok = ids == OFFICIAL_SUBMISSION_IDS
    return {
        "present": True,
        "path": rel(path),
        "ids": ids,
        "expected_ids": OFFICIAL_SUBMISSION_IDS,
        "ok": ok,
        "message": None if ok else "submission.csv Id rows do not match official four-row contract",
    }


def resolve_kernel_metadata(
    *,
    metadata_json: Path | None,
    kernel_slug: str | None,
    kernel_version: str | None,
    machine_shape: str | None,
) -> dict[str, Any]:
    metadata = load_json_file(metadata_json)
    resolved_slug = (
        kernel_slug
        or metadata.get("id")
        or metadata.get("kernel_slug")
        or metadata.get("slug")
    )
    resolved_version = kernel_version or metadata.get("version") or metadata.get("kernel_version")
    resolved_machine_shape = (
        machine_shape
        or metadata.get("machine_shape")
        or metadata.get("accelerator")
        or metadata.get("acc")
    )
    ok = resolved_machine_shape == "NvidiaTeslaT4"
    return {
        "metadata_json": rel(metadata_json) if metadata_json else None,
        "kernel_slug": resolved_slug,
        "kernel_version": resolved_version,
        "machine_shape": resolved_machine_shape,
        "ok": ok,
        "message": None if ok else "machine_shape must be NvidiaTeslaT4 before code submit",
    }


def pending_status(pending_refs: list[str], allow_pending: bool) -> dict[str, Any]:
    checked_at = now_iso()
    ok = allow_pending or not pending_refs
    return {
        "checked_at": checked_at,
        "pending_refs": pending_refs,
        "allow_pending": allow_pending,
        "ok": ok,
        "message": None if ok else "pending Kaggle ref(s) present without --allow-pending",
    }


def kaggle_status_snapshot(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"present": False, "ok": True}
    data = load_json_file(path)
    submissions = data.get("submissions", {})
    kernel_status = data.get("kernel_status", {})
    kernel_metadata = data.get("kernel_metadata", {})
    return {
        "present": True,
        "path": rel(path),
        "sha256": sha256_file(path),
        "created_at": data.get("created_at"),
        "competition": data.get("competition"),
        "pending_refs": list(submissions.get("pending_refs") or []),
        "pending_count": submissions.get("pending_count"),
        "submissions_ok": submissions.get("ok"),
        "kernel_status": kernel_status,
        "kernel_metadata": kernel_metadata,
        "ok": bool(submissions.get("ok", True))
        and bool(kernel_status.get("ok", True))
        and bool(kernel_metadata.get("ok", True)),
    }


def candidate_bank_summary(
    *,
    bank: Path | None,
    scored: bool,
    eval_bank: bool,
    max_total_messages: int,
    budget_s: float,
    max_tool_hops: int,
) -> dict[str, Any]:
    if bank is None:
        return {
            "present": False,
            "ok": True,
            "message": "no candidate bank supplied; using source audit only",
        }
    specs = load_candidate_bank(bank)
    lint_result = lint_candidate_bank(
        specs,
        scored=scored,
        max_total_messages=max_total_messages,
        fail_on_warning=False,
    )
    summary: dict[str, Any] = {
        "present": True,
        "path": rel(bank),
        "scored_mode": scored,
        "lint": lint_result,
        "ok": bool(lint_result.get("ok")),
    }
    if eval_bank:
        eval_result = evaluate_bank(
            bank=bank,
            budget_s=budget_s,
            max_tool_hops=max_tool_hops,
            limit=None,
            agent_label="compliant",
        )
        summary["eval"] = eval_result
        summary["ok"] = summary["ok"] and bool(eval_result.get("ok"))
    return summary


def validation_summary(path: Path | None) -> dict[str, Any]:
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
    return {
        "present": True,
        "path": rel(path),
        "sha256": sha256_file(path),
        "ok": True,
    }


def collect_blockers(
    manifest: dict[str, Any],
    *,
    allow_missing_validation: bool,
    require_submission_csv: bool,
) -> list[str]:
    blockers: list[str] = []

    audit = manifest["gates"]["attack_audit"]
    if not audit.get("ok"):
        blockers.append("attack audit failed")

    parity = manifest["gates"]["notebook_parity"]
    if not parity.get("ok"):
        blockers.append("notebook/source parity failed")

    kernel = manifest["kaggle"]["kernel"]
    if not kernel.get("ok"):
        blockers.append("Kaggle kernel metadata does not prove NvidiaTeslaT4")

    pending = manifest["kaggle"]["pending"]
    if not pending.get("ok"):
        blockers.append("pending Kaggle submission ref(s) present")

    csv_status = manifest["kaggle"]["commit_run_submission_csv"]
    if require_submission_csv and not csv_status.get("present"):
        blockers.append("required commit-run submission.csv not supplied")
    elif csv_status.get("present") and not csv_status.get("ok"):
        blockers.append("commit-run submission.csv has invalid Id rows")

    validation = manifest["validation_summary"]
    if not allow_missing_validation and not validation.get("ok"):
        blockers.append("required validation summary missing or invalid")

    bank = manifest["candidate_bank"]
    if bank.get("present") and not bank.get("ok"):
        blockers.append("candidate bank lint/eval failed")

    return blockers


def strict_submit_blockers(manifest: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if not manifest["gates"]["attack_audit"].get("ok"):
        blockers.append("attack audit failed")
    if not manifest["gates"]["notebook_parity"].get("ok"):
        blockers.append("notebook/source parity failed")
    if not manifest["validation_summary"].get("ok"):
        blockers.append("GGUF validation summary missing or invalid")
    if not manifest["kaggle"]["kernel"].get("ok"):
        blockers.append("Kaggle kernel metadata does not prove NvidiaTeslaT4")
    if not manifest["kaggle"]["pending"].get("ok"):
        blockers.append("pending Kaggle submission ref(s) present")
    if not manifest["kaggle"]["commit_run_submission_csv"].get("ok"):
        blockers.append("official four-row submission.csv evidence missing or invalid")
    if manifest["candidate_bank"].get("present") and not manifest["candidate_bank"].get("ok"):
        blockers.append("candidate bank lint/eval failed")
    return blockers


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    audit_result = audit_attack(
        n=args.n,
        source=args.source,
        allow_high_n=args.allow_high_n,
        allow_stacking=args.allow_stacking,
    )
    parity_result = check_notebook(
        source_path=args.source,
        notebook_path=args.notebook,
        allow_inline=args.allow_inline,
    )

    status_snapshot = kaggle_status_snapshot(args.kaggle_status_json)
    pending_refs = list(args.pending_ref)
    for ref in status_snapshot.get("pending_refs", []):
        ref_text = str(ref)
        if ref_text not in pending_refs:
            pending_refs.append(ref_text)

    manifest: dict[str, Any] = {
        "schema_version": "2026-06-22",
        "created_at": now_iso(),
        "competition": "ai-agent-security-multi-step-tool-attacks",
        "description": args.description,
        "git": git_info(),
        "source": {
            "path": rel(args.source),
            "sha256": audit_result.get("source_sha256"),
            "requested_n_candidates": args.n,
            "module_default_n_candidates": audit_result.get("module_default_n_candidates"),
        },
        "notebook": {
            "path": rel(args.notebook),
            "writefile_cell_index": parity_result.get("writefile_cell_index"),
            "notebook_attack_sha256": parity_result.get("notebook_attack_sha256"),
            "source_match": parity_result.get("match"),
            "allow_inline": args.allow_inline,
        },
        "gates": {
            "attack_audit": audit_result,
            "notebook_parity": parity_result,
        },
        "candidate_bank": candidate_bank_summary(
            bank=args.candidate_bank,
            scored=args.candidate_bank_scored,
            eval_bank=args.eval_candidate_bank,
            max_total_messages=args.max_total_messages,
            budget_s=args.eval_budget,
            max_tool_hops=args.max_tool_hops,
        ),
        "validation_summary": validation_summary(args.validation_summary),
        "kaggle": {
            "status_snapshot": status_snapshot,
            "kernel": resolve_kernel_metadata(
                metadata_json=args.kernel_metadata_json,
                kernel_slug=args.kernel_slug,
                kernel_version=args.kernel_version,
                machine_shape=args.machine_shape,
            ),
            "pending": pending_status(pending_refs, args.allow_pending),
            "commit_run_submission_csv": read_submission_csv(args.submission_csv),
        },
        "references": {
            "design_docs": [
                "docs/project-engineering-design.md",
                "docs/superpowers/specs/2026-06-22-agent-attack-research-design.md",
                "docs/superpowers/specs/2026-06-22-attack-algorithm-design.md",
            ],
            "paper_manifest": "docs/references/README.md",
        },
        "notes": args.note,
    }
    blockers = collect_blockers(
        manifest,
        allow_missing_validation=args.allow_missing_validation,
        require_submission_csv=args.require_submission_csv,
    )
    manifest["blockers"] = blockers
    manifest["strict_submit_blockers"] = strict_submit_blockers(manifest)
    manifest["local_gates_ready"] = not blockers
    manifest["submit_ready"] = not manifest["strict_submit_blockers"]
    return manifest


def default_output_path(manifest: dict[str, Any], out_dir: Path) -> Path:
    ts = manifest["created_at"].replace(":", "").replace("-", "")
    n = manifest["source"]["requested_n_candidates"]
    source_sha = str(manifest["source"]["sha256"])[:12]
    return out_dir / f"{ts}-n{n}-{source_sha}.json"


def pass_fail(ok: Any) -> str:
    return "pass" if bool(ok) else "fail"


def list_or_none(items: list[str]) -> list[str]:
    return items if items else ["none"]


def render_manifest_summary(manifest: dict[str, Any], manifest_path: Path) -> str:
    source = manifest["source"]
    audit = manifest["gates"]["attack_audit"]
    parity = manifest["gates"]["notebook_parity"]
    bank = manifest["candidate_bank"]
    kernel = manifest["kaggle"]["kernel"]
    pending = manifest["kaggle"]["pending"]
    csv_status = manifest["kaggle"]["commit_run_submission_csv"]
    validation = manifest["validation_summary"]
    status_snapshot = manifest["kaggle"]["status_snapshot"]

    lines = [
        "# Submission Manifest Summary",
        "",
        f"- Manifest: `{rel(manifest_path)}`",
        f"- Created: `{manifest['created_at']}`",
        f"- Competition: `{manifest['competition']}`",
        f"- Description: {manifest['description']}",
        f"- Local gates ready: `{str(manifest['local_gates_ready']).lower()}`",
        f"- Submit ready: `{str(manifest['submit_ready']).lower()}`",
        "",
        "## Source",
        "",
        f"- Source: `{source['path']}`",
        f"- Source SHA256: `{source['sha256']}`",
        f"- Requested candidates: `{source['requested_n_candidates']}`",
        f"- Module default candidates: `{source['module_default_n_candidates']}`",
        f"- Notebook source match: `{str(parity.get('match')).lower()}`",
        "",
        "## Gates",
        "",
        "| Gate | Result | Detail |",
        "|---|---|---|",
        (
            "| attack audit | "
            f"{pass_fail(audit.get('ok'))} | "
            f"{audit.get('total_candidates')} candidates, "
            f"{audit.get('total_messages')} messages, "
            f"{audit.get('unique_host_buckets')} unique host buckets |"
        ),
        (
            "| notebook parity | "
            f"{pass_fail(parity.get('ok'))} | "
            f"attack SHA `{parity.get('notebook_attack_sha256')}` |"
        ),
        (
            "| candidate bank | "
            f"{pass_fail(bank.get('ok'))} | "
            f"{bank.get('path', 'not supplied')} |"
        ),
        (
            "| validation summary | "
            f"{pass_fail(validation.get('ok'))} | "
            f"{validation.get('path') or validation.get('message')} |"
        ),
        (
            "| T4 metadata | "
            f"{pass_fail(kernel.get('ok'))} | "
            f"machine_shape=`{kernel.get('machine_shape')}` |"
        ),
        (
            "| pending refs | "
            f"{pass_fail(pending.get('ok'))} | "
            f"{len(pending.get('pending_refs') or [])} pending |"
        ),
        (
            "| commit-run csv | "
            f"{pass_fail(csv_status.get('ok'))} | "
            f"{csv_status.get('path') or csv_status.get('message')} |"
        ),
        "",
    ]

    if bank.get("present"):
        lint = bank.get("lint", {})
        eval_result = bank.get("eval", {})
        lines.extend(
            [
                "## Candidate Bank",
                "",
                f"- Lint candidates: `{lint.get('total_candidates')}`",
                f"- Lint messages: `{lint.get('total_messages')}`",
                f"- Scored mode: `{str(bank.get('scored_mode')).lower()}`",
                f"- Lint blockers: `{len(lint.get('blockers') or [])}`",
                f"- Lint warnings: `{len(lint.get('warnings') or [])}`",
            ]
        )
        if eval_result:
            lines.extend(
                [
                    f"- Eval findings: `{eval_result.get('findings')}`",
                    f"- Eval raw score: `{eval_result.get('score_raw')}`",
                    f"- Eval raw per message: `{eval_result.get('raw_per_message')}`",
                    f"- Eval over budget: `{str(eval_result.get('over_budget')).lower()}`",
                ]
            )
        lines.append("")

    lines.extend(
        [
            "## Kaggle Status",
            "",
            f"- Status snapshot present: `{str(status_snapshot.get('present')).lower()}`",
            f"- Snapshot path: `{status_snapshot.get('path')}`",
            f"- Snapshot pending refs: `{status_snapshot.get('pending_refs') or []}`",
            f"- Kernel slug: `{kernel.get('kernel_slug')}`",
            f"- Kernel version: `{kernel.get('kernel_version')}`",
            "",
            "## Blockers",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in list_or_none(manifest["blockers"]))
    lines.extend(["", "## Strict Submit Blockers", ""])
    lines.extend(f"- {item}" for item in list_or_none(manifest["strict_submit_blockers"]))

    if manifest.get("notes"):
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {item}" for item in manifest["notes"])

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=200, help="candidate count to audit")
    parser.add_argument("--source", type=Path, default=SRC)
    parser.add_argument("--notebook", type=Path, default=NOTEBOOK)
    parser.add_argument("--description", default="pre-submit manifest")
    parser.add_argument("--note", action="append", default=[], help="freeform manifest note")
    parser.add_argument("--out", type=Path, help="manifest output path")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--summary-md", type=Path, help="optional markdown summary path")

    parser.add_argument("--allow-high-n", action="store_true")
    parser.add_argument("--allow-stacking", action="store_true")
    parser.add_argument("--allow-inline", action="store_true")

    parser.add_argument("--candidate-bank", type=Path)
    parser.add_argument("--candidate-bank-scored", action="store_true")
    parser.add_argument("--eval-candidate-bank", action="store_true")
    parser.add_argument("--max-total-messages", type=int, default=400)
    parser.add_argument("--eval-budget", type=float, default=20.0)
    parser.add_argument("--max-tool-hops", type=int, default=4)

    parser.add_argument("--validation-summary", type=Path)
    parser.add_argument(
        "--allow-missing-validation",
        action="store_true",
        help="record a local-gates manifest even without GGUF validation evidence",
    )

    parser.add_argument("--kernel-metadata-json", type=Path)
    parser.add_argument("--kaggle-status-json", type=Path)
    parser.add_argument("--kernel-slug")
    parser.add_argument("--kernel-version")
    parser.add_argument("--machine-shape")
    parser.add_argument("--pending-ref", action="append", default=[])
    parser.add_argument("--allow-pending", action="store_true")
    parser.add_argument("--submission-csv", type=Path)
    parser.add_argument("--require-submission-csv", action="store_true")
    args = parser.parse_args()

    manifest = build_manifest(args)
    out_path = args.out or default_output_path(manifest, args.out_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.summary_md:
        args.summary_md.parent.mkdir(parents=True, exist_ok=True)
        args.summary_md.write_text(
            render_manifest_summary(manifest, out_path),
            encoding="utf-8",
        )

    output = {
        "manifest": rel(out_path),
        "local_gates_ready": manifest["local_gates_ready"],
        "submit_ready": manifest["submit_ready"],
        "blockers": manifest["blockers"],
        "strict_submit_blockers": manifest["strict_submit_blockers"],
    }
    if args.summary_md:
        output["summary_md"] = rel(args.summary_md)
    print(
        json.dumps(output, indent=2, sort_keys=True)
    )
    return 0 if manifest["local_gates_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
