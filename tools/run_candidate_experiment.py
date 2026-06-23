"""Run a local CandidateSpec experiment with lint and compliant replay.

This is the fast, repo-local experiment loop. It proves that a candidate family
has the intended scorer shape before spending T4/GGUF time. It does not rank
real-model output-suppression behavior; use `tools/run_gguf_bank_experiment.py`
for that.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_FAMILIES = (
    "direct_exfil_suppress_once,"
    "direct_exfil_suppress_stop,"
    "direct_exfil_suppress_no_summary,"
    "direct_exfil_exactly_once,"
    "direct_exfil_minimal_function"
)
DEFAULT_BANK_OUT = REPO / "research" / "results" / "candidate_bank.suppress_ab.jsonl"
DEFAULT_OUT = REPO / "research" / "results" / "suppress-ab-local.latest.json"

sys.path.insert(0, str(REPO / "research"))
sys.path.insert(0, str(REPO / "tools"))

from candidate_families import generate_specs, iter_jsonl, parse_families  # noqa: E402
from eval_candidate_bank import evaluate_bank  # noqa: E402
from lint_candidate_bank import lint  # noqa: E402


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def family_ranking(eval_result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for family, metrics in (eval_result.get("by_family") or {}).items():
        rows.append(
            {
                "family": family,
                "attempted_candidates": metrics.get("attempted_candidates"),
                "findings": metrics.get("findings"),
                "hit_rate": metrics.get("hit_rate"),
                "score_raw": metrics.get("score_raw"),
                "raw_per_message": metrics.get("raw_per_message"),
                "raw_per_second": metrics.get("raw_per_second"),
                "seconds_per_candidate": metrics.get("seconds_per_candidate"),
                "guardrail_blocks": metrics.get("guardrail_blocks"),
                "failed_tool_events": metrics.get("failed_tool_events"),
            }
        )
    return sorted(
        rows,
        key=lambda item: (
            float(item.get("hit_rate") or 0.0),
            float(item.get("raw_per_message") or 0.0),
            float(item.get("raw_per_second") or 0.0),
        ),
        reverse=True,
    )


def run_experiment(args: argparse.Namespace) -> dict[str, Any]:
    families = parse_families(args.families)
    specs = generate_specs(families=families, n=args.n, start=args.start)
    spec_dicts = [asdict(spec) for spec in specs]

    write_jsonl(args.bank_out, list(iter_jsonl(specs)))
    lint_result = lint(
        spec_dicts,
        scored=args.scored_lint,
        max_total_messages=args.max_total_messages,
        fail_on_warning=args.fail_on_warning,
    )
    eval_result = evaluate_bank(
        bank=args.bank_out,
        budget_s=args.budget,
        max_tool_hops=args.max_tool_hops,
        limit=None,
        agent_label="compliant",
    )

    result = {
        "schema_version": "2026-06-22.local-candidate-experiment.v1",
        "created_at": now_iso(),
        "experiment": args.name,
        "families": families,
        "n_per_family": args.n,
        "start": args.start,
        "bank": rel(args.bank_out),
        "lint": lint_result,
        "eval": eval_result,
        "family_ranking": family_ranking(eval_result),
        "ok": bool(lint_result.get("ok")) and bool(eval_result.get("ok")),
    }
    write_json(args.out, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="suppress_ab_local")
    parser.add_argument("--families", default=DEFAULT_FAMILIES)
    parser.add_argument("--n", type=int, default=5, help="candidates per family")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--bank-out", type=Path, default=DEFAULT_BANK_OUT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--budget", type=float, default=20.0)
    parser.add_argument("--max-tool-hops", type=int, default=4)
    parser.add_argument("--max-total-messages", type=int, default=400)
    parser.add_argument("--scored-lint", action="store_true")
    parser.add_argument("--fail-on-warning", action="store_true")
    args = parser.parse_args()

    if args.n <= 0:
        parser.error("--n must be positive")
    if args.start < 0:
        parser.error("--start must be non-negative")
    if args.max_tool_hops <= 0:
        parser.error("--max-tool-hops must be positive")

    result = run_experiment(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
