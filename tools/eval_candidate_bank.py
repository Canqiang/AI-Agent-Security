"""Evaluate CandidateSpec banks with the local scorer pipeline.

This is a dev-only bridge from `research/candidate_families.py` output to the
official SDK scoring machinery. It uses the compliant mock agent by default, so
it proves scorer plumbing and controls; it does not predict gpt-oss/gemma hit
rates.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any


REPO = Path(__file__).resolve().parent.parent
SDK = REPO / "competition_files"
sys.path.insert(0, str(SDK))
sys.path.insert(0, str(REPO / "tools"))

from aicomp_sdk.attacks.contracts import (  # noqa: E402
    AttackCandidate,
)
from aicomp_sdk.evaluation.ops import (  # noqa: E402
    resolve_fixtures_dir,
    summarize_attack_findings,
    _replay_candidate_trace,
)
from aicomp_sdk.core.cells import cell_signature  # noqa: E402
from aicomp_sdk.core.predicates import eval_predicates  # noqa: E402
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail  # noqa: E402
from aicomp_sdk.scoring import get_score_cell_hash, score_attack_raw  # noqa: E402

from compliant_agent import CompliantAgent  # noqa: E402
from lint_candidate_bank import load_candidate_bank  # noqa: E402


@dataclass(frozen=True)
class CandidateMeta:
    spec_id: str
    family: str
    route: str
    attack_class: str
    public_score_posture: str
    promotion_status: str
    expected_predicates: tuple[str, ...]
    expected_tools: tuple[str, ...]
    message_count: int
    runtime_cost_units: int


@dataclass(frozen=True)
class ReplayRecord:
    meta: CandidateMeta
    candidate: AttackCandidate
    trace: dict[str, Any]
    predicates: list[dict[str, Any]]
    finding: dict[str, Any] | None
    elapsed_s: float


def spec_messages(spec: dict[str, Any]) -> tuple[str, ...]:
    messages = spec.get("messages", [])
    if not isinstance(messages, list) or not all(isinstance(item, str) for item in messages):
        raise ValueError(f"{spec.get('id', '<missing-id>')}: messages must be a list of strings")
    return tuple(messages)


def finding_key(finding: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(message) for message in finding.get("user_messages", []))


def predicate_names(finding: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for predicate in finding.get("predicates", []):
        name = predicate.get("predicate")
        if name is not None:
            names.append(str(name))
    return names


def trace_status(finding: dict[str, Any]) -> dict[str, int]:
    trace = finding.get("trace", finding)
    events = trace.get("tool_events", [])
    guardrail_blocks = 0
    ok_events = 0
    failed_events = 0
    for event in events:
        if event.get("ok") is True:
            ok_events += 1
        else:
            failed_events += 1
            err = str(event.get("error", ""))
            if err.startswith("denied:") or err.startswith("confirm_required:"):
                guardrail_blocks += 1
            elif err in {"denied", "confirm_required"}:
                guardrail_blocks += 1
    return {
        "ok_tool_events": ok_events,
        "failed_tool_events": failed_events,
        "guardrail_blocks": guardrail_blocks,
    }


def raw_by_finding(findings: list[dict[str, Any]]) -> dict[tuple[str, ...], float]:
    raw_scores: dict[tuple[str, ...], float] = {}
    for finding in findings:
        raw_scores[finding_key(finding)] = score_attack_raw([finding])  # type: ignore[arg-type]
    return raw_scores


def summarize_group(
    *,
    group_specs: list[CandidateMeta],
    group_records: list[ReplayRecord],
    raw_scores: dict[tuple[str, ...], float],
) -> dict[str, Any]:
    predicate_counts: Counter[str] = Counter()
    tool_counts: Counter[str] = Counter()
    score_cells: set[str] = set()
    ok_tool_events = 0
    failed_tool_events = 0
    guardrail_blocks = 0
    finding_raw_scores: list[float] = []
    group_findings = [record.finding for record in group_records if record.finding is not None]
    elapsed_s = sum(record.elapsed_s for record in group_records)

    for record in group_records:
        for event in record.trace.get("tool_events", []):
            if event.get("ok") is True:
                tool_counts[str(event.get("name"))] += 1
        status = trace_status(record.trace)
        ok_tool_events += status["ok_tool_events"]
        failed_tool_events += status["failed_tool_events"]
        guardrail_blocks += status["guardrail_blocks"]

    for finding in group_findings:
        predicate_counts.update(predicate_names(finding))
        cell = get_score_cell_hash(finding)
        if cell is not None:
            score_cells.add(str(cell))
        finding_raw_scores.append(raw_scores.get(finding_key(finding), 0.0))

    attempted = len(group_specs)
    findings_count = len(group_findings)
    total_messages = sum(meta.message_count for meta in group_specs)
    raw = sum(finding_raw_scores)
    return {
        "attempted_candidates": attempted,
        "findings": findings_count,
        "hit_rate": round(findings_count / attempted, 4) if attempted else 0.0,
        "zero_finding_candidates": attempted - findings_count,
        "total_messages": total_messages,
        "runtime_cost_units": sum(meta.runtime_cost_units for meta in group_specs),
        "score_raw": round(raw, 3),
        "unique_score_cells": len(score_cells),
        "raw_per_message": round(raw / total_messages, 3) if total_messages else 0.0,
        "raw_per_second": round(raw / elapsed_s, 3) if elapsed_s > 0 else 0.0,
        "raw_per_finding": round(raw / findings_count, 3) if findings_count else 0.0,
        "time_taken_s": round(elapsed_s, 4),
        "seconds_per_candidate": round(elapsed_s / attempted, 4) if attempted else 0.0,
        "seconds_per_message": round(elapsed_s / total_messages, 4) if total_messages else 0.0,
        "predicate_counts": dict(sorted(predicate_counts.items())),
        "ok_tool_events": ok_tool_events,
        "failed_tool_events": failed_tool_events,
        "guardrail_blocks": guardrail_blocks,
        "tool_counts": dict(sorted(tool_counts.items())),
        "expected_predicates": sorted(
            {name for meta in group_specs for name in meta.expected_predicates}
        ),
        "expected_tools": sorted({name for meta in group_specs for name in meta.expected_tools}),
    }


def load_specs(path: Path, limit: int | None) -> tuple[list[dict[str, Any]], list[AttackCandidate], list[CandidateMeta]]:
    specs = load_candidate_bank(path)
    if limit is not None:
        specs = specs[:limit]

    candidates: list[AttackCandidate] = []
    metas: list[CandidateMeta] = []
    for spec in specs:
        messages = spec_messages(spec)
        candidates.append(AttackCandidate.from_messages(messages))
        metas.append(
            CandidateMeta(
                spec_id=str(spec.get("id", "")),
                family=str(spec.get("family", "")),
                route=str(spec.get("route", "")),
                attack_class=str(spec.get("attack_class", "")),
                public_score_posture=str(spec.get("public_score_posture", "")),
                promotion_status=str(spec.get("promotion_status", "")),
                expected_predicates=tuple(str(x) for x in spec.get("expected_predicates", [])),
                expected_tools=tuple(str(x) for x in spec.get("expected_tools", [])),
                message_count=len(messages),
                runtime_cost_units=int(spec.get("runtime_cost_units", len(messages))),
            )
        )
    return specs, candidates, metas


def evaluate_bank(
    *,
    bank: Path,
    budget_s: float,
    max_tool_hops: int,
    limit: int | None,
    agent_label: str,
) -> dict[str, Any]:
    _specs, candidates, metas = load_specs(bank, limit)
    findings: list[dict[str, Any]] = []
    records: list[ReplayRecord] = []
    fixtures_dir = resolve_fixtures_dir()
    started_at = time.perf_counter()
    for idx, (candidate, meta) in enumerate(zip(candidates, metas, strict=True)):
        candidate_started_at = time.perf_counter()
        trace = _replay_candidate_trace(
            candidate=candidate,
            index=idx,
            seed=123,
            fixtures_dir=fixtures_dir,
            agent_factory=CompliantAgent,
            guardrail=OptimalGuardrail(),
            env_selection="sandbox",
            max_tool_hops=max_tool_hops,
        )
        elapsed_s = time.perf_counter() - candidate_started_at
        predicates = eval_predicates(trace)
        finding: dict[str, Any] | None = None
        if predicates:
            finding = {
                "seed": trace["seed"],
                "user_messages": list(trace.get("user_messages", [])),
                "trace": trace,
                "predicates": predicates,
                "cell_signature": cell_signature(
                    trace.get("tool_events", []),
                    egress_data=trace.get("egress", []),
                    user_messages=trace.get("user_messages", []),
                ),
                "score_cell_signature": cell_signature(trace.get("tool_events", [])),
            }
            findings.append(finding)
        records.append(
            ReplayRecord(
                meta=meta,
                candidate=candidate,
                trace=trace,
                predicates=predicates,
                finding=finding,
                elapsed_s=elapsed_s,
            )
        )
    elapsed_total_s = time.perf_counter() - started_at

    summary = summarize_attack_findings(findings)
    raw_scores = raw_by_finding(findings)  # type: ignore[arg-type]

    family_specs: dict[str, list[CandidateMeta]] = defaultdict(list)
    route_specs: dict[str, list[CandidateMeta]] = defaultdict(list)
    posture_specs: dict[str, list[CandidateMeta]] = defaultdict(list)
    family_records: dict[str, list[ReplayRecord]] = defaultdict(list)
    route_records: dict[str, list[ReplayRecord]] = defaultdict(list)
    posture_records: dict[str, list[ReplayRecord]] = defaultdict(list)

    for meta in metas:
        family_specs[meta.family].append(meta)
        route_specs[meta.route].append(meta)
        posture_specs[meta.public_score_posture].append(meta)

    for record in records:
        family_records[record.meta.family].append(record)
        route_records[record.meta.route].append(record)
        posture_records[record.meta.public_score_posture].append(record)

    total_messages = sum(meta.message_count for meta in metas)
    total_runtime_cost_units = sum(meta.runtime_cost_units for meta in metas)
    finding_raw_values = list(raw_scores.values())

    return {
        "ok": True,
        "bank": str(bank),
        "agent": agent_label,
        "budget_s": budget_s,
        "max_tool_hops": max_tool_hops,
        "total_candidates": len(candidates),
        "total_messages": total_messages,
        "total_runtime_cost_units": total_runtime_cost_units,
        "time_taken_s": round(elapsed_total_s, 4),
        "seconds_per_candidate": (
            round(elapsed_total_s / len(candidates), 4) if candidates else 0.0
        ),
        "seconds_per_message": (
            round(elapsed_total_s / total_messages, 4) if total_messages else 0.0
        ),
        "over_budget": elapsed_total_s > budget_s,
        "score": round(summary["score"], 3),
        "score_raw": round(summary["score_raw"], 3),
        "findings": summary["findings_count"],
        "unique_cells": summary["unique_cells"],
        "unique_canonical_cells": summary["unique_canonical_cells"],
        "hit_rate": round(summary["findings_count"] / len(candidates), 4) if candidates else 0.0,
        "raw_per_message": (
            round(summary["score_raw"] / total_messages, 3) if total_messages else 0.0
        ),
        "raw_per_second": round(summary["score_raw"] / elapsed_total_s, 3)
        if elapsed_total_s > 0
        else 0.0,
        "raw_per_finding_mean": round(mean(finding_raw_values), 3) if finding_raw_values else 0.0,
        "by_family": {
            name: summarize_group(
                group_specs=family_specs[name],
                group_records=family_records.get(name, []),
                raw_scores=raw_scores,
            )
            for name in sorted(family_specs)
        },
        "by_route": {
            name: summarize_group(
                group_specs=route_specs[name],
                group_records=route_records.get(name, []),
                raw_scores=raw_scores,
            )
            for name in sorted(route_specs)
        },
        "by_public_score_posture": {
            name: summarize_group(
                group_specs=posture_specs[name],
                group_records=posture_records.get(name, []),
                raw_scores=raw_scores,
            )
            for name in sorted(posture_specs)
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bank", type=Path, help="CandidateSpec JSONL/JSON file")
    parser.add_argument("--budget", type=float, default=20.0, help="time_budget_s")
    parser.add_argument("--max-tool-hops", type=int, default=4)
    parser.add_argument("--limit", type=int, help="evaluate only the first N specs")
    parser.add_argument(
        "--agent",
        choices=("compliant",),
        default="compliant",
        help="local agent backend; only compliant is supported for now",
    )
    args = parser.parse_args()

    if args.limit is not None and args.limit <= 0:
        parser.error("--limit must be positive")
    if args.max_tool_hops <= 0:
        parser.error("--max-tool-hops must be positive")

    result = evaluate_bank(
        bank=args.bank,
        budget_s=args.budget,
        max_tool_hops=args.max_tool_hops,
        limit=args.limit,
        agent_label=args.agent,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
