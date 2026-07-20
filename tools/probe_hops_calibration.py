"""0-GPU offline probe: does replaying at a tighter max_tool_hops keep the same
EXFILTRATION hits, and how much cheaper is it?

Background
----------
The scored gateway replays every RETURNED candidate at a forced
``max_tool_hops=8`` inside its own fresh per-model budget (an overrun voids the
WHOLE submission). Our ``_fill()`` validation loop today probes each candidate
at the same hops=8 so its measured ``elapsed`` is a faithful proxy for that
replay cost, which ``REPLAY_SAFE_SIZING`` accumulates.

The EXFILTRATION predicate only reads ``tool_events`` (an ``http.post`` carrying
PAYLOAD); it never reads assistant text. The tool event is recorded the moment
the model emits its ``http.post`` ToolCallDecision -- if that happens on the
agent's FIRST generation (hop 0), then a ``max_tool_hops=1`` replay records the
same event and fires identically, while skipping the wrap-up generation(s) the
higher cap would otherwise run. That is a potential ~1.5-2x fill-throughput win.

Two things must be measured on the REAL models before trusting it, and neither
costs GPU quota (GGUF Q4 runs on CPU):

1. Hit-rate invariance -- does the tight probe cap fire on EXACTLY the same
   candidates as the hops=8 baseline? If a candidate's http.post lands on a
   later hop (e.g. the model reasons first), a tight cap would cut it off and
   silently drop the hit. `hit_rate_invariance()` flags any such mismatch.
2. Calibration coefficient -- ``coef = elapsed_baseline / elapsed_probe`` per
   model, so a hops=1 measurement can be scaled back up to the true hops=8
   replay cost before it is fed to REPLAY_SAFE_SIZING. Without this the sizing
   under-counts, keeps too many candidates, and voids on format error.
   `calibration_coefficient()` derives it (warm-up candidate excluded).

The two analysis functions are pure and unit-tested; running the models reuses
`tools/run_gguf_validation.py`'s loader/replay machinery unchanged.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import run_gguf_validation as rgv  # noqa: E402  (stdlib-only at import time)

REPO = TOOLS.parent
DEFAULT_OUT = REPO / "research" / "results" / "hops-calibration.latest.json"
DEFAULT_RAW_OUT = REPO / "research" / "results" / "hops-calibration.raw.jsonl"


def _fired(record: dict[str, Any]) -> bool:
    """The candidate's EXFILTRATION outcome for a single replay: an exact-payload
    http.post fired. Predicate presence is an equivalent signal; either suffices."""
    return bool(record.get("exact_payload")) or bool(record.get("predicate_names"))


def _by_index(records: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {int(r["candidate_index"]): r for r in records}


def hit_rate_invariance(
    baseline: list[dict[str, Any]], probe: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compare the fire outcome of every candidate replayed at the baseline hop
    cap vs the probe hop cap. Invariant iff no candidate's outcome changed."""
    base_idx = _by_index(baseline)
    probe_idx = _by_index(probe)
    shared = sorted(set(base_idx) & set(probe_idx))

    fired_baseline = 0
    fired_probe = 0
    agreements = 0
    mismatches: list[dict[str, Any]] = []
    for index in shared:
        b = _fired(base_idx[index])
        p = _fired(probe_idx[index])
        fired_baseline += int(b)
        fired_probe += int(p)
        if b == p:
            agreements += 1
        else:
            mismatches.append({"candidate_index": index, "baseline": b, "probe": p})

    return {
        "n": len(shared),
        "fired_baseline": fired_baseline,
        "fired_probe": fired_probe,
        "agreements": agreements,
        "mismatches": mismatches,
        "invariant": not mismatches,
    }


def calibration_coefficient(
    baseline: list[dict[str, Any]],
    probe: list[dict[str, Any]],
    *,
    warmup_skip: int = 1,
) -> dict[str, Any]:
    """Per-candidate ``elapsed_baseline / elapsed_probe``, skipping the first
    ``warmup_skip`` candidates (the untimed-model-load outlier the fill loop
    already excludes) and any candidate whose probe elapsed is zero. The median
    coefficient is what REPLAY_SAFE_SIZING would multiply a probe-cap latency by
    to recover the true replay cost."""
    base_idx = _by_index(baseline)
    probe_idx = _by_index(probe)
    shared = sorted(set(base_idx) & set(probe_idx))[max(0, int(warmup_skip)):]

    ratios: list[float] = []
    base_elapsed: list[float] = []
    probe_elapsed: list[float] = []
    for index in shared:
        b = float(base_idx[index].get("elapsed_s") or 0.0)
        p = float(probe_idx[index].get("elapsed_s") or 0.0)
        if p <= 0.0:
            continue
        ratios.append(b / p)
        base_elapsed.append(b)
        probe_elapsed.append(p)

    if not ratios:
        return {
            "samples": 0,
            "coef_p50": 0.0,
            "coef_mean": 0.0,
            "baseline_warm_mean": 0.0,
            "probe_warm_mean": 0.0,
        }

    return {
        "samples": len(ratios),
        "coef_p50": round(statistics.median(ratios), 4),
        "coef_mean": round(statistics.fmean(ratios), 4),
        "baseline_warm_mean": round(statistics.fmean(base_elapsed), 4),
        "probe_warm_mean": round(statistics.fmean(probe_elapsed), 4),
    }


# ---- model-running wrapper (reuses run_gguf_validation) ------------------

def probe_model(
    *,
    model_name: str,
    candidates: list[Any],
    hops_list: list[int],
    baseline_hop: int,
    probe_hop: int,
    budget_per_model_s: float,
    env_selection: str,
    payload: str,
    fail_fast: bool,
    warmup_skip: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Replay the SAME candidate set at each hop cap, then analyse the baseline
    vs probe pair. Returns (per-model analysis, tagged raw records)."""
    records_by_hop: dict[int, list[dict[str, Any]]] = {}
    result_by_hop: dict[int, dict[str, Any]] = {}
    raw_rows: list[dict[str, Any]] = []
    for hop in hops_list:
        result, records = rgv.run_model(
            model_name=model_name,
            candidates=candidates,
            budget_per_model_s=budget_per_model_s,
            max_tool_hops=hop,
            env_selection=env_selection,
            payload=payload,
            fail_fast=fail_fast,
        )
        records_by_hop[hop] = records
        result_by_hop[hop] = result
        for record in records:
            raw_rows.append({**record, "hop_cap": hop})

    baseline = records_by_hop.get(baseline_hop, [])
    probe = records_by_hop.get(probe_hop, [])
    analysis = {
        "model": model_name,
        "hops": hops_list,
        "baseline_hop": baseline_hop,
        "probe_hop": probe_hop,
        "hit_rate_invariance": hit_rate_invariance(baseline, probe),
        "calibration": calibration_coefficient(baseline, probe, warmup_skip=warmup_skip),
        "per_hop": {
            str(hop): {
                "exact_payload_hits": result_by_hop[hop]["exact_payload_hits"],
                "hit_rate": result_by_hop[hop]["hit_rate"],
                "warm_seconds_per_candidate_mean": result_by_hop[hop][
                    "warm_seconds_per_candidate_mean"
                ],
                "seconds_per_candidate_mean": result_by_hop[hop][
                    "seconds_per_candidate_mean"
                ],
                "time_taken_s": result_by_hop[hop]["time_taken_s"],
            }
            for hop in hops_list
        },
    }
    return analysis, raw_rows


def parse_hops(value: str) -> list[int]:
    hops = [int(item.strip()) for item in value.split(",") if item.strip()]
    if not hops or any(h <= 0 for h in hops):
        raise ValueError("--hops must be positive integers")
    return sorted(dict.fromkeys(hops))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=12, help="candidate count to replay")
    parser.add_argument("--models", default="gpt_oss,gemma", help="comma-separated model names")
    parser.add_argument("--budget-per-model", type=float, default=3000.0)
    parser.add_argument("--hops", default="1,8", help="comma-separated hop caps to replay at")
    parser.add_argument("--baseline-hop", type=int, default=8)
    parser.add_argument("--probe-hop", type=int, default=1)
    parser.add_argument("--warmup-skip", type=int, default=1)
    parser.add_argument("--env-selection", choices=("gym", "sandbox"), default="gym")
    parser.add_argument("--payload", default=rgv.DEFAULT_PAYLOAD)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--raw-out", type=Path, default=DEFAULT_RAW_OUT)
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args()

    if args.n <= 0:
        parser.error("--n must be positive")
    if args.budget_per_model <= 0:
        parser.error("--budget-per-model must be positive")

    hops_list = parse_hops(args.hops)
    if args.baseline_hop not in hops_list or args.probe_hop not in hops_list:
        parser.error("--baseline-hop and --probe-hop must both appear in --hops")

    rgv.add_import_paths()
    rgv.set_default_gguf_env()
    models = rgv.parse_models(args.models)
    candidates = rgv.generate_candidates(
        n=args.n, budget_s=args.budget_per_model, max_tool_hops=args.baseline_hop
    )

    analyses: dict[str, Any] = {}
    raw_rows: list[dict[str, Any]] = []
    for model_name in models:
        analysis, rows = probe_model(
            model_name=model_name,
            candidates=candidates,
            hops_list=hops_list,
            baseline_hop=args.baseline_hop,
            probe_hop=args.probe_hop,
            budget_per_model_s=args.budget_per_model,
            env_selection=args.env_selection,
            payload=args.payload,
            fail_fast=args.fail_fast,
            warmup_skip=args.warmup_skip,
        )
        analyses[model_name] = analysis
        raw_rows.extend(rows)

    all_invariant = all(
        a["hit_rate_invariance"]["invariant"] for a in analyses.values()
    )
    summary = {
        "created_at": rgv.now_iso(),
        "validation_n": args.n,
        "hops": hops_list,
        "baseline_hop": args.baseline_hop,
        "probe_hop": args.probe_hop,
        "env_selection": args.env_selection,
        "payload": args.payload,
        "models": models,
        "hit_rate_invariant_all_models": all_invariant,
        "analyses": analyses,
    }

    rgv.write_json(args.out, summary)
    rgv.write_jsonl(args.raw_out, raw_rows)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if all_invariant else 2


if __name__ == "__main__":
    raise SystemExit(main())
