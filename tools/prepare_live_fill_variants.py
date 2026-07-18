"""Build Kaggle submission variants that sweep the live validation-fill cushion
(MARGIN_S, FILL_BUDGET_FRAC) over the engine in `src/attack.py`.

2026-07-06 context: `src/attack.py` was rebuilt from probe-then-blind-emit to
LIVE per-model validation-fill (memory break60-recipe-2026-07-06 / spec
2026-07-06-live-validation-fill-design). The fill self-sizes N to each model's
real speed and keeps only firing candidates, so the ONLY tuning knob is the
safety cushion: MARGIN_S seconds of headroom before the per-model deadline, plus
FILL_BUDGET_FRAC of the budget. yusuke's live 60.125 kernel laddered the cushion
DOWN (50->45->44->42->37), each tighter margin gaining points up to the
whole-submission-0 timeout edge. This script generates canary-first sibling rungs
that vary only those two knobs -- TEMPLATE, PAYLOAD, and the fill loop stay
byte-identical to `src/attack.py` -- so a fresh submission quota maps where
today's real timeout wall sits instead of guessing one aggressive value.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
BASE_NOTEBOOK = REPO / "notebooks" / "submission.ipynb"
BASE_SOURCE = REPO / "src" / "attack.py"
DEFAULT_OUT_ROOT = REPO / "kaggle_push" / "submission_variants"
KERNEL_ID = "canqiang/aiagsec-submission"
KERNEL_TITLE = "AIAgSec Submission"


@dataclass(frozen=True)
class Rung:
    name: str
    margin_s: float
    fill_budget_frac: float
    description: str
    # None -> leave MARGIN_FLOOR_MIN at the source default (backward compatible
    # with the pre-adaptive-engine rungs). A value bakes an adaptive floor_min
    # (or, when >= margin_s, a flat-margin anchor).
    floor_min: float | None = None
    # None -> leave BURST_K at the source default (1 == single-post, unchanged).
    # A value bakes hop-saturation: each candidate's single message drives that
    # many http.post calls in one trace (2026-07-13 empirical test; keep <= the
    # grader's max_tool_hops of 4-8). See frontier-technique-research memo.
    burst_k: int | None = None
    # None -> leave SPLIT_BY_LATENCY at the source default (False). A value
    # bakes the per-model split-messages mechanism on/off for this variant.
    split_by_latency: bool | None = None
    # None -> leave REPLAY_SAFE_SIZING at the source default (False). A value bakes
    # the 2026-07-18 replay-safe sizing stop (accumulate KEPT candidates' measured
    # replay cost, cap at REPLAY_SAFE_FRAC * replay budget) on/off for this variant.
    replay_safe_sizing: bool | None = None
    # None -> leave REPLAY_SAFE_FRAC at the source default (0.99). A value bakes a
    # tighter/looser clamp (e.g. 0.97 as a hedge against the replay-overrun void).
    replay_safe_frac: float | None = None


RUNGS: dict[str, Rung] = {
    # Canary-first: largest MARGIN_S (safest) first, tightening downward toward
    # yusuke's proven-safe ~37 floor. FILL_BUDGET_FRAC climbs to 1.0 in step.
    "fill_canary_m90_f085": Rung(
        name="fill_canary_m90_f085",
        margin_s=90.0,
        fill_budget_frac=0.85,
        description="canary == engine default; confirm live-fill LANDS (no format-error) and > 47",
    ),
    "fill_step_m60_f090": Rung(
        name="fill_step_m60_f090",
        margin_s=60.0,
        fill_budget_frac=0.90,
        description="moderate tighten",
    ),
    "fill_step_m45_f095": Rung(
        name="fill_step_m45_f095",
        margin_s=45.0,
        fill_budget_frac=0.95,
        description="aggressive tighten; approaching yusuke's ladder",
    ),
    "fill_push_m40_f100": Rung(
        name="fill_push_m40_f100",
        margin_s=40.0,
        fill_budget_frac=1.0,
        description="near yusuke's proven 37; full-budget fill -> chase the 57-60 band",
    ),
}


def load_notebook(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("cells"), list):
        raise ValueError(f"{path} is not a notebook JSON object")
    return data


def kernel_metadata() -> dict[str, Any]:
    return {
        "id": KERNEL_ID,
        "title": KERNEL_TITLE,
        "code_file": "submission.ipynb",
        "language": "python",
        "kernel_type": "notebook",
        "is_private": True,
        "enable_gpu": True,
        "enable_tpu": False,
        "enable_internet": False,
        "machine_shape": "NvidiaTeslaT4",
        "dataset_sources": [],
        "competition_sources": ["ai-agent-security-multi-step-tool-attacks"],
        "kernel_sources": [],
    }


def _substitute_once(
    text: str, const: str, value: int | float | bool, comment: str
) -> str:
    r"""Replace the single `<const> = <value>` assignment (with any inline
    `# comment`) by `<const> = <value>       # <comment>`, matching ONLY that
    one line and raising if it is not found exactly once. Values may be ints,
    floats, or the Python boolean literals True/False.

    The optional inline-comment group uses `[ \t]*` (horizontal whitespace), NOT
    `\s*`: `\s` matches newlines, so `\s*#.*` on an assignment that carries no
    inline comment would span the line boundary and silently swallow a following
    comment-only continuation line -- breaking the tool's
    byte-identical-outside-the-swept-line invariant while the exactly-once guard
    still sees one match. The replacement is a *function* so backslashes / group
    references in `comment` (e.g. a rung name like `fm\1`) stay literal instead
    of being interpreted as regex replacement escapes.
    """
    pattern = re.compile(
        rf"^{re.escape(const)} = (?:[0-9.]+|True|False)([ \t]*#.*)?$",
        re.MULTILINE,
    )
    new_line = f"{const} = {value}       # {comment}"
    text, n = pattern.subn(lambda _m: new_line, text)
    if n != 1:
        raise ValueError(f"expected exactly one {const} assignment, found {n}")
    return text


def _source_value(text: str, const: str) -> float | None:
    """Read the numeric value of `<const> = <number>` from source text, or None
    if the constant is absent -- used to record the value a rung actually bakes
    into its variant when it leaves that knob unswept (rather than a bare null)."""
    match = re.search(rf"^{re.escape(const)} = ([0-9.]+)", text, re.MULTILINE)
    return float(match.group(1)) if match else None


def _source_value_bool(text: str, const: str) -> bool | None:
    """Read `<const> = True|False` from source text, or None if absent."""
    match = re.search(rf"^{re.escape(const)} = (True|False)", text, re.MULTILINE)
    return match.group(1) == "True" if match else None


def _source_value_int(text: str, const: str) -> int | None:
    """Read a signed integer assignment without conflating zero with missing."""
    match = re.search(rf"^{re.escape(const)} = (-?[0-9]+)", text, re.MULTILINE)
    return int(match.group(1)) if match else None


def _effective_burst_k(rung: Rung, base_source: str) -> int:
    """Return the configured BURST_K shared by validation and the manifest."""
    if rung.burst_k is not None:
        return int(rung.burst_k)
    source_value = _source_value_int(base_source, "BURST_K")
    return source_value if source_value is not None else 1


def rung_attack_code(rung: Rung, base_source: str) -> str:
    effective_burst_k = _effective_burst_k(rung, base_source)
    source_split = _source_value_bool(base_source, "SPLIT_BY_LATENCY")
    effective_split = (
        rung.split_by_latency
        if rung.split_by_latency is not None
        else bool(source_split)
    )
    if effective_burst_k < 1:
        raise ValueError(
            "effective burst_k must be at least 1; invalid with split_by_latency"
        )
    if effective_burst_k != 1 and effective_split:
        raise ValueError(
            "effective burst_k must equal 1 when split_by_latency=True"
        )

    text = _substitute_once(base_source, "MARGIN_S", rung.margin_s,
                            f"07-06 live-fill sweep rung: {rung.name}")
    text = _substitute_once(text, "FILL_BUDGET_FRAC", rung.fill_budget_frac,
                            f"07-06 live-fill sweep rung: {rung.name}")
    if rung.floor_min is not None:
        text = _substitute_once(text, "MARGIN_FLOOR_MIN", rung.floor_min,
                                f"07-09 adaptive floor_min sweep rung: {rung.name}")
    if rung.burst_k is not None:
        text = _substitute_once(text, "BURST_K", rung.burst_k,
                                f"07-13 hop-saturation burst rung: {rung.name}")
    if rung.split_by_latency is not None:
        text = _substitute_once(
            text,
            "SPLIT_BY_LATENCY",
            rung.split_by_latency,
            f"07-11 per-model split-messages rung: {rung.name}",
        )
    if rung.replay_safe_sizing is not None:
        text = _substitute_once(
            text,
            "REPLAY_SAFE_SIZING",
            rung.replay_safe_sizing,
            f"07-18 replay-safe sizing rung: {rung.name}",
        )
    if rung.replay_safe_frac is not None:
        text = _substitute_once(
            text,
            "REPLAY_SAFE_FRAC",
            rung.replay_safe_frac,
            f"07-18 replay-safe sizing rung: {rung.name}",
        )
    return text


def write_variant(rung: Rung, out_root: Path) -> dict[str, Any]:
    base_source = BASE_SOURCE.read_text(encoding="utf-8")
    code = rung_attack_code(rung, base_source)
    effective_burst_k = _effective_burst_k(rung, base_source)
    source_split = _source_value_bool(base_source, "SPLIT_BY_LATENCY")
    effective_split = (
        rung.split_by_latency
        if rung.split_by_latency is not None
        else bool(source_split)
    )
    split_threshold_s = _source_value(base_source, "SPLIT_THRESHOLD_S")
    split_classify_n = _source_value(base_source, "SPLIT_CLASSIFY_N")

    notebook = load_notebook(BASE_NOTEBOOK)
    code_cell = notebook["cells"][2]
    if code_cell.get("cell_type") != "code":
        raise ValueError("expected submission attack cell at index 2")
    source = "%%writefile /kaggle/working/attack.py\n" + code
    code_cell["source"] = [line + "\n" for line in source.splitlines()]
    code_cell["outputs"] = []
    code_cell["execution_count"] = None

    out_dir = out_root / rung.name
    out_dir.mkdir(parents=True, exist_ok=True)
    notebook_path = out_dir / "submission.ipynb"
    metadata_path = out_dir / "kernel-metadata.json"
    manifest_path = out_dir / "variant-manifest.json"
    source_path = out_dir / "attack.py"
    notebook_path.write_text(json.dumps(notebook, indent=1) + "\n", encoding="utf-8")
    metadata_path.write_text(
        json.dumps(kernel_metadata(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    source_path.write_text(code, encoding="utf-8")

    manifest = {
        "name": rung.name,
        "chain_k": 1,
        "mode": "live_validation_fill_sweep",
        # n_candidates is a display upper bound (SDK cap); the live fill self-sizes.
        "n_candidates": 2000,
        "margin_s": rung.margin_s,
        "fill_budget_frac": rung.fill_budget_frac,
        # None means the rung left MARGIN_FLOOR_MIN at the source default, but the
        # variant still bakes that default in -- record the effective value so a
        # later knob->score correlation reads the baseline point, not a null.
        "floor_min": (rung.floor_min if rung.floor_min is not None
                      else _source_value(base_source, "MARGIN_FLOOR_MIN")),
        "burst_k": effective_burst_k,
        "split_by_latency": effective_split,
        "split_threshold_s": split_threshold_s,
        "split_classify_n": (
            max(1, int(split_classify_n))
            if split_classify_n is not None
            else None
        ),
        # None means the rung left the knob at the source default; still record the
        # effective baked value (not a bare null) for a later knob->score read.
        "replay_safe_sizing": (
            rung.replay_safe_sizing if rung.replay_safe_sizing is not None
            else _source_value_bool(base_source, "REPLAY_SAFE_SIZING")
        ),
        "replay_safe_frac": (
            rung.replay_safe_frac if rung.replay_safe_frac is not None
            else _source_value(base_source, "REPLAY_SAFE_FRAC")
        ),
        "expected_public_score": None,
        "description": rung.description,
        "folder": str(out_dir),
        "notebook": str(notebook_path),
        "metadata": str(metadata_path),
        "source": str(source_path),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def parse_rungs(value: str) -> list[Rung]:
    names = [item.strip() for item in value.split(",") if item.strip()]
    unknown = sorted(set(names) - set(RUNGS))
    if unknown:
        raise ValueError(f"unknown rung(s): {', '.join(unknown)}")
    return [RUNGS[name] for name in names]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rungs", default=",".join(RUNGS), help="comma-separated rung names")
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    args = parser.parse_args()

    manifests = [write_variant(rung, args.out_root) for rung in parse_rungs(args.rungs)]
    print(json.dumps({"ok": True, "variants": manifests}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
