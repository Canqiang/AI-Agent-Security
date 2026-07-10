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

_MARGIN_RE = re.compile(r"^MARGIN_S = [0-9.]+(\s*#.*)?$", re.MULTILINE)
_FRAC_RE = re.compile(r"^FILL_BUDGET_FRAC = [0-9.]+(\s*#.*)?$", re.MULTILINE)
# 2026-07-09: the engine gained a per-model adaptive margin floor. Sweeping
# MARGIN_FLOOR_MIN down (toward 0) reclaims fill cushion for a genuinely fast
# model; setting it >= MARGIN_S degenerates the adaptive margin back to the old
# flat floor (a clean "flat" anchor). Only the assignment line is matched -- the
# constant's multi-line explanatory comment below it is left byte-identical.
_FLOOR_RE = re.compile(r"^MARGIN_FLOOR_MIN = [0-9.]+(\s*#.*)?$", re.MULTILINE)


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


def rung_attack_code(rung: Rung, base_source: str) -> str:
    text, n_margin = _MARGIN_RE.subn(
        f"MARGIN_S = {rung.margin_s}               # 07-06 live-fill sweep rung: {rung.name}",
        base_source,
    )
    if n_margin != 1:
        raise ValueError(f"expected exactly one MARGIN_S assignment, found {n_margin}")
    text, n_frac = _FRAC_RE.subn(
        f"FILL_BUDGET_FRAC = {rung.fill_budget_frac}       # 07-06 live-fill sweep rung: {rung.name}",
        text,
    )
    if n_frac != 1:
        raise ValueError(f"expected exactly one FILL_BUDGET_FRAC assignment, found {n_frac}")
    if rung.floor_min is not None:
        text, n_floor = _FLOOR_RE.subn(
            f"MARGIN_FLOOR_MIN = {rung.floor_min}       # 07-09 adaptive floor_min sweep rung: {rung.name}",
            text,
        )
        if n_floor != 1:
            raise ValueError(f"expected exactly one MARGIN_FLOOR_MIN assignment, found {n_floor}")
    return text


def write_variant(rung: Rung, out_root: Path) -> dict[str, Any]:
    base_source = BASE_SOURCE.read_text(encoding="utf-8")
    code = rung_attack_code(rung, base_source)

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
        "floor_min": rung.floor_min,
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
